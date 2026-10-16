use super::schema::{Action, Config, InterfaceConfig, InterfaceMethod};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

pub const WAN_MARK_MASK: u32 = 0xffff0000;

pub enum WanRouteKind {
    Static {
        address: Ipv4Addr,
        subnet: String,
        gateway: Ipv4Addr,
    },
    Dhcp,
    Pppoe,
}

pub struct WanReturnRoute<'a> {
    pub name: &'a str,
    pub interface: &'a str,
    pub kind: WanRouteKind,
    pub table: u16,
    strict_mark: u32,
}

impl WanReturnRoute<'_> {
    pub fn mark(&self) -> u32 {
        u32::from(self.table) << 16
    }

    pub fn strict_mark(&self) -> u32 {
        self.strict_mark
    }

    pub fn source_address(&self) -> Option<Ipv4Addr> {
        match self.kind {
            WanRouteKind::Static { address, .. } => Some(address),
            _ => None,
        }
    }
}

pub fn automatic_return_table(interface: &str) -> u16 {
    let hash = interface.bytes().fold(2166136261u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(16777619)
    });
    (10000 + hash % 50000) as u16
}

pub fn wan_return_routes(config: &Config) -> Result<Vec<WanReturnRoute<'_>>> {
    let ppp_count = config
        .interfaces
        .items
        .iter()
        .filter(|interface| interface.method == InterfaceMethod::Pppoe)
        .count();
    if ppp_count > 1 {
        bail!("only one managed PPPoE interface is supported (ppp0)");
    }
    if ppp_count > 0
        && config
            .interfaces
            .items
            .iter()
            .any(|interface| interface.name == "ppp0")
    {
        bail!("ppp0 is reserved for the managed PPPoE connection");
    }
    let mut routes = Vec::new();
    let mut tables = HashMap::new();
    let mut addresses = HashSet::new();
    for interface in &config.interfaces.items {
        if !interface.is_wan() {
            if interface.return_route_table.is_some() || interface.return_routing == Some(true) {
                bail!("{}: return routing is a WAN-only setting", interface.name);
            }
            continue;
        }
        if interface.return_routing == Some(false) {
            continue;
        }
        let table = interface
            .return_route_table
            .unwrap_or_else(|| automatic_return_table(&interface.name));
        if matches!(table, 0 | 253 | 254 | 255) {
            bail!(
                "{}: return_route_table cannot be 0, 253, 254 or 255",
                interface.name
            );
        }
        if let Some(previous) = tables.insert(table, interface.name.as_str()) {
            bail!(
                "{} and {} select return table {}; set a unique return_route_table override",
                previous,
                interface.name,
                table
            );
        }
        let kind = match interface.method {
            InterfaceMethod::Static => static_route(interface)?,
            InterfaceMethod::Dhcp => WanRouteKind::Dhcp,
            InterfaceMethod::Pppoe => WanRouteKind::Pppoe,
        };
        if let WanRouteKind::Static { address, .. } = &kind {
            if !addresses.insert(*address) {
                bail!(
                    "{}: return-routing WAN addresses must be unique",
                    interface.name
                );
            }
        }
        routes.push(WanReturnRoute {
            name: &interface.name,
            interface: if interface.method == InterfaceMethod::Pppoe {
                "ppp0"
            } else {
                &interface.name
            },
            kind,
            table,
            strict_mark: 0,
        });
    }
    if !routes.is_empty() {
        for rule in config
            .firewall
            .rules
            .input
            .iter()
            .chain(&config.firewall.rules.forward)
        {
            if rule.enabled && rule.action == Action::Tproxy {
                let mark = rule.mark.unwrap_or(1);
                if mark & WAN_MARK_MASK != 0 || tables.contains_key(&(mark as u16)) {
                    bail!("TPROXY rule {}: mark must fit in the low 16 bits and use a different table from WAN return routing", rule.id);
                }
            }
        }
    }
    // Allocate a disjoint upper-bit mark for strict table selection, without
    // consuming TPROXY's low bits or changing existing WAN marks/table IDs.
    // Sorting keeps allocation stable across rule/interface reordering.
    let mut used: HashSet<u16> = routes.iter().map(|route| route.table).collect();
    used.insert(0);
    let mut indices: Vec<usize> = (0..routes.len()).collect();
    indices.sort_by_key(|index| routes[*index].name);
    for index in indices {
        let mut candidate = automatic_return_table(&format!("strict/{}", routes[index].name));
        let start = candidate;
        while used.contains(&candidate) {
            candidate = candidate.wrapping_add(1);
            if candidate == start {
                bail!("no free mark for strict WAN routing");
            }
        }
        used.insert(candidate);
        routes[index].strict_mark = u32::from(candidate) << 16;
    }
    Ok(routes)
}

fn static_route(interface: &InterfaceConfig) -> Result<WanRouteKind> {
    let settings = interface.static_config.as_ref().with_context(|| {
        format!(
            "{}: return routing requires static address settings",
            interface.name
        )
    })?;
    let parsed = (|| -> Option<(Ipv4Addr, u32, Ipv4Addr)> {
        let (address, prefix) = settings.address.split_once('/')?;
        Some((
            address.parse().ok()?,
            prefix.parse().ok()?,
            settings.gateway.parse().ok()?,
        ))
    })();
    let Some((address, prefix, gateway)) = parsed.filter(|(_, prefix, _)| *prefix <= 32) else {
        bail!("{}: return routing requires an IPv4 address/prefix and IPv4 gateway; disable return_routing for an IPv6-only WAN", interface.name);
    };
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    let network = u32::from(address) & mask;
    if u32::from(gateway) & mask != network || gateway == address || gateway.is_unspecified() {
        bail!(
            "{}: return routing requires a distinct gateway in the WAN subnet",
            interface.name
        );
    }
    Ok(WanRouteKind::Static {
        address,
        subnet: format!("{}/{}", Ipv4Addr::from(network), prefix),
        gateway,
    })
}

pub fn internal_ipv4_subnets(config: &Config) -> std::collections::BTreeSet<String> {
    config
        .interfaces
        .items
        .iter()
        .filter(|interface| interface.method == InterfaceMethod::Static && !interface.is_wan())
        .filter_map(|interface| interface.static_config.as_ref())
        .filter_map(|settings| {
            let (address, prefix) = settings.address.split_once('/')?;
            let address = address.parse::<std::net::Ipv4Addr>().ok()?;
            let prefix = prefix.parse::<u32>().ok().filter(|prefix| *prefix <= 32)?;
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            let network = std::net::Ipv4Addr::from(u32::from(address) & mask);
            Some(format!("{}/{}", network, prefix))
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    serde_json::from_value(serde_json::json!({
        "interfaces": { "items": [
            {"name": "wan0", "method": "static", "return_route_table": 100,
             "static_config": {"address": "203.0.113.2/29", "gateway": "203.0.113.1"}},
            {"name": "wan1", "method": "static", "return_route_table": 101,
             "static_config": {"address": "192.0.2.2/24", "gateway": "192.0.2.1"}},
            {"name": "lan0", "method": "static", "static_config": {"address": "192.168.0.1/23"}},
            {"name": "vlan2", "method": "static", "vlan_id": 2, "parent": "lan0",
             "static_config": {"address": "192.168.2.1/23"}}
        ]},
        "firewall": {"nat": {"port_forward": [
            {"proto": "tcp", "interfaces": ["wan0", "lan0", "vlan2"],
             "target_address": "203.0.113.2", "target_port": 32443,
             "redirect_address": "192.168.2.50", "redirect_port": 443}
        ]}}
    }))
    .unwrap()
}

#[cfg(test)]
pub(crate) fn outbound_test_config() -> Config {
    let mut config = test_config();
    config.firewall.sets = serde_json::from_value(serde_json::json!([
        {"name": "clients", "set_type": "ipv4_addr", "elements": "192.168.0.0/23", "interval": true},
        {"name": "remote", "set_type": "ipv4_addr", "elements": "198.51.100.0/24", "interval": true},
        {"name": "web", "set_type": "inet_service", "elements": "80\n443"}
    ])).unwrap();
    config.firewall.rules.forward = serde_json::from_value(serde_json::json!([
        {"id": 11, "action": "accept", "interfaces": ["lan0", "vlan2"],
         "saddr": "@clients", "daddr": "@remote", "proto": ["tcp", "udp"],
         "dport": "@web", "route_via": "wan0", "counter": true, "log": true},
        {"id": 12, "action": "accept", "interfaces": ["lan0"], "route_via": "wan1"}
    ]))
    .unwrap();
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_marks_are_disjoint_and_stable_across_interface_and_rule_reordering() {
        let mut config = outbound_test_config();
        config.interfaces.items[0].return_route_table = Some(automatic_return_table("strict/wan1"));
        let marks = |config: &Config| -> std::collections::BTreeMap<String, (u32, u32)> {
            wan_return_routes(config)
                .unwrap()
                .iter()
                .map(|route| (route.name.into(), (route.mark(), route.strict_mark())))
                .collect()
        };
        let original = marks(&config);
        let all: HashSet<_> = original
            .values()
            .flat_map(|(normal, strict)| [*normal, *strict])
            .collect();
        assert_eq!(all.len(), original.len() * 2);
        assert!(!all.contains(&0));
        config.interfaces.items.reverse();
        config.firewall.rules.forward.reverse();
        config.firewall.rules.forward[0].preserve_internal_routes = false;
        assert_eq!(marks(&config), original);
    }

    #[test]
    fn return_routes_are_stable_across_interface_reordering() {
        assert!(wan_return_routes(&Config::default()).unwrap().is_empty());
        let mut config = test_config();
        let routes = wan_return_routes(&config).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(
            matches!(&routes[0].kind, WanRouteKind::Static { subnet, .. } if subnet == "203.0.113.0/29")
        );
        assert_eq!(routes[0].mark(), 100 << 16);
        assert_eq!(routes[1].mark(), 101 << 16);
        config.interfaces.items.reverse();
        let routes = wan_return_routes(&config).unwrap();
        assert_eq!(
            routes
                .iter()
                .find(|route| route.interface == "wan0")
                .unwrap()
                .table,
            100
        );
        assert!(super::super::validator::validate(&config).is_empty());
    }

    #[test]
    fn automatic_tables_are_stable_and_support_explicit_opt_out() {
        let mut config = test_config();
        for interface in &mut config.interfaces.items {
            interface.return_route_table = None;
        }
        let expected = automatic_return_table("wan0");
        assert!((10000..60000).contains(&expected));
        assert_eq!(wan_return_routes(&config).unwrap()[0].table, expected);
        config.interfaces.items.reverse();
        assert_eq!(
            wan_return_routes(&config)
                .unwrap()
                .iter()
                .find(|route| route.interface == "wan0")
                .unwrap()
                .table,
            expected
        );
        config
            .interfaces
            .items
            .iter_mut()
            .find(|interface| interface.name == "wan0")
            .unwrap()
            .return_routing = Some(false);
        assert_eq!(wan_return_routes(&config).unwrap().len(), 1);
        config
            .interfaces
            .items
            .iter_mut()
            .find(|interface| interface.name == "wan1")
            .unwrap()
            .return_route_table = Some(expected);
        config
            .interfaces
            .items
            .iter_mut()
            .find(|interface| interface.name == "wan0")
            .unwrap()
            .return_routing = None;
        assert!(wan_return_routes(&config).is_err());
    }

    #[test]
    fn rejects_multiple_pppoe_and_reserved_tunnel_name() {
        let mut config = test_config();
        config.interfaces.items[0].method = InterfaceMethod::Pppoe;
        config.interfaces.items[1].method = InterfaceMethod::Pppoe;
        assert!(wan_return_routes(&config).is_err());
        config.interfaces.items[1].method = InterfaceMethod::Dhcp;
        config.interfaces.items[1].name = "ppp0".into();
        assert!(wan_return_routes(&config).is_err());
    }

    #[test]
    fn rejects_reserved_duplicate_and_conflicting_tables() {
        for table in [0, 253, 254, 255, 101] {
            let mut config = test_config();
            config.interfaces.items[0].return_route_table = Some(table);
            assert!(wan_return_routes(&config).is_err(), "table {table}");
            assert!(super::super::validator::validate(&config)
                .iter()
                .any(|error| error.field.contains("return_route_table")));
        }
        for mark in [100u32, 101, 0x10000, 0xffff0001] {
            let mut config = test_config();
            config.firewall.rules.forward.push(
                serde_json::from_value(serde_json::json!({
                    "id": 1, "action": "tproxy", "interfaces": ["lan0"],
                    "mark": mark, "tproxy_port": 12345
                }))
                .unwrap(),
            );
            assert!(wan_return_routes(&config).is_err(), "mark {mark}");
            config.firewall.rules.forward[0].mark = Some(1);
            assert!(wan_return_routes(&config).is_ok());
        }
    }

    #[test]
    fn accepts_dynamic_and_rejects_ipv6_and_unreachable_gateways() {
        for method in [InterfaceMethod::Dhcp, InterfaceMethod::Pppoe] {
            let mut config = test_config();
            config.interfaces.items[0].method = method;
            assert!(wan_return_routes(&config).is_ok());
        }
        for (address, gateway) in [
            ("2001:db8::2/64", "2001:db8::1"),
            ("203.0.113.2/33", "203.0.113.1"),
            ("203.0.113.2/29", "192.0.2.1"),
            ("203.0.113.2/29", "203.0.113.2"),
            ("203.0.113.2/29", ""),
        ] {
            let mut config = test_config();
            let settings = config.interfaces.items[0].static_config.as_mut().unwrap();
            settings.address = address.into();
            settings.gateway = gateway.into();
            assert!(
                wan_return_routes(&config).is_err(),
                "{address} via {gateway}"
            );
        }
    }
}
