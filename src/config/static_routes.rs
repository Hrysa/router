use super::schema::{Action, Config};
use super::validator::ValidationError;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Canonical network prefix, also accepting a bare IP as a host route.
pub fn destination(value: &str) -> Result<(IpAddr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, prefix)| (ip, Some(prefix)));
    let address: IpAddr = address
        .parse()
        .context("destination must be an IPv4/IPv6 address or prefix")?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = match prefix {
        Some(prefix) => prefix.parse().context("invalid prefix length")?,
        None => bits,
    };
    if prefix > bits {
        bail!("prefix length exceeds address size");
    }
    let network = match address {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(
            u32::from(ip) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0),
        )),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(
            u128::from(ip) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0),
        )),
    };
    Ok((network, prefix))
}

pub fn validate(config: &Config) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    let tproxy_tables: HashSet<_> = config
        .firewall
        .rules
        .input
        .iter()
        .chain(&config.firewall.rules.forward)
        .filter(|rule| rule.enabled && rule.action == Action::Tproxy)
        .map(|rule| rule.mark.unwrap_or(1))
        .collect();
    let wan_routes = super::routing::wan_return_routes(config).unwrap_or_default();
    for (index, route) in config.routing.routes.iter().enumerate() {
        let prefix = format!("routing.routes[{index}]");
        let mut error = |field: &str, message: &str| {
            errors.push(ValidationError {
                field: format!("{prefix}.{field}"),
                message: message.into(),
            })
        };
        if route.id == 0 || !ids.insert(route.id) {
            error("id", "route IDs must be nonzero and unique");
        }
        if !config
            .interfaces
            .items
            .iter()
            .any(|interface| interface.name == route.interface)
        {
            error(
                "interface",
                "select a configured interface (use the physical interface name for PPPoE)",
            );
        }
        if matches!(route.table, 0 | 253 | 255) || tproxy_tables.contains(&route.table) {
            error(
                "table",
                "table must be nonzero, not 253/255 or an active TPROXY table; 254 is main",
            );
        }
        if route.comment.chars().any(char::is_control) {
            error("comment", "control characters are not allowed");
        }
        if route.on_link && route.gateway.is_none() {
            error("on_link", "gateway-on-link requires a gateway");
        }
        match destination(&route.destination) {
            Err(problem) => error("destination", &problem.to_string()),
            Ok((network, length)) => {
                if route.enabled && !keys.insert((network, length, route.table, route.metric)) {
                    error("destination", "duplicate enabled route for this prefix, table and metric; multipath routes are not supported");
                }
                if let Some(gateway) = &route.gateway {
                    match gateway.parse::<IpAddr>() {
                        Ok(ip) if ip.is_ipv4() == network.is_ipv4() && !ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::V4(Ipv4Addr::BROADCAST) => {
                            if !route.on_link {
                                let settings = config.interfaces.items.iter()
                                    .find(|interface| interface.name == route.interface && interface.method == super::schema::InterfaceMethod::Static)
                                    .and_then(|interface| interface.static_config.as_ref());
                                if let Some(settings) = settings {
                                    if let Ok((subnet, prefix)) = destination(&settings.address) {
                                        let link_local = matches!(ip, IpAddr::V6(address) if address.is_unicast_link_local());
                                        if subnet.is_ipv4() == ip.is_ipv4() && !link_local && destination(&format!("{ip}/{prefix}")).ok() != Some((subnet, prefix)) {
                                            error("gateway", "gateway is outside this static interface's subnet; use gateway-on-link only if it is directly reachable");
                                        }
                                    }
                                }
                            }
                        },
                        _ => error("gateway", "gateway must be a unicast address of the same IP family as the destination"),
                    }
                }
                if route.enabled && route.table == 254 && route.metric == 0 {
                    let conflict = config
                        .interfaces
                        .items
                        .iter()
                        .filter(|interface| {
                            interface.method == super::schema::InterfaceMethod::Static
                        })
                        .filter_map(|interface| interface.static_config.as_ref())
                        .any(|settings| {
                            let connected =
                                destination(&settings.address).ok() == Some((network, length));
                            let default = length == 0
                                && settings
                                    .gateway
                                    .parse::<IpAddr>()
                                    .is_ok_and(|gateway| gateway.is_ipv4() == network.is_ipv4());
                            connected || default
                        });
                    if conflict {
                        error("metric", "metric 0 conflicts with an automatic static interface route in main; use a distinct metric");
                    }
                }
                if route.enabled && route.metric == 0 && network.is_ipv4() {
                    for wan in &wan_routes {
                        if route.table == u32::from(wan.table) {
                            let connected = match &wan.kind {
                                super::routing::WanRouteKind::Static { subnet, .. } => {
                                    destination(subnet).ok() == Some((network, length))
                                }
                                _ => false,
                            };
                            if length == 0 || connected {
                                error("metric", "metric 0 conflicts with an automatic WAN route in this table; use a distinct metric");
                            }
                        }
                    }
                }
            }
        }
    }
    errors
}

#[cfg(test)]
pub(crate) fn test_route() -> super::schema::StaticRoute {
    serde_json::from_value(serde_json::json!({"id": 1, "destination": "198.51.100.9", "gateway": "203.0.113.1", "interface": "wan0"})).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_host_and_network_destinations_for_both_families() {
        assert_eq!(
            destination("192.0.2.77/24").unwrap(),
            ("192.0.2.0".parse().unwrap(), 24)
        );
        assert_eq!(destination("192.0.2.77").unwrap().1, 32);
        assert_eq!(
            destination("2001:db8::123/64").unwrap(),
            ("2001:db8::".parse().unwrap(), 64)
        );
        assert_eq!(destination("::/0").unwrap(), ("::".parse().unwrap(), 0));
        for value in [
            "default",
            "192.0.2.1/33",
            "::1/129",
            "192.0.2.1\nScope=link",
            "::1/-1",
        ] {
            assert!(destination(value).is_err(), "{value}");
        }
    }

    #[test]
    fn validates_routes_and_rejects_collisions_and_injection() {
        let mut config = super::super::routing::test_config();
        config.routing.routes.push(test_route());
        assert!(validate(&config).is_empty());
        for (field, value) in [
            ("id", serde_json::json!(0)),
            ("table", serde_json::json!(255)),
            ("table", serde_json::json!(253)),
            ("table", serde_json::json!(0)),
            ("destination", serde_json::json!("invalid")),
            ("gateway", serde_json::json!("::1")),
            ("gateway", serde_json::json!("0.0.0.0")),
            ("gateway", serde_json::json!("192.0.2.1")),
            ("gateway", serde_json::json!("203.0.113.1\nTable=254")),
            ("interface", serde_json::json!("unknown")),
            ("comment", serde_json::json!("x\n[Route]")),
        ] {
            let mut changed = config.clone();
            let mut route = serde_json::to_value(test_route()).unwrap();
            route[field] = value;
            changed.routing.routes[0] = serde_json::from_value(route).unwrap();
            assert!(!validate(&changed).is_empty(), "accepted invalid {field}");
        }
        let mut duplicate = test_route();
        duplicate.id = 2;
        duplicate.destination = "198.51.100.9/32".into();
        config.routing.routes.push(duplicate);
        assert!(validate(&config)
            .iter()
            .any(|error| error.field.ends_with("destination")));
        config.routing.routes[1].enabled = false;
        assert!(validate(&config).is_empty());
        config.routing.routes[0].destination = "0.0.0.0/0".into();
        config.routing.routes[0].table = 100;
        config.routing.routes[0].metric = 0;
        assert!(validate(&config)
            .iter()
            .any(|error| error.field.ends_with("metric")));
    }
}
