use crate::config::schema::*;
use crate::config::routing::{internal_ipv4_subnets, wan_return_routes, WanRouteKind, WAN_MARK_MASK};
use anyhow::Result;

/// A single systemd-networkd config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkFile {
    /// Filename within /etc/systemd/network/ (e.g. "50-routerd-wan.network").
    pub filename: String,
    /// File content.
    pub content: String,
}

const PREFIX: &str = "50-routerd";

/// Render systemd-networkd config files from config.
///
/// Returns a list of .network/.netdev files to place in /etc/systemd/network/.
/// Loopback is handled automatically by systemd-networkd (no file needed).
pub fn render(config: &Config) -> Result<Vec<NetworkFile>> {
    let mut files = Vec::new();

    // Render non-VLAN interfaces first
    for iface in &config.interfaces.items {
        if iface.is_vlan() {
            continue;
        }
        if iface.is_wan() {
            render_wan(iface, &mut files);
        } else if iface.is_lan() {
            render_lan(iface, &mut files);
        }
    }

    // Render VLANs and add VLAN= directive to parent's .network file
    for iface in &config.interfaces.items {
        if iface.is_vlan() {
            render_vlan(iface, &mut files);
            // Add VLAN= directive to parent interface's .network [Network] section
            if let Some(parent) = &iface.parent {
                let parent_file = format!("{}-{}.network", PREFIX, parent);
                if let Some(pf) = files.iter_mut().find(|f| f.filename == parent_file) {
                    let vlan_line = format!("VLAN={}\n", iface.name);
                    if !pf.content.contains(&vlan_line) {
                        pf.content = pf.content.replacen("[Network]\n", &format!("[Network]\n{}", vlan_line), 1);
                    }
                }
            }
        }
    }

    // Apply the device MTU to every managed interface, independent of its role.
    for iface in &config.interfaces.items {
        if let Some(mtu) = iface.mtu {
            let filename = format!("{}-{}.network", PREFIX, iface.name);
            let file = files.iter_mut().find(|file| file.filename == filename)
                .ok_or_else(|| anyhow::anyhow!("missing network file for {}", iface.name))?;
            if file.content.contains("[Link]\n") {
                file.content = file.content.replacen("[Link]\n", &format!("[Link]\nMTUBytes={}\n", mtu), 1);
            } else {
                file.content.push_str(&format!("\n[Link]\nMTUBytes={}\n", mtu));
            }
            // For virtual devices, set creation MTU as well as link MTU.
            if let Some(netdev) = files.iter_mut().find(|file| file.filename == format!("{}-{}.netdev", PREFIX, iface.name)) {
                netdev.content = netdev.content.replacen("[NetDev]\n", &format!("[NetDev]\nMTUBytes={}\n", mtu), 1);
            }
        }
    }

    let internal_subnets = internal_ipv4_subnets(config);
    for route in wan_return_routes(config)? {
        let filename = format!("{}-{}.network", PREFIX, route.interface);
        let file = files.iter_mut().find(|file| file.filename == filename)
            .ok_or_else(|| anyhow::anyhow!("missing network file for {}", route.interface))?;
        match &route.kind {
            WanRouteKind::Static { subnet, gateway, .. } => file.content.push_str(&format!(
                "\n[Route]\nDestination={}\nScope=link\nTable={}\n\n[Route]\nDestination=0.0.0.0/0\nGateway={}\nTable={}\n",
                subnet, route.table, gateway, route.table,
            )),
            WanRouteKind::Dhcp => file.content.push_str(&format!(
                "\n[Route]\nDestination=0.0.0.0/0\nGateway=_dhcp4\nGatewayOnLink=yes\nTable={}\n", route.table,
            )),
            WanRouteKind::Pppoe => file.content.push_str(&format!(
                "\n[Route]\nDestination=0.0.0.0/0\nScope=link\nTable={}\n", route.table,
            )),
        }
        let mut selectors = vec![format!("FirewallMark={}/{}", route.mark(), WAN_MARK_MASK)];
        if let Some(address) = route.source_address() {
            selectors.push(format!("From={}/32", address));
        }
        for selector in selectors {
            for subnet in &internal_subnets {
                file.content.push_str(&format!(
                    "\n[RoutingPolicyRule]\nFamily=ipv4\n{}\nTo={}\nTable=main\nSuppressPrefixLength=0\nPriority=100\n",
                    selector, subnet,
                ));
            }
            file.content.push_str(&format!(
                "\n[RoutingPolicyRule]\nFamily=ipv4\n{}\nTable={}\nPriority=110\n",
                selector, route.table,
            ));
        }
    }

    super::routes::append(config, &mut files)?;
    Ok(files)
}


fn render_wan(iface: &InterfaceConfig, files: &mut Vec<NetworkFile>) {
    match iface.method {
        InterfaceMethod::Pppoe => {
            // Physical interface: unmanaged (pppd handles it)
            let content = format!(
                "# Managed by routerd\n\
                 [Match]\n\
                 Name={}\n\n\
                 [Link]\n\
                 Unmanaged=yes\n",
                iface.name,
            );
            let content = if iface.mtu.is_some() {
                content.replace("[Link]\nUnmanaged=yes\n", "[Network]\nDHCP=no\nLinkLocalAddressing=no\n")
            } else { content };
            files.push(NetworkFile {
                filename: format!("{}-{}.network", PREFIX, iface.name),
                content,
            });

            // PPP0 tunnel: let pppd manage, but configure routing/DNS
            let content = format!(
                "# Managed by routerd\n\
                 [Match]\n\
                 Name=ppp0\n\n\
                 [Network]\n\
                 DHCP=no\n\
                 KeepConfiguration=yes\n\
                 DNSDefaultRoute=yes\n",
            );
            files.push(NetworkFile {
                filename: format!("{}-ppp0.network", PREFIX),
                content,
            });
        }
        InterfaceMethod::Dhcp => {
            let mut sections = format!(
                "# Managed by routerd\n\
                 [Match]\n\
                 Name={}\n\n\
                 [Network]\n\
                 DHCP=yes\n",
                iface.name,
            );

            // DHCP options
            if let Some(dhcp_cfg) = &iface.dhcp {
                if dhcp_cfg.hostname.is_some() {
                    sections.push_str("\n[DHCPv4]\n");
                    if let Some(hostname) = &dhcp_cfg.hostname {
                        sections.push_str(&format!("Hostname={}\n", hostname));
                    }
                }
            }

            files.push(NetworkFile {
                filename: format!("{}-{}.network", PREFIX, iface.name),
                content: sections,
            });
        }
        InterfaceMethod::Static => {
            let mut sections = format!(
                "# Managed by routerd\n\
                 [Match]\n\
                 Name={}\n\n\
                 [Network]\n",
                iface.name,
            );

            if let Some(static_cfg) = &iface.static_config {
                sections.push_str(&format!("Address={}\n", static_cfg.address));
                if !static_cfg.gateway.is_empty() {
                    sections.push_str(&format!("Gateway={}\n", static_cfg.gateway));
                }
                for dns in &static_cfg.dns {
                    sections.push_str(&format!("DNS={}\n", dns));
                }
            }

            files.push(NetworkFile {
                filename: format!("{}-{}.network", PREFIX, iface.name),
                content: sections,
            });
        }
    }
}

fn render_lan(iface: &InterfaceConfig, files: &mut Vec<NetworkFile>) {
    if iface.name.is_empty() {
        return;
    }

    if iface.bridge_ports.is_empty() {
        // Single interface LAN — no bridge
        let mut network_content = format!(
            "# Managed by routerd\n\
             [Match]\n\
             Name={}\n\n\
             [Network]\n",
            iface.name,
        );

        if let Some(static_cfg) = &iface.static_config {
            network_content.push_str(&format!("Address={}\n", static_cfg.address));
        }

        files.push(NetworkFile {
            filename: format!("{}-{}.network", PREFIX, iface.name),
            content: network_content,
        });
    } else {
        // Bridge LAN
        let netdev_content = format!(
            "# Managed by routerd\n\
             [NetDev]\n\
             Kind=bridge\n\
             Name={}\n",
            iface.name,
        );
        files.push(NetworkFile {
            filename: format!("{}-{}.netdev", PREFIX, iface.name),
            content: netdev_content,
        });

        let mut network_content = format!(
            "# Managed by routerd\n\
             [Match]\n\
             Name={}\n\n\
             [Network]\n",
            iface.name,
        );

        if let Some(static_cfg) = &iface.static_config {
            network_content.push_str(&format!("Address={}\n", static_cfg.address));
        }

        files.push(NetworkFile {
            filename: format!("{}-{}.network", PREFIX, iface.name),
            content: network_content,
        });

        // Bridge slave ports — one Name= per port
        let mut match_section = "# Managed by routerd\n[Match]\n".to_string();
        for port in &iface.bridge_ports {
            match_section.push_str(&format!("Name={}\n", port));
        }
        let slave_content = format!(
            "{}\n[Network]\nBridge={}\n",
            match_section, iface.name,
        );
        files.push(NetworkFile {
            filename: format!("{}-{}-slave.network", PREFIX, iface.name),
            content: slave_content,
        });
    }
}

fn render_vlan(iface: &InterfaceConfig, files: &mut Vec<NetworkFile>) {
    let vlan_id = match iface.vlan_id {
        Some(id) => id,
        None => return,
    };

    // 1. VLAN netdev definition
    let netdev_content = format!(
        "# Managed by routerd — VLAN {}\n\
         [NetDev]\n\
         Kind=vlan\n\
         Name={}\n\n\
         [VLAN]\n\
         Id={}\n",
        vlan_id,
        iface.name,
        vlan_id,
    );
    files.push(NetworkFile {
        filename: format!("{}-{}.netdev", PREFIX, iface.name),
        content: netdev_content,
    });

    render_wan(iface, files);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_mtu_renders_for_physical_vlan_bridge_and_pppoe_parent() {
        let mut config = crate::config::routing::test_config();
        config.interfaces.items[0].mtu = Some(1492);
        config.interfaces.items[1].mtu = Some(1500);
        config.interfaces.items[1].method = InterfaceMethod::Pppoe;
        config.interfaces.items.push(make_lan("br0", vec!["port0".into()], None));
        config.interfaces.items.last_mut().unwrap().mtu = Some(1400);
        config.interfaces.items.push(make_vlan(10, "wan0", "vlan10", "10.10.0.1/24"));
        config.interfaces.items.last_mut().unwrap().mtu = Some(1400);
        let files = render(&config).unwrap();
        for (name, mtu) in [("wan0", 1492), ("wan1", 1500), ("br0", 1400), ("vlan10", 1400)] {
            let file = files.iter().find(|file| file.filename == format!("50-routerd-{}.network", name)).unwrap();
            assert!(file.content.contains(&format!("[Link]\nMTUBytes={}\n", mtu)), "{}", file.content);
            assert!(!file.content.contains("Unmanaged=yes"));
        }
        for name in ["br0", "vlan10"] {
            let file = files.iter().find(|file| file.filename == format!("50-routerd-{}.netdev", name)).unwrap();
            assert!(file.content.contains("[NetDev]\nMTUBytes=1400\n"));
        }
    }

    #[test]
    fn dynamic_wans_keep_main_routes_and_render_dedicated_return_routes() {
        let mut config = crate::config::routing::test_config();
        config.interfaces.items[0].method = InterfaceMethod::Dhcp;
        config.interfaces.items[1].method = InterfaceMethod::Pppoe;
        let files = render(&config).unwrap();
        let dhcp = &files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap().content;
        assert!(dhcp.contains("DHCP=yes"));
        assert!(dhcp.contains("Gateway=_dhcp4\nGatewayOnLink=yes\nTable=100"));
        assert!(dhcp.contains("FirewallMark=6553600/4294901760"));
        assert!(!dhcp.contains("From="));
        let ppp = &files.iter().find(|file| file.filename == "50-routerd-ppp0.network").unwrap().content;
        assert!(ppp.contains("KeepConfiguration=yes"));
        assert!(ppp.contains("Destination=0.0.0.0/0\nScope=link\nTable=101"));
        assert!(ppp.contains("FirewallMark=6619136/4294901760"));
        assert!(!ppp.contains("From="));
        config.interfaces.items[0].return_routing = Some(false);
        let files = render(&config).unwrap();
        let dhcp = &files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap().content;
        assert!(dhcp.contains("DHCP=yes"));
        assert!(!dhcp.contains("RoutingPolicyRule"));
    }

    #[test]
    fn return_routing_uses_networkd_tables_and_preserves_internal_routes() {
        let mut config = crate::config::routing::test_config();
        let files = render(&config).unwrap();
        let wan = files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap();
        assert!(wan.content.contains("Destination=203.0.113.0/29\nScope=link\nTable=100"));
        assert!(wan.content.contains("Destination=0.0.0.0/0\nGateway=203.0.113.1\nTable=100"));
        assert!(wan.content.contains("From=203.0.113.2/32\nTo=192.168.0.0/23\nTable=main\nSuppressPrefixLength=0\nPriority=100"));
        assert!(wan.content.contains("From=203.0.113.2/32\nTable=100\nPriority=110"));
        assert!(wan.content.contains("FirewallMark=6553600/4294901760\nTo=192.168.2.0/23\nTable=main\nSuppressPrefixLength=0\nPriority=100"));
        assert!(wan.content.contains("FirewallMark=6553600/4294901760\nTable=100\nPriority=110"));
        assert_eq!(wan.content.matches("[RoutingPolicyRule]").count(), 6);
        assert!(!files.iter().find(|file| file.filename == "50-routerd-vlan2.network").unwrap().content.contains("RoutingPolicyRule"));
        config.interfaces.items[0].return_routing = Some(false);
        let updated = render(&config).unwrap();
        let wan = updated.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap();
        assert!(!wan.content.contains("RoutingPolicyRule"));
        assert!(!wan.content.contains("Table=100"));
        assert!(wan.content.contains("Gateway=203.0.113.1"));
    }

    fn policy_tables_for_destination<'a>(content: &'a str, selector: &str, destination: &str) -> Vec<&'a str> {
        let destination = u32::from(destination.parse::<std::net::Ipv4Addr>().unwrap());
        content.split("[RoutingPolicyRule]\n").skip(1)
            .filter(|section| section.lines().any(|line| line == selector))
            .filter(|section| {
                let Some(subnet) = section.lines().find_map(|line| line.strip_prefix("To=")) else { return true };
                let (network, prefix) = subnet.split_once('/').unwrap();
                let network = u32::from(network.parse::<std::net::Ipv4Addr>().unwrap());
                let prefix = prefix.parse::<u32>().unwrap();
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                destination & mask == network & mask
            })
            .map(|section| section.lines().find_map(|line| line.strip_prefix("Table=")).unwrap())
            .collect()
    }

    #[test]
    fn external_return_destinations_cannot_consult_more_specific_main_routes() {
        let config = crate::config::routing::test_config();
        let files = render(&config).unwrap();
        for route in wan_return_routes(&config).unwrap() {
            let filename = format!("50-routerd-{}.network", route.interface);
            let wan = files.iter().find(|file| file.filename == filename).unwrap();
            let table = route.table.to_string();
            for selector in [
                format!("From={}/32", route.source_address().unwrap()),
                format!("FirewallMark={}/{}", route.mark(), WAN_MARK_MASK),
            ] {
                for external in ["1.1.1.1", "8.8.8.8", "192.0.2.50", "203.0.113.3", "192.168.4.1"] {
                    assert_eq!(policy_tables_for_destination(&wan.content, &selector, external), vec![table.as_str()], "{selector} to {external}");
                }
                for internal in ["192.168.0.50", "192.168.1.254", "192.168.2.50", "192.168.3.254"] {
                    assert_eq!(policy_tables_for_destination(&wan.content, &selector, internal), vec!["main", table.as_str()], "{selector} to {internal}");
                }
            }
        }
    }

    #[test]
    fn internal_exceptions_follow_subnet_changes_and_table_removal() {
        let mut config = crate::config::routing::test_config();
        config.interfaces.items[3].static_config.as_mut().unwrap().address = "10.20.0.1/24".into();
        let files = render(&config).unwrap();
        let wan = files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap();
        assert!(wan.content.contains("To=10.20.0.0/24\nTable=main"));
        assert!(!wan.content.contains("To=192.168.2.0/23"));
        config.interfaces.items.retain(|interface| interface.name != "vlan2");
        config.interfaces.items[0].return_route_table = Some(102);
        let files = render(&config).unwrap();
        let wan = files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap();
        assert!(!wan.content.contains("To=10.20.0.0/24"));
        assert!(wan.content.contains("Table=102\nPriority=110"));
        assert!(!wan.content.contains("Table=100\n"));
        assert!(!wan.content.contains("FirewallMark=6553600/"));
        assert!(wan.content.contains("FirewallMark=6684672/4294901760"));
    }

    #[test]
    fn internal_exceptions_exclude_wans_dynamic_interfaces_and_ipv6() {
        let mut config = crate::config::routing::test_config();
        config.interfaces.items[2].bridge_ports = vec!["eth2".into(), "eth3".into()];
        config.interfaces.items.push(InterfaceConfig {
            name: "dhcp0".into(),
            method: InterfaceMethod::Dhcp,
            static_config: Some(StaticConfig { address: "10.99.0.1/24".into(), gateway: String::new(), dns: vec![] }),
            ..Default::default()
        });
        config.interfaces.items.push(InterfaceConfig {
            name: "lan6".into(),
            method: InterfaceMethod::Static,
            static_config: Some(StaticConfig { address: "2001:db8::1/64".into(), gateway: String::new(), dns: vec![] }),
            ..Default::default()
        });
        assert_eq!(internal_ipv4_subnets(&config).into_iter().collect::<Vec<_>>(), vec!["192.168.0.0/23", "192.168.2.0/23"]);
        config.interfaces.items.retain(|interface| interface.is_wan());
        let files = render(&config).unwrap();
        let wan = files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap();
        assert!(!wan.content.contains("Table=main"));
        assert_eq!(wan.content.matches("[RoutingPolicyRule]").count(), 2);
    }

    #[test]
    fn return_routing_supports_static_vlan_wans() {
        let mut config = crate::config::routing::test_config();
        config.interfaces.items[0].vlan_id = Some(10);
        config.interfaces.items[0].parent = Some("wan1".into());
        let files = render(&config).unwrap();
        assert!(files.iter().any(|file| file.filename == "50-routerd-wan0.netdev"));
        let wan = files.iter().find(|file| file.filename == "50-routerd-wan0.network").unwrap();
        assert!(wan.content.contains("Table=100"));
    }

    #[test]
    fn dhcp_vlan_has_one_network_file_and_attaches_in_network_section() {
        let parent = make_wan(InterfaceMethod::Dhcp, None, Some(DhcpClientConfig {
            hostname: Some("router".into()),
        }), None);
        let mut vlan = make_vlan(10, "eth0", "eth0.10", "192.168.10.1/24");
        vlan.method = InterfaceMethod::Dhcp;
        vlan.static_config = None;
        let config = Config { interfaces: Interfaces { items: vec![parent, vlan] }, ..Default::default() };
        let files = render(&config).unwrap();
        let vlan_files: Vec<_> = files.iter().filter(|file| file.filename == "50-routerd-eth0.10.network").collect();
        assert_eq!(vlan_files.len(), 1);
        assert!(vlan_files[0].content.contains("DHCP=yes"));
        let parent_file = files.iter().find(|file| file.filename == "50-routerd-eth0.network").unwrap();
        assert!(parent_file.content.contains("[Network]\nVLAN=eth0.10\n"));
        assert!(parent_file.content.find("VLAN=").unwrap() < parent_file.content.find("[DHCPv4]").unwrap());
    }

    fn make_wan(method: InterfaceMethod, pppoe: Option<PppoeConfig>, dhcp: Option<DhcpClientConfig>, static_cfg: Option<StaticConfig>) -> InterfaceConfig {
        InterfaceConfig {
            mtu: None, mss_clamp_mtu: None,
            name: "eth0".into(), label: "WAN".into(), method,
            static_config: static_cfg, pppoe, dhcp,
            bridge_ports: vec![], vlan_id: None, parent: None,
            return_route_table: None,
            return_routing: None,
        }
    }

    fn make_lan(name: &str, bridge_ports: Vec<String>, static_cfg: Option<StaticConfig>) -> InterfaceConfig {
        InterfaceConfig {
            mtu: None, mss_clamp_mtu: None,
            name: name.into(), label: "LAN".into(), method: InterfaceMethod::Static,
            static_config: static_cfg, pppoe: None, dhcp: None,
            bridge_ports, vlan_id: None, parent: None,
            return_route_table: None,
            return_routing: None,
        }
    }

    fn make_vlan(vlan_id: u16, parent: &str, name: &str, address: &str) -> InterfaceConfig {
        InterfaceConfig {
            mtu: None, mss_clamp_mtu: None,
            name: name.into(), label: String::new(), method: InterfaceMethod::Static,
            static_config: Some(StaticConfig { address: address.into(), gateway: String::new(), dns: vec![] }),
            pppoe: None, dhcp: None,
            bridge_ports: vec![], vlan_id: Some(vlan_id), parent: Some(parent.into()),
            return_route_table: None,
            return_routing: None,
        }
    }

    #[test]
    fn test_render_default_pppoe() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![make_wan(InterfaceMethod::Pppoe, Some(PppoeConfig::default()), None, None)],
            },
            ..Config::default()
        };
        let files = render(&config).unwrap();

        // WAN (pppoe) + ppp0
        assert_eq!(files.len(), 2);

        let wan = files.iter().find(|f| f.filename.contains("eth0")).unwrap();
        assert!(wan.content.contains("Unmanaged=yes"));

        let ppp0 = files.iter().find(|f| f.filename == "50-routerd-ppp0.network").unwrap();
        assert!(ppp0.content.contains("Name=ppp0"));
    }

    #[test]
    fn test_render_pppoe_with_bridge() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![
                    make_wan(InterfaceMethod::Pppoe, Some(PppoeConfig::default()), None, None),
                    make_lan("br-lan", vec!["eth1".into(), "eth2".into()], Some(StaticConfig {
                        address: "192.168.1.1/24".into(), gateway: String::new(), dns: vec![],
                    })),
                ],
            },
            ..Config::default()
        };
        let files = render(&config).unwrap();

        // eth0 + ppp0 + br-lan.netdev + br-lan.network + br-lan-slave.network
        assert_eq!(files.len(), 5);
        assert!(files.iter().any(|f| f.filename == "50-routerd-br-lan.netdev"));
        assert!(files.iter().any(|f| f.filename == "50-routerd-br-lan-slave.network"));
    }

    #[test]
    fn test_render_dhcp_wan() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![make_wan(InterfaceMethod::Dhcp, None, Some(DhcpClientConfig {
                    hostname: Some("myrouter".into()),
                }), None)],
            },
            ..Config::default()
        };
        let files = render(&config).unwrap();
        let wan = files.iter().find(|f| f.filename.contains("eth0")).unwrap();
        assert!(wan.content.contains("DHCP=yes"));
        assert!(wan.content.contains("Hostname=myrouter"));
    }

    #[test]
    fn test_render_static_wan() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![make_wan(InterfaceMethod::Static, None, None, Some(StaticConfig {
                    address: "203.0.113.2/30".into(),
                    gateway: "203.0.113.1".into(),
                    dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
                }))],
            },
            ..Config::default()
        };
        let files = render(&config).unwrap();
        let wan = files.iter().find(|f| f.filename.contains("eth0")).unwrap();
        assert!(wan.content.contains("Address=203.0.113.2/30"));
        assert!(wan.content.contains("Gateway=203.0.113.1"));
        assert!(wan.content.contains("DNS=1.1.1.1"));
        assert!(wan.content.contains("DNS=8.8.8.8"));
    }

    #[test]
    fn test_render_vlans() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![
                    make_lan("eth1", vec![], Some(StaticConfig {
                        address: "192.168.1.1/24".into(), gateway: String::new(), dns: vec![],
                    })),
                    make_vlan(100, "eth1", "vlan100", "10.100.0.1/24"),
                ],
            },
            ..Config::default()
        };
        let files = render(&config).unwrap();

        // VLAN netdev
        let vlan_netdev = files.iter().find(|f| f.filename == "50-routerd-vlan100.netdev").unwrap();
        assert!(vlan_netdev.content.contains("Kind=vlan"));
        assert!(vlan_netdev.content.contains("Id=100"));

        // VLAN network
        let vlan_network = files.iter().find(|f| f.filename == "50-routerd-vlan100.network").unwrap();
        assert!(vlan_network.content.contains("Name=vlan100"));
        assert!(vlan_network.content.contains("Address=10.100.0.1/24"));

        // Parent interface should have VLAN= directive
        let parent = files.iter().find(|f| f.filename == "50-routerd-eth1.network").unwrap();
        assert!(parent.content.contains("VLAN=vlan100"), "parent .network should have VLAN=vlan100");
    }
}
