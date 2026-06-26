use crate::config::schema::*;
use anyhow::Result;

/// A single systemd-networkd config file.
#[derive(Debug, Clone)]
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
                        pf.content.push_str(&vlan_line);
                    }
                }
            }
        }
    }

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

        // Bridge slave ports
        let slave_content = format!(
            "# Managed by routerd\n\
             [Match]\n\
             Name={}\n\n\
             [Network]\n\
             Bridge={}\n",
            iface.bridge_ports.join(" "),
            iface.name,
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

    // 2. VLAN network config (static IP)
    let address = iface.static_config.as_ref()
        .map(|s| s.address.as_str())
        .unwrap_or("");

    let network_content = format!(
        "# Managed by routerd — VLAN {}\n\
         [Match]\n\
         Name={}\n\n\
         [Network]\n\
         Address={}\n",
        vlan_id,
        iface.name,
        address,
    );
    files.push(NetworkFile {
        filename: format!("{}-{}.network", PREFIX, iface.name),
        content: network_content,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wan(method: InterfaceMethod, pppoe: Option<PppoeConfig>, dhcp: Option<DhcpClientConfig>, static_cfg: Option<StaticConfig>) -> InterfaceConfig {
        InterfaceConfig {
            name: "eth0".into(), label: "WAN".into(), method,
            static_config: static_cfg, pppoe, dhcp,
            bridge_ports: vec![], vlan_id: None, parent: None,
        }
    }

    fn make_lan(name: &str, bridge_ports: Vec<String>, static_cfg: Option<StaticConfig>) -> InterfaceConfig {
        InterfaceConfig {
            name: name.into(), label: "LAN".into(), method: InterfaceMethod::Static,
            static_config: static_cfg, pppoe: None, dhcp: None,
            bridge_ports, vlan_id: None, parent: None,
        }
    }

    fn make_vlan(vlan_id: u16, parent: &str, name: &str, address: &str) -> InterfaceConfig {
        InterfaceConfig {
            name: name.into(), label: String::new(), method: InterfaceMethod::Static,
            static_config: Some(StaticConfig { address: address.into(), gateway: String::new(), dns: vec![] }),
            pppoe: None, dhcp: None,
            bridge_ports: vec![], vlan_id: Some(vlan_id), parent: Some(parent.into()),
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
