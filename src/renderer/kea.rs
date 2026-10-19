use crate::config::schema::*;
use anyhow::Result;
use serde_json::json;

/// Render kea-dhcp4 JSON config from routerd config.
pub fn render(config: &Config) -> Result<String> {
    render_with_lease_commands(config, lease_commands_library())
}

// Distribution packages install this hook in different library directories.
fn lease_commands_library() -> Option<&'static str> {
    [
        "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so",
        "/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so",
        "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
        "/usr/lib64/kea/hooks/libdhcp_lease_cmds.so",
        "/usr/local/lib/kea/hooks/libdhcp_lease_cmds.so",
    ]
    .into_iter()
    .find(|path| std::path::Path::new(path).is_file())
}

fn render_with_lease_commands(config: &Config, library: Option<&str>) -> Result<String> {
    // Gateway: use LAN IP
    let default_gateway = config
        .interfaces
        .lan()
        .and_then(|lan| lan.static_config.as_ref())
        .map(|cfg| ip_from_cidr(&cfg.address).to_string())
        .unwrap_or_else(|| "192.168.1.1".to_string());

    let mut subnet4 = Vec::new();

    for (i, pool) in config.dhcp.pools.iter().enumerate() {
        if !pool.enabled {
            continue;
        }

        let lease_secs = lease_duration_seconds(&pool.lease_time).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid lease time for pool '{}': {}",
                pool.name,
                pool.lease_time
            )
        })?;

        // Gateway: pool override or default LAN IP
        let gateway = if pool.gateway.is_empty() {
            config
                .interfaces
                .items
                .iter()
                .filter(|interface| {
                    interface.method == InterfaceMethod::Static && !interface.is_wan()
                })
                .filter_map(|interface| interface.static_config.as_ref())
                .map(|settings| ip_from_cidr(&settings.address))
                .find(|address| is_ip_in_cidr(address, &pool.subnet))
                .map(str::to_owned)
                .unwrap_or_else(|| default_gateway.clone())
        } else {
            pool.gateway.clone()
        };

        // DNS servers: pool config or fallback to gateway
        let dns_servers = if pool.dns_servers.is_empty() {
            gateway.clone()
        } else {
            pool.dns_servers.join(", ")
        };

        let mut options = vec![
            json!({ "name": "routers", "data": gateway }),
            json!({ "name": "domain-name-servers", "data": dns_servers }),
        ];
        let domain = pool.domain.trim();
        if !domain.is_empty() {
            options.push(json!({ "name": "domain-name", "data": domain }));
        }

        let mut subnet = json!({
            "id": (i + 1) as u32,
            "subnet": pool.subnet,
            "pools": [{
                "pool": format!("{} - {}", pool.range.start, pool.range.end)
            }],
            "option-data": options,
            "valid-lifetime": lease_secs,
            "max-valid-lifetime": lease_secs * 2
        });

        // Add static leases that fall within this pool's subnet
        let pool_leases: Vec<&StaticLease> = config
            .dhcp
            .static_leases
            .iter()
            .filter(|lease| is_ip_in_cidr(&lease.ip, &pool.subnet))
            .collect();

        if !pool_leases.is_empty() {
            let reservations: Vec<serde_json::Value> = pool_leases
                .iter()
                .map(|lease| {
                    json!({
                        "hw-address": crate::config::validator::mac_identity(&lease.mac),
                        "ip-address": lease.ip,
                        "hostname": lease.hostname
                    })
                })
                .collect();
            subnet["reservations"] = serde_json::Value::Array(reservations);
        }

        subnet4.push(subnet);
    }

    // Interfaces: bind to all LAN interfaces
    let lan_ifaces: Vec<&str> = config
        .interfaces
        .items
        .iter()
        .filter(|i| i.method == InterfaceMethod::Static && !i.is_wan() && !i.name.is_empty())
        .map(|i| i.name.as_str())
        .collect();
    let ifaces: Vec<&str> = if lan_ifaces.is_empty() {
        vec!["lo"]
    } else {
        lan_ifaces
    };

    let mut kea_config = json!({
        "Dhcp4": {
            "expired-leases-processing": {
                "hold-reclaimed-time": config.dhcp.hold_reclaimed_time
            },
            "interfaces-config": {
                "interfaces": ifaces
            },
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea-dhcp4.sock"
            },
            "lease-database": {
                "type": "memfile",
                "persist": true,
                "name": "/var/lib/kea/kea-leases4.csv"
            },
            "loggers": [{
                "name": "kea-dhcp4",
                "output_options": [{ "output": "syslog" }],
                "severity": "INFO"
            }],
            "subnet4": subnet4
        }
    });

    if let Some(library) = library {
        kea_config["Dhcp4"]["hooks-libraries"] = json!([{ "library": library }]);
    }
    let out = serde_json::to_string_pretty(&kea_config)?;
    Ok(out)
}

/// Check if an IP falls within a CIDR subnet.
fn is_ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let ip_parts: Vec<u8> = match ip.split('.').map(|p| p.parse::<u8>()).collect() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if ip_parts.len() != 4 {
        return false;
    }
    let ip_u32 = ((ip_parts[0] as u32) << 24)
        | ((ip_parts[1] as u32) << 16)
        | ((ip_parts[2] as u32) << 8)
        | (ip_parts[3] as u32);

    let (net_str, prefix_len) = match cidr.split_once('/') {
        Some((net, prefix)) => (net, prefix.parse::<u32>().unwrap_or(32)),
        None => (cidr, 32),
    };
    let net_parts: Vec<u8> = match net_str.split('.').map(|p| p.parse::<u8>()).collect() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if net_parts.len() != 4 {
        return false;
    }
    let net_u32 = ((net_parts[0] as u32) << 24)
        | ((net_parts[1] as u32) << 16)
        | ((net_parts[2] as u32) << 8)
        | (net_parts[3] as u32);

    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    (ip_u32 & mask) == (net_u32 & mask)
}

/// Extract IP from CIDR notation.
fn ip_from_cidr(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or(cidr)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config_with_pool(subnet: &str, start: &str, end: &str) -> Config {
        Config {
            interfaces: Interfaces {
                items: vec![InterfaceConfig {
                    name: "eth1".into(),
                    label: "LAN".into(),
                    method: InterfaceMethod::Static,
                    static_config: Some(StaticConfig {
                        address: "192.168.1.1/24".into(),
                        gateway: String::new(),
                        dns: vec![],
                    }),
                    ..Default::default()
                }],
            },
            dhcp: Dhcp {
                pools: vec![DhcpPool {
                    name: "default".into(),
                    subnet: subnet.into(),
                    range: DhcpRange {
                        start: start.into(),
                        end: end.into(),
                    },
                    ..DhcpPool::default()
                }],
                ..Dhcp::default()
            },
            ..Config::default()
        }
    }

    #[test]
    fn reclaimed_lease_retention_defaults_and_renders() {
        let dhcp: Dhcp = serde_json::from_str(r#"{"pools":[],"static_leases":[]}"#).unwrap();
        assert_eq!(dhcp.hold_reclaimed_time, 3600);
        let mut config = Config::default();
        for seconds in [3600, 0, 7200, u32::MAX] {
            config.dhcp.hold_reclaimed_time = seconds;
            let output: serde_json::Value =
                serde_json::from_str(&render(&config).unwrap()).unwrap();
            assert_eq!(
                output["Dhcp4"]["expired-leases-processing"]["hold-reclaimed-time"],
                seconds
            );
            let saved = serde_json::to_string(&config.dhcp).unwrap();
            assert_eq!(
                serde_json::from_str::<Dhcp>(&saved)
                    .unwrap()
                    .hold_reclaimed_time,
                seconds
            );
        }
        for invalid in ["-1", "1.5", "4294967296"] {
            assert!(serde_json::from_str::<Dhcp>(&format!(
                r#"{{"hold_reclaimed_time":{invalid}}}"#
            ))
            .is_err());
        }
    }

    #[test]
    fn lease_commands_hook_is_optional() {
        let config = Config::default();
        let without: serde_json::Value =
            serde_json::from_str(&render_with_lease_commands(&config, None).unwrap()).unwrap();
        assert!(without["Dhcp4"].get("hooks-libraries").is_none());
        let with: serde_json::Value = serde_json::from_str(
            &render_with_lease_commands(&config, Some("/isolated/libdhcp_lease_cmds.so")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            with["Dhcp4"]["hooks-libraries"][0]["library"],
            "/isolated/libdhcp_lease_cmds.so"
        );
    }

    #[test]
    fn vlan_pools_bind_to_their_lan_and_derive_a_gateway_in_their_own_subnet() {
        let mut config = crate::config::routing::test_config();
        config.dhcp.pools = vec![
            DhcpPool {
                subnet: "192.168.0.0/23".into(),
                dns_servers: vec![],
                ..DhcpPool::default()
            },
            DhcpPool {
                name: "vlan".into(),
                subnet: "192.168.2.0/23".into(),
                range: DhcpRange {
                    start: "192.168.2.100".into(),
                    end: "192.168.2.200".into(),
                },
                dns_servers: vec![],
                ..DhcpPool::default()
            },
        ];
        let value: serde_json::Value = serde_json::from_str(&render(&config).unwrap()).unwrap();
        assert_eq!(
            value["Dhcp4"]["interfaces-config"]["interfaces"],
            json!(["lan0", "vlan2"])
        );
        for (index, expected) in [(0, "192.168.0.1"), (1, "192.168.2.1")] {
            let options = value["Dhcp4"]["subnet4"][index]["option-data"]
                .as_array()
                .unwrap();
            for name in ["routers", "domain-name-servers"] {
                assert_eq!(
                    options
                        .iter()
                        .find(|option| option["name"] == name)
                        .unwrap()["data"],
                    expected
                );
            }
        }
        config.dhcp.pools[1].gateway = "192.168.2.254".into();
        let value: serde_json::Value = serde_json::from_str(&render(&config).unwrap()).unwrap();
        assert_eq!(
            value["Dhcp4"]["subnet4"][1]["option-data"][0]["data"],
            "192.168.2.254"
        );
    }

    #[test]
    #[ignore = "requires root, unshare, ip and kea-dhcp4; checks a temporary config in an isolated network namespace"]
    fn native_check_internal_and_vlan_pools() {
        let mut config = Config::default();
        config.interfaces.items = serde_json::from_value(json!([
            {"name":"lan0","method":"static","static_config":{"address":"192.168.1.1/24"}},
            {"name":"vlan2","method":"static","vlan_id":2,"parent":"lan0","static_config":{"address":"192.168.2.1/24"}}
        ])).unwrap();
        config.dhcp.pools.push(DhcpPool {
            name: "vlan".into(),
            subnet: "192.168.2.0/24".into(),
            range: DhcpRange {
                start: "192.168.2.100".into(),
                end: "192.168.2.200".into(),
            },
            dns_servers: vec![],
            ..DhcpPool::default()
        });
        assert!(crate::config::validator::validate(&config).is_empty());
        let staged = crate::service::files::StagedFile::new(
            &std::env::temp_dir(),
            render(&config).unwrap().as_bytes(),
            0o644,
        )
        .unwrap();
        let kea = crate::service::manager::find_command("kea-dhcp4").unwrap();
        let script = r#"
import subprocess,sys
for args in [
    ['link','set','lo','up'],
    ['link','add','lan0','type','dummy'],
    ['addr','add','192.168.1.1/24','dev','lan0'],
    ['link','set','lan0','up'],
    ['link','add','link','lan0','name','vlan2','type','vlan','id','2'],
    ['addr','add','192.168.2.1/24','dev','vlan2'],
    ['link','set','vlan2','up'],
]:
    subprocess.run(['ip', *args], check=True, timeout=5)
subprocess.run([sys.argv[2], '-t', sys.argv[1]], check=True, timeout=15)
"#;
        let output = std::process::Command::new("unshare")
            .args(["-n", "python3", "-c", script])
            .arg(staged.path())
            .arg(kea)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_render_default() {
        let config = make_config_with_pool("192.168.1.0/24", "192.168.1.100", "192.168.1.250");
        let output = render(&config).unwrap();
        assert!(output.contains("\"Dhcp4\""));
        assert!(output.contains("\"subnet4\""));
        assert!(output.contains("192.168.1.0/24"));
        assert!(output.contains("192.168.1.100 - 192.168.1.250"));
        assert!(output.contains("\"routers\""));
        assert!(output.contains("lan.local"));
    }

    #[test]
    fn blank_domain_omits_option_15_without_removing_other_options() {
        let mut config = make_config_with_pool("192.168.1.0/24", "192.168.1.100", "192.168.1.250");
        for domain in ["", "   ", "\t\n", "home.example", " home.example "] {
            config.dhcp.pools[0].domain = domain.into();
            let output: serde_json::Value =
                serde_json::from_str(&render(&config).unwrap()).unwrap();
            let options = output["Dhcp4"]["subnet4"][0]["option-data"]
                .as_array()
                .unwrap();
            assert!(options.iter().any(|option| option["name"] == "routers"));
            assert!(options
                .iter()
                .any(|option| option["name"] == "domain-name-servers"));
            let domain_option = options
                .iter()
                .find(|option| option["name"] == "domain-name");
            if domain.trim().is_empty() {
                assert!(domain_option.is_none());
                assert_eq!(options.len(), 2);
            } else {
                assert_eq!(domain_option.unwrap()["data"], "home.example");
                assert_eq!(options.len(), 3);
            }
        }
    }

    #[test]
    fn test_render_multiple_pools() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![InterfaceConfig {
                    name: "eth1".into(),
                    label: "LAN".into(),
                    method: InterfaceMethod::Static,
                    static_config: Some(StaticConfig {
                        address: "192.168.1.1/24".into(),
                        gateway: String::new(),
                        dns: vec![],
                    }),
                    ..Default::default()
                }],
            },
            dhcp: Dhcp {
                pools: vec![
                    DhcpPool {
                        name: "main".into(),
                        subnet: "192.168.1.0/24".into(),
                        range: DhcpRange {
                            start: "192.168.1.100".into(),
                            end: "192.168.1.200".into(),
                        },
                        ..DhcpPool::default()
                    },
                    DhcpPool {
                        name: "guest".into(),
                        subnet: "192.168.2.0/24".into(),
                        range: DhcpRange {
                            start: "192.168.2.100".into(),
                            end: "192.168.2.200".into(),
                        },
                        gateway: "192.168.2.1".into(),
                        ..DhcpPool::default()
                    },
                ],
                ..Dhcp::default()
            },
            ..Config::default()
        };
        let output = render(&config).unwrap();
        assert!(output.contains("192.168.1.0/24"));
        assert!(output.contains("192.168.2.0/24"));
        assert!(output.contains("192.168.1.100 - 192.168.1.200"));
        assert!(output.contains("192.168.2.100 - 192.168.2.200"));
        // Second pool should use its own gateway
        assert!(output.contains("192.168.2.1"));
    }

    #[test]
    fn test_render_static_leases() {
        let mut config = make_config_with_pool("192.168.1.0/24", "192.168.1.100", "192.168.1.250");
        config.dhcp.static_leases = vec![
            StaticLease {
                mac: "AA:BB:CC:DD:EE:01".into(),
                ip: "192.168.1.10".into(),
                hostname: "nas".into(),
            },
            StaticLease {
                mac: "AA:BB:CC:DD:EE:02".into(),
                ip: "192.168.1.11".into(),
                hostname: "printer".into(),
            },
        ];
        let output = render(&config).unwrap();
        assert!(output.contains("\"reservations\""));
        assert!(output.contains("aa:bb:cc:dd:ee:01"));
        assert!(output.contains("192.168.1.10"));
    }

    #[test]
    fn test_render_disabled_pool_skipped() {
        let config = Config {
            interfaces: Interfaces {
                items: vec![InterfaceConfig {
                    name: "eth1".into(),
                    label: "LAN".into(),
                    method: InterfaceMethod::Static,
                    static_config: Some(StaticConfig {
                        address: "192.168.1.1/24".into(),
                        gateway: String::new(),
                        dns: vec![],
                    }),
                    ..Default::default()
                }],
            },
            dhcp: Dhcp {
                pools: vec![DhcpPool {
                    name: "disabled".into(),
                    subnet: "192.168.1.0/24".into(),
                    range: DhcpRange {
                        start: "192.168.1.100".into(),
                        end: "192.168.1.200".into(),
                    },
                    enabled: false,
                    ..DhcpPool::default()
                }],
                ..Dhcp::default()
            },
            ..Config::default()
        };
        let output = render(&config).unwrap();
        assert!(!output.contains("192.168.1.0/24"));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(lease_duration_seconds("12h"), Some(43200));
        assert_eq!(lease_duration_seconds("30m"), Some(1800));
        assert_eq!(lease_duration_seconds("1d"), Some(86400));
        assert_eq!(lease_duration_seconds("60s"), Some(60));
        assert_eq!(lease_duration_seconds("3600"), Some(3600));
        assert_eq!(lease_duration_seconds("4294967295d"), None);
        assert_eq!(lease_duration_seconds("4294967295"), None);
        assert_eq!(lease_duration_seconds("0"), None);
        assert_eq!(lease_duration_seconds("invalid"), None);
    }
}
