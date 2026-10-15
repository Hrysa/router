use crate::config::schema::*;
use anyhow::Result;
use serde_json::json;

/// Render kea-dhcp4 JSON config from routerd config.
pub fn render(config: &Config) -> Result<String> {
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

        let lease_secs = lease_duration_seconds(&pool.lease_time)
            .ok_or_else(|| anyhow::anyhow!("invalid lease time for pool '{}': {}", pool.name, pool.lease_time))?;

        // Gateway: pool override or default LAN IP
        let gateway = if pool.gateway.is_empty() {
            default_gateway.clone()
        } else {
            pool.gateway.clone()
        };

        // DNS servers: pool config or fallback to gateway
        let dns_servers = if pool.dns_servers.is_empty() {
            gateway.clone()
        } else {
            pool.dns_servers.join(", ")
        };

        let mut subnet = json!({
            "id": (i + 1) as u32,
            "subnet": pool.subnet,
            "pools": [{
                "pool": format!("{} - {}", pool.range.start, pool.range.end)
            }],
            "option-data": [
                { "name": "routers", "data": gateway },
                { "name": "domain-name-servers", "data": dns_servers },
                { "name": "domain-name", "data": pool.domain }
            ],
            "valid-lifetime": lease_secs,
            "max-valid-lifetime": lease_secs * 2
        });

        // Add static leases that fall within this pool's subnet
        let pool_leases: Vec<&StaticLease> = config.dhcp.static_leases.iter()
            .filter(|lease| is_ip_in_cidr(&lease.ip, &pool.subnet))
            .collect();

        if !pool_leases.is_empty() {
            let reservations: Vec<serde_json::Value> = pool_leases.iter().map(|lease| {
                json!({
                    "hw-address": lease.mac,
                    "ip-address": lease.ip,
                    "hostname": lease.hostname
                })
            }).collect();
            subnet["reservations"] = serde_json::Value::Array(reservations);
        }

        subnet4.push(subnet);
    }

    // Interfaces: bind to all LAN interfaces
    let lan_ifaces: Vec<&str> = config.interfaces.items.iter()
        .filter(|i| i.is_lan() && !i.name.is_empty())
        .map(|i| i.name.as_str())
        .collect();
    let ifaces: Vec<&str> = if lan_ifaces.is_empty() { vec!["lo"] } else { lan_ifaces };

    let kea_config = json!({
        "Dhcp4": {
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

    let out = serde_json::to_string_pretty(&kea_config)?;
    Ok(out)
}

/// Check if an IP falls within a CIDR subnet.
fn is_ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let ip_parts: Vec<u8> = match ip.split('.').map(|p| p.parse::<u8>()).collect() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if ip_parts.len() != 4 { return false; }
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
    if net_parts.len() != 4 { return false; }
    let net_u32 = ((net_parts[0] as u32) << 24)
        | ((net_parts[1] as u32) << 16)
        | ((net_parts[2] as u32) << 8)
        | (net_parts[3] as u32);

    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
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
                    range: DhcpRange { start: start.into(), end: end.into() },
                    ..DhcpPool::default()
                }],
                ..Dhcp::default()
            },
            ..Config::default()
        }
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
                        range: DhcpRange { start: "192.168.1.100".into(), end: "192.168.1.200".into() },
                        ..DhcpPool::default()
                    },
                    DhcpPool {
                        name: "guest".into(),
                        subnet: "192.168.2.0/24".into(),
                        range: DhcpRange { start: "192.168.2.100".into(), end: "192.168.2.200".into() },
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
            StaticLease { mac: "AA:BB:CC:DD:EE:01".into(), ip: "192.168.1.10".into(), hostname: "nas".into() },
            StaticLease { mac: "AA:BB:CC:DD:EE:02".into(), ip: "192.168.1.11".into(), hostname: "printer".into() },
        ];
        let output = render(&config).unwrap();
        assert!(output.contains("\"reservations\""));
        assert!(output.contains("AA:BB:CC:DD:EE:01"));
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
                    range: DhcpRange { start: "192.168.1.100".into(), end: "192.168.1.200".into() },
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
