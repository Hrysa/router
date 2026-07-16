use super::Config;
use regex::Regex;
use std::net::IpAddr;
use std::sync::OnceLock;

/// Validation errors with field paths for API error responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

/// Validate the entire config. Returns all errors found.
pub fn validate(config: &Config) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    validate_interfaces(config, &mut errors);
    validate_dhcp(config, &mut errors);
    validate_firewall(config, &mut errors);

    if let Some(vpn) = &config.vpn {
        if let Some(wg) = &vpn.wireguard {
            if wg.enabled {
                if wg.private_key.is_empty() {
                    errors.push(ValidationError {
                        field: "vpn.wireguard.private_key".into(),
                        message: "private key is required when wireguard is enabled".into(),
                    });
                }
                if wg.address.is_empty() {
                    errors.push(ValidationError {
                        field: "vpn.wireguard.address".into(),
                        message: "address is required".into(),
                    });
                }
            }
        }
    }

    errors
}

fn validate_interfaces(config: &Config, errors: &mut Vec<ValidationError>) {
    for (i, iface) in config.interfaces.items.iter().enumerate() {
        let prefix = format!("interfaces.items[{}]", i);

        // Validate name
        if iface.name.is_empty() {
            errors.push(ValidationError {
                field: format!("{}.name", prefix),
                message: "interface name cannot be empty".into(),
            });
        }

        match iface.method {
            super::schema::InterfaceMethod::Pppoe => {
                if let Some(pppoe) = &iface.pppoe {
                    if !pppoe.username.is_empty() {
                        if pppoe.password.is_empty() {
                            errors.push(ValidationError {
                                field: format!("{}.pppoe.password", prefix),
                                message: "PPPoE password is required when username is set".into(),
                            });
                        }
                        if pppoe.mtu < 576 || pppoe.mtu > 1500 {
                            errors.push(ValidationError {
                                field: format!("{}.pppoe.mtu", prefix),
                                message: "MTU must be between 576 and 1500".into(),
                            });
                        }
                    }
                }
            }
            super::schema::InterfaceMethod::Static => {
                if let Some(static_cfg) = &iface.static_config {
                    if !is_valid_cidr(&static_cfg.address) {
                        errors.push(ValidationError {
                            field: format!("{}.static_config.address", prefix),
                            message: format!("invalid address: {}", static_cfg.address),
                        });
                    }
                    // Gateway is required for WAN, optional for LAN
                    if !static_cfg.gateway.is_empty() && !is_valid_ip(&static_cfg.gateway) {
                        errors.push(ValidationError {
                            field: format!("{}.static_config.gateway", prefix),
                            message: format!("invalid gateway: {}", static_cfg.gateway),
                        });
                    }
                } else {
                    errors.push(ValidationError {
                        field: format!("{}.static_config", prefix),
                        message: "static config required when method is static".into(),
                    });
                }

                // VLAN validation
                if let Some(vlan_id) = iface.vlan_id {
                    if vlan_id == 0 || vlan_id > 4094 {
                        errors.push(ValidationError {
                            field: format!("{}.vlan_id", prefix),
                            message: "VLAN ID must be between 1 and 4094".into(),
                        });
                    }
                }
            }
            super::schema::InterfaceMethod::Dhcp => {}
        }
    }
}

fn validate_dhcp(config: &Config, errors: &mut Vec<ValidationError>) {
    // Validate pools
    for (i, pool) in config.dhcp.pools.iter().enumerate() {
        if pool.name.is_empty() {
            errors.push(ValidationError {
                field: format!("dhcp.pools[{}].name", i),
                message: "pool name cannot be empty".into(),
            });
        }
        if pool.subnet.is_empty() {
            errors.push(ValidationError {
                field: format!("dhcp.pools[{}].subnet", i),
                message: "pool subnet cannot be empty".into(),
            });
        } else if !is_valid_cidr(&pool.subnet) {
            errors.push(ValidationError {
                field: format!("dhcp.pools[{}].subnet", i),
                message: format!("invalid CIDR: {}, expected format like 192.168.1.0/24", pool.subnet),
            });
        }
        if !is_valid_ip(&pool.range.start) {
            errors.push(ValidationError {
                field: format!("dhcp.pools[{}].range.start", i),
                message: format!("invalid IP: {}", pool.range.start),
            });
        }
        if !is_valid_ip(&pool.range.end) {
            errors.push(ValidationError {
                field: format!("dhcp.pools[{}].range.end", i),
                message: format!("invalid IP: {}", pool.range.end),
            });
        }
    }

    // Check for duplicate pool names
    let mut seen_names = std::collections::HashSet::new();
    for (i, pool) in config.dhcp.pools.iter().enumerate() {
        if !seen_names.insert(&pool.name) {
            errors.push(ValidationError {
                field: format!("dhcp.pools[{}].name", i),
                message: format!("duplicate pool name: {}", pool.name),
            });
        }
    }

    // Validate static leases
    for (i, lease) in config.dhcp.static_leases.iter().enumerate() {
        if !is_valid_mac(&lease.mac) {
            errors.push(ValidationError {
                field: format!("dhcp.static_leases[{}].mac", i),
                message: format!("invalid MAC: {}", lease.mac),
            });
        }
        if !is_valid_ip(&lease.ip) {
            errors.push(ValidationError {
                field: format!("dhcp.static_leases[{}].ip", i),
                message: format!("invalid IP: {}", lease.ip),
            });
        }
    }

    // Check for duplicate static lease IPs
    let mut seen_ips = std::collections::HashSet::new();
    for (i, lease) in config.dhcp.static_leases.iter().enumerate() {
        if !seen_ips.insert(&lease.ip) {
            errors.push(ValidationError {
                field: format!("dhcp.static_leases[{}].ip", i),
                message: format!("duplicate IP: {}", lease.ip),
            });
        }
    }
}

fn validate_firewall(config: &Config, errors: &mut Vec<ValidationError>) {
    let valid_policies = ["accept", "drop", "reject"];

    if !valid_policies.contains(&config.firewall.default_policy.input.as_str()) {
        errors.push(ValidationError {
            field: "firewall.default_policy.input".into(),
            message: format!(
                "invalid policy: '{}', must be one of: {:?}",
                config.firewall.default_policy.input, valid_policies
            ),
        });
    }

    if !valid_policies.contains(&config.firewall.default_policy.forward.as_str()) {
        errors.push(ValidationError {
            field: "firewall.default_policy.forward".into(),
            message: format!(
                "invalid policy: '{}', must be one of: {:?}",
                config.firewall.default_policy.forward, valid_policies
            ),
        });
    }

    if !valid_policies.contains(&config.firewall.default_policy.output.as_str()) {
        errors.push(ValidationError {
            field: "firewall.default_policy.output".into(),
            message: format!(
                "invalid policy: '{}', must be one of: {:?}",
                config.firewall.default_policy.output, valid_policies
            ),
        });
    }

    // Validate port forwards
    for (i, pf) in config.firewall.nat.port_forward.iter().enumerate() {
        if pf.interfaces.is_empty() {
            errors.push(ValidationError {
                field: format!("firewall.nat.port_forward[{}].interfaces", i),
                message: "at least one interface must be specified".into(),
            });
        }
        if let Some(super::schema::PortSpec::Single(port)) = pf.target_port {
            if port == 0 {
                errors.push(ValidationError {
                    field: format!("firewall.nat.port_forward[{}].target_port", i),
                    message: "port cannot be 0".into(),
                });
            }
        }
        if let Some(ref saddr) = pf.source_address {
            if !saddr.starts_with('@') && !is_valid_ip(saddr) {
                errors.push(ValidationError {
                    field: format!("firewall.nat.port_forward[{}].source_address", i),
                    message: format!("invalid IP: {}", saddr),
                });
            }
        }
        if !pf.redirect_address.starts_with('@') && !is_valid_ip(&pf.redirect_address) {
            errors.push(ValidationError {
                field: format!("firewall.nat.port_forward[{}].redirect_address", i),
                message: format!("invalid IP: {}", pf.redirect_address),
            });
        }
        if let Some(super::schema::PortSpec::Single(port)) = pf.redirect_port {
            if port == 0 {
                errors.push(ValidationError {
                    field: format!("firewall.nat.port_forward[{}].redirect_port", i),
                    message: "port cannot be 0".into(),
                });
            }
        }
        if pf.proto != "tcp" && pf.proto != "udp" && pf.proto != "tcp+udp" {
            errors.push(ValidationError {
                field: format!("firewall.nat.port_forward[{}].proto", i),
                message: format!("invalid protocol: '{}', must be tcp, udp, or tcp+udp", pf.proto),
            });
        }
    }

    // Validate firewall rules (input + forward)
    let all_rules = config
        .firewall
        .rules
        .input
        .iter()
        .chain(config.firewall.rules.forward.iter());
    for rule in all_rules {
        if rule.interfaces.is_empty() {
            errors.push(ValidationError {
                field: format!("firewall.rules.*.{}.interfaces", rule.comment),
                message: "at least one interface must be specified".into(),
            });
        }
        // Protocol is required when dport or sport is specified
        if rule.dport.is_some() || rule.sport.is_some() {
            if rule.proto.is_none() || rule.proto.as_ref().unwrap().is_empty() {
                errors.push(ValidationError {
                    field: format!("firewall.rules.*.{}.proto", rule.comment),
                    message: "protocol is required when dport or sport is specified".into(),
                });
            }
        }
        if rule.action == crate::config::schema::Action::Tproxy {
            if rule.tproxy_port.is_none() || rule.tproxy_port == Some(0) {
                errors.push(ValidationError {
                    field: format!("firewall.rules.*.{}.tproxy_port", rule.comment),
                    message: "tproxy_port is required and must be non-zero for tproxy rules".into(),
                });
            }
            if rule.mark.is_none() {
                errors.push(ValidationError {
                    field: format!("firewall.rules.*.{}.mark", rule.comment),
                    message: "mark is required for tproxy rules".into(),
                });
            }
        }
    }

    // Validate blackhole entries
    for (i, cidr) in config.firewall.blackhole.iter().enumerate() {
        if !is_valid_cidr(cidr) {
            errors.push(ValidationError {
                field: format!("firewall.blackhole[{}]", i),
                message: format!("invalid CIDR: {}", cidr),
            });
        }
    }
}

// ── Validation helpers ────────────────────────────────────────────────────────

fn is_valid_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

fn is_valid_cidr(s: &str) -> bool {
    if let Some((ip, prefix)) = s.split_once('/') {
        let addr = match ip.parse::<IpAddr>() {
            Ok(a) => a,
            Err(_) => return false,
        };
        if let Ok(prefix) = prefix.parse::<u8>() {
            return match addr {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            };
        }
        false
    } else {
        is_valid_ip(s)
    }
}

fn mac_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$").unwrap()
    })
}

fn is_valid_mac(s: &str) -> bool {
    mac_regex().is_match(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::*;

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_valid_default_config() {
        // Factory default has empty PPPoE credentials — that's expected.
        // Only check that the config parses and no structural errors exist.
        let config = default_config();
        let errors = validate(&config);
        // PPPoE credentials are empty in factory default, filter those out
        let structural_errors: Vec<_> = errors
            .iter()
            .filter(|e| !e.field.contains("pppoe"))
            .collect();
        assert!(
            structural_errors.is_empty(),
            "default config has structural errors: {:?}",
            structural_errors
        );
    }

    #[test]
    fn test_pppoe_missing_credentials() {
        // Empty username means PPPoE is not configured — no errors expected
        let mut config = default_config();
        config.interfaces.items = vec![InterfaceConfig {
            name: "eth0".into(),
            method: InterfaceMethod::Pppoe,
            pppoe: Some(PppoeConfig {
                username: String::new(),
                password: String::new(),
                ..Default::default()
            }),
            ..Default::default()
        }];
        let errors = validate(&config);
        assert!(!errors.iter().any(|e| e.field.contains("pppoe")));

        // Username set but password empty — should error
        let mut config = default_config();
        config.interfaces.items = vec![InterfaceConfig {
            name: "eth0".into(),
            method: InterfaceMethod::Pppoe,
            pppoe: Some(PppoeConfig {
                username: "user@isp".into(),
                password: String::new(),
                ..Default::default()
            }),
            ..Default::default()
        }];
        let errors = validate(&config);
        assert!(errors.iter().any(|e| e.field.contains("pppoe.password")));
    }

    #[test]
    fn test_invalid_mac_address() {
        let mut config = default_config();
        config.dhcp.static_leases.push(StaticLease {
            mac: "not-a-mac".into(),
            ip: "192.168.1.50".into(),
            hostname: "test".into(),
        });
        let errors = validate(&config);
        assert!(errors.iter().any(|e| e.field.contains("mac")));
    }

    #[test]
    fn test_duplicate_static_ip() {
        let mut config = default_config();
        config.dhcp.static_leases = vec![
            StaticLease {
                mac: "AA:BB:CC:DD:EE:01".into(),
                ip: "192.168.1.10".into(),
                hostname: "a".into(),
            },
            StaticLease {
                mac: "AA:BB:CC:DD:EE:02".into(),
                ip: "192.168.1.10".into(),
                hostname: "b".into(),
            },
        ];
        let errors = validate(&config);
        assert!(errors.iter().any(|e| e.message.contains("duplicate")));
    }

    #[test]
    fn test_invalid_default_policy() {
        let mut config = default_config();
        config.firewall.default_policy.output = "accep".into();
        let errors = validate(&config);
        assert!(errors.iter().any(|e| e.field == "firewall.default_policy.output"));
    }

    #[test]
    fn test_valid_cidr() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.1/32"));
        assert!(is_valid_cidr("::1/128"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
        assert!(!is_valid_cidr("not-an-ip/24"));
    }
}
