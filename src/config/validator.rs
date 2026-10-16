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
    errors.extend(super::shaper::validate(config));
    errors.extend(super::static_routes::validate(config));
    if let Err(error) = super::routing::wan_return_routes(config) {
        errors.push(ValidationError {
            field: "interfaces.items.return_route_table".into(),
            message: error.to_string(),
        });
    }
    validate_dhcp(config, &mut errors);
    validate_firewall(config, &mut errors);

    if config
        .singbox
        .as_ref()
        .is_some_and(|singbox| singbox.config.trim().is_empty())
    {
        errors.push(ValidationError {
            field: "singbox.config".into(),
            message:
                "sing-box JSONC configuration must not be empty; omit singbox to leave it unmanaged"
                    .into(),
        });
    }

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
                if !is_valid_cidr(&wg.address) {
                    errors.push(ValidationError {
                        field: "vpn.wireguard.address".into(),
                        message: "invalid WireGuard address".into(),
                    });
                }
                if !is_valid_wireguard_key(&wg.private_key) {
                    errors.push(ValidationError {
                        field: "vpn.wireguard.private_key".into(),
                        message: "invalid WireGuard private key".into(),
                    });
                }
                if wg.listen_port == 0 {
                    errors.push(ValidationError {
                        field: "vpn.wireguard.listen_port".into(),
                        message: "port must be non-zero".into(),
                    });
                }
                for (index, peer) in wg.peers.iter().enumerate().filter(|(_, peer)| peer.enabled) {
                    let prefix = format!("vpn.wireguard.peers[{}]", index);
                    validate_single_line(&format!("{}.name", prefix), &peer.name, &mut errors);
                    if !is_valid_wireguard_key(&peer.public_key) {
                        errors.push(ValidationError {
                            field: format!("{}.public_key", prefix),
                            message: "invalid WireGuard public key".into(),
                        });
                    }
                    if peer.allowed_ips.is_empty()
                        || peer
                            .allowed_ips
                            .iter()
                            .any(|address| !is_valid_cidr(address))
                    {
                        errors.push(ValidationError {
                            field: format!("{}.allowed_ips", prefix),
                            message: "at least one valid allowed IP is required".into(),
                        });
                    }
                    if let Some(endpoint) = &peer.endpoint {
                        validate_single_line(
                            &format!("{}.endpoint", prefix),
                            endpoint,
                            &mut errors,
                        );
                    }
                }
            }
        }
    }

    errors
}

fn validate_interfaces(config: &Config, errors: &mut Vec<ValidationError>) {
    let mut names = std::collections::HashSet::new();
    for (i, iface) in config.interfaces.items.iter().enumerate() {
        let prefix = format!("interfaces.items[{}]", i);

        for (field, value) in [("mtu", iface.mtu), ("mss_clamp_mtu", iface.mss_clamp_mtu)] {
            if value.is_some_and(|value| !(1280..=9216).contains(&value)) {
                errors.push(ValidationError {
                    field: format!("{}.{}", prefix, field),
                    message: "must be between 1280 and 9216 bytes".into(),
                });
            }
        }

        // Validate name
        if !is_valid_interface_name(&iface.name) {
            errors.push(ValidationError {
                field: format!("{}.name", prefix),
                message: "interface name must be 1-15 ASCII letters, digits, '.', '_' or '-', and cannot be '.' or '..'".into(),
            });
        }
        if !names.insert(&iface.name) {
            errors.push(ValidationError {
                field: format!("{}.name", prefix),
                message: "duplicate interface name".into(),
            });
        }
        for port in &iface.bridge_ports {
            if !is_valid_interface_name(port) || port == &iface.name {
                errors.push(ValidationError {
                    field: format!("{}.bridge_ports", prefix),
                    message: "invalid bridge port".into(),
                });
            }
        }
        if let Some(parent) = &iface.parent {
            if !is_valid_interface_name(parent) || parent == &iface.name {
                errors.push(ValidationError {
                    field: format!("{}.parent", prefix),
                    message: "invalid parent interface".into(),
                });
            }
        }
        if let Some(vlan_id) = iface.vlan_id {
            if vlan_id == 0 || vlan_id > 4094 || iface.parent.is_none() {
                errors.push(ValidationError {
                    field: format!("{}.vlan_id", prefix),
                    message: "VLAN requires an ID from 1 to 4094 and a parent".into(),
                });
            }
        }
        if let Some(dhcp) = &iface.dhcp {
            if let Some(hostname) = &dhcp.hostname {
                validate_single_line(&format!("{}.dhcp.hostname", prefix), hostname, errors);
            }
        }

        match iface.method {
            super::schema::InterfaceMethod::Pppoe => {
                if let Some(pppoe) = &iface.pppoe {
                    validate_single_line(
                        &format!("{}.pppoe.username", prefix),
                        &pppoe.username,
                        errors,
                    );
                    validate_single_line(
                        &format!("{}.pppoe.password", prefix),
                        &pppoe.password,
                        errors,
                    );
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
                    for dns in &static_cfg.dns {
                        if !is_valid_ip(dns) {
                            errors.push(ValidationError {
                                field: format!("{}.static_config.dns", prefix),
                                message: "DNS server must be an IP address".into(),
                            });
                        }
                    }
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
            }
            super::schema::InterfaceMethod::Dhcp => {}
        }
    }
}

fn validate_dhcp(config: &Config, errors: &mut Vec<ValidationError>) {
    // Validate pools
    for (i, pool) in config.dhcp.pools.iter().enumerate() {
        if super::schema::lease_duration_seconds(&pool.lease_time).is_none() {
            errors.push(ValidationError { field: format!("dhcp.pools[{}].lease_time", i), message: "lease time must be positive seconds or an s/m/h/d duration, with a maximum of 2147483647 seconds".into() });
        }
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
                message: format!(
                    "invalid CIDR: {}, expected format like 192.168.1.0/24",
                    pool.subnet
                ),
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
    validate_outbound_routes(config, errors);
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
                message: format!(
                    "invalid protocol: '{}', must be tcp, udp, or tcp+udp",
                    pf.proto
                ),
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
    let mut rule_ids = std::collections::HashSet::new();
    for rule in all_rules {
        if !rule_ids.insert(rule.id) {
            errors.push(ValidationError {
                field: "firewall.rules".into(),
                message: format!("duplicate rule ID: {}", rule.id),
            });
        }
        if rule.interfaces.is_empty() {
            errors.push(ValidationError {
                field: format!("firewall.rules.*.{}.interfaces", rule.comment),
                message: "at least one interface must be specified".into(),
            });
        }
        // Protocol is required when dport or sport is specified
        if (rule.dport.is_some() || rule.sport.is_some())
            && rule.proto.as_ref().is_none_or(Vec::is_empty)
        {
            errors.push(ValidationError {
                field: format!("firewall.rules.*.{}.proto", rule.comment),
                message: "protocol is required when dport or sport is specified".into(),
            });
        }
        if rule.action == crate::config::schema::Action::Tproxy {
            if rule.tproxy_port.is_none() || rule.tproxy_port == Some(0) {
                errors.push(ValidationError {
                    field: format!("firewall.rules.*.{}.tproxy_port", rule.comment),
                    message: "tproxy_port is required and must be non-zero for tproxy rules".into(),
                });
            }
            if rule.mark.is_none() || matches!(rule.mark, Some(0 | 253 | 254 | 255)) {
                errors.push(ValidationError {
                    field: format!("firewall.rules.*.{}.mark", rule.comment),
                    message:
                        "mark is required and cannot use reserved routing tables 0, 253, 254 or 255"
                            .into(),
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

fn validate_outbound_routes(config: &Config, errors: &mut Vec<ValidationError>) {
    use super::schema::Action;
    for (chain, rules) in [
        ("input", &config.firewall.rules.input),
        ("forward", &config.firewall.rules.forward),
    ] {
        for (index, rule) in rules.iter().enumerate() {
            if !rule.preserve_internal_routes
                && (chain != "forward" || rule.action != Action::Accept || rule.route_via.is_none())
            {
                errors.push(ValidationError {
                    field: format!("firewall.rules.{}[{}].preserve_internal_routes", chain, index),
                    message: "disabling internal-route preservation requires a forward Accept rule with route_via".into(),
                });
            }
            let Some(target) = &rule.route_via else {
                continue;
            };
            let problem = if chain != "forward" || rule.action != Action::Accept {
                Some("route_via is only supported on forward Accept rules")
            } else if !config.interfaces.items.iter().any(|interface| {
                interface.name == *target
                    && interface.is_wan()
                    && interface.return_routing != Some(false)
            }) {
                Some("route_via must name a configured WAN with return routing enabled")
            } else if rule.oif.is_some() {
                Some("route_via cannot be combined with an egress interface match")
            } else if rule.rate.is_some() {
                Some("route_via cannot be combined with a rate limit")
            } else if rule.state.as_ref().is_some_and(|states| {
                !states.is_empty() && !states.iter().any(|state| state == "new")
            }) {
                Some("route_via connection states must include new, or be empty")
            } else if rule.proto.as_ref().is_some_and(|protocols| {
                protocols
                    .iter()
                    .any(|protocol| !matches!(protocol.as_str(), "ip" | "tcp" | "udp" | "icmp"))
            }) {
                Some("route_via supports IPv4 protocols ip, tcp, udp and icmp only")
            } else if (rule.sport.is_some() || rule.dport.is_some())
                && rule.proto.as_ref().is_some_and(|protocols| {
                    protocols
                        .iter()
                        .any(|protocol| !matches!(protocol.as_str(), "tcp" | "udp"))
                })
            {
                Some("route_via port matches require tcp or udp")
            } else {
                None
            };
            if let Some(message) = problem {
                errors.push(ValidationError {
                    field: format!("firewall.rules.{}[{}].route_via", chain, index),
                    message: message.into(),
                });
            }
            for (field, address) in [("saddr", &rule.saddr), ("daddr", &rule.daddr)] {
                let Some(address) = address else { continue };
                let valid = if address == "@local" {
                    true
                } else if let Some(name) = address.strip_prefix('@') {
                    config
                        .firewall
                        .sets
                        .iter()
                        .any(|set| set.name == name && set.set_type == "ipv4_addr")
                } else {
                    is_valid_cidr(address)
                        && address
                            .split('/')
                            .next()
                            .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                };
                if !valid {
                    errors.push(ValidationError {
                        field: format!("firewall.rules.{}[{}].{}", chain, index, field),
                        message: "WAN selection requires an IPv4 address/subnet, @local or an ipv4_addr set".into(),
                    });
                }
            }
            for (field, port) in [("sport", &rule.sport), ("dport", &rule.dport)] {
                if let Some(super::schema::PortSpec::Set(name)) = port {
                    if !config.firewall.sets.iter().any(|set| {
                        set.name == name.trim_start_matches('@') && set.set_type == "inet_service"
                    }) {
                        errors.push(ValidationError {
                            field: format!("firewall.rules.{}[{}].{}", chain, index, field),
                            message:
                                "WAN selection port sets must name a configured inet_service set"
                                    .into(),
                        });
                    }
                }
            }
        }
    }
}

fn validate_single_line(field: &str, value: &str, errors: &mut Vec<ValidationError>) {
    if value.chars().any(char::is_control) {
        errors.push(ValidationError {
            field: field.into(),
            message: "control characters are not allowed".into(),
        });
    }
}

fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_valid_wireguard_key(key: &str) -> bool {
    key.len() == 44
        && key.ends_with('=')
        && key[..43]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

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
    RE.get_or_init(|| Regex::new(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$").unwrap())
}

fn is_valid_mac(s: &str) -> bool {
    mac_regex().is_match(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn common_mtu_limits_are_validated_independently_of_interface_role() {
        let mut config = Config::default();
        config.interfaces.items = vec![InterfaceConfig {
            name: "lan0".into(),
            ..Default::default()
        }];
        for value in [0, 1279, 9217] {
            config.interfaces.items[0].mtu = Some(value);
            config.interfaces.items[0].mss_clamp_mtu = Some(value);
            let errors = validate(&config);
            assert!(errors.iter().any(|e| e.field.ends_with(".mtu")));
            assert!(errors.iter().any(|e| e.field.ends_with(".mss_clamp_mtu")));
        }
        config.interfaces.items[0].mtu = Some(1492);
        config.interfaces.items[0].mss_clamp_mtu = Some(1492);
        assert!(!validate(&config)
            .iter()
            .any(|e| e.field.ends_with(".mtu") || e.field.ends_with(".mss_clamp_mtu")));
        let old: InterfaceConfig =
            serde_json::from_value(serde_json::json!({"name":"lan0"})).unwrap();
        assert_eq!((old.mtu, old.mss_clamp_mtu), (None, None));
    }

    #[test]
    fn disabling_internal_preservation_requires_an_explicit_forward_wan_selector() {
        let mut config = crate::config::routing::outbound_test_config();
        config.firewall.rules.forward[0].preserve_internal_routes = false;
        assert!(super::validate(&config).is_empty());
        config.firewall.rules.forward[0].route_via = None;
        assert!(super::validate(&config)
            .iter()
            .any(|error| error.field.ends_with("preserve_internal_routes")));
    }
    #[test]
    fn outbound_wan_selection_validates_targets_and_prerouting_matches() {
        let config = crate::config::routing::outbound_test_config();
        assert!(super::validate(&config).is_empty());
        let base = serde_json::to_value(&config.firewall.rules.forward[0]).unwrap();
        for (field, value) in [
            ("route_via", serde_json::json!("missing")),
            ("route_via", serde_json::json!("lan0")),
            ("action", serde_json::json!("drop")),
            ("action", serde_json::json!("tproxy")),
            ("oif", serde_json::json!("wan0")),
            ("rate", serde_json::json!("10/second")),
            ("state", serde_json::json!(["established"])),
            ("proto", serde_json::json!(["ipv6-icmp"])),
            ("proto", serde_json::json!(["icmp"])),
            ("saddr", serde_json::json!("2001:db8::/64")),
            ("daddr", serde_json::json!("@missing")),
            ("daddr", serde_json::json!("@web")),
            ("dport", serde_json::json!("@clients")),
        ] {
            let mut changed = config.clone();
            let mut rule = base.clone();
            rule[field] = value;
            changed.firewall.rules.forward[0] = serde_json::from_value(rule).unwrap();
            assert!(
                !super::validate(&changed).is_empty(),
                "accepted invalid {field}"
            );
        }
        let mut disabled = config.clone();
        disabled.interfaces.items[0].return_routing = Some(false);
        assert!(super::validate(&disabled)
            .iter()
            .any(|error| error.field.ends_with("route_via")));
        let mut input = config.clone();
        input
            .firewall
            .rules
            .input
            .push(input.firewall.rules.forward.remove(0));
        assert!(super::validate(&input)
            .iter()
            .any(|error| error.field.starts_with("firewall.rules.input")
                && error.field.ends_with("route_via")));
        for method in [
            super::super::schema::InterfaceMethod::Dhcp,
            super::super::schema::InterfaceMethod::Pppoe,
        ] {
            let mut dynamic = config.clone();
            dynamic.interfaces.items[0].method = method;
            assert!(super::validate(&dynamic).is_empty());
        }
    }
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
        assert!(errors
            .iter()
            .any(|e| e.field == "firewall.default_policy.output"));
    }

    #[test]
    fn test_valid_cidr() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.1/32"));
        assert!(is_valid_cidr("::1/128"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
        assert!(!is_valid_cidr("not-an-ip/24"));
    }

    #[test]
    fn rejects_interface_paths_and_directive_injection() {
        for name in [
            "../../etc/evil",
            "eth0\n[Network]",
            "eth0*",
            "",
            "abcdefghijklmnop",
        ] {
            let mut config = default_config();
            config.interfaces.items.push(InterfaceConfig {
                name: name.into(),
                method: InterfaceMethod::Dhcp,
                ..Default::default()
            });
            assert!(
                validate(&config)
                    .iter()
                    .any(|error| error.field.ends_with(".name")),
                "{}",
                name
            );
        }
        let mut config = default_config();
        config.interfaces.items.push(InterfaceConfig {
            name: "eth0".into(),
            method: InterfaceMethod::Pppoe,
            pppoe: Some(PppoeConfig {
                username: "user".into(),
                password: "secret\nplugin /tmp/evil.so".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(validate(&config)
            .iter()
            .any(|error| error.field.ends_with("pppoe.password")));
    }

    #[test]
    fn rejects_wireguard_hook_injection() {
        let mut config = default_config();
        config.vpn = Some(Vpn {
            wireguard: Some(WireguardConfig {
                enabled: true,
                private_key: "key\nPostUp = touch /tmp/evil".into(),
                address: "10.0.0.1/24\nPostUp = false".into(),
                listen_port: 51820,
                peers: vec![],
            }),
        });
        let errors = validate(&config);
        assert!(errors
            .iter()
            .any(|error| error.field == "vpn.wireguard.private_key"));
        assert!(errors
            .iter()
            .any(|error| error.field == "vpn.wireguard.address"));
    }

    #[test]
    fn rejects_reserved_tproxy_routing_tables_and_duplicate_ids() {
        for mark in [0, 253, 254, 255] {
            let mut config = default_config();
            let rule: FirewallRule = serde_json::from_value(serde_json::json!({
                "id": 1, "action": "tproxy", "interfaces": ["eth0"], "mark": mark, "tproxy_port": 7893
            })).unwrap();
            config.firewall.rules.input.push(rule.clone());
            config.firewall.rules.forward.push(rule);
            let errors = validate(&config);
            assert!(errors.iter().any(|error| error.field.ends_with(".mark")));
            assert!(errors
                .iter()
                .any(|error| error.message.contains("duplicate rule ID")));
        }
    }
}
