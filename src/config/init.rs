use super::schema::*;
use anyhow::{Context, Result};
use std::path::Path;

/// Generate a first-time config without changing the host's networking.
/// The detected config is a draft for review before an explicit apply.
pub fn run(config_dir: &Path) -> Result<Config> {
    crate::service::files::require_absent(&config_dir.join("config.yml"))?;
    tracing::info!("config not found, generating initial config without applying it");

    let config = detect_config()?;

    // Write config.yml
    let config_path = config_dir.join("config.yml");
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create config dir: {}", config_dir.display()))?;

    let yaml = serde_yaml::to_string(&config).context("failed to serialize config")?;
    crate::service::files::atomic_create(&config_path, yaml.as_bytes(), 0o600)
        .with_context(|| format!("failed to write config: {}", config_path.display()))?;

    tracing::info!("init config written to {}", config_path.display());
    Ok(config)
}

/// Detect current network configuration from the running system.
/// Detects WAN interface and first unused interface for LAN.
fn detect_config() -> Result<Config> {
    let system_ifaces = list_system_interfaces()?;

    // Identify WAN: interface with default route, or fall back to eth0
    let wan_name = detect_wan_interface().unwrap_or_else(|| "eth0".to_string());
    tracing::info!(wan = %wan_name, "detected WAN interface");

    // Find first unused interface for LAN
    let lan_name = system_ifaces.iter().find(|i| *i != &wan_name).cloned();

    let lan_name = match lan_name {
        Some(name) => {
            tracing::info!(lan = %name, "detected LAN interface");
            name
        }
        None => {
            anyhow::bail!(
                "no available interface for LAN — all interfaces are in use or none found. \
                 Available: {:?}, WAN: {}",
                system_ifaces,
                wan_name
            );
        }
    };

    // Detect WAN config (check if it has a DHCP lease or static IP)
    let (wan_method, wan_static, wan_dhcp) = detect_wan_config(&wan_name);

    // Determine masquerade output interface (ppp0 for PPPoE, otherwise WAN name)
    let masq_oif = if wan_method == InterfaceMethod::Pppoe {
        "ppp0".to_string()
    } else {
        wan_name.clone()
    };

    // Build WAN interface config
    let wan = InterfaceConfig {
        name: wan_name.clone(),
        label: "WAN".into(),
        method: wan_method.clone(),
        pppoe: if wan_method == InterfaceMethod::Pppoe {
            Some(PppoeConfig::default())
        } else {
            None
        },
        dhcp: if wan_method == InterfaceMethod::Dhcp {
            Some(wan_dhcp.unwrap_or_default())
        } else {
            None
        },
        static_config: wan_static,
        ..Default::default()
    };

    // Build LAN interface config
    let lan = InterfaceConfig {
        name: lan_name.clone(),
        label: "LAN".into(),
        method: InterfaceMethod::Static,
        static_config: Some(StaticConfig {
            address: "192.168.1.1/24".into(),
            gateway: String::new(),
            dns: vec![],
        }),
        ..Default::default()
    };

    Ok(build_config(wan, lan, masq_oif))
}

fn build_config(wan: InterfaceConfig, lan: InterfaceConfig, masq_oif: String) -> Config {
    Config {
        interfaces: Interfaces {
            items: vec![wan, lan],
        },
        firewall: Firewall {
            default_policy: DefaultPolicy {
                input: "accept".into(),
                forward: "accept".into(),
                output: "accept".into(),
            },
            rules: FirewallRules::default(),
            nat: Nat {
                masquerade: vec![MasqueradeRule { oif: masq_oif }],
                port_forward: vec![],
            },
            blackhole: vec![],
            ..Default::default()
        },
        auth: Auth {
            jwt_secret: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        },
        ..Config::default()
    }
}

/// List network interfaces from /sys/class/net/.
fn list_system_interfaces() -> Result<Vec<String>> {
    let mut ifaces = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net").context("failed to read /sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip loopback and virtual interfaces
        if name == "lo" || name.starts_with("veth") || name.starts_with("virbr") {
            continue;
        }
        ifaces.push(name);
    }
    ifaces.sort();
    Ok(ifaces)
}

/// Detect WAN interface by finding the one with a default route.
fn detect_wan_interface() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(dev_pos) = line.find(" dev ") {
            let after_dev = &line[dev_pos + 5..];
            let iface = after_dev.split_whitespace().next()?;
            return Some(iface.to_string());
        }
    }
    None
}

/// Get the IPv4 address/mask of an interface via `ip addr show`.
fn get_interface_ip(iface: &str) -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "addr", "show", iface])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let addr = trimmed.split_whitespace().nth(1)?;
            return Some(addr.to_string());
        }
    }
    None
}

/// Detect WAN method and static config from current state.
fn detect_wan_config(
    wan_name: &str,
) -> (
    InterfaceMethod,
    Option<StaticConfig>,
    Option<DhcpClientConfig>,
) {
    // Check if interface has a DHCP lease
    let lease_files = [
        format!("/var/lib/dhcp/dhclient.{}.leases", wan_name),
        format!("/var/lib/dhclient/dhclient.{}.leases", wan_name),
        format!("/var/lib/NetworkManager/dhclient-{}.lease", wan_name),
    ];

    let has_dhcp_lease = lease_files.iter().any(|p| Path::new(p).exists());
    let ip = get_interface_ip(wan_name);

    if has_dhcp_lease {
        tracing::debug!(wan = wan_name, "WAN detected as DHCP");
        (
            InterfaceMethod::Dhcp,
            None,
            Some(DhcpClientConfig {
                hostname: Some(gethostname()),
            }),
        )
    } else if let Some(addr) = ip {
        let gateway = get_default_gateway();
        let dns = get_system_dns();

        tracing::debug!(wan = wan_name, addr = %addr, "WAN detected as static");
        (
            InterfaceMethod::Static,
            Some(StaticConfig {
                address: addr,
                gateway: gateway.unwrap_or_default(),
                dns,
            }),
            None,
        )
    } else {
        tracing::debug!(wan = wan_name, "WAN has no IP, defaulting to DHCP");
        (
            InterfaceMethod::Dhcp,
            None,
            Some(DhcpClientConfig::default()),
        )
    }
}

/// Get the default gateway from `ip route`.
fn get_default_gateway() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("default") {
            if let Some(via_pos) = line.find(" via ") {
                let after_via = &line[via_pos + 5..];
                let gw = after_via.split_whitespace().next()?;
                return Some(gw.to_string());
            }
        }
    }
    None
}

/// Get system DNS servers from /etc/resolv.conf.
fn get_system_dns() -> Vec<String> {
    let content = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let addr = trimmed.split_whitespace().nth(1)?;
                Some(addr.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Get the system hostname.
fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "router".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_firewall_accepts_all_with_empty_rules() {
        let config = build_config(
            InterfaceConfig {
                name: "eth0".into(),
                ..Default::default()
            },
            InterfaceConfig {
                name: "eth1".into(),
                ..Default::default()
            },
            "eth0".into(),
        );
        let yaml = serde_yaml::to_string(&config).unwrap();
        let restored: Config = serde_yaml::from_str(&yaml).unwrap();
        let rules = &restored.firewall.rules;
        assert!(rules.input.is_empty());
        assert!(rules.forward.is_empty());
        assert_eq!(rules.next_id(), 1);
        assert_eq!(restored.firewall, config.firewall);
        assert_eq!(
            restored.firewall.default_policy,
            DefaultPolicy {
                input: "accept".into(),
                forward: "accept".into(),
                output: "accept".into(),
            }
        );
        assert_eq!(restored.firewall.nat.masquerade[0].oif, "eth0");
        assert!(restored.firewall.nat.port_forward.is_empty());
        assert!(restored.firewall.blackhole.is_empty());
    }

    #[test]
    fn test_next_firewall_rule_id_uses_max_across_chains() {
        let mut rules = FirewallRules::default();
        assert_eq!(rules.next_id(), 1);

        rules
            .input
            .push(serde_yaml::from_str("id: 12\naction: accept").unwrap());
        rules
            .forward
            .push(serde_yaml::from_str("id: 7\naction: accept").unwrap());
        assert_eq!(rules.next_id(), 13);

        rules.forward[0].id = 20;
        assert_eq!(rules.next_id(), 21);

        rules.forward.clear();
        assert_eq!(rules.next_id(), 13);
    }
}
