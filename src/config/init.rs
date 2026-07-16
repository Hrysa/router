use super::schema::*;
use anyhow::{Context, Result};
use std::path::Path;

/// Run first-time init setup when config.yml doesn't exist.
///
/// 1. Checks systemd-networkd is available
/// 2. Detects current network interfaces from the system
/// 3. Disables networking.service (ifupdown) if present
/// 4. Writes systemd-networkd .network/.netdev files to /etc/systemd/network/
/// 5. Enables systemd-networkd.service (after config is in place)
/// 6. Writes config.yml with detected interface config
pub fn run(config_dir: &Path) -> Result<Config> {
    tracing::info!("config not found, running init setup");

    // Check systemd-networkd is available
    check_systemd_networkd()?;

    // Detect interfaces from running system
    let config = detect_config()?;

    // Manage service transition
    disable_networking_service();

    // Write systemd-networkd config files BEFORE enabling the service
    write_networkd_configs(&config)?;

    // Now enable and start systemd-networkd (config files are already in place)
    enable_systemd_networkd()?;

    // Write config.yml
    let config_path = config_dir.join("config.yml");
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("failed to create config dir: {}", config_dir.display()))?;

    let yaml = serde_yaml::to_string(&config).context("failed to serialize config")?;
    std::fs::write(&config_path, &yaml)
        .with_context(|| format!("failed to write config: {}", config_path.display()))?;

    tracing::info!("init config written to {}", config_path.display());
    Ok(config)
}

/// Verify systemd-networkd binary/unit exists.
fn check_systemd_networkd() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["cat", "systemd-networkd.service"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            tracing::debug!("systemd-networkd.service unit found");
            Ok(())
        }
        _ => {
            anyhow::bail!(
                "systemd-networkd.service not found on this system. \
                 Install systemd and ensure systemd-networkd is available."
            );
        }
    }
}

/// Write systemd-networkd .network/.netdev files to /etc/systemd/network/.
fn write_networkd_configs(config: &Config) -> Result<()> {
    use crate::renderer::interfaces;

    let files = interfaces::render(config)?;
    let network_dir = "/etc/systemd/network";
    std::fs::create_dir_all(network_dir)
        .with_context(|| format!("failed to create {}", network_dir))?;

    // Remove any existing routerd-managed files
    if let Ok(entries) = std::fs::read_dir(network_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("50-routerd-") {
                std::fs::remove_file(entry.path())?;
                tracing::debug!(file = %name, "removed old network config");
            }
        }
    }

    // Write new .network/.netdev files
    for file in &files {
        let path = format!("{}/{}", network_dir, file.filename);
        std::fs::write(&path, &file.content)
            .with_context(|| format!("failed to write {}", path))?;
        tracing::info!(file = %file.filename, "wrote network config");
    }

    Ok(())
}

/// Detect current network configuration from the running system.
/// Detects WAN interface and first unused interface for LAN.
fn detect_config() -> Result<Config> {
    let system_ifaces = list_system_interfaces()?;

    // Identify WAN: interface with default route, or fall back to eth0
    let wan_name = detect_wan_interface().unwrap_or_else(|| "eth0".to_string());
    tracing::info!(wan = %wan_name, "detected WAN interface");

    // Find first unused interface for LAN
    let lan_name = system_ifaces.iter()
        .find(|i| *i != &wan_name)
        .cloned();

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

    let config = Config {
        interfaces: Interfaces {
            items: vec![wan, lan],
        },
        firewall: Firewall {
            default_policy: DefaultPolicy {
                input: "drop".into(),
                forward: "drop".into(),
                output: "accept".into(),
            },
            rules: FirewallRules {
                input: vec![
                    FirewallRule {
                        id: 0,
                        action: Action::Accept,
                        comment: "allow-loopback".into(),
                        interfaces: vec!["lo".into()],
                        oif: None, proto: None, dport: None, sport: None,
                        saddr: None, daddr: None,
                        interfaces_invert: false, saddr_invert: false, daddr_invert: false,
                        state: None, rate: None,
                        log: false, log_prefix: None, mark: None, tproxy_port: None, counter: false, enabled: true,
                    },
                    FirewallRule {
                        id: 0,
                        action: Action::Accept,
                        comment: "allow-established".into(),
                        interfaces: vec![wan_name.clone(), lan_name.clone()], oif: None, proto: None, dport: None, sport: None,
                        saddr: None, daddr: None,
                        interfaces_invert: false, saddr_invert: false, daddr_invert: false,
                        state: Some(vec!["established".into(), "related".into()]),
                        rate: None, log: false, log_prefix: None, mark: None, tproxy_port: None, counter: false, enabled: true,
                    },
                    FirewallRule {
                        id: 0,
                        action: Action::Accept,
                        comment: "allow-lan".into(),
                        interfaces: vec![lan_name.clone()],
                        oif: None, proto: None, dport: None, sport: None,
                        saddr: None, daddr: None,
                        interfaces_invert: false, saddr_invert: false, daddr_invert: false,
                        state: None, rate: None,
                        log: false, log_prefix: None, mark: None, tproxy_port: None, counter: false, enabled: true,
                    },
                ],
                forward: vec![
                    FirewallRule {
                        id: 0,
                        action: Action::Accept,
                        comment: "lan-to-wan".into(),
                        interfaces: vec![lan_name.clone()],
                        oif: Some(masq_oif.clone()),
                        proto: None, dport: None, sport: None,
                        saddr: None, daddr: None,
                        interfaces_invert: false, saddr_invert: false, daddr_invert: false,
                        state: None, rate: None,
                        log: false, log_prefix: None, mark: None, tproxy_port: None, counter: false, enabled: true,
                    },
                    FirewallRule {
                        id: 0,
                        action: Action::Accept,
                        comment: "allow-established".into(),
                        interfaces: vec![wan_name.clone(), lan_name.clone()], oif: None, proto: None, dport: None, sport: None,
                        saddr: None, daddr: None,
                        interfaces_invert: false, saddr_invert: false, daddr_invert: false,
                        state: Some(vec!["established".into(), "related".into()]),
                        rate: None, log: false, log_prefix: None, mark: None, tproxy_port: None, counter: false, enabled: true,
                    },
                ],
            },
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
    };

    Ok(config)
}

/// List network interfaces from /sys/class/net/.
fn list_system_interfaces() -> Result<Vec<String>> {
    let mut ifaces = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net")
        .context("failed to read /sys/class/net")?
    {
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
) -> (InterfaceMethod, Option<StaticConfig>, Option<DhcpClientConfig>) {
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
        (InterfaceMethod::Dhcp, None, Some(DhcpClientConfig::default()))
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

/// Disable networking.service (ifupdown) if it exists and is enabled.
fn disable_networking_service() {
    let check = std::process::Command::new("systemctl")
        .args(["cat", "networking.service"])
        .output();

    match check {
        Ok(o) if o.status.success() => {
            tracing::info!("disabling networking.service (ifupdown)");
            let _ = std::process::Command::new("systemctl")
                .args(["disable", "--now", "networking.service"])
                .output();
        }
        _ => {
            tracing::debug!("networking.service not found, skipping disable");
        }
    }
}

/// Enable and start systemd-networkd.service.
fn enable_systemd_networkd() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["enable", "--now", "systemd-networkd.service"])
        .output()
        .context("failed to run systemctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to enable systemd-networkd: {}", stderr.trim());
    }

    tracing::info!("systemd-networkd.service enabled and started");
    Ok(())
}
