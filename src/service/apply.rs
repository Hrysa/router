use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;

use crate::config::diff::ChangeSet;
use crate::config::Config;
use crate::renderer;
use crate::renderer::interfaces::NetworkFile;
use crate::service::manager::{Service, ServiceManager};

/// Result of an apply operation.
#[derive(Debug, serde::Serialize)]
pub struct ApplyResult {
    pub success: bool,
    pub services_restarted: Vec<String>,
    pub errors: Vec<String>,
    pub changeset: ChangeSet,
}

/// Apply orchestrator: render → validate → copy → restart.
///
/// `config_path` is the path to config.yml on disk (used for change detection).
/// `force` applies all services regardless of changes (used on startup).
pub async fn apply(config: &Config, prev_config: &Config, _config_path: &Path, service_manager: &ServiceManager, force: bool) -> Result<ApplyResult> {
    let errors = crate::config::validator::validate(config);
    if !errors.is_empty() {
        anyhow::bail!("config validation failed: {:?}", errors);
    }
    // Render all service configs
    let rendered = render_all(config)?;

    // Syntax check rendered configs
    syntax_check(&rendered, service_manager).await?;

    // Detect changes by comparing rendered configs against files on disk
    let changeset = if force {
        ChangeSet {
            nftables: true,
            dhcpd: true,
            ppp: true,
            interfaces: true,
            wireguard: true,
            sysctl: true,
            shaper: true,
        }
    } else {
        let mut changes = detect_rendered_changes(&rendered, config);
        let previous = render_all(prev_config)?;
        changes.dhcpd |= rendered.kea_dhcp4 != previous.kea_dhcp4;
        changes.ppp |= rendered.ppp_peers != previous.ppp_peers || rendered.ppp_chap != previous.ppp_chap;
        changes.interfaces |= rendered.interfaces != previous.interfaces;
        changes.wireguard |= rendered.wireguard != previous.wireguard;
        changes.sysctl |= rendered.sysctl != previous.sysctl;
        changes.shaper |= config.shaper != prev_config.shaper;
        changes
    };

    crate::service::shaper::suspend().await;
    crate::service::shaper::preflight_config(config).await?;

    // Strict WAN selection must have a lookup and terminal guard before packets
    // can receive its mark. These global rules survive networkd/link changes.
    crate::service::wan_policy::prepare(prev_config, config).await?;

    // Only write configs that changed
    write_changed_configs(&rendered, &changeset, config).await?;

    // Restart changed services
    let services_restarted = restart_services(config, &rendered, &changeset, service_manager).await?;
    crate::service::wan_policy::cleanup(prev_config, config).await?;

    // Always set up tproxy routing (ip rule + ip route) — these are ephemeral
    // and need to be re-applied on every boot/config change.
    if let Err(e) = apply_tproxy_routing(prev_config, config).await {
        return Err(e.context("tproxy routing setup failed"));
    }

    crate::service::shaper::reconcile(config).await?;
    crate::service::shaper::activate(config).await;

    tracing::info!(
        services = ?services_restarted,
        "config applied successfully"
    );

    Ok(ApplyResult {
        success: true,
        services_restarted,
        errors: vec![],
        changeset,
    })
}

/// Detect changes by comparing rendered configs against actual files on disk.
fn detect_rendered_changes(rendered: &RenderedConfigs, config: &Config) -> ChangeSet {
    // nftables: JSON is applied directly, not written to disk.
    // Always treat as changed to ensure rules are applied.
    let nftables = true;
    let dhcpd = file_changed("/etc/kea/kea-dhcp4.conf", &rendered.kea_dhcp4);
    let ppp = file_changed("/etc/ppp/peers/isp", &rendered.ppp_peers)
        || file_changed("/etc/ppp/chap-secrets", &rendered.ppp_chap);
    let wireguard = wireguard_enabled(config)
        && file_changed("/etc/wireguard/wg0.conf", &rendered.wireguard);
    let sysctl = file_changed("/etc/sysctl.d/90-routerd.conf", &rendered.sysctl);

    // Check if any network file changed
    let network_dir = "/etc/systemd/network";
    let mut interfaces = false;
    for file in &rendered.interfaces {
        let path = format!("{}/{}", network_dir, file.filename);
        if file_changed(&path, &file.content) {
            interfaces = true;
            break;
        }
    }
    // Also check for stale files that need removal
    if !interfaces {
        if let Ok(entries) = std::fs::read_dir(network_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("50-routerd-") {
                    let managed: std::collections::HashSet<&str> =
                        rendered.interfaces.iter().map(|f| f.filename.as_str()).collect();
                    if !managed.contains(name.as_str()) {
                        interfaces = true;
                        break;
                    }
                }
            }
        }
    }

    if nftables || dhcpd || ppp || interfaces || wireguard || sysctl {
        tracing::info!(
            nftables, dhcpd, ppp, interfaces, wireguard, sysctl,
            "detected rendered config changes"
        );
    } else {
        tracing::info!("all rendered configs unchanged, nothing to apply");
    }

    ChangeSet { nftables, dhcpd, ppp, interfaces, wireguard, sysctl, shaper: config.shaper.profiles.iter().any(|p| p.enabled) }
}

/// Check if a file's content differs from the rendered string.
fn file_changed(path: &str, new_content: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(existing) => existing != new_content,
        Err(_) => true, // file doesn't exist or can't read → treat as changed
    }
}

/// Render all service configs from the unified config.
fn render_all(config: &Config) -> Result<RenderedConfigs> {
    Ok(RenderedConfigs {
        nftables: renderer::nftables::render(config)?,
        kea_dhcp4: renderer::kea::render(config)?,
        ppp_peers: renderer::ppp::render(config)?,
        ppp_chap: renderer::ppp::render_chap_secrets(config)?,
        interfaces: renderer::interfaces::render(config)?,
        wireguard: renderer::wireguard::render(config)?,
        sysctl: renderer::sysctl::render(config)?,
    })
}

/// All rendered service configs.
struct RenderedConfigs {
    nftables: String,
    kea_dhcp4: String,
    ppp_peers: String,
    ppp_chap: String,
    interfaces: Vec<NetworkFile>,
    wireguard: String,
    sysctl: String,
}

/// Syntax-check rendered configs before applying.
async fn syntax_check(
    rendered: &RenderedConfigs,
    service_manager: &ServiceManager,
) -> Result<()> {
    // Syntax-check nftables via JSON
    service_manager.check_nftables_json(&rendered.nftables).await?;

    // Write kea-dhcp4 to staged file and check (optional — may not be installed)
    if crate::service::manager::find_command("kea-dhcp4").is_ok() {
        let kea_file = crate::service::files::StagedFile::new(
            &std::env::temp_dir(), rendered.kea_dhcp4.as_bytes(), 0o644,
        )?;
        service_manager.check_dhcpd(&kea_file.path().to_string_lossy()).await?;
    } else {
        tracing::debug!("kea-dhcp4 not installed, skipping syntax check");
    }

    tracing::debug!("syntax checks passed");
    Ok(())
}

/// Write only rendered configs that changed.
async fn write_changed_configs(rendered: &RenderedConfigs, changeset: &ChangeSet, config: &Config) -> Result<()> {
    // nftables: JSON is applied directly, not written to disk
    if changeset.nftables {
        tracing::debug!("nftables rules will be applied via JSON (not written to disk)");
    }

    if changeset.dhcpd {
        tracing::debug!("writing /etc/kea/kea-dhcp4.conf");
        std::fs::create_dir_all("/etc/kea")?;
        atomic_write("/etc/kea/kea-dhcp4.conf", &rendered.kea_dhcp4)?;
    }

    if changeset.ppp {
        tracing::debug!("writing ppp configs");
        std::fs::create_dir_all("/etc/ppp/peers")?;
        atomic_write_with_mode("/etc/ppp/peers/isp", &rendered.ppp_peers, Some(0o600))?;
        atomic_write_with_mode("/etc/ppp/chap-secrets", &rendered.ppp_chap, Some(0o600))?;
    }

    if changeset.interfaces {
        tracing::debug!("writing network config files");
        write_network_files(&rendered.interfaces)?;
    }

    if changeset.sysctl {
        tracing::debug!("writing /etc/sysctl.d/90-routerd.conf");
        atomic_write("/etc/sysctl.d/90-routerd.conf", &rendered.sysctl)?;
    }

    if changeset.wireguard && wireguard_enabled(config) {
        tracing::debug!("writing /etc/wireguard/wg0.conf");
        std::fs::create_dir_all("/etc/wireguard")?;
        atomic_write_with_mode("/etc/wireguard/wg0.conf", &rendered.wireguard, Some(0o600))?;
    }

    tracing::debug!("changed configs written to /etc");
    Ok(())
}

/// Write systemd-networkd config files, cleaning up stale ones first.
fn write_network_files(files: &[NetworkFile]) -> Result<()> {
    let network_dir = "/etc/systemd/network";
    std::fs::create_dir_all(network_dir)?;

    // Remove old routerd-managed files
    let managed_names: std::collections::HashSet<&str> =
        files.iter().map(|f| f.filename.as_str()).collect();

    if let Ok(entries) = std::fs::read_dir(network_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("50-routerd-") && !managed_names.contains(name.as_str()) {
                tracing::debug!(file = %name, "removing stale network config");
                std::fs::remove_file(entry.path())?;
            }
        }
    }

    // Write new files
    for file in files {
        let path = format!("{}/{}", network_dir, file.filename);
        atomic_write(&path, &file.content)?;
        tracing::debug!(file = %file.filename, "wrote network config");
    }

    Ok(())
}

/// Atomic file write (write to .tmp, then rename).
fn atomic_write(path: &str, content: &str) -> Result<()> {
    atomic_write_with_mode(path, content, None)
}

/// Atomic file write with explicit Unix permissions.
fn atomic_write_with_mode(path: &str, content: &str, mode: Option<u32>) -> Result<()> {
    crate::service::files::atomic_write(Path::new(path), content.as_bytes(), mode.unwrap_or(0o644))
}

/// Apply sysctl settings by loading the config file.
async fn apply_sysctl() -> Result<()> {
    use tokio::process::Command;

    let output = Command::new("sysctl")
        .args(["-p", "/etc/sysctl.d/90-routerd.conf"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("sysctl apply failed: {}", stderr.trim());
    }

    tracing::info!("sysctl settings applied");
    Ok(())
}

/// Extract unique tproxy marks from a config.
fn extract_tproxy_marks(config: &Config) -> HashSet<u32> {
    config
        .firewall
        .rules
        .input
        .iter()
        .chain(config.firewall.rules.forward.iter())
        .filter(|r| r.enabled && r.action == crate::config::schema::Action::Tproxy)
        .filter_map(|r| r.mark)
        .collect()
}

/// Set up ip rule + ip route for TPROXY.
///
/// For each unique fwmark in tproxy rules:
///   ip rule add fwmark <N> lookup <N>
///   ip route add local 0.0.0.0/0 dev lo table <N>
///
/// Old rules/routes are cleaned up first to handle config changes,
/// including marks that were removed from the config.
async fn apply_tproxy_routing(prev_config: &Config, config: &Config) -> Result<()> {
    let prev_marks = extract_tproxy_marks(prev_config);
    let curr_marks = extract_tproxy_marks(config);
    let removed_marks: HashSet<u32> = prev_marks.difference(&curr_marks).copied().collect();

    let marks_to_clean: HashSet<u32> = curr_marks.union(&removed_marks).copied().collect();
    for mark in &marks_to_clean {
        if removed_marks.contains(mark) {
            let _ = tokio::process::Command::new("ip")
                .args(["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", &mark.to_string()])
                .output()
                .await;
        }
        let _ = tokio::process::Command::new("ip")
            .args(["rule", "del", "fwmark", &mark.to_string(), "lookup", &mark.to_string()])
            .output()
            .await;
    }

    // Set up routing for each current mark
    for mark in &curr_marks {
        // ip rule add fwmark <N> lookup <N>
        let output = tokio::process::Command::new("ip")
            .args(["rule", "add", "fwmark", &mark.to_string(), "lookup", &mark.to_string()])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ip rule add failed for mark {}: {}", mark, stderr.trim());
        }

        // ip route add local 0.0.0.0/0 dev lo table <N>
        let output = tokio::process::Command::new("ip")
            .args(["route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", &mark.to_string()])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ip route replace failed for mark {}: {}", mark, stderr.trim());
        }
    }

    if !removed_marks.is_empty() {
        tracing::info!(?removed_marks, "cleaned up removed tproxy marks");
    }
    if !curr_marks.is_empty() {
        tracing::info!(?curr_marks, "tproxy routing configured");
    }

    Ok(())
}

/// Restart services that changed.
async fn restart_services(
    config: &Config,
    rendered: &RenderedConfigs,
    changeset: &ChangeSet,
    service_manager: &ServiceManager,
) -> Result<Vec<String>> {
    let mut restarted = Vec::new();

    // nftables: apply rules via JSON if config changed
    if changeset.nftables {
        tracing::info!("nftables config changed, applying rules via JSON");
        service_manager.apply_nftables_json(&rendered.nftables).await?;
        restarted.push("nftables".into());
    }

    // All systemd-managed services: start if not running, restart if config changed
    let systemd_services = [
        (changeset.interfaces, Service::Networking, true),
        (changeset.dhcpd, Service::Dhcpd, config.dhcp.pools.iter().any(|pool| pool.enabled)),
        (changeset.wireguard, Service::Wireguard, wireguard_enabled(config)),
        (changeset.ppp, Service::Pppd, ppp_enabled(config)),
    ];

    for (changed, service, enabled) in systemd_services {
        let status = service_manager.status(service).await;
        let is_running = status.map(|s| s.active).unwrap_or(false);

        if !enabled {
            if is_running {
                service_manager.stop(service).await?;
                restarted.push(format!("{} (stopped)", service.systemd_name()));
            }
            continue;
        }

        if !is_running {
            tracing::info!(service = service.display_name(), "service not running, starting");
            service_manager.start(service).await?;
            restarted.push(service.systemd_name().into());
        } else if changed {
            if service == Service::Networking {
                // systemd-networkd: use networkctl reload for lighter reconfiguration
                tracing::info!(service = service.display_name(), "config changed, reloading");
                if let Err(e) = service_manager.networkctl_reload().await {
                    tracing::debug!(error = %e, "networkctl reload failed, falling back to restart");
                    service_manager.restart(service).await?;
                    restarted.push(service.systemd_name().into());
                } else {
                    restarted.push("systemd-networkd (reload)".into());
                }
            } else {
                tracing::info!(service = service.display_name(), "config changed, restarting");
                service_manager.restart(service).await?;
                restarted.push(service.systemd_name().into());
            }
        } else {
            tracing::info!(service = service.display_name(), "config unchanged and running, skipping");
        }
    }

    // sing-box: always restart if running (config is managed directly by user, not via changeset)
    let singbox_status = service_manager.status(Service::SingBox).await;
    let singbox_running = singbox_status.as_ref().map(|s| s.active).unwrap_or(false);
    if singbox_running {
        tracing::info!("sing-box config applied, restarting service");
        if let Err(e) = service_manager.restart(Service::SingBox).await {
            if Path::new("/etc/sing-box/config.jsonc").exists() {
                return Err(e);
            }
            tracing::warn!(error = %e, "sing-box service restart failed");
        } else {
            restarted.push("sing-box".into());
        }
    } else {
        tracing::info!("sing-box service not running, starting");
        if let Err(e) = service_manager.start(Service::SingBox).await {
            if Path::new("/etc/sing-box/config.jsonc").exists() {
                return Err(e);
            }
            tracing::warn!(error = %e, "sing-box service start failed");
        } else {
            restarted.push("sing-box".into());
        }
    }

    // Apply sysctl settings
    if changeset.sysctl {
        tracing::info!("sysctl config changed, applying");
        apply_sysctl().await?;
        restarted.push("sysctl".into());
    } else {
        tracing::info!("sysctl config unchanged, skipping");
    }

    Ok(restarted)
}

fn wireguard_enabled(config: &Config) -> bool {
    config.vpn.as_ref().and_then(|vpn| vpn.wireguard.as_ref()).is_some_and(|wireguard| wireguard.enabled)
}

fn ppp_enabled(config: &Config) -> bool {
    config.interfaces.items.iter().any(|wan| {
        wan.method == crate::config::schema::InterfaceMethod::Pppoe
            && wan.pppoe.as_ref().is_some_and(|pppoe| !pppoe.username.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_tunnels_are_disabled_by_default() {
        let config = Config::default();
        assert!(!wireguard_enabled(&config));
        assert!(!ppp_enabled(&config));
    }

    #[tokio::test]
    async fn apply_rejects_invalid_config_before_touching_services() {
        let mut config = Config::default();
        config.firewall.default_policy.input = "invalid".into();
        let error = apply(&config, &config, Path::new("unused"), &ServiceManager::new(), false).await.unwrap_err();
        assert!(error.to_string().contains("config validation failed"));
    }

    #[test]
    fn test_rendered_configs_not_empty() {
        use crate::config::schema::*;
        let config = Config {
            interfaces: Interfaces {
                items: vec![
                    InterfaceConfig {
                        name: "eth0".into(),
                        label: "WAN".into(),
                        method: InterfaceMethod::Pppoe,
                        pppoe: Some(PppoeConfig::default()),
                        ..Default::default()
                    },
                    InterfaceConfig {
                        name: "eth1".into(),
                        label: "LAN".into(),
                        method: InterfaceMethod::Static,
                        static_config: Some(StaticConfig {
                            address: "192.168.1.1/24".into(),
                            gateway: String::new(),
                            dns: vec![],
                        }),
                        ..Default::default()
                    },
                ],
            },
            ..Config::default()
        };
        let rendered = render_all(&config).unwrap();
        assert!(!rendered.nftables.is_empty());
        assert!(!rendered.kea_dhcp4.is_empty());
        assert!(!rendered.interfaces.is_empty());
        // Verify each network file has content
        for file in &rendered.interfaces {
            assert!(!file.content.is_empty(), "network file {} is empty", file.filename);
        }
    }
}
