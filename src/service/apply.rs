use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;
use tokio::sync::{Mutex, MutexGuard};

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

#[derive(Default)]
pub struct ApplyState {
    last_successful: Mutex<Option<AppliedServices>>,
}

impl ApplyState {
    pub async fn pending(&self, config: &Config, previous: &Config) -> bool {
        let last_successful = self.last_successful.lock().await;
        last_successful.is_none() || config != previous
    }

    async fn begin(&self) -> ApplyAttempt<'_> {
        let mut last_successful = self.last_successful.lock().await;
        let previous = last_successful.take();
        ApplyAttempt {
            last_successful,
            previous,
        }
    }
}

struct ApplyAttempt<'a> {
    last_successful: MutexGuard<'a, Option<AppliedServices>>,
    previous: Option<AppliedServices>,
}

impl ApplyAttempt<'_> {
    fn commit(mut self, applied: AppliedServices) {
        *self.last_successful = Some(applied);
    }
}

struct AppliedServices {
    nftables: String,
    singbox: Option<Vec<u8>>,
}

impl AppliedServices {
    fn changes_from(&self, previous: Option<&Self>, force: bool) -> (bool, bool) {
        match previous {
            Some(previous) if !force => (
                self.nftables != previous.nftables,
                self.singbox != previous.singbox,
            ),
            _ => (true, true),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyMode {
    Full,
    Startup,
}

impl ApplyMode {
    fn service_snapshot(self, rendered: &RenderedConfigs) -> Option<AppliedServices> {
        if self == Self::Startup {
            return None;
        }
        Some(AppliedServices {
            nftables: rendered.nftables.clone(),
            singbox: rendered
                .singbox
                .as_ref()
                .map(|content| content.as_bytes().to_vec()),
        })
    }
}

trait NftablesControl {
    async fn check(&self, rendered: &str) -> Result<()>;
    async fn install(&self, rendered: &str) -> Result<()>;
}

impl NftablesControl for ServiceManager {
    async fn check(&self, rendered: &str) -> Result<()> {
        self.check_nftables_json(rendered).await
    }

    async fn install(&self, rendered: &str) -> Result<()> {
        self.apply_nftables_json(rendered).await
    }
}

pub async fn boot_nftables(
    config: &Config,
    service_manager: &ServiceManager,
) -> Result<ApplyResult> {
    let result = boot_nftables_with(config, service_manager).await?;
    crate::service::wan_groups::activate(config, true).await;
    Ok(result)
}

async fn boot_nftables_with(
    config: &Config,
    service_manager: &impl NftablesControl,
) -> Result<ApplyResult> {
    let errors = crate::config::validator::validate(config);
    if !errors.is_empty() {
        anyhow::bail!("config validation failed: {:?}", errors);
    }
    let rendered = renderer::nftables::render(config)?;
    service_manager.check(&rendered).await?;
    service_manager.install(&rendered).await?;
    Ok(ApplyResult {
        success: true,
        services_restarted: vec!["nftables".into()],
        errors: Vec::new(),
        changeset: ChangeSet {
            nftables: true,
            ..Default::default()
        },
    })
}

pub async fn startup(
    config: &Config,
    service_manager: &ServiceManager,
    apply_state: &ApplyState,
) -> Result<ApplyResult> {
    apply_with_mode(
        config,
        config,
        service_manager,
        apply_state,
        false,
        ApplyMode::Startup,
    )
    .await
}

/// Apply orchestrator: render → validate → copy → restart.
///
/// `force` applies all services regardless of changes.
pub async fn apply(
    config: &Config,
    prev_config: &Config,
    _config_path: &Path,
    service_manager: &ServiceManager,
    apply_state: &ApplyState,
    force: bool,
) -> Result<ApplyResult> {
    apply_with_mode(
        config,
        prev_config,
        service_manager,
        apply_state,
        force,
        ApplyMode::Full,
    )
    .await
}

async fn apply_with_mode(
    config: &Config,
    prev_config: &Config,
    service_manager: &ServiceManager,
    apply_state: &ApplyState,
    force: bool,
    mode: ApplyMode,
) -> Result<ApplyResult> {
    let attempt = apply_state.begin().await;
    let errors = crate::config::validator::validate(config);
    if !errors.is_empty() {
        anyhow::bail!("config validation failed: {:?}", errors);
    }
    // Render all service configs
    let rendered = render_all(config)?;

    // Syntax check rendered configs
    syntax_check(&rendered, service_manager, mode).await?;

    let applied_services = mode.service_snapshot(&rendered);
    let (nftables, mut singbox) = applied_services
        .as_ref()
        .map(|applied| applied.changes_from(attempt.previous.as_ref(), force))
        .unwrap_or((false, false));
    singbox &= rendered.singbox.is_some();
    if mode == ApplyMode::Full {
        if let Some(content) = &rendered.singbox {
            singbox |= crate::service::singbox::config_changed(
                Path::new(crate::service::singbox::CONFIG_PATH),
                content,
            )?;
        }
    }

    // Detect changes by comparing rendered configs against files on disk
    let changeset = if force {
        ChangeSet {
            nftables,
            singbox,
            dhcpd: true,
            ppp: true,
            interfaces: true,
            wireguard: true,
            sysctl: true,
            shaper: true,
        }
    } else {
        let mut changes = detect_rendered_changes(&rendered, config, nftables, singbox);
        let previous = render_all(prev_config)?;
        changes.dhcpd |= rendered.kea_dhcp4 != previous.kea_dhcp4;
        changes.ppp |= rendered.ppp_peers != previous.ppp_peers
            || rendered.ppp_chap != previous.ppp_chap
            || rendered.ppp_ip_up != previous.ppp_ip_up;
        changes.interfaces |= rendered.interfaces != previous.interfaces;
        changes.wireguard |= rendered.wireguard != previous.wireguard;
        changes.sysctl |= rendered.sysctl != previous.sysctl;
        changes.shaper |= config.shaper != prev_config.shaper;
        changes
    };

    tracing::debug!(?changeset, "detected service config changes");

    if mode == ApplyMode::Full {
        crate::service::wan_groups::suspend().await;
    }
    crate::service::shaper::suspend().await;
    crate::service::shaper::preflight_config(config).await?;

    // Strict WAN selection must have a lookup and terminal guard before packets
    // can receive its mark. These global rules survive networkd/link changes.
    crate::service::wan_policy::prepare(prev_config, config).await?;

    // Only write configs that changed
    write_changed_configs(&rendered, &changeset, config).await?;

    // Restart changed services
    let services_restarted =
        restart_services(config, &rendered, &changeset, service_manager, mode).await?;
    crate::service::wan_policy::cleanup(prev_config, config).await?;

    // Always set up tproxy routing (ip rule + ip route) — these are ephemeral
    // and need to be re-applied on every boot/config change.
    if let Err(e) = apply_tproxy_routing(prev_config, config).await {
        return Err(e.context("tproxy routing setup failed"));
    }

    crate::service::shaper::reconcile(config).await?;
    crate::service::shaper::activate(config).await;

    if let Some(applied_services) = applied_services {
        crate::service::wan_groups::activate(config, changeset.nftables).await;
        attempt.commit(applied_services);
    }

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
fn detect_rendered_changes(
    rendered: &RenderedConfigs,
    config: &Config,
    nftables: bool,
    singbox: bool,
) -> ChangeSet {
    let dhcpd = file_changed("/etc/kea/kea-dhcp4.conf", &rendered.kea_dhcp4);
    let ppp = file_changed("/etc/ppp/peers/isp", &rendered.ppp_peers)
        || file_changed("/etc/ppp/chap-secrets", &rendered.ppp_chap)
        || file_changed(
            "/etc/ppp/ip-up.d/50-routerd-wan-routing",
            &rendered.ppp_ip_up,
        );
    let wireguard =
        wireguard_enabled(config) && file_changed("/etc/wireguard/wg0.conf", &rendered.wireguard);
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
                    let managed: std::collections::HashSet<&str> = rendered
                        .interfaces
                        .iter()
                        .map(|f| f.filename.as_str())
                        .collect();
                    if !managed.contains(name.as_str()) {
                        interfaces = true;
                        break;
                    }
                }
            }
        }
    }

    ChangeSet {
        nftables,
        singbox,
        dhcpd,
        ppp,
        interfaces,
        wireguard,
        sysctl,
        shaper: config.shaper.profiles.iter().any(|p| p.enabled),
    }
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
        singbox: config
            .singbox
            .as_ref()
            .map(|singbox| singbox.config.clone()),
        kea_dhcp4: renderer::kea::render(config)?,
        ppp_peers: renderer::ppp::render(config)?,
        ppp_chap: renderer::ppp::render_chap_secrets(config)?,
        ppp_ip_up: renderer::ppp::render_ip_up(config)?,
        interfaces: renderer::interfaces::render(config)?,
        wireguard: renderer::wireguard::render(config)?,
        sysctl: renderer::sysctl::render(config)?,
    })
}

/// All rendered service configs.
struct RenderedConfigs {
    nftables: String,
    singbox: Option<String>,
    kea_dhcp4: String,
    ppp_peers: String,
    ppp_chap: String,
    ppp_ip_up: String,
    interfaces: Vec<NetworkFile>,
    wireguard: String,
    sysctl: String,
}

/// Syntax-check rendered configs before applying.
async fn syntax_check(
    rendered: &RenderedConfigs,
    service_manager: &ServiceManager,
    mode: ApplyMode,
) -> Result<()> {
    if mode == ApplyMode::Full {
        service_manager
            .check_nftables_json(&rendered.nftables)
            .await?;
        if let Some(content) = &rendered.singbox {
            crate::service::singbox::validate_config(content).await?;
        }
    }

    // Write kea-dhcp4 to staged file and check (optional — may not be installed)
    if crate::service::manager::find_command("kea-dhcp4").is_ok() {
        let kea_file = crate::service::files::StagedFile::new(
            &std::env::temp_dir(),
            rendered.kea_dhcp4.as_bytes(),
            0o644,
        )?;
        service_manager
            .check_dhcpd(&kea_file.path().to_string_lossy())
            .await?;
    } else {
        tracing::debug!("kea-dhcp4 not installed, skipping syntax check");
    }

    tracing::debug!("syntax checks passed");
    Ok(())
}

/// Write only rendered configs that changed.
async fn write_changed_configs(
    rendered: &RenderedConfigs,
    changeset: &ChangeSet,
    config: &Config,
) -> Result<()> {
    if changeset.singbox {
        if let Some(content) = &rendered.singbox {
            crate::service::singbox::write_config(
                Path::new(crate::service::singbox::CONFIG_PATH),
                content,
            )?;
        }
    }

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
        std::fs::create_dir_all("/etc/ppp/ip-up.d")?;
        atomic_write_with_mode(
            "/etc/ppp/ip-up.d/50-routerd-wan-routing",
            &rendered.ppp_ip_up,
            Some(0o700),
        )?;
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
                .args([
                    "route",
                    "del",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    &mark.to_string(),
                ])
                .output()
                .await;
        }
        let _ = tokio::process::Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                &mark.to_string(),
                "lookup",
                &mark.to_string(),
            ])
            .output()
            .await;
    }

    // Set up routing for each current mark
    for mark in &curr_marks {
        // ip rule add fwmark <N> lookup <N>
        let output = tokio::process::Command::new("ip")
            .args([
                "rule",
                "add",
                "fwmark",
                &mark.to_string(),
                "lookup",
                &mark.to_string(),
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ip rule add failed for mark {}: {}", mark, stderr.trim());
        }

        // ip route add local 0.0.0.0/0 dev lo table <N>
        let output = tokio::process::Command::new("ip")
            .args([
                "route",
                "replace",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                &mark.to_string(),
            ])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "ip route replace failed for mark {}: {}",
                mark,
                stderr.trim()
            );
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
    mode: ApplyMode,
) -> Result<Vec<String>> {
    let mut restarted = Vec::new();

    // nftables: apply rules via JSON if config changed
    if changeset.nftables {
        tracing::info!("nftables config changed, applying rules via JSON");
        service_manager
            .apply_nftables_json(&rendered.nftables)
            .await?;
        restarted.push("nftables".into());
    } else if mode == ApplyMode::Full {
        tracing::info!("nftables config unchanged, skipping");
    }

    // All systemd-managed services: start if not running, restart if config changed
    let systemd_services = [
        (changeset.interfaces, Service::Networking, true),
        (
            changeset.dhcpd,
            Service::Dhcpd,
            config.dhcp.pools.iter().any(|pool| pool.enabled),
        ),
        (
            changeset.wireguard,
            Service::Wireguard,
            wireguard_enabled(config),
        ),
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
            tracing::info!(
                service = service.display_name(),
                "service not running, starting"
            );
            service_manager.start(service).await?;
            restarted.push(service.systemd_name().into());
        } else if changed {
            if service == Service::Networking {
                // systemd-networkd: use networkctl reload for lighter reconfiguration
                tracing::info!(
                    service = service.display_name(),
                    "config changed, reloading"
                );
                if let Err(e) = service_manager.networkctl_reload().await {
                    tracing::debug!(error = %e, "networkctl reload failed, falling back to restart");
                    service_manager.restart(service).await?;
                    restarted.push(service.systemd_name().into());
                } else {
                    restarted.push("systemd-networkd (reload)".into());
                }
            } else {
                tracing::info!(
                    service = service.display_name(),
                    "config changed, restarting"
                );
                service_manager.restart(service).await?;
                restarted.push(service.systemd_name().into());
            }
        } else {
            tracing::info!(
                service = service.display_name(),
                "config unchanged and running, skipping"
            );
        }
    }

    if mode == ApplyMode::Full && rendered.singbox.is_some() {
        reconcile_singbox(changeset.singbox, service_manager, &mut restarted).await?;
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

async fn reconcile_singbox(
    changed: bool,
    service_manager: &ServiceManager,
    restarted: &mut Vec<String>,
) -> Result<()> {
    let singbox_status = service_manager.status(Service::SingBox).await;
    let singbox_running = singbox_status.as_ref().map(|s| s.active).unwrap_or(false);
    if let Some(action) = singbox_action(changed, singbox_running) {
        let result = match action {
            SingBoxAction::Start => {
                tracing::info!("sing-box service not running, starting");
                service_manager.start(Service::SingBox).await
            }
            SingBoxAction::Restart => {
                tracing::info!("sing-box config changed, restarting service");
                service_manager.restart(Service::SingBox).await
            }
        };
        result?;
        restarted.push("sing-box".into());
    } else {
        tracing::info!("sing-box config unchanged and running, skipping");
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum SingBoxAction {
    Start,
    Restart,
}

fn singbox_action(changed: bool, running: bool) -> Option<SingBoxAction> {
    if !running {
        Some(SingBoxAction::Start)
    } else if changed {
        Some(SingBoxAction::Restart)
    } else {
        None
    }
}

fn wireguard_enabled(config: &Config) -> bool {
    config
        .vpn
        .as_ref()
        .and_then(|vpn| vpn.wireguard.as_ref())
        .is_some_and(|wireguard| wireguard.enabled)
}

fn ppp_enabled(config: &Config) -> bool {
    config.interfaces.items.iter().any(|wan| {
        wan.method == crate::config::schema::InterfaceMethod::Pppoe
            && wan
                .pppoe
                .as_ref()
                .is_some_and(|pppoe| !pppoe.username.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeNftables {
        calls: std::sync::Mutex<Vec<(&'static str, String)>>,
        fail_check: bool,
        fail_install: bool,
    }

    impl NftablesControl for FakeNftables {
        async fn check(&self, rendered: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(("check", rendered.to_owned()));
            anyhow::ensure!(!self.fail_check, "nftables check failed");
            Ok(())
        }

        async fn install(&self, rendered: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(("install", rendered.to_owned()));
            anyhow::ensure!(!self.fail_install, "nftables install failed");
            Ok(())
        }
    }

    #[tokio::test]
    async fn boot_checks_then_installs_only_nftables() {
        let config = Config {
            singbox: Some(crate::config::schema::Singbox {
                config: "not JSONC: boot must not validate or deploy this".into(),
            }),
            ..Default::default()
        };
        let manager = FakeNftables::default();
        let result = boot_nftables_with(&config, &manager).await.unwrap();
        let rendered = renderer::nftables::render(&config).unwrap();
        assert_eq!(
            *manager.calls.lock().unwrap(),
            vec![("check", rendered.clone()), ("install", rendered)]
        );
        assert!(result.success);
        assert!(result.errors.is_empty());
        assert_eq!(result.services_restarted, vec!["nftables"]);
        assert_eq!(
            serde_json::to_value(result.changeset).unwrap(),
            serde_json::to_value(ChangeSet {
                nftables: true,
                ..Default::default()
            })
            .unwrap()
        );
    }

    #[tokio::test]
    async fn boot_requires_successful_nftables_check_before_installing() {
        let manager = FakeNftables {
            fail_check: true,
            ..Default::default()
        };
        let error = boot_nftables_with(&Config::default(), &manager)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("nftables check failed"));
        let calls = manager.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "check");
    }

    #[tokio::test]
    async fn boot_propagates_nftables_install_failure() {
        let manager = FakeNftables {
            fail_install: true,
            ..Default::default()
        };
        let error = boot_nftables_with(&Config::default(), &manager)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("nftables install failed"));
        let calls = manager.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "install");
    }

    #[tokio::test]
    async fn boot_rejects_invalid_config_before_nftables_commands() {
        let mut config = Config::default();
        config.firewall.default_policy.input = "invalid".into();
        let manager = FakeNftables::default();
        let error = boot_nftables_with(&config, &manager).await.unwrap_err();
        assert!(error.to_string().contains("config validation failed"));
        assert!(manager.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn startup_skips_singbox_file_reads_and_has_no_full_apply_snapshot() {
        let config = Config {
            singbox: Some(crate::config::schema::Singbox {
                config: "// saved JSONC\n{}".into(),
            }),
            ..Default::default()
        };
        let rendered = render_all(&config).unwrap();
        assert!(ApplyMode::Startup.service_snapshot(&rendered).is_none());
        assert_eq!(
            ApplyMode::Full.service_snapshot(&rendered).unwrap().singbox,
            Some(b"// saved JSONC\n{}".to_vec())
        );
    }

    #[tokio::test]
    async fn startup_rejects_invalid_config_before_touching_services() {
        let mut config = Config::default();
        config.firewall.default_policy.input = "invalid".into();
        let state = ApplyState::default();
        let error = startup(&config, &ServiceManager::new(), &state)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("config validation failed"));
        assert!(state.last_successful.lock().await.is_none());
    }

    fn services(config: &Config, singbox: Option<&[u8]>) -> AppliedServices {
        AppliedServices {
            nftables: render_all(config).unwrap().nftables,
            singbox: singbox.map(<[u8]>::to_vec),
        }
    }

    #[tokio::test]
    async fn pending_status_compares_saved_config_and_supports_noop_saves_and_reverts() {
        let fixture = crate::config::store::tests::TestStore::new();
        let config = fixture.store.get().await;
        let state = fixture.store.apply_state();
        assert!(state.pending(&config, &config).await);

        state.begin().await.commit(services(&config, None));
        fixture.store.set(config.clone()).await.unwrap();
        assert!(
            !state
                .pending(
                    &fixture.store.get().await,
                    &fixture.store.get_applied().await
                )
                .await
        );

        let mut changed = config.clone();
        changed.firewall.blackhole.push("203.0.113.1".into());
        fixture.store.set(changed).await.unwrap();
        assert!(
            state
                .pending(
                    &fixture.store.get().await,
                    &fixture.store.get_applied().await
                )
                .await
        );

        fixture.store.set(config.clone()).await.unwrap();
        assert!(
            !state
                .pending(
                    &fixture.store.get().await,
                    &fixture.store.get_applied().await
                )
                .await
        );
        drop(state.begin().await);
        assert!(state.pending(&config, &config).await);
    }

    #[tokio::test]
    async fn pending_status_tracks_saved_singbox_changes_not_deployed_file_edits() {
        let config = Config {
            singbox: Some(crate::config::schema::Singbox {
                config: "// original\n{}".into(),
            }),
            ..Default::default()
        };
        let state = ApplyState::default();
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        state.begin().await.commit(
            ApplyMode::Full
                .service_snapshot(&render_all(&config).unwrap())
                .unwrap(),
        );
        let mut changed = config.clone();
        changed.singbox.as_mut().unwrap().config = "// changed\n{}".into();
        assert!(state.pending(&changed, &config).await);
        assert!(!state.pending(&config, &config).await);
        changed.singbox = None;
        assert!(state.pending(&changed, &config).await);
        crate::service::singbox::write_config(
            &directory.path().join("config.jsonc"),
            "// external\n{}",
        )
        .unwrap();
        assert!(!state.pending(&config, &config).await);
    }

    #[tokio::test]
    async fn failed_apply_leaves_status_pending_even_when_config_is_unchanged() {
        let mut config = Config::default();
        let state = ApplyState::default();
        state.begin().await.commit(services(&config, None));
        config.firewall.default_policy.input = "invalid".into();
        assert!(apply(
            &config,
            &config,
            Path::new("unused"),
            &ServiceManager::new(),
            &state,
            false
        )
        .await
        .is_err());
        assert!(state.pending(&config, &config).await);
    }

    #[test]
    fn unchanged_services_are_skipped_only_after_a_successful_apply() {
        let config = Config::default();
        let previous = services(&config, Some(b"{\"log\":{}}"));
        let current = services(&config, Some(b"{\"log\":{}}"));
        assert_eq!(current.changes_from(None, false), (true, true));
        assert_eq!(current.changes_from(Some(&previous), false), (false, false));
        assert_eq!(current.changes_from(Some(&previous), true), (true, true));
    }

    #[test]
    fn nftables_and_raw_singbox_changes_are_independent() {
        let config = Config {
            singbox: Some(crate::config::schema::Singbox {
                config: "{\"log\":{}}".into(),
            }),
            ..Default::default()
        };
        let snapshot = |config: &Config| {
            ApplyMode::Full
                .service_snapshot(&render_all(config).unwrap())
                .unwrap()
        };
        let previous = snapshot(&config);
        let mut changed = config.clone();
        changed.firewall.blackhole.push("203.0.113.1".into());
        assert_eq!(
            snapshot(&changed).changes_from(Some(&previous), false),
            (true, false)
        );
        changed = config.clone();
        changed.singbox.as_mut().unwrap().config = "// comment\n{\"log\":{}}".into();
        assert_eq!(
            snapshot(&changed).changes_from(Some(&previous), false),
            (false, true)
        );
        changed.singbox = None;
        let absent = snapshot(&changed);
        assert_eq!(absent.changes_from(Some(&previous), false), (false, true));
        assert_eq!(absent.changes_from(Some(&absent), false), (false, false));
        assert_eq!(previous.changes_from(Some(&absent), false), (false, true));
    }

    #[test]
    fn unrelated_saved_settings_do_not_reload_services() {
        let config = Config::default();
        let previous = services(&config, Some(b"{}"));
        let mut changed = config.clone();
        changed.hooks.after_start = "echo changed".into();
        changed.auth.jwt_secret = "changed".into();
        assert_eq!(
            services(&changed, Some(b"{}")).changes_from(Some(&previous), false),
            (false, false)
        );
    }

    #[tokio::test]
    async fn failed_or_cancelled_attempts_invalidate_the_service_snapshot() {
        let config = Config::default();
        let state = ApplyState::default();
        let first = state.begin().await;
        assert!(first.previous.is_none());
        first.commit(services(&config, Some(b"{}")));

        let successful = state.begin().await;
        assert_eq!(
            services(&config, Some(b"{}")).changes_from(successful.previous.as_ref(), false),
            (false, false)
        );
        successful.commit(services(&config, Some(b"{}")));

        let failed = state.begin().await;
        assert!(failed.previous.is_some());
        drop(failed);

        let retry = state.begin().await;
        assert_eq!(
            services(&config, Some(b"{}")).changes_from(retry.previous.as_ref(), false),
            (true, true)
        );
    }

    #[tokio::test]
    async fn loading_and_saving_yaml_do_not_advance_service_snapshots() {
        let fixture = crate::config::store::tests::TestStore::new();
        let config = fixture.store.get().await;
        assert_eq!(config, fixture.store.get_applied().await);
        let first = fixture.store.apply_state().begin().await;
        assert_eq!(
            services(&config, Some(b"{}")).changes_from(first.previous.as_ref(), false),
            (true, true)
        );
        first.commit(services(&config, Some(b"{}")));

        let mut saved = config.clone();
        saved.firewall.blackhole.push("203.0.113.1".into());
        fixture.store.set(saved.clone()).await.unwrap();
        let pending = fixture.store.apply_state().begin().await;
        assert_eq!(
            services(&saved, Some(b"{}")).changes_from(pending.previous.as_ref(), false),
            (true, false)
        );
        assert_eq!(
            services(&config, Some(b"{}")).changes_from(pending.previous.as_ref(), false),
            (false, false)
        );
    }

    #[test]
    fn singbox_restarts_only_when_changed_but_recovers_an_inactive_service() {
        assert_eq!(singbox_action(false, true), None);
        assert_eq!(singbox_action(true, true), Some(SingBoxAction::Restart));
        assert_eq!(singbox_action(false, false), Some(SingBoxAction::Start));
        assert_eq!(singbox_action(true, false), Some(SingBoxAction::Start));
    }

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
        let error = apply(
            &config,
            &config,
            Path::new("unused"),
            &ServiceManager::new(),
            &ApplyState::default(),
            false,
        )
        .await
        .unwrap_err();
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
            assert!(
                !file.content.is_empty(),
                "network file {} is empty",
                file.filename
            );
        }
    }
}
