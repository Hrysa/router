use anyhow::Result;
use std::time::Duration;
use tokio::process::Command;

/// Services managed by routerd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Service {
    Nftables,
    #[serde(rename = "kea-dhcp4-server")]
    Dhcpd,
    Pppd,
    Networking,
    Wireguard,
    SingBox,
    Vnstat,
}

impl Service {
    pub fn systemd_name(&self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Dhcpd => "kea-dhcp4-server",
            Self::Pppd => "pppd",
            Self::Networking => "systemd-networkd",
            Self::Wireguard => "wg-quick@wg0",
            Self::SingBox => "sing-box",
            Self::Vnstat => "vnstat",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Dhcpd => "Kea DHCPv4",
            Self::Pppd => "PPPoE",
            Self::Networking => "systemd-networkd",
            Self::Wireguard => "WireGuard",
            Self::SingBox => "sing-box",
            Self::Vnstat => "vnStat",
        }
    }

    /// All managed services.
    pub fn all() -> &'static [Service] {
        &[
            Self::Nftables,
            Self::Dhcpd,
            Self::Pppd,
            Self::Networking,
            Self::Wireguard,
            Self::SingBox,
            Self::Vnstat,
        ]
    }
}

/// Status of a service.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceStatus {
    pub service: Service,
    pub active: bool,
    pub status: String, // "active", "inactive", "failed", "unknown"
    pub pid: Option<u32>,
    pub uptime: Option<String>,
}

/// Service lifecycle manager.
pub struct ServiceManager {
    apply_timeout: Duration,
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            apply_timeout: Duration::from_secs(30),
        }
    }

    /// Check if a service is currently active.
    pub async fn status(&self, service: Service) -> Result<ServiceStatus> {
        let output = Command::new("systemctl")
            .args(["is-active", service.systemd_name()])
            .output()
            .await?;

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let active = status == "active";

        // Get PID if active
        let pid = if active {
            self.get_pid(service).await.ok()
        } else {
            None
        };

        Ok(ServiceStatus {
            service,
            active,
            status,
            pid,
            uptime: None, // TODO: parse from systemctl show
        })
    }

    /// Get status of all managed services.
    pub async fn status_all(&self) -> Result<Vec<ServiceStatus>> {
        let mut statuses = Vec::with_capacity(Service::all().len());
        for &service in Service::all() {
            statuses.push(self.status(service).await?);
        }
        Ok(statuses)
    }

    /// Start a service.
    pub async fn start(&self, service: Service) -> Result<()> {
        let output = Command::new("systemctl")
            .args(["start", service.systemd_name()])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "failed to start {}: {}",
                service.display_name(),
                stderr.trim()
            );
        }

        tracing::info!(service = service.display_name(), "service started");
        Ok(())
    }

    /// Stop a service.
    pub async fn stop(&self, service: Service) -> Result<()> {
        let output = Command::new("systemctl")
            .args(["stop", service.systemd_name()])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "failed to stop {}: {}",
                service.display_name(),
                stderr.trim()
            );
        }

        tracing::info!(service = service.display_name(), "service stopped");
        Ok(())
    }

    /// Restart a service.
    pub async fn restart(&self, service: Service) -> Result<()> {
        let output = Command::new("systemctl")
            .args(["restart", service.systemd_name()])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "failed to restart {}: {}",
                service.display_name(),
                stderr.trim()
            );
        }

        // Verify it's running after restart
        tokio::time::sleep(Duration::from_millis(500)).await;
        let status = self.status(service).await?;
        if !status.active {
            tracing::warn!(
                service = service.display_name(),
                "service not active after restart"
            );
        }

        tracing::info!(service = service.display_name(), "service restarted");
        Ok(())
    }

    /// Reload systemd-networkd configuration (lighter than restart).
    ///
    /// Runs `networkctl reload` which re-reads .network/.netdev files
    /// without tearing down existing connections.
    pub async fn networkctl_reload(&self) -> Result<()> {
        let output = Command::new("networkctl")
            .arg("reload")
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("networkctl reload failed: {}", stderr.trim());
        }

        tracing::info!("systemd-networkd configuration reloaded");
        Ok(())
    }

    /// Apply nftables rules (special handling: use nft -f instead of systemctl).
    pub async fn apply_nftables(&self, config_path: &str) -> Result<()> {
        let nft = find_command("nft")?;
        let output = Command::new(&nft)
            .args(["-f", config_path])
            .timeout_run(self.apply_timeout)
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nftables apply failed: {}", stderr.trim());
        }

        tracing::info!("nftables rules applied");
        Ok(())
    }

    /// Validate nftables config syntax.
    pub async fn check_nftables(&self, config_path: &str) -> Result<()> {
        let nft = find_command("nft")?;
        let output = Command::new(&nft)
            .args(["-c", "-f", config_path])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nftables syntax check failed: {}", stderr.trim());
        }

        Ok(())
    }

    /// Validate kea-dhcp4 config syntax.
    pub async fn check_dhcpd(&self, config_path: &str) -> Result<()> {
        let kea = find_command("kea-dhcp4")?;
        // kea-dhcp4 drops privileges to _kea user when run as root,
        // so the file must be world-readable
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config_path, std::fs::Permissions::from_mode(0o644))?;
        tracing::debug!(path = config_path, bin = %kea, "running kea-dhcp4 syntax check");
        let output = Command::new(&kea)
            .args(["-t", config_path])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            anyhow::bail!("kea-dhcp4 syntax check failed: {} {}", stderr.trim(), stdout.trim());
        }

        Ok(())
    }

    /// Get PID of a running service.
    async fn get_pid(&self, service: Service) -> Result<u32> {
        let output = Command::new("systemctl")
            .args(["show", service.systemd_name(), "--property=MainPID"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: MainPID=12345
        let pid_str = stdout
            .trim()
            .strip_prefix("MainPID=")
            .unwrap_or("0");

        Ok(pid_str.parse().unwrap_or(0))
    }
}

/// Extension trait for tokio Command timeout.
trait CommandExt {
    async fn timeout_run(&mut self, duration: Duration) -> Result<std::process::Output>;
}

impl CommandExt for Command {
    async fn timeout_run(&mut self, duration: Duration) -> Result<std::process::Output> {
        self.kill_on_drop(true);
        tokio::select! {
            output = self.output() => Ok(output?),
            _ = tokio::time::sleep(duration) => {
                anyhow::bail!("command timed out after {:?}", duration)
            }
        }
    }
}

/// Check that a command binary exists in PATH or common system paths.
/// Returns the full path if found, error if not.
pub fn find_command(name: &str) -> Result<String> {
    // Try which first (respects PATH)
    if let Ok(path) = which::which(name) {
        return Ok(path.to_string_lossy().to_string());
    }
    // Try common system paths
    for dir in ["/sbin", "/usr/sbin", "/usr/local/sbin", "/usr/local/bin"] {
        let path = format!("{}/{}", dir, name);
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }
    tracing::error!(command = name, "required command not found");
    anyhow::bail!("{}: command not found — is it installed?", name);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_names() {
        assert_eq!(Service::Nftables.systemd_name(), "nftables");
        assert_eq!(Service::Dhcpd.systemd_name(), "kea-dhcp4-server");
        assert_eq!(Service::Networking.systemd_name(), "systemd-networkd");
        assert_eq!(Service::Wireguard.systemd_name(), "wg-quick@wg0");
    }

    #[test]
    fn test_service_display_names() {
        assert_eq!(Service::Nftables.display_name(), "nftables");
        assert_eq!(Service::Dhcpd.display_name(), "Kea DHCPv4");
    }

    #[test]
    fn test_all_services() {
        assert_eq!(Service::all().len(), 7);
    }
}
