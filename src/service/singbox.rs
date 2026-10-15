use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;

const SINGBOX_SERVICE: &str = r#"[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.jsonc
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"#;

/// Detect system architecture for download URL.
fn detect_arch() -> Result<&'static str> {
    let output = std::process::Command::new("uname")
        .arg("-m")
        .output()
        .context("failed to run uname")?;

    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match arch.as_str() {
        "x86_64" | "amd64" => Ok("amd64"),
        "aarch64" | "arm64" => Ok("arm64"),
        "armv7l" => Ok("armv7"),
        _ => anyhow::bail!("unsupported architecture: {}", arch),
    }
}

/// Detect OS (always linux for this project).
fn detect_os() -> &'static str {
    "linux"
}

/// Get the latest sing-box version from GitHub API (including RC/alpha/beta).
async fn get_latest_version(arch: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.github.com/repos/SagerNet/sing-box/releases")
        .header("User-Agent", "routerd")
        .send()
        .await
        .context("failed to fetch releases")?;

    let releases: Vec<serde_json::Value> = resp
        .json()
        .await
        .context("failed to parse releases")?;

    // Find the first release that has a linux-amd64 asset
    for release in &releases {
        let tag = release["tag_name"]
            .as_str()
            .unwrap_or("")
            .to_string();

        if tag.is_empty() {
            continue;
        }

        // Check if this release has a linux-amd64 asset
        let has_linux_asset = release["assets"]
            .as_array()
            .map(|assets| {
                assets.iter().any(|a| {
                    a["name"]
                        .as_str()
                        .map(|n| n.ends_with(&format!("-linux-{}.tar.gz", arch)))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        if has_linux_asset {
            let version = tag.strip_prefix('v').unwrap_or(&tag).to_string();
            return Ok(version);
        }
    }

    anyhow::bail!("no sing-box release found with linux-{} asset", arch);
}

/// Download and install sing-box binary.
pub async fn install() -> Result<()> {
    let arch = detect_arch()?;
    let os = detect_os();

    tracing::info!("detecting latest sing-box version");
    let version = get_latest_version(arch).await?;
    tracing::info!(version = %version, arch = %arch, "downloading sing-box");

    // Asset naming: sing-box-{version}-{os}-{arch}.tar.gz
    let filename = format!("sing-box-{}-{}-{}.tar.gz", version, os, arch);
    let url = format!(
        "https://github.com/SagerNet/sing-box/releases/download/v{}/{}",
        version, filename
    );

    tracing::info!(url = %url, "downloading sing-box");

    // Download to /tmp
    let staged = crate::service::files::StagedDirectory::new()?;
    let download_path = staged.path().join(&filename);
    let download_path = download_path.to_string_lossy().to_string();
    let status = Command::new("curl")
        .args(["-fSL", "-o", &download_path, &url])
        .status()
        .await
        .context("failed to run curl")?;

    if !status.success() {
        anyhow::bail!("failed to download sing-box from {}", url);
    }

    // Extract binary from tarball
    let extract_path = staged.path().join("extract");
    std::fs::create_dir(&extract_path)?;
    let tmp_extract = extract_path.to_str().context("invalid staging path")?;

    let status = Command::new("tar")
        .args(["xzf", &download_path, "-C", tmp_extract])
        .status()
        .await
        .context("failed to extract tarball")?;

    if !status.success() {
        anyhow::bail!("failed to extract sing-box tarball");
    }

    // Find and copy the binary
    // The tarball extracts to: sing-box-{version}-{os}-{arch}/sing-box
    let binary_dir = format!("sing-box-{}-{}-{}", version, os, arch);
    let extracted_binary = format!("{}/{}/sing-box", tmp_extract, binary_dir);

    let binary_path = if Path::new(&extracted_binary).is_file() {
        extracted_binary
    } else {
        // Try finding sing-box anywhere in the extracted directory
        let found = find_binary(tmp_extract)?;
        found.context("sing-box binary not found in extracted archive")?
    };

    // Make executable
    crate::service::files::atomic_write(Path::new("/usr/local/bin/sing-box"), &std::fs::read(binary_path)?, 0o755)?;

    // Create systemd service file
    std::fs::create_dir_all("/etc/sing-box")?;
    crate::service::files::atomic_write(Path::new("/etc/systemd/system/sing-box.service"), SINGBOX_SERVICE.as_bytes(), 0o644)?;

    // Reload systemd
    let status = Command::new("systemctl")
        .args(["daemon-reload"])
        .status()
        .await
        .context("failed to reload systemd")?;

    if !status.success() {
        tracing::warn!("systemctl daemon-reload failed");
    }

    // Enable the service
    let status = Command::new("systemctl")
        .args(["enable", "sing-box"])
        .status()
        .await
        .context("failed to enable sing-box")?;

    if !status.success() {
        tracing::warn!("systemctl enable sing-box failed");
    }

    tracing::info!(version = %version, "sing-box installed successfully");
    Ok(())
}

/// Recursively find a binary named "sing-box" in a directory.
fn find_binary(dir: &str) -> Result<Option<String>> {
    let entries = std::fs::read_dir(dir).context("failed to read directory")?;
    for entry in entries.flatten() {
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_binary(&path.to_string_lossy())? {
                return Ok(Some(found));
            }
        } else if entry.file_name() == "sing-box" {
            return Ok(Some(path.to_string_lossy().to_string()));
        }
    }
    Ok(None)
}
