use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;

pub const CONFIG_PATH: &str = "/etc/sing-box/config.jsonc";
const SERVICE_PATH: &str = "/etc/systemd/system/sing-box.service";

pub async fn validate_config(content: &str) -> Result<()> {
    let Ok(binary) = crate::service::manager::find_command("sing-box") else {
        return Ok(());
    };
    validate_with_binary(content, Path::new(&binary)).await
}

async fn validate_with_binary(content: &str, binary: &Path) -> Result<()> {
    let staged =
        crate::service::files::StagedFile::new(&std::env::temp_dir(), content.as_bytes(), 0o600)?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Command::new(binary)
            .args(["check", "-c"])
            .arg(staged.path())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("sing-box config validation timed out")?
    .context("failed to validate sing-box config")?;
    anyhow::ensure!(
        output.status.success(),
        "sing-box config validation failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

pub fn config_changed(path: &Path, content: &str) -> Result<bool> {
    match std::fs::read(path) {
        Ok(existing) => Ok(existing != content.as_bytes()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read sing-box config {}", path.display()))
        }
    }
}

pub fn write_config(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::service::files::atomic_write(path, content.as_bytes(), 0o600)
}

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

pub async fn install(config_path: &Path) -> Result<()> {
    install_with_systemctl(
        config_path,
        Path::new(CONFIG_PATH),
        Path::new(SERVICE_PATH),
        Path::new("systemctl"),
    )
    .await
}

async fn install_with_systemctl(
    config_path: &Path,
    deployed_path: &Path,
    service_path: &Path,
    systemctl_path: &Path,
) -> Result<()> {
    install_to(config_path, deployed_path, service_path)?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Command::new(systemctl_path)
            .arg("daemon-reload")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("systemctl daemon-reload timed out; sing-box files already installed")?
    .context("failed to execute systemctl daemon-reload; sing-box files already installed")?;
    anyhow::ensure!(
        output.status.success(),
        "systemctl daemon-reload failed; sing-box files already installed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    tracing::info!(
        "systemd daemon reloaded; sing-box enable/start/restart left to the administrator"
    );
    Ok(())
}

fn install_to(config_path: &Path, deployed_path: &Path, service_path: &Path) -> Result<()> {
    let yaml = std::fs::read_to_string(config_path)
        .with_context(|| format!("failed to read routerd config {}", config_path.display()))?;
    let config: crate::config::Config = serde_yaml::from_str(&yaml)
        .with_context(|| format!("failed to parse routerd config {}", config_path.display()))?;
    let singbox = config.singbox.context("singbox.config is missing; save sing-box JSONC in routerd config before using --install-singbox")?;
    anyhow::ensure!(
        !singbox.config.trim().is_empty(),
        "singbox.config must not be empty"
    );

    write_config(deployed_path, &singbox.config).with_context(|| {
        format!(
            "failed to install sing-box config {}",
            deployed_path.display()
        )
    })?;
    if let Some(parent) = service_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::service::files::atomic_write(service_path, SINGBOX_SERVICE.as_bytes(), 0o644)
        .with_context(|| format!("failed to install sing-box unit {}", service_path.display()))?;
    tracing::info!(config = %deployed_path.display(), unit = %service_path.display(), "sing-box configuration and systemd unit installed; existing files overwritten");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn save_install_fixture(path: &Path, raw: &str) -> Vec<u8> {
        let config = crate::config::Config {
            singbox: Some(crate::config::schema::Singbox { config: raw.into() }),
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&config).unwrap().into_bytes();
        crate::service::files::atomic_write(path, &yaml, 0o600).unwrap();
        yaml
    }

    #[tokio::test]
    async fn install_reloads_systemd_only_after_both_files_are_written() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        let systemctl = directory.path().join("fake-systemctl");
        let calls = directory.path().join("calls");
        save_install_fixture(&source, "// saved JSONC\n{}");
        let script = format!(
            "#!/bin/sh\n[ -f '{}' ] && [ -f '{}' ] || exit 2\nprintf '%s\\n' \"$@\" > '{}'\n",
            deployed.display(),
            unit.display(),
            calls.display()
        );
        crate::service::files::atomic_write(&systemctl, script.as_bytes(), 0o700).unwrap();

        install_with_systemctl(&source, &deployed, &unit, &systemctl)
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(calls).unwrap(), "daemon-reload\n");
        assert_eq!(
            std::fs::read_to_string(deployed).unwrap(),
            "// saved JSONC\n{}"
        );
        assert_eq!(std::fs::read_to_string(unit).unwrap(), SINGBOX_SERVICE);
    }

    #[tokio::test]
    async fn install_does_not_reload_systemd_when_config_or_unit_write_fails() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        let systemctl = directory.path().join("fake-systemctl");
        let calls = directory.path().join("calls");
        let script = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", calls.display());
        crate::service::files::atomic_write(&systemctl, script.as_bytes(), 0o700).unwrap();
        assert!(
            install_with_systemctl(&source, &deployed, &unit, &systemctl)
                .await
                .is_err()
        );
        assert!(!calls.exists());

        save_install_fixture(&source, "{}");
        std::fs::create_dir(&deployed).unwrap();
        assert!(
            install_with_systemctl(&source, &deployed, &unit, &systemctl)
                .await
                .is_err()
        );
        assert!(!calls.exists());
        std::fs::remove_dir(&deployed).unwrap();
        std::fs::create_dir(&unit).unwrap();
        assert!(
            install_with_systemctl(&source, &deployed, &unit, &systemctl)
                .await
                .is_err()
        );
        assert!(!calls.exists());
    }

    #[tokio::test]
    async fn install_propagates_reload_failures_without_claiming_success() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        let systemctl = directory.path().join("fake-systemctl");
        save_install_fixture(&source, "{}");
        crate::service::files::atomic_write(
            &systemctl,
            b"#!/bin/sh\necho reload-refused >&2\nexit 1\n",
            0o700,
        )
        .unwrap();
        let error = install_with_systemctl(&source, &deployed, &unit, &systemctl)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reload-refused"));
        assert!(error.to_string().contains("files already installed"));
        assert!(deployed.exists());
        assert!(unit.exists());

        std::fs::remove_file(&systemctl).unwrap();
        let error = install_with_systemctl(&source, &deployed, &unit, &systemctl)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to execute systemctl daemon-reload"));
    }

    #[test]
    fn install_creates_only_config_and_unit_from_saved_jsonc() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let deployed = directory.path().join("etc/sing-box/config.jsonc");
        let unit = directory.path().join("etc/systemd/system/sing-box.service");
        let raw = "{\n  // keep this exact comment\n  \"log\": { \"level\": \"info\" }\n}\n";
        let original = save_install_fixture(&source, raw);

        install_to(&source, &deployed, &unit).unwrap();

        assert_eq!(std::fs::read_to_string(&deployed).unwrap(), raw);
        assert_eq!(
            std::fs::metadata(&deployed).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&unit).unwrap(), SINGBOX_SERVICE);
        assert_eq!(
            std::fs::metadata(&unit).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert!(!directory.path().join("backups").exists());
        assert!(!directory.path().join("usr").exists());
        assert!(SINGBOX_SERVICE
            .contains("ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.jsonc"));
    }

    #[test]
    fn install_always_overwrites_existing_files_even_when_unchanged() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        let raw = "// saved\n{}\n";
        save_install_fixture(&source, raw);
        crate::service::files::atomic_write(&deployed, b"old config", 0o644).unwrap();
        crate::service::files::atomic_write(&unit, b"old unit", 0o600).unwrap();

        for _attempt in 0..2 {
            let previous_config = std::fs::File::open(&deployed).unwrap();
            let previous_unit = std::fs::File::open(&unit).unwrap();
            install_to(&source, &deployed, &unit).unwrap();
            assert_ne!(
                std::fs::metadata(&deployed).unwrap().ino(),
                previous_config.metadata().unwrap().ino()
            );
            assert_ne!(
                std::fs::metadata(&unit).unwrap().ino(),
                previous_unit.metadata().unwrap().ino()
            );
            assert_eq!(std::fs::read_to_string(&deployed).unwrap(), raw);
            assert_eq!(std::fs::read_to_string(&unit).unwrap(), SINGBOX_SERVICE);
            assert_eq!(
                std::fs::metadata(&deployed).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&unit).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }

    #[test]
    fn install_rejects_missing_or_invalid_saved_config_before_overwriting_files() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        assert!(install_to(&source, &deployed, &unit).is_err());
        assert!(!deployed.exists());
        assert!(!unit.exists());
        write_config(&deployed, "existing config").unwrap();
        crate::service::files::atomic_write(&unit, b"existing unit", 0o644).unwrap();
        for yaml in [
            "{}\n",
            "singbox: {config: ''}\n",
            "singbox: {config: '  '}\n",
            "singbox: {config: []}\n",
            "singbox: [invalid\n",
        ] {
            crate::service::files::atomic_write(&source, yaml.as_bytes(), 0o600).unwrap();
            assert!(install_to(&source, &deployed, &unit).is_err());
            assert_eq!(
                std::fs::read_to_string(&deployed).unwrap(),
                "existing config"
            );
            assert_eq!(std::fs::read_to_string(&unit).unwrap(), "existing unit");
        }
    }

    #[test]
    fn install_replaces_symlinks_without_overwriting_their_targets() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        let original = save_install_fixture(&source, "// saved\n{}");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        std::os::unix::fs::symlink(&source, &deployed).unwrap();
        std::os::unix::fs::symlink(&source, &unit).unwrap();
        install_to(&source, &deployed, &unit).unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert!(!std::fs::symlink_metadata(deployed)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!std::fs::symlink_metadata(unit)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn install_propagates_destination_write_failures() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let source = directory.path().join("config.yml");
        save_install_fixture(&source, "{}");
        let deployed = directory.path().join("config.jsonc");
        let unit = directory.path().join("sing-box.service");
        std::fs::create_dir(&deployed).unwrap();
        assert!(install_to(&source, &deployed, &unit).is_err());
        assert!(!unit.exists());
        std::fs::remove_dir(&deployed).unwrap();
        std::fs::create_dir(&unit).unwrap();
        assert!(install_to(&source, &deployed, &unit).is_err());
    }

    #[test]
    fn deploy_preserves_jsonc_and_private_permissions_and_detects_drift() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let path = directory.path().join("sing-box/config.jsonc");
        let content = "{\n  // keep comments and whitespace\n  \"log\": {}\n}\n";
        assert!(config_changed(&path, content).unwrap());
        write_config(&path, content).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!config_changed(&path, content).unwrap());
        write_config(&path, "// external edit\n{}").unwrap();
        assert!(config_changed(&path, content).unwrap());
        assert!(config_changed(directory.path(), content).is_err());
    }

    #[tokio::test]
    async fn validation_checks_an_isolated_staged_copy_and_propagates_failure() {
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let binary = directory.path().join("fake-sing-box");
        let captured = directory.path().join("captured.jsonc");
        let content = "// raw JSONC\n{}\n";
        let script = format!(
            "#!/bin/sh\n[ \"$1\" = check ] && [ \"$2\" = -c ] || exit 1\ncat \"$3\" > '{}'\n",
            captured.display()
        );
        crate::service::files::atomic_write(&binary, script.as_bytes(), 0o700).unwrap();
        validate_with_binary(content, &binary).await.unwrap();
        assert_eq!(std::fs::read_to_string(captured).unwrap(), content);
        crate::service::files::atomic_write(
            &binary,
            b"#!/bin/sh\necho invalid-config >&2\nexit 1\n",
            0o700,
        )
        .unwrap();
        let error = validate_with_binary(content, &binary).await.unwrap_err();
        assert!(error.to_string().contains("invalid-config"));
        assert!(
            validate_with_binary(content, &directory.path().join("missing-binary"))
                .await
                .is_err()
        );
    }
}
