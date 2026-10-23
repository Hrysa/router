use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;

pub const UNIT_PATH: &str = "/etc/systemd/system/routerd.service";

fn quote_argument(value: &str) -> Result<String> {
    anyhow::ensure!(
        !value.chars().any(char::is_control),
        "systemd arguments must not contain control characters"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

pub async fn install(arguments: &[String]) -> Result<()> {
    install_with_systemctl(arguments, Path::new(UNIT_PATH), Path::new("systemctl")).await
}

async fn install_with_systemctl(
    arguments: &[String],
    unit_path: &Path,
    systemctl: &Path,
) -> Result<()> {
    let command = arguments
        .iter()
        .map(|argument| quote_argument(argument))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let unit = format!(
        "[Unit]\nDescription=routerd router daemon\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={command}\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n"
    );
    super::files::atomic_create(unit_path, unit.as_bytes(), 0o644)
        .context("failed to install routerd.service")?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        Command::new(systemctl)
            .arg("daemon-reload")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("daemon-reload timed out; routerd.service already installed")?
    .context("failed to execute daemon-reload; routerd.service already installed")?;
    anyhow::ensure!(
        output.status.success(),
        "daemon-reload failed; routerd.service already installed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    tracing::info!("routerd.service installed and systemd reloaded; enable/start left to the administrator (the unit uses normal startup)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn arguments_escape_systemd_expansion_and_reject_line_injection() {
        assert_eq!(
            quote_argument("/a b/\"\\%n$HOME").unwrap(),
            "\"/a b/\\\"\\\\%%n$$HOME\""
        );
        for invalid in ["a\nb", "a\rb", "a\0b", "a\tb"] {
            assert!(quote_argument(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn installation_only_reloads_after_write_and_propagates_failures() {
        let directory = super::super::files::StagedDirectory::new().unwrap();
        let unit = directory.path().join("routerd.service");
        let systemctl = directory.path().join("systemctl");
        let calls = directory.path().join("calls");
        let script = format!(
            "#!/bin/sh\n[ -f '{}' ] || exit 2\nprintf '%s\\n' \"$@\" > '{}'\n",
            unit.display(),
            calls.display()
        );
        super::super::files::atomic_write(&systemctl, script.as_bytes(), 0o700).unwrap();
        let arguments = vec![
            "/usr/local/bin/routerd".into(),
            "--config-dir".into(),
            "/tmp/config space".into(),
        ];
        install_with_systemctl(&arguments, &unit, &systemctl)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&calls).unwrap(), "daemon-reload\n");
        assert!(std::fs::read_to_string(&unit).unwrap().contains(
            "ExecStart=\"/usr/local/bin/routerd\" \"--config-dir\" \"/tmp/config space\""
        ));
        assert_eq!(
            std::fs::metadata(&unit).unwrap().permissions().mode() & 0o777,
            0o644
        );
        std::fs::remove_file(&calls).unwrap();
        let original = std::fs::read(&unit).unwrap();
        assert!(install_with_systemctl(&arguments, &unit, &systemctl)
            .await
            .is_err());
        assert_eq!(std::fs::read(&unit).unwrap(), original);
        assert!(!calls.exists());
        assert!(
            install_with_systemctl(&arguments, directory.path(), &systemctl)
                .await
                .is_err()
        );
        assert!(!calls.exists());
        super::super::files::atomic_write(&systemctl, b"#!/bin/sh\nexit 1\n", 0o700).unwrap();
        std::fs::remove_file(&unit).unwrap();
        let error = install_with_systemctl(&arguments, &unit, &systemctl)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already installed"));
        assert!(unit.exists());
    }
}
