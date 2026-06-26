use anyhow::Result;
use tokio::process::Command;

/// Run hook commands for a given lifecycle stage.
///
/// `commands` is a multi-line string where each non-empty line is a command
/// executed sequentially via `sh -c`. If any command exits non-zero,
/// execution stops and an error is returned.
pub async fn run_hooks(stage: &str, commands: &str) -> Result<()> {
    let lines: Vec<&str> = commands
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Ok(());
    }

    tracing::info!(stage = stage, count = lines.len(), "running hooks");

    for cmd in &lines {
        tracing::info!(cmd = *cmd, stage = stage, "executing hook");

        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let code = output.status.code().unwrap_or(-1);
            tracing::error!(
                cmd = *cmd,
                stage = stage,
                exit_code = code,
                stdout = %stdout.trim(),
                stderr = %stderr.trim(),
                "hook command failed"
            );
            anyhow::bail!(
                "hook command '{}' exited with code {}: {}",
                cmd,
                code,
                stderr.trim()
            );
        }

        tracing::info!(cmd = *cmd, stage = stage, "hook completed");
    }

    tracing::info!(stage = stage, "all hooks completed");
    Ok(())
}
