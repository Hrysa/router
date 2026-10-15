mod api;
mod auth;
mod config;
mod metrics;
mod monitor;
mod renderer;
mod service;

use clap::Parser;
use std::path::Path;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "routerd", about = "Linux router daemon")]
struct Args {
    /// Path to config directory (contains config.yml)
    #[arg(short = 'c', long = "config-dir", default_value = "config")]
    config_dir: String,

    /// API server listen address
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log format (text, json)
    #[arg(long, default_value = "text")]
    log_format: String,

    /// Create config.yml if missing and start the API without changing networking.
    /// Skips startup apply, offload changes, and hooks even with an existing config.
    #[arg(long)]
    init: bool,

    /// Path to TLS certificate (PEM). If set, --tls-key must also be set.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    tls_cert: Option<String>,

    /// Path to TLS private key (PEM). If set, --tls-cert must also be set.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    tls_key: Option<String>,

    /// Download and install sing-box from GitHub releases, then exit.
    #[arg(long)]
    install_singbox: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    match args.log_format.as_str() {
        "json" => {
            fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
        _ => {
            fmt()
                .with_env_filter(filter)
                .with_target(true)
                .init();
        }
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %args.listen,
        "routerd starting"
    );

    // Handle --install-singbox: download, install, and exit
    if args.install_singbox {
        tracing::info!("installing sing-box");
        service::singbox::install().await?;
        tracing::info!("sing-box installation complete");
        return Ok(());
    }
    tracing::info!("config directory: {}", std::fs::canonicalize(&args.config_dir).map(|p| p.display().to_string()).unwrap_or_else(|_| args.config_dir.clone()));

    let config_dir = Path::new(&args.config_dir);
    let config_path = config_dir.join("config.yml");

    // Initialization only writes a draft config; --init also skips startup changes below.
    if !config_path.exists() {
        if args.init {
            tracing::info!("config.yml not found, running init setup");
            config::init::run(config_dir)?;
        } else {
            anyhow::bail!(
                "config.yml not found at {}. Run with --init to perform first-boot setup.",
                config_path.display()
            );
        }
    }

    // Load config
    let config_store = config::ConfigStore::new(&args.config_dir)?;
    let config = config_store.get().await;

    // Validate config
    let errors = config::validator::validate(&config);
    if !errors.is_empty() {
        tracing::error!(errors = ?errors, "config validation failed");
        anyhow::bail!("config validation failed: {:?}", errors);
    }
    tracing::info!("config validated");

    if args.init {
        tracing::info!(
            "init mode: preserving host networking; review the config and use POST /api/config/apply when ready"
        );
    } else {
        // Normal startup applies the saved config and runs startup hooks.
        disable_offloads();
        service::hooks::run_hooks("before_start", &config.hooks.before_start).await?;

        let service_manager = service::manager::ServiceManager::new();
        let apply_result =
            service::apply::apply(&config, &config, &config_path, &service_manager, false).await?;
        tracing::info!(
            services = ?apply_result.services_restarted,
            "config applied"
        );

        service::hooks::run_hooks("after_start", &config.hooks.after_start).await?;
    }

    // Install the in-memory metrics recorder and start the interface/firewall collector.
    let metrics = crate::metrics::RouterdMetrics::new();
    metrics.install()?;

    // Ensure a JWT secret exists for API authentication.
    api::handlers::auth::ensure_jwt_secret(&config_store).await?;

    // Start API server
    let server_config = api::server::ServerConfig {
        listen: args.listen,
        config_store,
        config_path,
        tls_cert: args.tls_cert.map(std::path::PathBuf::from),
        tls_key: args.tls_key.map(std::path::PathBuf::from),
        metrics,
    };
    api::server::run(server_config).await?;

    Ok(())
}

/// Find all physical NICs and disable hardware offloads.
fn disable_offloads() {
    let offload_args = ["tso", "gso", "gro", "lro", "ufo", "rx", "tx", "sg"];

    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        // Physical NICs have a `device` symlink
        if !entry.path().join("device").exists() {
            continue;
        }

        let mut cmd = std::process::Command::new("ethtool");
        cmd.args(["-K", &name]);
        for arg in &offload_args {
            cmd.arg(arg).arg("off");
        }

        match cmd.output() {
            Ok(out) if out.status.success() => {
                tracing::info!(nic = %name, "disabled hardware offloads");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                tracing::warn!(nic = %name, error = %stderr.trim(), "failed to disable offloads");
            }
            Err(e) => {
                tracing::warn!(nic = %name, error = %e, "ethtool not available");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_requires_both_certificate_and_key() {
        assert!(Args::try_parse_from(["routerd", "--tls-cert", "cert.pem"]).is_err());
        assert!(Args::try_parse_from(["routerd", "--tls-key", "key.pem"]).is_err());
        assert!(Args::try_parse_from(["routerd", "--tls-cert", "cert.pem", "--tls-key", "key.pem"]).is_ok());
    }
}
