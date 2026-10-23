mod api;
mod auth;
mod config;
mod metrics;
mod renderer;
mod service;

use clap::Parser;
use std::path::Path;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "routerd", version, about = "Linux router daemon")]
struct Args {
    /// Path to config directory (contains config.yml)
    #[arg(short = 'c', long = "config-dir", default_value = "/etc/routerd/")]
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

    /// Create config and routerd.service, reload systemd, and exit without serving the API.
    /// Refuses existing config/unit files; skips startup apply, offload changes, and hooks.
    #[arg(long)]
    init: bool,

    #[arg(long, conflicts_with_all = ["init", "install_singbox"], help = "Apply only nftables at startup, then serve the API; leave sing-box to systemd")]
    boot: bool,

    /// Path to TLS certificate (PEM). If set, --tls-key must also be set.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    tls_cert: Option<String>,

    /// Path to TLS private key (PEM). If set, --tls-cert must also be set.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    tls_key: Option<String>,

    #[arg(long, conflicts_with_all = ["init", "boot"], help = "Overwrite sing-box config and systemd unit, reload systemd, then exit; no binary download or service start")]
    install_singbox: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

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
            fmt().with_env_filter(filter).with_target(true).init();
        }
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %args.listen,
        "routerd starting"
    );

    let config_dir = Path::new(&args.config_dir);
    let config_path = config_dir.join("config.yml");

    if args.init {
        check_init_paths(&config_path, Path::new(service::systemd::UNIT_PATH))?;
    }

    if args.install_singbox {
        service::singbox::install(&config_path).await?;
        tracing::info!("sing-box files installed and systemd reloaded; binary installation and service enable/start/restart are left to the administrator");
        return Ok(());
    }
    tracing::info!(
        "config directory: {}",
        std::fs::canonicalize(&args.config_dir)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| args.config_dir.clone())
    );

    // Initialization only writes a draft config; --init also skips startup changes below.
    if args.init {
        tracing::info!("creating initial config");
        config::init::run(config_dir)?;
    } else if !config_path.exists() {
        anyhow::bail!(
            "config.yml not found at {}. Run with --init to perform first-boot setup.",
            config_path.display()
        );
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
        service::systemd::install(&service_arguments(&args)?).await?;
        tracing::info!(
            "initialization complete; host networking unchanged; review the config before manually starting routerd.service"
        );
        return Ok(());
    } else if args.boot {
        let service_manager = service::manager::ServiceManager::new();
        service::apply::boot_nftables(&config, &service_manager).await?;
        tracing::info!(
            "boot mode: nftables restored; other services and startup hooks left untouched"
        );
    } else {
        disable_offloads();
        service::hooks::run_hooks("before_start", &config.hooks.before_start).await?;

        let service_manager = service::manager::ServiceManager::new();
        let apply_result =
            service::apply::startup(&config, &service_manager, config_store.apply_state()).await?;
        tracing::info!(
            services = ?apply_result.services_restarted,
            "startup config reconciled without nftables or sing-box"
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

fn check_init_paths(config: &Path, unit: &Path) -> anyhow::Result<()> {
    service::files::require_absent(config)?;
    service::files::require_absent(unit)?;
    Ok(())
}

fn service_arguments(args: &Args) -> anyhow::Result<Vec<String>> {
    let absolute = |path: &Path| -> anyhow::Result<String> {
        let path = std::fs::canonicalize(path)?;
        Ok(path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("service paths must be UTF-8"))?
            .to_owned())
    };
    let mut arguments = vec![
        absolute(&std::env::current_exe()?)?,
        "--config-dir".into(),
        absolute(Path::new(&args.config_dir))?,
        "--listen".into(),
        args.listen.clone(),
        "--log-level".into(),
        args.log_level.clone(),
        "--log-format".into(),
        args.log_format.clone(),
    ];
    for (flag, path) in [("--tls-cert", &args.tls_cert), ("--tls-key", &args.tls_key)] {
        if let Some(path) = path {
            arguments.extend([flag.into(), absolute(Path::new(path))?]);
        }
    }
    Ok(arguments)
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
    fn init_refuses_either_existing_path_including_dangling_symlinks() {
        let directory = service::files::StagedDirectory::new().unwrap();
        let config = directory.path().join("config.yml");
        let unit = directory.path().join("routerd.service");
        assert!(check_init_paths(&config, &unit).is_ok());
        for path in [&config, &unit] {
            std::fs::write(path, "existing").unwrap();
            assert!(check_init_paths(&config, &unit).is_err());
            assert_eq!(std::fs::read_to_string(path).unwrap(), "existing");
            std::fs::remove_file(path).unwrap();
            std::os::unix::fs::symlink(directory.path().join("missing"), path).unwrap();
            assert!(check_init_paths(&config, &unit).is_err());
            assert!(service::files::atomic_create(path, b"new", 0o600).is_err());
            std::fs::remove_file(path).unwrap();
        }
        assert_eq!(
            Args::try_parse_from(["routerd"]).unwrap().config_dir,
            "/etc/routerd/"
        );
    }

    #[test]
    fn init_service_uses_absolute_paths_and_normal_startup() {
        let directory = service::files::StagedDirectory::new().unwrap();
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&certificate, "certificate").unwrap();
        std::fs::write(&key, "key").unwrap();
        let args = Args::try_parse_from([
            "routerd",
            "--init",
            "-c",
            directory.path().to_str().unwrap(),
            "--listen",
            "127.0.0.1:9443",
            "--log-level",
            "debug",
            "--log-format",
            "json",
            "--tls-cert",
            certificate.to_str().unwrap(),
            "--tls-key",
            key.to_str().unwrap(),
        ])
        .unwrap();
        let arguments = service_arguments(&args).unwrap();
        assert!(Path::new(&arguments[0]).is_absolute());
        assert!(Path::new(&arguments[2]).is_absolute());
        assert!(!arguments
            .iter()
            .any(|argument| argument == "--init" || argument == "--boot"));
        let parsed = Args::try_parse_from(arguments).unwrap();
        assert_eq!(parsed.listen, args.listen);
        assert_eq!(parsed.log_level, args.log_level);
        assert_eq!(parsed.log_format, args.log_format);
        assert_eq!(parsed.tls_cert, args.tls_cert);
        assert_eq!(parsed.tls_key, args.tls_key);
    }

    #[test]
    fn version_is_available_without_starting_the_daemon() {
        let result = Args::try_parse_from(["routerd", "--version"]).unwrap_err();
        assert_eq!(result.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(result.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn singbox_install_uses_selected_config_directory_and_excludes_startup_modes() {
        let args = Args::try_parse_from([
            "routerd",
            "--install-singbox",
            "-c",
            "/tmp/routerd-install-test",
        ])
        .unwrap();
        assert!(args.install_singbox);
        assert_eq!(args.config_dir, "/tmp/routerd-install-test");
        assert!(Args::try_parse_from(["routerd", "--install-singbox", "--init"]).is_err());
        assert!(Args::try_parse_from(["routerd", "--install-singbox", "--boot"]).is_err());
    }

    #[test]
    fn boot_is_explicit_and_conflicts_with_other_startup_modes() {
        let normal = Args::try_parse_from(["routerd"]).unwrap();
        assert!(!normal.boot);
        assert!(!normal.init);
        let boot = Args::try_parse_from(["routerd", "--boot", "-c", "/tmp/routerd-test"]).unwrap();
        assert!(boot.boot);
        assert!(!boot.init);
        assert_eq!(boot.config_dir, "/tmp/routerd-test");
        assert!(Args::try_parse_from(["routerd", "--boot", "--init"]).is_err());
        assert!(Args::try_parse_from(["routerd", "--boot", "--install-singbox"]).is_err());
    }

    #[test]
    fn tls_requires_both_certificate_and_key() {
        assert!(Args::try_parse_from(["routerd", "--tls-cert", "cert.pem"]).is_err());
        assert!(Args::try_parse_from(["routerd", "--tls-key", "key.pem"]).is_err());
        assert!(Args::try_parse_from([
            "routerd",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem"
        ])
        .is_ok());
    }
}
