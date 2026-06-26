mod api;
mod auth;
mod config;
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
    tracing::info!("config directory: {}", std::fs::canonicalize(&args.config_dir).map(|p| p.display().to_string()).unwrap_or_else(|_| args.config_dir.clone()));

    let config_dir = Path::new(&args.config_dir);
    let config_path = config_dir.join("config.yml");

    // If config.yml doesn't exist, run init setup (auto-detect interfaces)
    if !config_path.exists() {
        tracing::info!("config.yml not found, running init setup");
        config::init::run(config_dir)?;
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

    // Run before_start hooks
    service::hooks::run_hooks("before_start", &config.hooks.before_start).await?;

    // Apply config on startup — change detection determines what needs restart.
    // On first boot (no config on disk), all services are started.
    // On subsequent boots, only changed services are restarted.
    let service_manager = service::manager::ServiceManager::new();
    let apply_result = service::apply::apply(&config, &config_path, &service_manager, false).await?;
    tracing::info!(
        services = ?apply_result.services_restarted,
        "config applied"
    );

    // Run after_start hooks
    service::hooks::run_hooks("after_start", &config.hooks.after_start).await?;

    // Start API server
    api::server::run(&args.listen, config_store, config_path).await?;

    Ok(())
}
