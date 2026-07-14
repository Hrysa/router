use axum::{
    middleware,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use rust_embed::Embed;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::handlers;
use crate::api::middleware::auth::{require_auth, AuthState};
use crate::config::ConfigStore;

#[derive(Embed)]
#[folder = "web/dist/"]
struct WebAssets;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ConfigStore>,
    pub config_path: PathBuf,
    pub auth: AuthState,
}

pub struct ServerConfig {
    pub listen: String,
    pub config_store: ConfigStore,
    pub config_path: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

pub async fn run(cfg: ServerConfig, jwt_secret: Arc<String>) -> anyhow::Result<()> {
    let state = AppState {
        config: Arc::new(cfg.config_store),
        config_path: cfg.config_path,
        auth: AuthState { jwt_secret },
    };

    // Public routes: login and static SPA assets (login page must be reachable).
    let public_routes = Router::new()
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/setup", post(handlers::auth::setup))
        .route("/api/auth/status", get(handlers::auth::status));

    // Protected API routes.
    let protected = Router::new()
        // Health / status
        .route("/api/status", get(handlers::status::get_status))
        .route("/api/status/system", get(handlers::status::get_system_stats))
        // Config endpoints
        .route(
            "/api/config",
            get(handlers::config::get_config).put(handlers::config::replace_config),
        )
        .route(
            "/api/config/interfaces",
            get(handlers::config::list_interfaces)
                .post(handlers::config::create_interface),
        )
        .route(
            "/api/config/interfaces/:name",
            put(handlers::config::update_interface)
                .delete(handlers::config::delete_interface),
        )
        .route(
            "/api/config/firewall",
            post(handlers::config::patch_firewall),
        )
        // Firewall rules CRUD
        .route(
            "/api/config/firewall/rules",
            get(handlers::config::list_firewall_rules)
                .post(handlers::config::add_firewall_rule),
        )
        .route(
            "/api/config/firewall/rules/:id",
            put(handlers::config::update_firewall_rule)
                .delete(handlers::config::delete_firewall_rule),
        )
        .route(
            "/api/config/firewall/rules/:id/move",
            post(handlers::config::move_firewall_rule),
        )
        .route(
            "/api/firewall/stats",
            get(handlers::config::firewall_stats),
        )
        // Firewall NAT CRUD
        .route(
            "/api/config/firewall/nat",
            get(handlers::config::list_nat_rules),
        )
        .route(
            "/api/config/firewall/nat/port-forward",
            post(handlers::config::add_port_forward),
        )
        .route(
            "/api/config/firewall/nat/port-forward/:id",
            put(handlers::config::update_port_forward)
                .delete(handlers::config::delete_port_forward),
        )
        // nftables Sets CRUD
        .route(
            "/api/config/firewall/sets",
            get(handlers::config::list_nft_sets)
                .post(handlers::config::add_nft_set),
        )
        .route(
            "/api/config/firewall/sets/:name",
            put(handlers::config::update_nft_set)
                .delete(handlers::config::delete_nft_set),
        )
        // DHCP
        .route(
            "/api/config/dhcp",
            post(handlers::config::patch_dhcp),
        )
        .route(
            "/api/config/dhcp/leases",
            get(handlers::config::list_dhcp_leases)
                .post(handlers::config::add_dhcp_lease),
        )
        .route(
            "/api/config/dhcp/leases/:mac",
            delete(handlers::config::delete_dhcp_lease),
        )
        // Hooks
        .route(
            "/api/config/hooks",
            post(handlers::config::patch_hooks),
        )
        // sing-box config
        .route(
            "/api/singbox/config",
            get(handlers::config::get_singbox_config)
                .put(handlers::config::put_singbox_config),
        )
        // Config operations
        .route(
            "/api/config/validate",
            post(handlers::config::validate_config),
        )
        .route(
            "/api/config/apply",
            post(handlers::config::apply_config),
        )
        .route(
            "/api/config/rollback",
            post(handlers::config::rollback_config),
        )
        .route(
            "/api/config/backups",
            get(handlers::config::list_backups),
        )
        .route(
            "/api/config/backups/:id/restore",
            post(handlers::config::restore_backup),
        )
        // Service endpoints
        .route("/api/services", get(handlers::service::list_services))
        .route(
            "/api/service/:name/status",
            get(handlers::service::get_service_status),
        )
        .route(
            "/api/service/:name/start",
            post(handlers::service::start_service),
        )
        .route(
            "/api/service/:name/stop",
            post(handlers::service::stop_service),
        )
        .route(
            "/api/service/:name/restart",
            post(handlers::service::restart_service),
        )
        // Monitor endpoints
        .route(
            "/api/monitor/system",
            get(handlers::monitor::get_system_monitor),
        )
        .route(
            "/api/monitor/interfaces",
            get(handlers::monitor::get_interface_monitor),
        )
        .route(
            "/api/monitor/traffic",
            get(handlers::monitor::get_traffic_stats),
        )
        .route(
            "/api/monitor/connections",
            get(handlers::monitor::get_connections),
        )
        .route(
            "/api/monitor/leases",
            get(handlers::monitor::get_leases),
        );

    let protected = protected
        .layer(middleware::from_fn_with_state(state.auth.clone(), require_auth));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected)
        .with_state(state)
        .fallback(spa_handler);

    match (cfg.tls_cert, cfg.tls_key) {
        (Some(cert), Some(key)) => {
            tracing::info!("API server listening on https://{}", cfg.listen);
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            axum_server::bind_rustls(cfg.listen.parse()?, tls_config)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            tracing::warn!(
                "API server listening on http://{} (no TLS — use --tls-cert/--tls-key or a reverse proxy)",
                cfg.listen
            );
            let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

/// Serve embedded SPA files. Falls back to index.html for client-side routing.
async fn spa_handler(uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // API routes should not reach here, but guard just in case.
    if path.starts_with("api/") {
        return (axum::http::StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Try to serve the exact file
    if let Some(content) = serve_file(path) {
        return content;
    }

    // Fall back to index.html for SPA routing
    serve_file("index.html").unwrap_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            "SPA not built. Run: cd web && npm run build",
        )
            .into_response()
    })
}

fn serve_file(path: &str) -> Option<axum::response::Response> {
    let file = WebAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();

    Some(
        (
            [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
            file.data.to_vec(),
        )
            .into_response(),
    )
}
