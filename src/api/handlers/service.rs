use axum::{extract::Path, Json};
use serde_json::{json, Value};

use crate::api::error::ApiError;
use crate::service::manager::{Service, ServiceManager};

/// GET /api/services — list all services with status
pub async fn list_services() -> Result<Json<Value>, ApiError> {
    let manager = ServiceManager::new();
    let statuses = manager.status_all().await?;

    let services: Vec<Value> = statuses
        .iter()
        .map(|s| {
            json!({
                "name": s.service.systemd_name(),
                "display_name": s.service.display_name(),
                "active": s.active,
                "status": s.status,
                "pid": s.pid,
            })
        })
        .collect();

    Ok(Json(json!({"services": services})))
}

/// GET /api/service/:name/status — get service status
pub async fn get_service_status(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let service = parse_service(&name)?;
    let manager = ServiceManager::new();
    let status = manager.status(service).await?;

    Ok(Json(json!({
        "name": status.service.systemd_name(),
        "display_name": status.service.display_name(),
        "active": status.active,
        "status": status.status,
        "pid": status.pid,
    })))
}

/// POST /api/service/:name/start — start service
pub async fn start_service(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let service = parse_service(&name)?;
    let manager = ServiceManager::new();
    manager.start(service).await?;
    Ok(Json(json!({"status": "ok", "message": format!("{} started", service.display_name())})))
}

/// POST /api/service/:name/stop — stop service
pub async fn stop_service(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let service = parse_service(&name)?;
    let manager = ServiceManager::new();
    manager.stop(service).await?;
    Ok(Json(json!({"status": "ok", "message": format!("{} stopped", service.display_name())})))
}

/// POST /api/service/:name/restart — restart service
pub async fn restart_service(Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let service = parse_service(&name)?;
    let manager = ServiceManager::new();
    manager.restart(service).await?;
    Ok(Json(json!({"status": "ok", "message": format!("{} restarted", service.display_name())})))
}

fn parse_service(name: &str) -> Result<Service, ApiError> {
    match name.to_lowercase().as_str() {
        "nftables" => Ok(Service::Nftables),
        "dhcpd" | "kea-dhcp4" | "dhcp" => Ok(Service::Dhcpd),
        "pppd" | "ppp" | "pppoe" => Ok(Service::Pppd),
        "networking" | "network" | "systemd-networkd" => Ok(Service::Networking),
        "wireguard" | "wg" | "wg0" => Ok(Service::Wireguard),
        "sing-box" | "singbox" => Ok(Service::SingBox),
        "vnstat" => Ok(Service::Vnstat),
        _ => Err(ApiError::NotFound(format!("unknown service: {}", name))),
    }
}
