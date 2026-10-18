use crate::api::{error::ApiError, server::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

/// GET /api/monitor/system — system resource stats
pub async fn get_system_monitor() -> Json<Value> {
    let uptime_secs = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .unwrap_or(0.0);

    let days = (uptime_secs / 86400.0) as u64;
    let hours = ((uptime_secs % 86400.0) / 3600.0) as u64;
    let mins = ((uptime_secs % 3600.0) / 60.0) as u64;
    let uptime_str = format!("{}d {}h {}m", days, hours, mins);

    let hostname = gethostname::gethostname().to_string_lossy().to_string();

    Json(json!({
        "hostname": hostname,
        "uptime_seconds": uptime_secs,
        "uptime_human": uptime_str,
    }))
}

/// GET /api/monitor/interfaces — list system network interfaces with live details
pub async fn get_interface_monitor() -> Json<Value> {
    let interfaces = list_system_interfaces();
    Json(json!({
        "interfaces": interfaces
    }))
}

#[derive(serde::Serialize)]
struct InterfaceDetail {
    name: String,
    up: bool,
    mac: String,
    mtu: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// List network interface names from /sys/class/net/, skipping loopback and virtual.
fn list_system_interfaces() -> Vec<InterfaceDetail> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" || name.starts_with("veth") || name.starts_with("virbr") {
                continue;
            }

            let path = entry.path();
            let up = std::fs::read_to_string(path.join("operstate"))
                .ok()
                .map(|s| s.trim().eq_ignore_ascii_case("up"))
                .unwrap_or(false);
            let mac = std::fs::read_to_string(path.join("address"))
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let mtu = std::fs::read_to_string(path.join("mtu"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            let rx_bytes = read_iface_stat(&name, "rx_bytes");
            let tx_bytes = read_iface_stat(&name, "tx_bytes");

            ifaces.push(InterfaceDetail {
                name,
                up,
                mac,
                mtu,
                rx_bytes,
                tx_bytes,
            });
        }
    }
    ifaces.sort_by(|a, b| a.name.cmp(&b.name));
    ifaces
}

fn read_iface_stat(iface: &str, stat: &str) -> u64 {
    let path = format!("/sys/class/net/{}/statistics/{}", iface, stat);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// GET /api/monitor/traffic/:iface — traffic stats (placeholder)
pub async fn get_traffic_stats() -> Json<Value> {
    Json(json!({
        "traffic": {}
    }))
}

/// GET /api/monitor/connections — conntrack table (placeholder)
pub async fn get_connections() -> Json<Value> {
    Json(json!({
        "connections": [],
        "total": 0
    }))
}

/// GET /api/monitor/leases — active DHCP leases from kea lease database
pub async fn get_leases() -> Json<Value> {
    let leases = match read_kea_leases().await {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!(error = %e, "failed to read kea leases");
            vec![]
        }
    };
    Json(json!({ "leases": leases }))
}

/// DELETE /api/dhcp/leases/:address — immediately delete a live Kea lease.
pub async fn delete_lease(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let address = address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| ApiError::BadRequest("a valid IPv4 lease address is required".into()))?;
    let _operation = state.config.lock_operation().await;
    crate::service::kea::delete_lease(address)
        .await
        .map_err(|error| match error {
            crate::service::kea::LeaseError::NotFound => {
                ApiError::NotFound(format!("lease {address} no longer exists"))
            }
            error => ApiError::Conflict(error.to_string()),
        })?;
    Ok(Json(json!({"status": "ok"})))
}

/// Read active leases from kea lease CSV files.
/// Reads older rotated files before the current append-only file.
/// The last record wins, including deletion tombstones and reclaimed leases.
async fn read_kea_leases() -> anyhow::Result<Vec<serde_json::Value>> {
    let paths = [
        "/var/lib/kea/kea-leases4.csv.2",
        "/var/lib/kea/kea-leases4.csv.1",
        "/var/lib/kea/kea-leases4.csv",
    ];

    // Collect all data lines from all files, later files override earlier (newer rotation wins)
    let mut all_lines: Vec<String> = Vec::new();
    for path in &paths {
        if let Ok(c) = tokio::fs::read_to_string(path).await {
            for line in c.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') && !line.starts_with("address,") {
                    all_lines.push(line.to_string());
                }
            }
        }
    }

    Ok(parse_kea_leases(&all_lines, chrono::Utc::now().timestamp()))
}

fn parse_kea_leases(all_lines: &[String], now: i64) -> Vec<Value> {
    use std::collections::HashMap;
    let mut by_ip = HashMap::new();
    for line in all_lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 10 {
            continue;
        }
        let address = fields[0].trim().to_string();
        if address.parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        // Remove older records even when this row is a deletion or reclamation.
        by_ip.remove(&address);
        let expire = fields[4].trim().parse::<i64>().unwrap_or(0);
        let valid_lifetime = fields[3].trim().parse::<u32>().unwrap_or(0);
        let mac = fields[1].trim().to_string();
        if fields[9].trim() == "0" && valid_lifetime > 0 && !mac.is_empty() && expire > now {
            by_ip.insert(
                address.clone(),
                (address, mac, fields[8].trim().to_string(), expire),
            );
        }
    }
    let mut leases: Vec<Value> = by_ip
        .into_values()
        .filter(|(_, _, _, expire)| *expire > now) // skip expired
        .map(|(address, mac, hostname, expire)| {
            let expires = chrono::DateTime::from_timestamp(expire, 0)
                .map(|dt| {
                    dt.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string()
                })
                .unwrap_or_default();
            json!({ "address": address, "mac": mac, "hostname": hostname, "expires": expires })
        })
        .collect();

    leases.sort_by(|a, b| {
        a["address"]
            .as_str()
            .unwrap_or("")
            .cmp(b["address"].as_str().unwrap_or(""))
    });

    leases
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    #[test]
    fn latest_records_override_active_leases_even_with_earlier_expiry() {
        let active = "192.0.2.1,aa:bb:cc:dd:ee:ff,,3600,9000,1,0,0,device,0";
        for newer in [
            "192.0.2.1,aa:bb:cc:dd:ee:ff,,0,9000,1,0,0,device,0",
            "192.0.2.1,aa:bb:cc:dd:ee:ff,,3600,9000,1,0,0,device,2",
            "192.0.2.1,aa:bb:cc:dd:ee:ff,,3600,500,1,0,0,device,0",
        ] {
            assert!(parse_kea_leases(&[active.into(), newer.into()], 1000).is_empty());
        }
        let newer = "192.0.2.1,11:22:33:44:55:66,,3600,8000,1,0,0,new-device,0";
        let leases = parse_kea_leases(&[active.into(), newer.into()], 1000);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0]["mac"], "11:22:33:44:55:66");
    }
}
