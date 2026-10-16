use axum::Json;
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

/// Read active leases from kea lease CSV files.
/// Reads all rotated files (.csv, .csv.1, .csv.2), deduplicates by IP,
/// keeps the entry with the latest expiry.
async fn read_kea_leases() -> anyhow::Result<Vec<serde_json::Value>> {
    let paths = [
        "/var/lib/kea/kea-leases4.csv",
        "/var/lib/kea/kea-leases4.csv.1",
        "/var/lib/kea/kea-leases4.csv.2",
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

    // Deduplicate by IP: keep the entry with the latest expiry (newest lease wins)
    use std::collections::HashMap;
    let mut by_ip: HashMap<String, (String, String, String, i64)> = HashMap::new();

    for line in &all_lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 10 {
            continue;
        }

        let address = fields[0].trim().to_string();
        let hwaddr = fields[1].trim().to_string();
        let hostname = fields[8].trim().to_string();
        let state = fields[9].trim();
        let expire: i64 = fields[4].trim().parse().unwrap_or(0);

        if address.is_empty() || hwaddr.is_empty() || state != "0" {
            continue;
        }

        // Keep the entry with the latest expiry
        let entry = by_ip.entry(address.clone());
        entry
            .and_modify(|e| {
                if expire > e.3 {
                    *e = (address.clone(), hwaddr.clone(), hostname.clone(), expire);
                }
            })
            .or_insert((address, hwaddr, hostname, expire));
    }

    let now = chrono::Utc::now().timestamp();
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

    Ok(leases)
}
