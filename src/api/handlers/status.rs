use axum::Json;
use serde_json::{json, Value};

/// GET /api/status — aggregated system status
pub async fn get_status() -> Json<Value> {
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(String::from))
        .unwrap_or_default();

    let hostname = gethostname::gethostname().to_string_lossy().to_string();

    let loadavg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| {
            let parts: Vec<&str> = s.split_whitespace().collect();
            json!({
                "1m": parts.first().unwrap_or(&"0"),
                "5m": parts.get(1).unwrap_or(&"0"),
                "15m": parts.get(2).unwrap_or(&"0"),
            })
        })
        .unwrap_or_default();

    Json(json!({
        "hostname": hostname,
        "uptime": uptime,
        "loadavg": loadavg,
    }))
}

/// GET /api/status/system — system resource stats
pub async fn get_system_stats() -> Json<Value> {
    let meminfo = parse_meminfo();
    let cpu_usage = get_cpu_usage().await;

    Json(json!({
        "memory": meminfo,
        "cpu": cpu_usage,
    }))
}

fn parse_meminfo() -> Value {
    let content = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mut total = 0u64;
    let mut available = 0u64;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("MemTotal:") {
            total = parse_kb_value(val);
        } else if let Some(val) = line.strip_prefix("MemAvailable:") {
            available = parse_kb_value(val);
        }
    }

    json!({
        "total_kb": total,
        "available_kb": available,
        "used_kb": total.saturating_sub(available),
        "usage_percent": if total > 0 {
            ((total - available) as f64 / total as f64 * 100.0).round()
        } else {
            0.0
        },
    })
}

fn parse_kb_value(s: &str) -> u64 {
    s.trim()
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

async fn get_cpu_usage() -> Value {
    // Simple CPU usage snapshot from /proc/stat
    let content = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    if let Some(line) = content.lines().find(|l| l.starts_with("cpu ")) {
        let parts: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();

        if parts.len() >= 4 {
            let idle = parts[3];
            let total: u64 = parts.iter().sum();
            return json!({
                "idle": idle,
                "total": total,
            });
        }
    }

    json!({})
}
