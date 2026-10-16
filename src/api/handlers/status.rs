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

fn parse_kb_value(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or(0)
}

async fn get_cpu_usage() -> Value {
    let content = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    match parse_cpu_counters(&content) {
        Some((idle, total)) => json!({"idle": idle, "total": total}),
        None => json!({}),
    }
}

fn parse_cpu_counters(content: &str) -> Option<(u64, u64)> {
    let line = content
        .lines()
        .find(|line| line.split_whitespace().next() == Some("cpu"))?;
    let parts = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let idle = parts
        .get(3)?
        .checked_add(parts.get(4).copied().unwrap_or(0))?;
    let total = parts
        .iter()
        .try_fold(0u64, |total, value| total.checked_add(*value))?;
    Some((idle, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_counters_include_iowait_without_double_counting_guest_time() {
        assert_eq!(
            parse_cpu_counters("cpu 100 20 30 400 50 6 7 8 10 2\ncpu0 1 2 3 4"),
            Some((450, 621))
        );
    }

    #[test]
    fn cpu_counters_support_older_four_field_snapshots() {
        assert_eq!(
            parse_cpu_counters("cpu0 1 2 3 4\ncpu\t10 20 30 40"),
            Some((40, 100))
        );
    }

    #[test]
    fn cpu_counters_reject_missing_malformed_and_overflowing_fields() {
        for content in [
            "",
            "cpu0 1 2 3 4",
            "cpu 1 2 3",
            "cpu 1 invalid 3 4",
            "cpu -1 2 3 4",
            "cpu 18446744073709551615 1 0 0",
        ] {
            assert_eq!(parse_cpu_counters(content), None);
        }
    }
}
