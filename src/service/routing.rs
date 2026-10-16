use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::process::Command;

/// Read kernel routes; never mutates routing or treats a command failure as an empty table.
pub async fn live_routes() -> Result<Value> {
    let ip = super::manager::find_command("ip")?;
    let mut routes = Vec::new();
    for (flag, family) in [("-4", "ipv4"), ("-6", "ipv6")] {
        let mut command = Command::new(&ip);
        command
            .args(["-j", flag, "route", "show", "table", "all"])
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .context("reading kernel routes timed out")??;
        if !output.status.success() {
            bail!(
                "ip {flag} route show failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        routes.extend(parse_routes(&output.stdout, family)?);
    }
    Ok(json!({"routes": routes}))
}

fn parse_routes(bytes: &[u8], family: &str) -> Result<Vec<Value>> {
    let mut routes: Vec<Value> = serde_json::from_slice(bytes).context("invalid ip route JSON")?;
    for route in &mut routes {
        let object = route.as_object_mut().context("invalid route entry")?;
        object.insert("family".into(), json!(family));
        object.entry("table").or_insert(json!("main"));
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_routes_keep_table_device_metric_and_multipath_details() {
        let routes = super::parse_routes(br#"[{"dst":"default","gateway":"192.0.2.1","dev":"wan0","metric":100},{"dst":"198.51.100.0/24","table":100,"nexthops":[{"dev":"wan1","gateway":"192.0.2.2","weight":1}]}]"#, "ipv4").unwrap();
        assert_eq!(routes[0]["table"], "main");
        assert_eq!(routes[0]["family"], "ipv4");
        assert_eq!(routes[1]["nexthops"][0]["dev"], "wan1");
        assert!(super::parse_routes(b"invalid", "ipv4").is_err());
        assert!(super::parse_routes(b"[null]", "ipv4").is_err());
    }
}
