//! Global policy rules for WAN selection that deliberately bypasses internal routes.
//! These rules outlive WAN links; an unreachable companion prevents main-table fallback.
use super::manager::CommandExt;
use crate::config::{
    routing::{wan_return_routes, WAN_MARK_MASK},
    schema::Action,
    Config,
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::time::Duration;
use tokio::process::Command;

const LOOKUP_PRIORITY: u32 = 90;
const UNREACHABLE_PRIORITY: u32 = 91;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Policy {
    mark: u32,
    table: Option<u16>,
}

impl Policy {
    fn priority(&self) -> u32 {
        if self.table.is_some() {
            LOOKUP_PRIORITY
        } else {
            UNREACHABLE_PRIORITY
        }
    }

    fn same_selector(&self, value: &Value) -> bool {
        number(&value["priority"]) == Some(self.priority())
            && number(&value["fwmark"]) == Some(self.mark)
            && number(&value["fwmask"]) == Some(WAN_MARK_MASK)
    }

    fn matches(&self, value: &Value) -> bool {
        self.same_selector(value)
            && value.as_object().is_some_and(|object| {
                object.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "priority"
                            | "src"
                            | "dst"
                            | "srclen"
                            | "dstlen"
                            | "fwmark"
                            | "fwmask"
                            | "protocol"
                            | "table"
                            | "action"
                            | "type"
                            | "not"
                    )
                })
            })
            && (value["protocol"] == "kernel" || number(&value["protocol"]) == Some(2))
            && ["src", "dst"]
                .iter()
                .all(|key| value[*key].is_null() || value[*key] == "all")
            && [
                "iif", "oif", "uidrange", "ipproto", "sport", "dport", "tos", "l3mdev",
            ]
            .iter()
            .all(|key| value[*key].is_null())
            && value["not"].as_bool() != Some(true)
            && ["srclen", "dstlen"]
                .iter()
                .all(|key| value[*key].is_null() || number(&value[*key]) == Some(0))
            && match self.table {
                Some(table) => {
                    number(&value["table"]) == Some(u32::from(table))
                        && (value["action"].is_null()
                            || value["action"] == "to_tbl"
                            || number(&value["action"]) == Some(1))
                }
                None => {
                    value["action"] == "unreachable"
                        || value["type"] == "unreachable"
                        || number(&value["action"]) == Some(7)
                }
            }
    }

    fn args(&self, operation: &str) -> Vec<String> {
        // Protocol kernel prevents networkd's foreign-policy cleanup from removing
        // these rules when the WAN is reconfigured or disappears.
        let mut args = vec![
            "-4".into(),
            "rule".into(),
            operation.into(),
            "priority".into(),
            self.priority().to_string(),
            "fwmark".into(),
            format!("{}/{}", self.mark, WAN_MARK_MASK),
            "protocol".into(),
            "kernel".into(),
        ];
        match self.table {
            Some(table) => args.extend(["lookup".into(), table.to_string()]),
            None => args.push("unreachable".into()),
        }
        args
    }
}

fn number(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| number.try_into().ok())
        .or_else(|| {
            let text = value.as_str()?;
            if let Some(hex) = text.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()
            } else {
                text.parse().ok()
            }
        })
}

fn policies(config: &Config) -> Result<Vec<Policy>> {
    if config.wan_groups.is_empty()
        && !config
            .firewall
            .rules
            .forward
            .iter()
            .any(|rule| rule.enabled && rule.action == Action::Accept && rule.route_via.is_some())
    {
        return Ok(Vec::new());
    }
    let routes = wan_return_routes(config)?;
    // Install all terminal guards first, including for old pinned flows after a rule edit.
    let mut policies: Vec<_> = routes
        .iter()
        .map(|route| Policy {
            mark: route.strict_mark(),
            table: None,
        })
        .collect();
    policies.extend(routes.iter().map(|route| Policy {
        mark: route.strict_mark(),
        table: Some(route.table),
    }));
    Ok(policies)
}

fn prepare_plan(
    previous: &[Policy],
    desired: &[Policy],
    live: &[Value],
) -> Result<Vec<Vec<String>>> {
    let mut commands = Vec::new();
    for policy in desired {
        for conflict in live
            .iter()
            .filter(|value| policy.same_selector(value) && !policy.matches(value))
        {
            let old = previous.iter().find(|old| old.matches(conflict)).context(
                "conflicting administrator policy rule at reserved WAN routing priority/mark",
            )?;
            commands.push(old.args("del"));
        }
        if !live.iter().any(|value| policy.matches(value)) {
            commands.push(policy.args("add"));
        }
    }
    Ok(commands)
}

fn cleanup_plan(removed: &[Policy], live: &[Value]) -> Result<Vec<Vec<String>>> {
    let mut commands = Vec::new();
    for policy in removed {
        let owned: Vec<_> = live.iter().filter(|value| policy.matches(value)).collect();
        if owned.is_empty() {
            continue;
        }
        // ip-rule deletion has no unique kernel handle. Refuse an ambiguous key
        // rather than risk deleting an administrator's differently scoped rule.
        if live
            .iter()
            .any(|value| policy.same_selector(value) && !policy.matches(value))
        {
            bail!("ambiguous WAN policy key; refusing to remove an administrator policy rule");
        }
        commands.extend(owned.iter().map(|_| policy.args("del")));
    }
    Ok(commands)
}

async fn snapshot(ip: &str) -> Result<Vec<Value>> {
    let output = Command::new(ip)
        .args(["-j", "-4", "-N", "-d", "rule", "show"])
        .timeout_run(Duration::from_secs(30))
        .await?;
    if !output.status.success() {
        bail!(
            "reading WAN policy rules failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("invalid ip rule JSON")
}

async fn execute(ip: &str, commands: Vec<Vec<String>>) -> Result<()> {
    for args in commands {
        let output = Command::new(ip)
            .args(&args)
            .timeout_run(Duration::from_secs(30))
            .await?;
        if !output.status.success() {
            bail!(
                "WAN policy operation {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    Ok(())
}

/// Called after staged syntax checks but before nftables can emit strict marks.
pub async fn prepare(previous: &Config, config: &Config) -> Result<()> {
    let desired = policies(config)?;
    if desired.is_empty() {
        return Ok(());
    }
    let previous = policies(previous)?;
    let ip = super::manager::find_command("ip")?;
    let live = snapshot(&ip).await?;
    execute(&ip, prepare_plan(&previous, &desired, &live)?).await
}

/// Remove only exact previously-owned rules, after new nftables rules are active.
pub async fn cleanup(previous: &Config, config: &Config) -> Result<()> {
    let desired = policies(config)?;
    let removed: Vec<_> = policies(previous)?
        .into_iter()
        .filter(|policy| !desired.contains(policy))
        .collect();
    if removed.is_empty() {
        return Ok(());
    }
    let ip = super::manager::find_command("ip")?;
    let live = snapshot(&ip).await?;
    execute(&ip, cleanup_plan(&removed, &live)?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn live(policy: &Policy) -> Value {
        let mut value = json!({"priority": policy.priority(), "fwmark": format!("0x{:x}", policy.mark), "fwmask": "0xffff0000", "protocol": "kernel", "src": "all"});
        if let Some(table) = policy.table {
            value["table"] = json!(table);
        } else {
            value["action"] = json!("unreachable");
        }
        value
    }

    #[test]
    fn installs_guards_first_and_reconciles_exact_owned_rules_idempotently() {
        let config = crate::config::routing::outbound_test_config();
        let desired = policies(&config).unwrap();
        assert_eq!(desired.len(), 4);
        assert!(desired[..2].iter().all(|policy| policy.table.is_none()));
        let commands = prepare_plan(&[], &desired, &[]).unwrap();
        assert_eq!(commands[0].last().unwrap(), "unreachable");
        let installed: Vec<_> = desired.iter().map(live).collect();
        assert!(prepare_plan(&desired, &desired, &installed)
            .unwrap()
            .is_empty());
        let mut foreign = installed.clone();
        foreign[0]["protocol"] = json!("static");
        assert!(prepare_plan(&desired, &desired, &foreign).is_err());
        let mut changed = desired.clone();
        changed[2].table = Some(200);
        let commands = prepare_plan(&desired, &changed, &installed).unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][2], "del");
        assert_eq!(commands[1][2], "add");
        assert!(commands[1].ends_with(&["lookup".into(), "200".into()]));
        assert_eq!(
            cleanup_plan(&desired, &installed).unwrap().len(),
            desired.len()
        );
        let mut ambiguous = installed.clone();
        let mut source_scoped = installed[0].clone();
        source_scoped["src"] = json!("192.0.2.0");
        source_scoped["srclen"] = json!(24);
        ambiguous.push(source_scoped);
        assert!(cleanup_plan(&desired, &ambiguous).is_err());
        assert!(cleanup_plan(&desired, &[]).unwrap().is_empty());
    }

    #[test]
    fn unrelated_source_scoped_and_different_protocol_rules_are_not_owned() {
        let policy = Policy {
            mark: 123 << 16,
            table: Some(100),
        };
        for (field, value) in [
            ("src", json!("192.0.2.0/24")),
            ("protocol", json!("static")),
            ("iif", json!("lan0")),
            ("priority", json!(100)),
            ("suppress_prefixlength", json!(0)),
            ("goto", json!(200)),
            ("not", json!(true)),
        ] {
            let mut rule = live(&policy);
            rule[field] = value;
            assert!(!policy.matches(&rule));
        }
        let mut rule = live(&policy);
        rule["protocol"] = json!(2);
        assert!(policy.matches(&rule));
    }

    #[test]
    #[ignore = "requires root/CAP_SYS_ADMIN, ip and python3; creates its own isolated network namespace"]
    fn native_strict_routes_bypass_main_respect_table_routes_and_fail_closed() {
        let config = crate::config::routing::outbound_test_config();
        let desired = policies(&config).unwrap();
        let routes = wan_return_routes(&config).unwrap();
        let commands = prepare_plan(&[], &desired, &[]).unwrap();
        let script = r#"
import json, subprocess, sys
def ip(*args, check=True):
    return subprocess.run(['ip', *args], check=check, text=True, capture_output=True)
ip('link', 'set', 'lo', 'up')
for name, address in [('wan0', '203.0.113.2/29'), ('lan0', '192.168.0.1/23')]:
    ip('link', 'add', name, 'type', 'dummy')
    ip('link', 'set', name, 'up')
    ip('address', 'add', address, 'dev', name)
ip('route', 'add', 'default', 'via', '203.0.113.1', 'dev', 'wan0', 'table', '100')
normal, strict = sys.argv[2], sys.argv[3]
ip('-4', 'rule', 'add', 'priority', '100', 'fwmark', normal + '/4294901760', 'to', '192.168.0.0/23', 'lookup', 'main')
ip('-4', 'rule', 'add', 'priority', '110', 'fwmark', normal + '/4294901760', 'lookup', '100')
for args in json.loads(sys.argv[1]):
    ip(*args)
def lookup(mark):
    return json.loads(ip('-j', '-4', 'route', 'get', '192.168.0.250', 'mark', mark).stdout)[0]
assert lookup(normal)['dev'] == 'lan0', 'preserved internal route changed'
assert lookup(strict)['dev'] == 'wan0', 'main-table LAN route bypassed strict selection'
ip('route', 'add', '192.168.0.0/23', 'dev', 'lan0', 'table', '100')
assert lookup(strict)['dev'] == 'lan0', 'specific route in selected table not honored'
ip('route', 'del', '192.168.0.0/23', 'dev', 'lan0', 'table', '100')
ip('route', 'del', 'default', 'via', '203.0.113.1', 'dev', 'wan0', 'table', '100')
assert ip('-4', 'route', 'get', '192.168.0.250', 'mark', strict, check=False).returncode != 0, 'strict traffic fell back to main after WAN route loss'
assert lookup(normal)['dev'] == 'lan0'
print(ip('-j', '-4', '-N', '-d', 'rule', 'show').stdout)
"#;
        // Always self-isolate, even if this ignored test is invoked directly as root.
        let output = std::process::Command::new("unshare")
            .args(["--net", "python3", "-c", script])
            .arg(serde_json::to_string(&commands).unwrap())
            .arg(routes[0].mark().to_string())
            .arg(routes[0].strict_mark().to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let installed: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        let plan = prepare_plan(&desired, &desired, &installed);
        assert!(matches!(&plan, Ok(commands) if commands.is_empty()), "actual kernel JSON failed ownership/idempotence matching: {plan:?}; rules={installed:?}");
    }
}
