//! Background health and atomic bucket-map reconciliation. No saved drafts or
//! startup-only reconciliation can activate this worker's network writes.
use crate::config::{
    routing::wan_return_routes,
    wan_groups::{self, WanGroup},
    Config, ConfigStore,
};
use crate::service::manager::{find_command, ServiceManager};
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::Mutex};

#[derive(Clone, Default, Serialize)]
pub struct Health {
    pub healthy: bool,
    pub successes: u32,
    pub failures: u32,
    pub reason: String,
    #[serde(skip)]
    recovered_since: Option<Instant>,
}
impl Health {
    fn observe(&mut self, success: bool, reason: String, group: &WanGroup, now: Instant) {
        self.reason = reason;
        if success {
            self.failures = 0;
            self.successes = self.successes.saturating_add(1);
            let since = *self.recovered_since.get_or_insert(now);
            if self.successes >= group.recovery_threshold
                && now.duration_since(since).as_secs() >= u64::from(group.recovery_delay_seconds)
            {
                self.healthy = true;
            }
        } else {
            self.successes = 0;
            self.recovered_since = None;
            self.failures = self.failures.saturating_add(1);
            if self.failures >= group.failure_threshold {
                self.healthy = false;
            }
        }
    }
}
#[derive(Default)]
struct Runtime {
    config: Option<Config>,
    enabled: bool,
    generation: u64,
    health: BTreeMap<(u32, String), Health>,
    due: BTreeMap<u32, Instant>,
    installed: Option<Value>,
    error: Option<String>,
}
static RUNTIME: OnceLock<Mutex<Runtime>> = OnceLock::new();
fn runtime() -> &'static Mutex<Runtime> {
    RUNTIME.get_or_init(Default::default)
}

pub async fn suspend() {
    let mut state = runtime().lock().await;
    state.enabled = false;
    state.generation = state.generation.wrapping_add(1);
}
pub async fn activate(config: &Config, maps_reset: bool) {
    let mut state = runtime().lock().await;
    if state
        .config
        .as_ref()
        .map(|c| (&c.wan_groups, &c.interfaces))
        != Some((&config.wan_groups, &config.interfaces))
    {
        state.health.clear();
        state.due.clear();
        state.installed = None;
    }
    if maps_reset {
        state.installed = None;
    }
    state.config = Some(config.clone());
    state.enabled = true;
    state.error = None;
    state.generation = state.generation.wrapping_add(1);
}

fn runtime_status(state: &Runtime) -> Value {
    let routes = state
        .config
        .as_ref()
        .and_then(|config| wan_return_routes(config).ok())
        .unwrap_or_default();
    let groups: Vec<_> = state.config.iter().flat_map(|c| &c.wan_groups).map(|group| {
        let name = wan_groups::map_name(group.id, false);
        let elements = state.installed.as_ref().and_then(|update| update["nftables"].as_array())
            .and_then(|commands| commands.iter().find(|command| command["add"]["element"]["name"] == name))
            .and_then(|command| command["add"]["element"]["elem"].as_array());
        let mut active_tier = None;
        let members: Vec<_> = group.members.iter().map(|member| {
            let health = state.health.get(&(group.id, member.interface.clone())).cloned().unwrap_or_default();
            let mark = routes.iter().find(|route| route.name == member.interface).map(|route| route.mark());
            let count = mark.map(|mark| elements.map(|elements| elements.iter().filter(|element| element[1] == mark).count()).unwrap_or(0)).unwrap_or(0);
            if count > 0 { active_tier = Some(active_tier.map_or(member.tier, |tier: u16| tier.min(member.tier))); }
            json!({"interface":member.interface,"tier":member.tier,"weight":member.weight,"health":health,"effective_percent":count as f64 * 100.0 / f64::from(wan_groups::BUCKETS)})
        }).collect();
        json!({"id":group.id,"name":group.name,"active_tier":active_tier,"members":members})
    }).collect();
    json!({"active":state.enabled,"error":state.error,"groups":groups})
}
pub async fn status() -> Value {
    runtime_status(&*runtime().lock().await)
}

async fn output(program: &str, args: &[String]) -> Result<std::process::Output> {
    let mut command = Command::new(program);
    command.args(args).kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(8), command.output())
        .await
        .context("probe command timed out")?
        .context("probe command failed")
}
fn table_number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}
async fn probe(config: &Config, group: &WanGroup, interface: &str) -> Result<()> {
    let routes = wan_return_routes(config)?;
    let route = routes
        .iter()
        .find(|r| r.name == interface)
        .context("WAN no longer configured")?;
    let ip = find_command("ip")?;
    let ping = find_command("ping")?;
    let defaults = output(
        &ip,
        &[
            "-j".into(),
            "-N".into(),
            "-4".into(),
            "route".into(),
            "show".into(),
            "table".into(),
            route.table.to_string(),
            "default".into(),
        ],
    )
    .await?;
    ensure!(defaults.status.success(), "cannot read WAN default route");
    let defaults: Value = serde_json::from_slice(&defaults.stdout)?;
    ensure!(
        defaults.as_array().is_some_and(|entries| entries
            .iter()
            .any(|entry| entry["dev"] == route.interface
                && (entry["type"].is_null() || entry["type"] == "unicast"))),
        "WAN has no usable IPv4 default route"
    );
    let mut failures = Vec::new();
    for target in &group.targets {
        // Check the actual marked FIB lookup. Even if policy rules disappear,
        // never send a probe via a fallback main-table route or another WAN.
        let lookup = output(
            &ip,
            &[
                "-j".into(),
                "-N".into(),
                "-4".into(),
                "route".into(),
                "get".into(),
                target.to_string(),
                "mark".into(),
                route.strict_mark().to_string(),
                "oif".into(),
                route.interface.into(),
            ],
        )
        .await?;
        if !lookup.status.success() {
            failures.push(format!("{target}: no marked route"));
            continue;
        }
        let value: Value = serde_json::from_slice(&lookup.stdout)?;
        let valid = value.as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["dev"] == route.interface
                    && table_number(&entry["table"]) == Some(u64::from(route.table))
                    && entry["prefsrc"]
                        .as_str()
                        .is_some_and(|src| src.parse::<std::net::Ipv4Addr>().is_ok())
            })
        });
        if !valid {
            failures.push(format!("{target}: WAN address/routing table unavailable"));
            continue;
        }
        let result = output(
            &ping,
            &[
                "-4".into(),
                "-n".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                group.timeout_seconds.to_string(),
                "-m".into(),
                route.strict_mark().to_string(),
                "-I".into(),
                route.interface.into(),
                target.to_string(),
            ],
        )
        .await?;
        if result.status.success() {
            return Ok(());
        }
        failures.push(format!("{target}: ICMP probe failed"));
    }
    anyhow::bail!("{}", failures.join("; "))
}

fn map_update(config: &Config, health: &BTreeMap<(u32, String), Health>) -> Result<Value> {
    let routes = wan_return_routes(config)?;
    let mut commands = Vec::new();
    for group in &config.wan_groups {
        let healthy: Vec<_> = group
            .members
            .iter()
            .map(|m| {
                health
                    .get(&(group.id, m.interface.clone()))
                    .is_some_and(|h| h.healthy)
            })
            .collect();
        let buckets = wan_groups::buckets(group, &healthy);
        for strict in [false, true] {
            let name = wan_groups::map_name(group.id, strict);
            let elements: Vec<_> = buckets
                .iter()
                .enumerate()
                .map(|(bucket, member)| {
                    let mark = member
                        .and_then(|i| routes.iter().find(|r| r.name == group.members[i].interface))
                        .map(|r| if strict { r.strict_mark() } else { r.mark() })
                        .unwrap_or(0);
                    json!([format!("0.0.0.{bucket}"), mark])
                })
                .collect();
            commands.push(json!({"flush":{"map":{"family":"inet","table":"mangle","name":name}}}));
            commands.push(json!({"add":{"element":{"family":"inet","table":"mangle","name":name,"elem":elements}}}));
        }
    }
    Ok(json!({"nftables":commands}))
}

pub fn start_background(store: Arc<ConfigStore>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = tick(&store).await {
                tracing::warn!(%error, "WAN group reconciliation failed");
                runtime().lock().await.error = Some(error.to_string());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}
async fn tick(store: &ConfigStore) -> Result<()> {
    let (config, generation, due) = {
        let state = runtime().lock().await;
        if !state.enabled {
            return Ok(());
        }
        let Some(config) = &state.config else {
            return Ok(());
        };
        if config.wan_groups.is_empty() {
            return Ok(());
        }
        (
            Arc::new(config.clone()),
            state.generation,
            state.due.clone(),
        )
    };
    let mut probes = tokio::task::JoinSet::new();
    let now = Instant::now();
    for group in &config.wan_groups {
        if due.get(&group.id).is_some_and(|time| *time > now) {
            continue;
        }
        for member in &group.members {
            let config = config.clone();
            let group = group.clone();
            let interface = member.interface.clone();
            probes.spawn(async move {
                let result = probe(&config, &group, &interface).await;
                (group, interface, result)
            });
        }
    }
    let mut observations = Vec::new();
    while let Some(result) = probes.join_next().await {
        observations.push(result.context("WAN probe task failed")?);
    }
    // Serialize only publication and the small nft batch with Apply/restore.
    // All potentially slow probes run outside the operation lock.
    let _operation = store.lock_operation().await;
    let update = {
        let mut state = runtime().lock().await;
        if !state.enabled || state.generation != generation {
            return Ok(());
        }
        for (group, interface, result) in observations {
            let reason = result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "Probe succeeded".into());
            state
                .health
                .entry((group.id, interface))
                .or_default()
                .observe(result.is_ok(), reason, &group, Instant::now());
            state.due.insert(
                group.id,
                Instant::now() + Duration::from_secs(u64::from(group.interval_seconds)),
            );
        }
        let update = map_update(&config, &state.health)?;
        if state.installed.as_ref() == Some(&update) {
            state.error = None;
            return Ok(());
        }
        update
    };
    ensure!(
        update["nftables"]
            .as_array()
            .is_some_and(|commands| !commands.is_empty()),
        "empty WAN map update"
    );
    ServiceManager::new()
        .apply_nftables_json(&serde_json::to_string(&update)?)
        .await?;
    let mut state = runtime().lock().await;
    state.installed = Some(update);
    state.error = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn health_hysteresis_and_delayed_recovery() {
        let group = WanGroup::default();
        let start = Instant::now();
        let mut health = Health::default();
        health.observe(true, "ok".into(), &group, start);
        health.observe(true, "ok".into(), &group, start + Duration::from_secs(5));
        assert!(!health.healthy);
        health.observe(true, "ok".into(), &group, start + Duration::from_secs(10));
        assert!(health.healthy);
        health.observe(
            false,
            "down".into(),
            &group,
            start + Duration::from_secs(15),
        );
        assert!(health.healthy);
        health.observe(
            false,
            "down".into(),
            &group,
            start + Duration::from_secs(20),
        );
        health.observe(
            false,
            "down".into(),
            &group,
            start + Duration::from_secs(25),
        );
        assert!(!health.healthy);
        health.observe(true, "ok".into(), &group, start + Duration::from_secs(26));
        assert!(!health.healthy);
    }
    #[test]
    fn map_updates_only_touch_owned_maps_and_use_wan_marks() {
        let config = crate::config::wan_groups::test_config();
        let mut health = BTreeMap::new();
        health.insert(
            (1, "wan0".into()),
            Health {
                healthy: true,
                ..Default::default()
            },
        );
        let update = map_update(&config, &health).unwrap();
        let commands = update["nftables"].as_array().unwrap();
        assert_eq!(commands.len(), 4);
        let routes = wan_return_routes(&config).unwrap();
        assert_eq!(
            commands[1]["add"]["element"]["elem"][0][1],
            routes[0].mark()
        );
        assert_eq!(
            commands[3]["add"]["element"]["elem"][0][1],
            routes[0].strict_mark()
        );
        assert!(commands
            .iter()
            .all(|command| command["flush"].get("map").is_some()
                || command["add"].get("element").is_some()));
        let down = map_update(&config, &BTreeMap::new()).unwrap();
        assert!(down["nftables"][1]["add"]["element"]["elem"]
            .as_array()
            .unwrap()
            .iter()
            .all(|element| element[1] == 0));
    }

    #[test]
    #[ignore = "requires root/CAP_SYS_ADMIN, nft, ip and python3; creates its own isolated network namespace"]
    fn native_group_maps_check_install_update_and_fail_closed() {
        let mut config = crate::config::wan_groups::test_config();
        for (preserve, weight) in [(true, 3), (false, 3), (true, 1), (false, 1)] {
            config.wan_groups[0].members[0].weight = weight;
            config.firewall.rules.forward[0].preserve_internal_routes = preserve;
            let directory = crate::service::files::StagedDirectory::new().unwrap();
            let rules = crate::service::files::StagedFile::new(
                directory.path(),
                crate::renderer::nftables::render(&config)
                    .unwrap()
                    .as_bytes(),
                0o600,
            )
            .unwrap();
            let mut health = BTreeMap::new();
            for member in &config.wan_groups[0].members {
                health.insert(
                    (1, member.interface.clone()),
                    Health {
                        healthy: true,
                        ..Default::default()
                    },
                );
            }
            let updates = json!([
                map_update(&config, &health).unwrap(),
                map_update(&config, &BTreeMap::new()).unwrap()
            ]);
            let updates = crate::service::files::StagedFile::new(
                directory.path(),
                serde_json::to_string(&updates).unwrap().as_bytes(),
                0o600,
            )
            .unwrap();
            let script = include_str!("wan_groups_native.py");
            let output = std::process::Command::new("unshare")
                .args(["--net", "python3", "-c", script])
                .arg(rules.path())
                .arg(updates.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn status_shares_describe_installed_maps_even_after_failed_update() {
        let config = crate::config::wan_groups::test_config();
        let mut health = BTreeMap::new();
        health.insert(
            (1, "wan0".into()),
            Health {
                healthy: true,
                ..Default::default()
            },
        );
        let installed = map_update(&config, &health).unwrap();
        health.clear();
        let runtime = Runtime {
            config: Some(config),
            enabled: true,
            health,
            installed: Some(installed),
            error: Some("nft failed".into()),
            ..Default::default()
        };
        let status = runtime_status(&runtime);
        assert_eq!(
            status["groups"][0]["members"][0]["effective_percent"],
            100.0
        );
        assert_eq!(status["groups"][0]["active_tier"], 1);
        assert_eq!(
            status["groups"][0]["members"][0]["health"]["healthy"],
            false
        );
    }

    #[tokio::test]
    async fn unactivated_worker_does_not_run_commands() {
        let fixture = crate::config::store::tests::TestStore::new();
        tick(&fixture.store).await.unwrap();
        assert_eq!(status().await["active"], false);
    }
}
