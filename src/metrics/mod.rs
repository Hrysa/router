use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::metrics::{
    atomics::AtomicU64, counter, Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use metrics_util::registry::{AtomicStorage, Registry};
use metrics_util::storage::AtomicBucket;
use serde::Serialize;

const COLLECT_INTERVAL_SECS: u64 = 2;
const MAX_SAMPLES: usize = 30 * 60 / COLLECT_INTERVAL_SECS as usize;

#[derive(Clone, Debug, Default, Serialize)]
pub struct IfaceSample {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuleSample {
    pub chain: String,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct MetricsSample {
    pub ts: u64,
    pub interfaces: HashMap<String, IfaceSample>,
    pub firewall: HashMap<String, RuleSample>,
}

#[derive(Clone, Debug, Default)]
struct PreviousIface {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

#[derive(Clone, Debug, Default)]
struct PreviousRule {
    packets: u64,
    bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct Previous {
    interfaces: HashMap<String, PreviousIface>,
    firewall: HashMap<String, PreviousRule>,
}

#[derive(Debug, Default)]
struct MetricsState {
    samples: VecDeque<MetricsSample>,
    prev: Previous,
}

/// In-memory metrics recorder and collector.
///
/// Implements the `metrics` facade and stores counters/gauges/histograms in a
/// `metrics-util` `Registry`. A background task periodically samples interface
/// traffic from `/sys/class/net` and firewall counters from nftables, turning
/// the deltas into both `metrics` counters and a short rolling history that the
/// UI can render with uPlot.
#[derive(Debug)]
pub struct RouterdMetrics {
    registry: Registry<Key, AtomicStorage>,
    state: Mutex<MetricsState>,
}

impl RouterdMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: Registry::atomic(),
            state: Mutex::new(MetricsState::default()),
        })
    }

    /// Install this recorder as the global `metrics` recorder and spawn the
    /// background collector.
    pub fn install(self: &Arc<Self>) -> anyhow::Result<()> {
        ::metrics::set_global_recorder(self.clone())?;
        spawn_collector(self.clone());
        Ok(())
    }

    /// Build a uPlot-friendly response from the current rolling history.
    pub fn to_uplot_response(&self) -> MetricsResponse {
        let state = self.state.lock().unwrap();
        let samples: Vec<&MetricsSample> = state.samples.iter().collect();

        let mut timestamps = Vec::with_capacity(samples.len());
        let mut iface_names: Vec<String> = samples
            .iter()
            .flat_map(|s| s.interfaces.keys().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        iface_names.sort();

        let mut rule_ids: Vec<String> = samples
            .iter()
            .flat_map(|s| s.firewall.keys().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        rule_ids.sort_by_key(|k| k.parse::<u32>().unwrap_or(u32::MAX));

        let mut interfaces: HashMap<String, IfaceSeries> = HashMap::new();
        for name in &iface_names {
            interfaces.insert(
                name.clone(),
                IfaceSeries {
                    rx_bps: Vec::with_capacity(samples.len()),
                    tx_bps: Vec::with_capacity(samples.len()),
                    rx_pps: Vec::with_capacity(samples.len()),
                    tx_pps: Vec::with_capacity(samples.len()),
                },
            );
        }

        let mut firewall: HashMap<String, RuleSeries> = HashMap::new();
        for id in &rule_ids {
            let chain = samples
                .iter()
                .find_map(|s| s.firewall.get(id).map(|r| r.chain.clone()))
                .unwrap_or_default();
            firewall.insert(
                id.clone(),
                RuleSeries {
                    chain,
                    packets_per_sec: Vec::with_capacity(samples.len()),
                    bytes_per_sec: Vec::with_capacity(samples.len()),
                },
            );
        }

        for sample in &samples {
            timestamps.push(sample.ts);
            for name in &iface_names {
                let s = sample.interfaces.get(name).cloned().unwrap_or_default();
                let series = interfaces.get_mut(name).unwrap();
                series.rx_bps.push(s.rx_bps);
                series.tx_bps.push(s.tx_bps);
                series.rx_pps.push(s.rx_pps);
                series.tx_pps.push(s.tx_pps);
            }
            for id in &rule_ids {
                let s = sample.firewall.get(id).cloned().unwrap_or_default();
                let series = firewall.get_mut(id).unwrap();
                series.packets_per_sec.push(s.packets_per_sec);
                series.bytes_per_sec.push(s.bytes_per_sec);
            }
        }

        MetricsResponse {
            timestamps,
            interfaces,
            firewall,
        }
    }

    /// Expose the raw current value of every counter in the registry.
    /// Useful for a simple `/metrics` text dump or debugging.
    pub fn current_counters(&self) -> HashMap<String, u64> {
        let mut out = HashMap::new();
        self.registry.visit_counters(|key, counter| {
            let value = counter.load(std::sync::atomic::Ordering::Relaxed);
            out.insert(format_key(key), value);
        });
        out
    }
}

impl Recorder for RouterdMetrics {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let handle = self
            .registry
            .get_or_create_counter(key, |c: &Arc<AtomicU64>| c.clone());
        Counter::from_arc(handle)
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let handle = self
            .registry
            .get_or_create_gauge(key, |g: &Arc<AtomicU64>| g.clone());
        Gauge::from_arc(handle)
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let handle = self
            .registry
            .get_or_create_histogram(key, |h: &Arc<AtomicBucket<f64>>| h.clone());
        Histogram::from_arc(handle)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MetricsResponse {
    pub timestamps: Vec<u64>,
    pub interfaces: HashMap<String, IfaceSeries>,
    pub firewall: HashMap<String, RuleSeries>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IfaceSeries {
    pub rx_bps: Vec<f64>,
    pub tx_bps: Vec<f64>,
    pub rx_pps: Vec<f64>,
    pub tx_pps: Vec<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleSeries {
    pub chain: String,
    pub packets_per_sec: Vec<f64>,
    pub bytes_per_sec: Vec<f64>,
}

fn format_key(key: &Key) -> String {
    let mut s = key.name().to_string();
    let labels: Vec<String> = key
        .labels()
        .map(|l| format!("{}={}", l.key(), l.value()))
        .collect();
    if !labels.is_empty() {
        s.push('{');
        s.push_str(&labels.join(","));
        s.push('}');
    }
    s
}

fn spawn_collector(metrics: Arc<RouterdMetrics>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(COLLECT_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            collect_once(&metrics).await;
        }
    });
}

async fn collect_once(metrics: &RouterdMetrics) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let prev = {
        let state = metrics.state.lock().unwrap();
        state.prev.clone()
    };

    let (iface_sample, iface_prev) = collect_interfaces(&prev.interfaces).await;
    let (fw_sample, fw_prev) = collect_firewall(&prev.firewall).await;

    let sample = MetricsSample {
        ts,
        interfaces: iface_sample,
        firewall: fw_sample,
    };

    {
        let mut state = metrics.state.lock().unwrap();
        state.samples.push_back(sample);
        while state.samples.len() > MAX_SAMPLES {
            state.samples.pop_front();
        }
        state.prev.interfaces = iface_prev;
        state.prev.firewall = fw_prev;
    }
}

async fn collect_interfaces(
    prev: &HashMap<String, PreviousIface>,
) -> (HashMap<String, IfaceSample>, HashMap<String, PreviousIface>) {
    let mut sample = HashMap::new();
    let mut next = HashMap::new();

    let names = list_iface_names();
    let interval = COLLECT_INTERVAL_SECS as f64;

    for name in names {
        let rx_bytes = read_iface_stat(&name, "rx_bytes");
        let tx_bytes = read_iface_stat(&name, "tx_bytes");
        let rx_packets = read_iface_stat(&name, "rx_packets");
        let tx_packets = read_iface_stat(&name, "tx_packets");

        let current = PreviousIface {
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
        };

        let delta = prev
            .get(&name)
            .map(|p| IfaceDelta {
                rx_bytes: current.rx_bytes.saturating_sub(p.rx_bytes),
                tx_bytes: current.tx_bytes.saturating_sub(p.tx_bytes),
                rx_packets: current.rx_packets.saturating_sub(p.rx_packets),
                tx_packets: current.tx_packets.saturating_sub(p.tx_packets),
            })
            .unwrap_or(IfaceDelta {
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
            });

        counter!("routerd_interface_bytes_total", "interface" => name.clone(), "direction" => "rx")
            .increment(delta.rx_bytes);
        counter!("routerd_interface_bytes_total", "interface" => name.clone(), "direction" => "tx")
            .increment(delta.tx_bytes);
        counter!("routerd_interface_packets_total", "interface" => name.clone(), "direction" => "rx")
            .increment(delta.rx_packets);
        counter!("routerd_interface_packets_total", "interface" => name.clone(), "direction" => "tx")
            .increment(delta.tx_packets);

        sample.insert(
            name.clone(),
            IfaceSample {
                rx_bps: delta.rx_bytes as f64 / interval,
                tx_bps: delta.tx_bytes as f64 / interval,
                rx_pps: delta.rx_packets as f64 / interval,
                tx_pps: delta.tx_packets as f64 / interval,
            },
        );

        next.insert(name, current);
    }

    (sample, next)
}

struct IfaceDelta {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

async fn collect_firewall(
    prev: &HashMap<String, PreviousRule>,
) -> (HashMap<String, RuleSample>, HashMap<String, PreviousRule>) {
    let mut sample = HashMap::new();
    let mut next = HashMap::new();
    let interval = COLLECT_INTERVAL_SECS as f64;

    for (rule_id, current) in read_firewall_counters().await {
        let delta = prev
            .get(&rule_id)
            .map(|previous| RuleDelta {
                packets: current.packets.saturating_sub(previous.packets),
                bytes: current.bytes.saturating_sub(previous.bytes),
            })
            .unwrap_or(RuleDelta {
                packets: 0,
                bytes: 0,
            });
        counter!("routerd_firewall_packets_total", "rule_id" => rule_id.clone(), "chain" => current.chain.clone()).increment(delta.packets);
        counter!("routerd_firewall_bytes_total", "rule_id" => rule_id.clone(), "chain" => current.chain.clone()).increment(delta.bytes);
        sample.insert(
            rule_id.clone(),
            RuleSample {
                chain: current.chain,
                packets_per_sec: delta.packets as f64 / interval,
                bytes_per_sec: delta.bytes as f64 / interval,
            },
        );
        next.insert(
            rule_id,
            PreviousRule {
                packets: current.packets,
                bytes: current.bytes,
            },
        );
    }

    (sample, next)
}

/// A logical rule can have counters in multiple protocol and proxy-policy rules.
#[derive(Default)]
pub(crate) struct FirewallCounter {
    pub chain: String,
    pub packets: u64,
    pub bytes: u64,
}

pub(crate) async fn read_firewall_counters() -> HashMap<String, FirewallCounter> {
    let mut counters = HashMap::new();
    for (table, chain, logical_chain) in [
        ("filter", "input", "input"),
        ("filter", "forward", "forward"),
        ("filter", "tproxy_policy", "forward"),
        ("filter", "tproxy_dispatch", "prerouting"),
        // Keep collecting rules installed by an older routerd until Apply.
        ("mangle", "prerouting", "prerouting"),
    ] {
        let mut command = tokio::process::Command::new("nft");
        command
            .args(["-j", "list", "chain", "inet", table, chain])
            .kill_on_drop(true);
        let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(3), command.output()).await
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        if let Ok(value) = serde_json::from_slice(&output.stdout) {
            merge_firewall_counters(&mut counters, &value, logical_chain);
        }
    }
    counters
}

fn merge_firewall_counters(
    counters: &mut HashMap<String, FirewallCounter>,
    value: &serde_json::Value,
    chain: &str,
) {
    let Some(entries) = value["nftables"].as_array() else {
        return;
    };
    for entry in entries {
        let rule = &entry["rule"];
        let Some(id) = rule["comment"]
            .as_str()
            .and_then(|comment| comment.strip_prefix('['))
            .and_then(|comment| comment.split_once(']').map(|(id, _)| id))
            .filter(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };
        let Some(expressions) = rule["expr"].as_array() else {
            continue;
        };
        for expression in expressions {
            if let Some(counter) = expression.get("counter") {
                let total = counters.entry(id.into()).or_default();
                total.chain = chain.into();
                total.packets = total
                    .packets
                    .saturating_add(counter["packets"].as_u64().unwrap_or(0));
                total.bytes = total
                    .bytes
                    .saturating_add(counter["bytes"].as_u64().unwrap_or(0));
                break;
            }
        }
    }
}

struct RuleDelta {
    packets: u64,
    bytes: u64,
}

fn list_iface_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" || name.starts_with("veth") || name.starts_with("virbr") {
                continue;
            }
            names.push(name);
        }
    }
    names.sort();
    names
}

fn read_iface_stat(iface: &str, stat: &str) -> u64 {
    let path = format!("/sys/class/net/{}/statistics/{}", iface, stat);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn firewall_counters_sum_proxy_policy_forward_and_protocol_variants() {
        let mut counters = std::collections::HashMap::new();
        for (packets, bytes) in [(2, 100), (3, 200), (4, 300)] {
            super::merge_firewall_counters(
                &mut counters,
                &serde_json::json!({"nftables":[{"rule":{"comment":"[7] rule", "expr":[{"counter":{"packets":packets,"bytes":bytes}}]}}]}),
                "forward",
            );
        }
        assert_eq!(counters["7"].packets, 9);
        assert_eq!(counters["7"].bytes, 600);
        assert_eq!(counters["7"].chain, "forward");
    }

    use super::*;

    #[test]
    fn sampling_cadence_preserves_thirty_minutes_of_history() {
        assert_eq!(COLLECT_INTERVAL_SECS, 2);
        assert_eq!(MAX_SAMPLES, 900);
    }

    #[test]
    fn recorder_stores_counter_value() {
        let metrics = RouterdMetrics::new();
        ::metrics::with_local_recorder(&metrics, || {
            ::metrics::counter!("test_counter", "foo" => "bar").increment(5);
        });

        let counters = metrics.current_counters();
        assert!(counters
            .iter()
            .any(|(k, v)| k == "test_counter{foo=bar}" && *v == 5));
    }

    #[test]
    fn empty_history_returns_empty_response() {
        let metrics = RouterdMetrics::new();
        let resp = metrics.to_uplot_response();
        assert!(resp.timestamps.is_empty());
        assert!(resp.interfaces.is_empty());
        assert!(resp.firewall.is_empty());
    }
}
