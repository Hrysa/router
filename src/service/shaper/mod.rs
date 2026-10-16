//! CAKE host fairness via rtnetlink. Only explicit Apply/startup activates shaping;
//! the background reconciler uses the last successful shaper settings, never drafts.
mod kernel;
mod netlink;

use crate::config::{Config, ConfigStore};
use anyhow::{ensure, Context, Result};
use kernel::{Kernel, Link, Qdisc};
use netlink::{CAKE, INGRESS, INGRESS_PARENT, ROOT};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::Mutex;

const STATE_DIR: &str = "/run/routerd-shaper";
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Owned {
    id: u32,
    device: String,
    index: u32,
    ifb_name: String,
    ifb_index: Option<u32>,
    egress: bool,
    ingress: bool,
}
#[derive(Default)]
struct Runtime {
    active: Option<Config>,
    error: Option<String>,
}
static RUNTIME: OnceLock<Mutex<Runtime>> = OnceLock::new();
fn runtime() -> &'static Mutex<Runtime> {
    RUNTIME.get_or_init(Default::default)
}
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn journal_path(directory: &Path) -> PathBuf {
    directory.join("ownership.json")
}
fn load(directory: &Path) -> Result<Vec<Owned>> {
    if directory.exists() {
        check_directory(directory)?;
    }
    let path = journal_path(directory);
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { nix::libc::geteuid() },
            "shaper ownership journal must be a private regular file owned by this service"
        );
        ensure!(
            metadata.len() <= 1_048_576,
            "shaper ownership journal is too large"
        );
    }
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context(
            "invalid shaper ownership journal; refusing to adopt or delete traffic control",
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}
fn check_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.mode() & 0o022 == 0
            && metadata.uid() == unsafe { nix::libc::geteuid() },
        "shaper state directory must be owned by this service and not writable by others"
    );
    Ok(())
}
fn save(directory: &Path, owned: &[Owned]) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    check_directory(directory)?;
    crate::service::files::atomic_write(
        &journal_path(directory),
        &serde_json::to_vec(owned)?,
        0o600,
    )
}
fn root(qdiscs: &[Qdisc], index: u32) -> Option<&Qdisc> {
    qdiscs.iter().find(|q| q.index == index && q.parent == ROOT)
}
fn owned_root(q: &Qdisc) -> bool {
    q.handle == CAKE && q.kind == "cake" && q.parent == ROOT
}
fn default_root(q: &Qdisc) -> bool {
    q.handle == 0
        && matches!(
            q.kind.as_str(),
            "noqueue" | "mq" | "fq" | "fq_codel" | "pfifo_fast"
        )
}
fn default_tree(qdiscs: &[Qdisc], index: u32) -> bool {
    // Replacing a default mq root also removes its children. Only implicit
    // default children may be replaced; preserve explicitly managed subtrees.
    qdiscs
        .iter()
        .filter(|q| q.index == index && q.kind != "ingress" && q.kind != "clsact")
        .all(default_root)
}
fn check_ifb_qdiscs(qdiscs: &[Qdisc], index: u32) -> Result<()> {
    for q in qdiscs.iter().filter(|q| q.index == index) {
        ensure!(
            owned_root(q) || (default_root(q) && default_tree(qdiscs, index)),
            "foreign qdisc or hook on owned IFB"
        );
    }
    Ok(())
}
fn same_link<'a>(links: &'a [Link], owned: &Owned) -> Option<&'a Link> {
    links
        .iter()
        .find(|link| link.name == owned.device && link.index == owned.index)
}
fn ifb<'a>(links: &'a [Link], owned: &Owned) -> Result<Option<&'a Link>> {
    let value = links.iter().find(|link| link.name == owned.ifb_name);
    if let Some(link) = value {
        ensure!(
            link.kind == "ifb"
                && link.alias == format!("routerd:shaper:{}", owned.id)
                && owned.ifb_index.is_none_or(|index| index == link.index),
            "IFB {} is foreign or was replaced (kind {}, alias {:?}, index {}, expected {:?})",
            owned.ifb_name,
            link.kind,
            link.alias,
            link.index,
            owned.ifb_index
        );
    }
    Ok(value)
}
fn check_ingress(
    kernel: &mut Kernel,
    qdiscs: &[Qdisc],
    owned: &Owned,
    allowed: bool,
    ifb: Option<u32>,
) -> Result<()> {
    let hooks: Vec<_> = qdiscs
        .iter()
        .filter(|q| {
            q.index == owned.index
                && (q.parent == INGRESS_PARENT
                    || q.handle == INGRESS
                    || q.kind == "clsact"
                    || q.kind == "ingress")
        })
        .collect();
    for hook in hooks {
        ensure!(
            allowed && hook.kind == "ingress" && hook.handle == INGRESS,
            "foreign ingress/clsact qdisc on {}",
            owned.device
        );
        for filter in kernel.filters(owned.index)? {
            ensure!(
                ifb.is_some_and(
                    |index| kernel::owned_filter(&filter, index, owned.id).unwrap_or(false)
                ),
                "foreign or changed ingress filter on {}",
                owned.device
            );
        }
    }
    Ok(())
}
fn preflight(
    kernel: &mut Kernel,
    config: &Config,
    records: &[Owned],
    links: &[Link],
    qdiscs: &[Qdisc],
) -> Result<()> {
    // Check all profiles and cleanup targets before the first mutation.
    for record in records {
        ensure!(
            !links
                .iter()
                .any(|l| l.index == record.index && l.name != record.device),
            "owned shaper interface was renamed; refusing ambiguous cleanup"
        );
        let owned_ifb = ifb(links, record)?;
        if let Some(link) = owned_ifb {
            check_ifb_qdiscs(qdiscs, link.index)?;
        }
        if same_link(links, record).is_some() {
            if record.egress {
                if let Some(q) = root(qdiscs, record.index) {
                    ensure!(
                        owned_root(q) || (default_root(q) && default_tree(qdiscs, record.index)),
                        "owned root qdisc was changed on {}",
                        record.device
                    );
                }
            }
            if record.ingress {
                check_ingress(kernel, qdiscs, record, true, owned_ifb.map(|l| l.index))?;
            }
        }
    }
    for profile in config.shaper.profiles.iter().filter(|p| p.enabled) {
        let device = profile.device(config);
        let Some(link) = links.iter().find(|l| l.name == device) else {
            continue;
        };
        let previous = records
            .iter()
            .find(|o| o.id == profile.id && o.index == link.index && o.device == device);
        if profile.egress_rate() != 0 {
            if let Some(q) = root(qdiscs, link.index) {
                ensure!(
                    (default_root(q) && default_tree(qdiscs, link.index))
                        || (records
                            .iter()
                            .any(|o| o.device == device && o.index == link.index && o.egress)
                            && owned_root(q)),
                    "foreign root qdisc on {device}; remove it explicitly before enabling shaping"
                );
            }
        }
        if profile.ingress_rate() != 0 {
            let record = Owned {
                id: profile.id,
                device: device.into(),
                index: link.index,
                ifb_name: profile.ifb_name(),
                ifb_index: previous.and_then(|o| o.ifb_index),
                egress: false,
                ingress: false,
            };
            // Never adopt a pre-existing IFB merely because its name/alias matches.
            if links.iter().any(|l| l.name == record.ifb_name) {
                ensure!(
                    previous.is_some_and(|o| o.ingress),
                    "IFB name {} already exists without ownership",
                    record.ifb_name
                );
            }
            let owned_ifb = ifb(links, &record)?;
            if let Some(old) = records.iter().find(|o| {
                o.device == device && o.index == link.index && o.ingress && o.id != profile.id
            }) {
                check_ingress(kernel, qdiscs, old, true, ifb(links, old)?.map(|l| l.index))?;
            } else {
                check_ingress(
                    kernel,
                    qdiscs,
                    &record,
                    previous.is_some_and(|o| o.ingress),
                    owned_ifb.map(|l| l.index),
                )?;
            }
        }
    }
    Ok(())
}
fn cleanup(
    kernel: &mut Kernel,
    owned: &Owned,
    remove_egress: bool,
    remove_ingress: bool,
) -> Result<()> {
    let links = kernel.links()?;
    let qdiscs = kernel.qdiscs()?;
    if same_link(&links, owned).is_some() {
        if remove_ingress && owned.ingress {
            let target = ifb(&links, owned)?;
            check_ingress(kernel, &qdiscs, owned, true, target.map(|l| l.index))?;
            if let Some(q) = qdiscs
                .iter()
                .find(|q| q.index == owned.index && q.kind == "ingress" && q.handle == INGRESS)
            {
                kernel.delete_qdisc(q)?;
            }
        }
        if remove_egress && owned.egress {
            if let Some(q) = root(&qdiscs, owned.index) {
                if owned_root(q) {
                    kernel.delete_qdisc(q)?;
                } else {
                    ensure!(
                        default_root(q),
                        "foreign qdisc replaced owned root on {}",
                        owned.device
                    );
                }
            }
        }
    }
    if remove_ingress && owned.ingress {
        if let Some(link) = ifb(&links, owned)? {
            check_ifb_qdiscs(&qdiscs, link.index)?;
            kernel.delete_link(link.index)?;
        }
    }
    Ok(())
}
fn reconcile_kernel(config: &Config, directory: &Path) -> Result<()> {
    let mut records = load(directory)?;
    let desired: Vec<_> = config
        .shaper
        .profiles
        .iter()
        .filter(|p| p.enabled)
        .collect();
    if desired.is_empty() && records.is_empty() {
        return Ok(());
    }
    let mut kernel = Kernel::open()?;
    let links = kernel.links()?;
    let qdiscs = kernel.qdiscs()?;
    preflight(&mut kernel, config, &records, &links, &qdiscs)?;
    // Obsolete records are deleted one at a time, journalled after exact cleanup.
    let mut index = 0;
    while index < records.len() {
        let old = &records[index];
        let keep = desired.iter().any(|p| {
            p.id == old.id
                && p.device(config) == old.device
                && links
                    .iter()
                    .any(|l| l.name == old.device && l.index == old.index)
        });
        if !keep {
            cleanup(&mut kernel, old, true, true)?;
            records.remove(index);
            save(directory, &records)?;
        } else {
            index += 1;
        }
    }
    for profile in desired {
        let links = kernel.links()?;
        let Some(link) = links.iter().find(|l| l.name == profile.device(config)) else {
            tracing::warn!(
                interface = profile.device(config),
                "shaper pending: interface is not present"
            );
            continue;
        };
        let pos = if let Some(pos) = records.iter().position(|o| o.id == profile.id) {
            pos
        } else {
            records.push(Owned {
                id: profile.id,
                device: link.name.clone(),
                index: link.index,
                ifb_name: profile.ifb_name(),
                ifb_index: None,
                egress: false,
                ingress: false,
            });
            records.len() - 1
        };
        // Disable individual directions without disturbing the other direction.
        if profile.egress_rate() == 0 && records[pos].egress {
            cleanup(&mut kernel, &records[pos], true, false)?;
            records[pos].egress = false;
            save(directory, &records)?;
        }
        if profile.ingress_rate() == 0 && records[pos].ingress {
            cleanup(&mut kernel, &records[pos], false, true)?;
            records[pos].ingress = false;
            records[pos].ifb_index = None;
            save(directory, &records)?;
        }
        if profile.egress_rate() != 0 {
            records[pos].egress = true;
            save(directory, &records)?; // Intent before mutation, including crash recovery.
            let qdiscs = kernel.qdiscs()?;
            let actual = root(&qdiscs, link.index);
            let matching = actual.is_some_and(|q| {
                owned_root(q)
                    && kernel::same_options(&q.options, &kernel::cake_options(profile, false))
                        .unwrap_or(false)
            });
            if !matching {
                ensure!(
                    actual
                        .is_none_or(|q| owned_root(q)
                            || (default_root(q) && default_tree(&qdiscs, link.index))),
                    "root qdisc changed during Apply on {}",
                    link.name
                );
                kernel.set_cake(link.index, profile, false, actual.is_some())?;
            }
        }
        if profile.ingress_rate() != 0 {
            records[pos].ingress = true;
            save(directory, &records)?;
            let mut links = kernel.links()?;
            if ifb(&links, &records[pos])?.is_none() {
                kernel.create_ifb(profile)?;
                links = kernel.links()?;
            }
            let ifb_index = ifb(&links, &records[pos])?
                .context("IFB creation returned no link")?
                .index;
            records[pos].ifb_index = Some(ifb_index);
            save(directory, &records)?;
            kernel.up(ifb_index, link.mtu)?;
            let qdiscs = kernel.qdiscs()?;
            let actual = root(&qdiscs, ifb_index);
            let matching = actual.is_some_and(|q| {
                owned_root(q)
                    && kernel::same_options(&q.options, &kernel::cake_options(profile, true))
                        .unwrap_or(false)
            });
            if !matching {
                ensure!(
                    actual
                        .is_none_or(|q| owned_root(q)
                            || (default_root(q) && default_tree(&qdiscs, ifb_index))),
                    "IFB qdisc changed during Apply"
                );
                kernel.set_cake(ifb_index, profile, true, actual.is_some())?;
            }
            if !qdiscs
                .iter()
                .any(|q| q.index == link.index && q.kind == "ingress")
            {
                kernel.ingress(link.index)?;
            }
            if kernel.filters(link.index)?.is_empty() {
                kernel.redirect(link.index, ifb_index, profile)?;
            }
        }
    }
    Ok(())
}

/// Suspend reconnect repairs during Apply; a failed Apply never reactivates them.
pub async fn suspend() {
    runtime().lock().await.active = None;
}
pub async fn activate(config: &Config) {
    let mut state = runtime().lock().await;
    state.active = Some(config.clone());
    state.error = None;
}
pub async fn preflight_config(config: &Config) -> Result<()> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let mut state = runtime().blocking_lock();
        let result = (|| {
            let records = load(Path::new(STATE_DIR))?;
            if records.is_empty() && !config.shaper.profiles.iter().any(|p| p.enabled) {
                return Ok(());
            }
            let mut kernel = Kernel::open()?;
            let links = kernel.links()?;
            let qdiscs = kernel.qdiscs()?;
            preflight(&mut kernel, &config, &records, &links, &qdiscs)
        })();
        state.error = result.as_ref().err().map(|error| format!("{error:#}"));
        result
    })
    .await?
}
pub async fn reconcile(config: &Config) -> Result<()> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let mut state = runtime().blocking_lock();
        let result = reconcile_kernel(&config, Path::new(STATE_DIR));
        state.error = result.as_ref().err().map(|e| format!("{e:#}"));
        result
    })
    .await?
}
pub fn start_background(store: Arc<ConfigStore>) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(5));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            let _operation = store.lock_operation().await;
            let config = runtime().lock().await.active.clone();
            if let Some(config) = config {
                if let Err(error) = reconcile(&config).await {
                    tracing::error!(%error, "shaper reconnect reconciliation failed");
                }
            }
        }
    });
}
pub async fn status() -> Result<Value> {
    tokio::task::spawn_blocking(|| {
        let state = runtime().blocking_lock();
        let records = load(Path::new(STATE_DIR))?;
        let mut kernel = Kernel::open()?;
        let links = kernel.links()?;
        let qdiscs = kernel.qdiscs()?;
        let profiles: Vec<_> = records.iter().map(|record| {
            let egress = same_link(&links, record).and_then(|_| root(&qdiscs, record.index)).filter(|q| record.egress && owned_root(q));
            let ingress = ifb(&links, record).ok().flatten().and_then(|l| root(&qdiscs, l.index)).filter(|q| record.ingress && owned_root(q));
            json!({"id":record.id,"interface":record.device,"egress":egress.map(|q| &q.stats),"ingress":ingress.map(|q| &q.stats)})
        }).collect();
        Ok(json!({"timestamp_ms":now_ms(),"profiles":profiles,"error":state.error,"reconnect_active":state.active.is_some()}))
    }).await?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_journal_is_atomic_and_root_claims_require_prior_ownership() {
        let temp = crate::service::files::StagedDirectory::new().unwrap();
        let directory = temp.path().join("state");
        assert!(load(&directory).unwrap().is_empty());
        let owned = Owned {
            id: 1,
            device: "wan0".into(),
            index: 42,
            ifb_name: "rdsh00000001".into(),
            ifb_index: Some(43),
            egress: true,
            ingress: true,
        };
        save(&directory, &[owned]).unwrap();
        assert_eq!(load(&directory).unwrap()[0].index, 42);
        let q = Qdisc {
            index: 42,
            handle: CAKE,
            parent: ROOT,
            kind: "cake".into(),
            options: vec![],
            stats: Default::default(),
        };
        assert!(owned_root(&q));
        assert!(!default_root(&q));
        let implicit = Qdisc {
            handle: 0,
            parent: ROOT,
            kind: "mq".into(),
            ..q.clone()
        };
        let child = Qdisc {
            handle: 0x10000,
            parent: 1,
            kind: "fq_codel".into(),
            ..q.clone()
        };
        assert!(default_tree(std::slice::from_ref(&implicit), 42));
        assert!(!default_tree(&[implicit, child], 42));
        std::fs::write(journal_path(&directory), b"corrupt").unwrap();
        assert!(load(&directory).is_err());
    }
}

#[cfg(test)]
mod native_tests {
    use super::netlink::*;
    use super::*;
    #[test]
    #[ignore = "requires root, unshare, CAKE, IFB, matchall and mirred; always self-isolates"]
    fn native_cake_lifecycle_conflicts_and_fairness() {
        if std::env::var_os("ROUTERD_SHAPER_NATIVE").is_none() {
            let result = std::process::Command::new("unshare")
                .args([
                    "--net",
                    "env",
                    "ROUTERD_SHAPER_NATIVE=1",
                    "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "service::shaper::native_tests::native_cake_lifecycle_conflicts_and_fairness",
                    "--ignored",
                    "--nocapture",
                ])
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            println!("{}", String::from_utf8_lossy(&result.stdout));
            return;
        }
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link("/proc/1/ns/net").unwrap(),
            "must be isolated from host networking"
        );
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        let mut config = crate::config::routing::test_config();
        let profile = crate::config::shaper::tests::profile();
        config.shaper.profiles = vec![profile.clone()];
        let mut kernel = Kernel::open().unwrap();
        kernel
            .nl
            .request(
                16,
                ACK | CREATE | EXCL,
                link(
                    0,
                    0,
                    0,
                    vec![string(3, "wan0"), nested(18, vec![string(1, "dummy")])],
                ),
            )
            .unwrap();
        let parent = kernel
            .links()
            .unwrap()
            .into_iter()
            .find(|l| l.name == "wan0")
            .unwrap();
        kernel.up(parent.index, 9000).unwrap();
        reconcile_kernel(&config, directory.path()).unwrap();
        let records = load(directory.path()).unwrap();
        let qdiscs = kernel.qdiscs().unwrap();
        let actual = root(&qdiscs, parent.index).unwrap();
        assert!(owned_root(actual));
        assert!(
            kernel::same_options(&actual.options, &kernel::cake_options(&profile, false)).unwrap(),
            "actual {:?}, desired {:?}",
            netlink::attrs(&actual.options).unwrap(),
            netlink::attrs(&kernel::cake_options(&profile, false)).unwrap()
        );
        let ifb_index = records[0].ifb_index.unwrap();
        assert_eq!(
            kernel
                .links()
                .unwrap()
                .iter()
                .find(|l| l.index == ifb_index)
                .unwrap()
                .mtu,
            9000
        );
        let filters = kernel.filters(parent.index).unwrap();
        assert!(
            kernel::owned_filter(&filters[0], ifb_index, profile.id).unwrap(),
            "filter {:?}; attrs {:?}",
            filters[0],
            netlink::attrs(&filters[0].options).unwrap()
        );
        reconcile_kernel(&config, directory.path()).unwrap();
        // Foreign filters must prevent cleanup, without removing the owned root.
        kernel
            .nl
            .request(45, ACK, tc(parent.index, 1, INGRESS, FILTER_INFO, vec![]))
            .unwrap();
        let mut foreign = profile.clone();
        foreign.id = 999;
        kernel.redirect(parent.index, ifb_index, &foreign).unwrap();
        config.shaper.profiles.clear();
        assert!(reconcile_kernel(&config, directory.path())
            .unwrap_err()
            .to_string()
            .contains("foreign"));
        assert!(owned_root(
            root(&kernel.qdiscs().unwrap(), parent.index).unwrap()
        ));
        kernel
            .nl
            .request(45, ACK, tc(parent.index, 1, INGRESS, FILTER_INFO, vec![]))
            .unwrap();
        kernel.redirect(parent.index, ifb_index, &profile).unwrap();
        kernel.ingress(ifb_index).unwrap();
        assert!(reconcile_kernel(&config, directory.path())
            .unwrap_err()
            .to_string()
            .contains("foreign"));
        assert!(kernel.links().unwrap().iter().any(|l| l.index == ifb_index));
        let foreign = kernel
            .qdiscs()
            .unwrap()
            .into_iter()
            .find(|q| q.index == ifb_index && q.kind == "ingress")
            .unwrap();
        kernel.delete_qdisc(&foreign).unwrap();
        reconcile_kernel(&config, directory.path()).unwrap();
        assert!(load(directory.path()).unwrap().is_empty());
        assert!(!kernel
            .links()
            .unwrap()
            .iter()
            .any(|l| l.name == profile.ifb_name()));
        assert!(!kernel
            .qdiscs()
            .unwrap()
            .iter()
            .any(|q| q.handle == CAKE || q.kind == "ingress"));
        // Competing hosts, four flows versus one, behind real SNAT. The Python
        // fixture only creates links inside this already isolated namespace.
        kernel.delete_link(parent.index).unwrap();
        use std::io::{BufRead, Write};
        let mut traffic = std::process::Command::new("python3")
            .args(["-u", "-c", include_str!("native_test.py")])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(traffic.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "READY");
        let mut profile = profile;
        profile.upload_kbit = 4000;
        profile.download_kbit = 4000;
        config.shaper.profiles = vec![profile.clone()];
        reconcile_kernel(&config, directory.path()).unwrap();
        traffic.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        let measurements: Value = serde_json::from_str(&line).unwrap();
        println!("traffic measurements: {measurements}");
        let current = load(directory.path()).unwrap();
        let qdiscs = kernel.qdiscs().unwrap();
        assert!(root(&qdiscs, current[0].index).unwrap().stats.packets > 0);
        assert!(
            root(&qdiscs, current[0].ifb_index.unwrap())
                .unwrap()
                .stats
                .packets
                > 0
        );
        assert!(root(&qdiscs, current[0].index).unwrap().stats.drops > 0);
        traffic
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"DONE\n")
            .unwrap();
        assert!(traffic.wait().unwrap().success());
        // Link disappearance cleans the IFB; a fresh index is reconciled safely.
        if kernel
            .links()
            .unwrap()
            .iter()
            .any(|l| l.index == current[0].index)
        {
            kernel.delete_link(current[0].index).unwrap();
        }
        reconcile_kernel(&config, directory.path()).unwrap();
        assert!(load(directory.path()).unwrap().is_empty());
        kernel
            .nl
            .request(
                16,
                ACK | CREATE | EXCL,
                link(
                    0,
                    0,
                    0,
                    vec![string(3, "wan0"), nested(18, vec![string(1, "dummy")])],
                ),
            )
            .unwrap();
        reconcile_kernel(&config, directory.path()).unwrap();
        assert_ne!(load(directory.path()).unwrap()[0].index, current[0].index);
        let mut replacement = profile.clone();
        replacement.id = 2;
        config.shaper.profiles = vec![replacement.clone()];
        reconcile_kernel(&config, directory.path()).unwrap();
        assert_eq!(load(directory.path()).unwrap()[0].id, 2);
        assert!(!kernel
            .links()
            .unwrap()
            .iter()
            .any(|l| l.name == profile.ifb_name()));
        replacement.download_kbit = 0;
        config.shaper.profiles = vec![replacement];
        reconcile_kernel(&config, directory.path()).unwrap();
        assert!(load(directory.path()).unwrap()[0].egress);
        assert!(!load(directory.path()).unwrap()[0].ingress);
        config.shaper.profiles.clear();
        reconcile_kernel(&config, directory.path()).unwrap();
        assert!(load(directory.path()).unwrap().is_empty());
        let device = kernel
            .links()
            .unwrap()
            .into_iter()
            .find(|l| l.name == "wan0")
            .unwrap();
        kernel
            .nl
            .request(
                36,
                ACK | CREATE | REPLACE,
                tc(device.index, 0x10000, ROOT, 0, vec![string(1, "fq")]),
            )
            .unwrap();
        config.shaper.profiles = vec![profile];
        assert!(reconcile_kernel(&config, directory.path())
            .unwrap_err()
            .to_string()
            .contains("foreign root"));
        assert_eq!(
            root(&kernel.qdiscs().unwrap(), device.index)
                .unwrap()
                .handle,
            0x10000
        );
        assert!(load(directory.path()).unwrap().is_empty());
    }
}
