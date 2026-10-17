//! Saved WAN group policy. Runtime health never changes this configuration.
use super::{routing::wan_return_routes, validator::ValidationError, Config};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr};

pub const BUCKETS: u32 = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WanGroup {
    pub id: u32,
    pub name: String,
    pub members: Vec<Member>,
    pub targets: Vec<Ipv4Addr>,
    pub interval_seconds: u32,
    pub timeout_seconds: u32,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub recovery_delay_seconds: u32,
}
impl Default for WanGroup {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            members: vec![],
            targets: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            interval_seconds: 5,
            timeout_seconds: 2,
            failure_threshold: 3,
            recovery_threshold: 2,
            recovery_delay_seconds: 10,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Member {
    pub interface: String,
    pub tier: u16,
    pub weight: u16,
}
pub fn target(config: &Config, value: &str) -> Option<u32> {
    value
        .strip_prefix("group:")?
        .parse::<u32>()
        .ok()
        .filter(|id| config.wan_groups.iter().any(|g| g.id == *id))
}
pub fn fingerprint(group: &WanGroup) -> String {
    let bytes = serde_json::to_vec(group).expect("serializable group");
    let hash = bytes.iter().fold(2166136261u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16777619)
    });
    format!("routerd WAN group {} policy {hash:08x}", group.id)
}
pub fn map_name(id: u32, strict: bool) -> String {
    format!("wg_{id}_{}", if strict { "strict" } else { "normal" })
}
pub fn validate(config: &Config) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let routes = wan_return_routes(config).unwrap_or_default();
    let mut ids = HashSet::new();
    for (index, group) in config.wan_groups.iter().enumerate() {
        let mut messages = Vec::new();
        if group.id == 0 || !ids.insert(group.id) {
            messages.push("group IDs must be unique and nonzero");
        }
        if group.name.trim().is_empty()
            || group.name.len() > 80
            || group.name.chars().any(char::is_control)
        {
            messages.push("name must contain 1–80 characters without control characters");
        }
        if group.members.is_empty() || group.members.len() > 16 {
            messages.push("a group requires 1–16 WAN members");
        }
        let mut names = HashSet::new();
        for member in &group.members {
            if !names.insert(&member.interface)
                || !routes.iter().any(|r| r.name == member.interface)
            {
                messages.push(
                    "members must be unique configured IPv4 WANs with return routing enabled",
                );
            }
            if member.tier == 0 || member.weight == 0 || member.weight > 100 {
                messages.push("tier must be positive; weight must be 1–100");
            }
        }
        if group.targets.is_empty()
            || group.targets.len() > 4
            || group.targets.iter().any(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || ip.is_broadcast()
            })
        {
            messages.push("provide 1–4 unicast IPv4 probe targets");
        }
        if !(2..=300).contains(&group.interval_seconds)
            || !(1..=5).contains(&group.timeout_seconds)
            || group.timeout_seconds > group.interval_seconds
            || !(1..=10).contains(&group.failure_threshold)
            || !(1..=10).contains(&group.recovery_threshold)
            || group.recovery_delay_seconds > 600
        {
            messages.push("invalid health timing: interval 2–300s, timeout 1–5s and no greater than interval, thresholds 1–10, recovery delay 0–600s");
        }
        errors.extend(messages.into_iter().map(|message| ValidationError {
            field: format!("wan_groups[{index}]"),
            message: message.into(),
        }));
    }
    if config
        .wan_groups
        .iter()
        .map(|g| g.members.len())
        .sum::<usize>()
        > 64
    {
        errors.push(ValidationError {
            field: "wan_groups".into(),
            message: "at most 64 total WAN group memberships are supported".into(),
        });
    }
    if config.wan_groups.len() > 32 {
        errors.push(ValidationError {
            field: "wan_groups".into(),
            message: "at most 32 WAN groups are supported".into(),
        });
    }
    errors
}

/// Smooth weighted buckets among healthy members of the best available tier.
/// Marks remain per-WAN; changing buckets never migrates established connections.
pub fn buckets(group: &WanGroup, healthy: &[bool]) -> Vec<Option<usize>> {
    let tier = group
        .members
        .iter()
        .enumerate()
        .filter(|(i, _)| healthy.get(*i) == Some(&true))
        .map(|(_, m)| m.tier)
        .min();
    let candidates: Vec<_> = group
        .members
        .iter()
        .enumerate()
        .filter(|(i, m)| Some(m.tier) == tier && healthy.get(*i) == Some(&true))
        .collect();
    let total: i64 = candidates.iter().map(|(_, m)| i64::from(m.weight)).sum();
    if total == 0 {
        return vec![None; BUCKETS as usize];
    }
    // Largest-remainder apportionment gives the closest integer slot counts;
    // then spread those slots smoothly across consecutive source-IP residues.
    let mut shares: Vec<i64> = candidates
        .iter()
        .map(|(_, member)| i64::from(member.weight) * i64::from(BUCKETS) / total)
        .collect();
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|i| {
        (
            std::cmp::Reverse(i64::from(candidates[*i].1.weight) * i64::from(BUCKETS) % total),
            *i,
        )
    });
    let remaining = i64::from(BUCKETS) - shares.iter().sum::<i64>();
    for i in order.into_iter().take(remaining as usize) {
        shares[i] += 1;
    }
    let mut scores = vec![0i64; candidates.len()];
    (0..BUCKETS)
        .map(|_| {
            for (score, share) in scores.iter_mut().zip(&shares) {
                *score += share;
            }
            let best = (0..scores.len())
                .max_by_key(|i| (scores[*i], std::cmp::Reverse(*i)))
                .unwrap();
            scores[best] -= i64::from(BUCKETS);
            Some(candidates[best].0)
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    let mut config = super::routing::test_config();
    config.wan_groups = vec![WanGroup {
        id: 1,
        name: "Internet".into(),
        members: vec![
            Member {
                interface: "wan0".into(),
                tier: 1,
                weight: 3,
            },
            Member {
                interface: "wan1".into(),
                tier: 1,
                weight: 1,
            },
        ],
        ..Default::default()
    }];
    config.firewall.rules.forward = serde_json::from_value(serde_json::json!([
        {"id": 20, "action":"accept", "interfaces":["lan0"], "route_via":"group:1"}
    ]))
    .unwrap();
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    fn group() -> WanGroup {
        WanGroup {
            members: vec![
                Member {
                    interface: "a".into(),
                    tier: 1,
                    weight: 3,
                },
                Member {
                    interface: "b".into(),
                    tier: 1,
                    weight: 1,
                },
                Member {
                    interface: "c".into(),
                    tier: 2,
                    weight: 1,
                },
            ],
            ..Default::default()
        }
    }
    #[test]
    fn tiers_weights_and_all_down() {
        let g = group();
        let selected = buckets(&g, &[true, true, true]);
        assert_eq!(selected.iter().filter(|m| **m == Some(0)).count(), 192);
        assert_eq!(selected.iter().filter(|m| **m == Some(1)).count(), 64);
        assert!(buckets(&g, &[false, true, true])
            .iter()
            .all(|m| *m == Some(1)));
        assert!(buckets(&g, &[false, false, true])
            .iter()
            .all(|m| *m == Some(2)));
        assert!(buckets(&g, &[false, false, false])
            .iter()
            .all(Option::is_none));
    }
    #[test]
    fn modulo_slots_alternate_equal_wans_and_round_weights() {
        let mut g = group();
        g.members[0].weight = 1;
        let slots = buckets(&g, &[true, true, false]);
        for pair in slots.as_chunks::<2>().0 {
            assert_eq!(*pair, [Some(0), Some(1)]);
        }
        // These user-reported clients now split even/even/odd rather than hash.
        assert_eq!(
            [slots[250], slots[102], slots[53]],
            [Some(0), Some(0), Some(1)]
        );
        g.members[0].weight = 1;
        g.members[1].weight = 2;
        g.members[2].tier = 1;
        g.members[2].weight = 100;
        let slots = buckets(&g, &[true, true, true]);
        let counts: Vec<_> = (0..3)
            .map(|index| slots.iter().filter(|slot| **slot == Some(index)).count())
            .collect();
        assert_eq!(counts, [2, 5, 249]);
        for member in &mut g.members {
            member.weight = 1;
        }
        let slots = buckets(&g, &[true, true, true]);
        let counts: Vec<_> = (0..3)
            .map(|index| slots.iter().filter(|slot| **slot == Some(index)).count())
            .collect();
        assert_eq!(counts, [86, 85, 85]);
    }

    #[test]
    fn rejects_unknown_duplicate_members_and_invalid_timing() {
        let mut config = Config::default();
        let mut g = group();
        g.interval_seconds = 0;
        g.members.push(g.members[0].clone());
        config.wan_groups = vec![g.clone(), g];
        let errors = validate(&config);
        assert!(errors.iter().any(|e| e.message.contains("IDs")));
        assert!(errors.iter().any(|e| e.message.contains("members")));
        assert!(errors.iter().any(|e| e.message.contains("timing")));
    }
}
