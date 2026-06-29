use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::api::error::ApiError;
use crate::api::server::AppState;
use crate::config::schema::*;

/// GET /api/config — get full config
pub async fn get_config(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.get().await;
    Json(serde_json::to_value(&config).unwrap_or_default())
}

/// PUT /api/config — replace full config
pub async fn replace_config(
    State(state): State<AppState>,
    Json(new_config): Json<Config>,
) -> Result<Json<Value>, ApiError> {
    let errors = crate::config::validator::validate(&new_config);
    if !errors.is_empty() {
        return Err(errors.into());
    }

    state.config.set(new_config).await?;

    Ok(Json(json!({
        "status": "ok",
        "message": "config saved"
    })))
}

/// GET /api/config/interfaces — list all interface configs
pub async fn list_interfaces(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.get().await;
    Json(json!({"items": config.interfaces.items}))
}

/// POST /api/config/interfaces — create a new interface config
pub async fn create_interface(
    State(state): State<AppState>,
    Json(iface): Json<InterfaceConfig>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    // Check for duplicate name
    if config.interfaces.items.iter().any(|i| i.name == iface.name) {
        return Err(ApiError::Conflict(format!("interface '{}' already exists", iface.name)));
    }

    config.interfaces.items.push(iface.clone());
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok", "interface": iface})))
}

/// PUT /api/config/interfaces/:name — update an interface config (name is immutable)
pub async fn update_interface(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(iface): Json<InterfaceConfig>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    if iface.name != name {
        return Err(ApiError::BadRequest("interface name cannot be changed".into()));
    }

    let existing = config.interfaces.items.iter_mut().find(|i| i.name == name);
    match existing {
        Some(existing) => {
            *existing = iface;
            let errors = crate::config::validator::validate(&config);
            if !errors.is_empty() {
                return Err(errors.into());
            }
            state.config.set(config).await?;
            Ok(Json(json!({"status": "ok"})))
        }
        None => Err(ApiError::NotFound(format!("interface '{}' not found", name))),
    }
}

/// DELETE /api/config/interfaces/:name — delete an interface config
pub async fn delete_interface(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    let len = config.interfaces.items.len();
    config.interfaces.items.retain(|i| i.name != name);
    if config.interfaces.items.len() < len {
        state.config.set(config).await?;
        Ok(Json(json!({"status": "ok", "deleted": name})))
    } else {
        Err(ApiError::NotFound(format!("interface '{}' not found", name)))
    }
}

/// PATCH /api/config/firewall — update firewall section
pub async fn patch_firewall(
    State(state): State<AppState>,
    Json(patch): Json<Firewall>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;
    config.firewall = patch;
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok"})))
}

// ── Firewall Rules CRUD ──────────────────────────────────────────────────────

/// GET /api/config/firewall/rules — list all firewall rules
pub async fn list_firewall_rules(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.get().await;
    Json(json!({
        "input": config.firewall.rules.input,
        "forward": config.firewall.rules.forward,
    }))
}

/// POST /api/config/firewall/rules — add a new firewall rule
/// Accepts optional ?chain=input|forward query param to override auto-detection.
/// Auto-generates a unique ID for the rule.
pub async fn add_firewall_rule(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    Json(mut rule): Json<FirewallRule>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    // Determine chain: explicit query param > oif-based detection > default input
    let chain = match params.get("chain").map(|s| s.as_str()) {
        Some("forward") => "forward",
        Some("input") => "input",
        _ => if rule.oif.is_some() { "forward" } else { "input" },
    };

    // Auto-generate ID
    let max_id = config.firewall.rules.input.iter()
        .chain(config.firewall.rules.forward.iter())
        .map(|r| r.id)
        .max()
        .unwrap_or(0);
    rule.id = max_id + 1;

    if chain == "forward" {
        config.firewall.rules.forward.push(rule.clone());
    } else {
        config.firewall.rules.input.push(rule.clone());
    }

    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }

    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok", "rule": rule})))
}

/// PUT /api/config/firewall/rules/:id — update a firewall rule by ID
pub async fn update_firewall_rule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u32>,
    Json(rule): Json<FirewallRule>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    // Find and update in input rules
    if let Some(existing) = config.firewall.rules.input.iter_mut().find(|r| r.id == id) {
        *existing = rule;
        let errors = crate::config::validator::validate(&config);
        if !errors.is_empty() {
            return Err(errors.into());
        }
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok"})));
    }

    // Find and update in forward rules
    if let Some(existing) = config.firewall.rules.forward.iter_mut().find(|r| r.id == id) {
        *existing = rule;
        let errors = crate::config::validator::validate(&config);
        if !errors.is_empty() {
            return Err(errors.into());
        }
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok"})));
    }

    Err(ApiError::NotFound(format!("rule id '{}' not found", id)))
}

/// DELETE /api/config/firewall/rules/:name — delete a firewall rule by name
pub async fn delete_firewall_rule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u32>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    let input_len = config.firewall.rules.input.len();
    config.firewall.rules.input.retain(|r| r.id != id);
    if config.firewall.rules.input.len() < input_len {
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok", "deleted": id})));
    }

    let forward_len = config.firewall.rules.forward.len();
    config.firewall.rules.forward.retain(|r| r.id != id);
    if config.firewall.rules.forward.len() < forward_len {
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok", "deleted": id})));
    }

    Err(ApiError::NotFound(format!("rule id '{}' not found", id)))
}

/// POST /api/config/firewall/rules/:id/move — move a rule up or down
pub async fn move_firewall_rule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u32>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let direction = body
        .get("direction")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("missing 'direction' field".into()))?;

    let mut config = state.config.get().await;

    // Try input chain first
    if let Some(idx) = config.firewall.rules.input.iter().position(|r| r.id == id) {
        let len = config.firewall.rules.input.len();
        match direction {
            "up" => {
                if idx == 0 {
                    return Err(ApiError::BadRequest("rule is already at the top".into()));
                }
                config.firewall.rules.input.swap(idx, idx - 1);
            }
            "down" => {
                if idx >= len - 1 {
                    return Err(ApiError::BadRequest("rule is already at the bottom".into()));
                }
                config.firewall.rules.input.swap(idx, idx + 1);
            }
            _ => return Err(ApiError::BadRequest("direction must be 'up' or 'down'".into())),
        }
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok", "chain": "input", "direction": direction})));
    }

    // Try forward chain
    if let Some(idx) = config.firewall.rules.forward.iter().position(|r| r.id == id) {
        let len = config.firewall.rules.forward.len();
        match direction {
            "up" => {
                if idx == 0 {
                    return Err(ApiError::BadRequest("rule is already at the top".into()));
                }
                config.firewall.rules.forward.swap(idx, idx - 1);
            }
            "down" => {
                if idx >= len - 1 {
                    return Err(ApiError::BadRequest("rule is already at the bottom".into()));
                }
                config.firewall.rules.forward.swap(idx, idx + 1);
            }
            _ => return Err(ApiError::BadRequest("direction must be 'up' or 'down'".into())),
        }
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok", "chain": "forward", "direction": direction})));
    }

    Err(ApiError::NotFound(format!("rule id '{}' not found", id)))
}

// ── Firewall NAT CRUD ────────────────────────────────────────────────────────

/// GET /api/config/firewall/nat — list NAT rules
pub async fn list_nat_rules(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.get().await;
    Json(json!({
        "masquerade": config.firewall.nat.masquerade,
        "port_forward": config.firewall.nat.port_forward,
    }))
}

/// POST /api/config/firewall/nat/port-forward — add a port forward rule
/// Auto-generates a unique ID.
pub async fn add_port_forward(
    State(state): State<AppState>,
    Json(mut rule): Json<PortForward>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    // Auto-generate ID
    let max_id = config.firewall.nat.port_forward.iter()
        .map(|r| r.id)
        .max()
        .unwrap_or(0);
    rule.id = max_id + 1;

    config.firewall.nat.port_forward.push(rule.clone());
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }

    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok", "rule": rule})))
}

/// PUT /api/config/firewall/nat/port-forward/:id — update a port forward rule
pub async fn update_port_forward(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u32>,
    Json(rule): Json<PortForward>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    if let Some(existing) = config
        .firewall
        .nat
        .port_forward
        .iter_mut()
        .find(|r| r.id == id)
    {
        *existing = rule;
        let errors = crate::config::validator::validate(&config);
        if !errors.is_empty() {
            return Err(errors.into());
        }
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok"})));
    }

    Err(ApiError::NotFound(format!("port forward id '{}' not found", id)))
}

/// DELETE /api/config/firewall/nat/port-forward/:id — delete a port forward rule
pub async fn delete_port_forward(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<u32>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    let len = config.firewall.nat.port_forward.len();
    config.firewall.nat.port_forward.retain(|r| r.id != id);
    if config.firewall.nat.port_forward.len() < len {
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok", "deleted": id})));
    }

    Err(ApiError::NotFound(format!("port forward id '{}' not found", id)))
}

// ── nftables Sets CRUD ──────────────────────────────────────────────────────

/// GET /api/config/firewall/sets — list all nftables sets
pub async fn list_nft_sets(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.get().await;
    Json(json!({"sets": config.firewall.sets}))
}

/// POST /api/config/firewall/sets — add a new nftables set
pub async fn add_nft_set(
    State(state): State<AppState>,
    Json(set): Json<NftSet>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    if config.firewall.sets.iter().any(|s| s.name == set.name) {
        return Err(ApiError::Conflict(format!("set '{}' already exists", set.name)));
    }

    config.firewall.sets.push(set.clone());
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok", "set": set})))
}

/// PUT /api/config/firewall/sets/:name — update an nftables set
pub async fn update_nft_set(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(set): Json<NftSet>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    if let Some(existing) = config.firewall.sets.iter_mut().find(|s| s.name == name) {
        *existing = set;
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok"})));
    }

    Err(ApiError::NotFound(format!("set '{}' not found", name)))
}

/// DELETE /api/config/firewall/sets/:name — delete an nftables set
pub async fn delete_nft_set(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    // Check that no rules or port forwards reference this set
    if let Some(location) = set_used_by(&config, &name) {
        return Err(ApiError::Conflict(format!(
            "set '{}' is still referenced by {}", name, location
        )));
    }

    let len = config.firewall.sets.len();
    config.firewall.sets.retain(|s| s.name != name);
    if config.firewall.sets.len() < len {
        state.config.set(config).await?;
        Ok(Json(json!({"status": "ok", "deleted": name})))
    } else {
        Err(ApiError::NotFound(format!("set '{}' not found", name)))
    }
}

/// Check if a set is referenced by any firewall rule or port forward.
/// Returns a description of the first match, or None.
fn set_used_by(config: &Config, set_name: &str) -> Option<String> {
    let prefix = format!("@{}", set_name);

    // Firewall rules (input + forward)
    for chain in [&config.firewall.rules.input, &config.firewall.rules.forward] {
        for rule in chain {
            let used = rule.dport.as_ref().map_or(false, |p| port_spec_uses_set(p, &prefix))
                || rule.sport.as_ref().map_or(false, |p| port_spec_uses_set(p, &prefix))
                || rule.saddr.as_ref().map_or(false, |v| *v == prefix)
                || rule.daddr.as_ref().map_or(false, |v| *v == prefix);
            if used {
                return Some(format!("firewall rule '{}'", rule.comment));
            }
        }
    }

    // Port forwards
    for pf in &config.firewall.nat.port_forward {
        let used = port_spec_uses_set(&pf.target_port, &prefix)
            || pf.source_address.as_ref().map_or(false, |v| *v == prefix)
            || pf.target_address.as_ref().map_or(false, |v| *v == prefix);
        if used {
            return Some(format!("port forward '{}'", pf.comment));
        }
    }

    None
}

fn port_spec_uses_set(spec: &PortSpec, prefix: &str) -> bool {
    matches!(spec, PortSpec::Set(name) if name == prefix)
}

// ── DHCP CRUD ────────────────────────────────────────────────────────────────

/// PATCH /api/config/dhcp — update DHCP section
pub async fn patch_dhcp(
    State(state): State<AppState>,
    Json(patch): Json<Dhcp>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;
    config.dhcp = patch;
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok"})))
}

/// GET /api/config/dhcp/leases — list static DHCP leases
pub async fn list_dhcp_leases(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.get().await;
    Json(json!({"static_leases": config.dhcp.static_leases}))
}

/// POST /api/config/dhcp/leases — add a static DHCP lease
pub async fn add_dhcp_lease(
    State(state): State<AppState>,
    Json(lease): Json<StaticLease>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    if config.dhcp.static_leases.iter().any(|l| l.mac == lease.mac || l.ip == lease.ip) {
        return Err(ApiError::Conflict("lease with same MAC or IP already exists".into()));
    }

    config.dhcp.static_leases.push(lease.clone());
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok", "lease": lease})))
}

/// DELETE /api/config/dhcp/leases/:mac — delete a static DHCP lease by MAC
pub async fn delete_dhcp_lease(
    State(state): State<AppState>,
    axum::extract::Path(mac): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;

    let len = config.dhcp.static_leases.len();
    config.dhcp.static_leases.retain(|l| l.mac != mac);
    if config.dhcp.static_leases.len() < len {
        state.config.set(config).await?;
        return Ok(Json(json!({"status": "ok", "deleted": mac})));
    }

    Err(ApiError::NotFound(format!("lease with MAC '{}' not found", mac)))
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

/// PATCH /api/config/hooks — update hooks section
pub async fn patch_hooks(
    State(state): State<AppState>,
    Json(patch): Json<Hooks>,
) -> Result<Json<Value>, ApiError> {
    let mut config = state.config.get().await;
    config.hooks = patch;
    state.config.set(config).await?;
    Ok(Json(json!({"status": "ok"})))
}

// ── Other Config ─────────────────────────────────────────────────────────────

/// POST /api/config/validate — validate config without saving
pub async fn validate_config(Json(config): Json<Config>) -> Json<Value> {
    let errors = crate::config::validator::validate(&config);
    if errors.is_empty() {
        Json(json!({"valid": true, "errors": []}))
    } else {
        Json(json!({"valid": false, "errors": errors}))
    }
}

/// POST /api/config/apply — render and apply all service configs
pub async fn apply_config(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let prev_config = state.config.get().await;
    let config = prev_config.clone();

    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }

    let service_manager = crate::service::manager::ServiceManager::new();
    // Use diff-based change detection — config.set() writes config.yml but
    // detect_rendered_changes compares rendered service configs against /etc/ files.
    let result = crate::service::apply::apply(&config, &prev_config, &state.config_path, &service_manager, false).await?;

    Ok(Json(serde_json::to_value(&result).unwrap_or_default()))
}

/// POST /api/config/rollback — rollback to last backup
pub async fn rollback_config(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let service_manager = crate::service::manager::ServiceManager::new();
    let result =
        crate::service::rollback::rollback(&state.config, &state.config_path, &service_manager).await?;

    Ok(Json(serde_json::to_value(&result).unwrap_or_default()))
}

/// GET /api/config/backups — list available backups
pub async fn list_backups(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let backups = state.config.list_backups()?;
    let entries: Vec<Value> = backups
        .iter()
        .map(|b| {
            json!({
                "id": b.id,
                "size": b.size,
                "created": b.created.to_rfc3339(),
            })
        })
        .collect();

    Ok(Json(json!({"backups": entries})))
}

/// POST /api/config/backups/:id/restore — restore specific backup
pub async fn restore_backup(
    State(state): State<AppState>,
    axum::extract::Path(backup_id): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let service_manager = crate::service::manager::ServiceManager::new();
    let result =
        crate::service::rollback::rollback_to(&backup_id, &state.config, &state.config_path, &service_manager)
            .await?;

    Ok(Json(serde_json::to_value(&result).unwrap_or_default()))
}

/// GET /api/firewall/stats — read nftables counter stats for firewall rules
pub async fn firewall_stats(State(_state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let mut stats = serde_json::Map::new();

    let chains = [
        ("inet", "filter", "input"),
        ("inet", "filter", "forward"),
        ("inet", "mangle", "prerouting"),
    ];

    for (table_family, table, chain) in &chains {
        let output = tokio::process::Command::new("nft")
            .args(["-j", "list", "chain", table_family, table, chain])
            .output()
            .await;

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };

        let json_str = String::from_utf8_lossy(&output.stdout);
        let parsed: Value = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // nft -j JSON: {"nftables": [ {"rule": {"comment": "...", "expr": [...]}}, ... ]}
        // comment is at rule level, counter is inside expr array
        if let Some(entries) = parsed.get("nftables").and_then(|v| v.as_array()) {
            for entry in entries {
                if let Some(rule) = entry.get("rule") {
                    let comment = rule
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let rule_name = comment.split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();

                    if rule_name.is_empty() {
                        continue;
                    }

                    // Find counter in expr array
                    if let Some(exprs) = rule.get("expr").and_then(|v| v.as_array()) {
                        for expr in exprs {
                            if let Some(counter) = expr.get("counter") {
                                let packets = counter.get("packets").and_then(|v| v.as_u64()).unwrap_or(0);
                                let bytes = counter.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                                stats.insert(
                                    rule_name.clone(),
                                    json!({"packets": packets, "bytes": bytes}),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Json(json!({"stats": stats})))
}
