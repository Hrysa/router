use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::api::server::AppState;

/// GET /api/metrics — rolling interface and firewall history formatted for uPlot.
pub async fn get_metrics(State(state): State<AppState>) -> Json<Value> {
    let response = state.metrics.to_uplot_response();
    Json(json!(response))
}

/// GET /api/metrics/current — current cumulative counters from the metrics registry.
pub async fn get_current_metrics(State(state): State<AppState>) -> Json<Value> {
    let counters = state.metrics.current_counters();
    Json(json!({ "counters": counters }))
}
