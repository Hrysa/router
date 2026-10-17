use crate::{
    api::{error::ApiError, server::AppState},
    config::wan_groups::WanGroup,
};
use axum::{extract::State, Json};
use serde_json::{json, Value};

pub async fn get_groups(State(state): State<AppState>) -> Json<Vec<WanGroup>> {
    Json(state.config.get().await.wan_groups)
}
pub async fn replace_groups(
    State(state): State<AppState>,
    Json(groups): Json<Vec<WanGroup>>,
) -> Result<Json<Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let mut config = state.config.get().await;
    config.wan_groups = groups;
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }
    state.config.set(config).await?;
    Ok(Json(json!({"status":"ok"})))
}
pub async fn status() -> Json<Value> {
    Json(crate::service::wan_groups::status().await)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn group_save_preserves_other_sections_and_does_not_apply() {
        let fixture = crate::config::store::tests::TestStore::new();
        let mut original = crate::config::wan_groups::test_config();
        original.firewall.rules.forward.clear();
        let groups = original.wan_groups.clone();
        original.wan_groups.clear();
        fixture.store.set(original.clone()).await.unwrap();
        let state = crate::api::handlers::auth::tests::state(fixture.store.clone());
        let _ = replace_groups(State(state.clone()), Json(groups.clone()))
            .await
            .unwrap();
        let saved = fixture.store.get().await;
        assert_eq!(saved.wan_groups, groups);
        assert_eq!(saved.firewall, original.firewall);
        assert_eq!(saved.interfaces, original.interfaces);
        assert_eq!(fixture.store.get_applied().await.wan_groups.len(), 0);
        let mut invalid = groups;
        invalid[0].members[0].interface = "missing".into();
        assert!(replace_groups(State(state.clone()), Json(invalid))
            .await
            .is_err());
        assert_eq!(fixture.store.get().await, saved);
        let mut referenced = saved.clone();
        referenced.firewall = crate::config::wan_groups::test_config().firewall;
        fixture.store.set(referenced.clone()).await.unwrap();
        assert!(replace_groups(State(state), Json(vec![])).await.is_err());
        assert_eq!(fixture.store.get().await, referenced);
    }
}
