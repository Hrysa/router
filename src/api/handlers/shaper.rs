use crate::{
    api::{error::ApiError, server::AppState},
    config::shaper::Shaper,
};
use axum::{extract::State, Json};
use serde_json::{json, Value};

pub async fn get_shaper(State(state): State<AppState>) -> Json<Shaper> {
    Json(state.config.get().await.shaper)
}
/// Section replacement saves only. Operation lock protects fresh read/modify/write.
pub async fn replace_shaper(
    State(state): State<AppState>,
    Json(shaper): Json<Shaper>,
) -> Result<Json<Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let mut config = state.config.get().await;
    config.shaper = shaper;
    let errors = crate::config::validator::validate(&config);
    if !errors.is_empty() {
        return Err(errors.into());
    }
    state.config.set(config).await?;
    Ok(Json(json!({"status":"ok"})))
}
pub async fn status() -> Result<Json<Value>, ApiError> {
    Ok(Json(crate::service::shaper::status().await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::store::tests::TestStore;
    #[tokio::test]
    async fn saving_profiles_preserves_other_sections_and_never_applies() {
        let fixture = TestStore::new();
        let original = crate::config::routing::test_config();
        fixture.store.set(original.clone()).await.unwrap();
        let state = crate::api::handlers::auth::tests::state(fixture.store.clone());
        let shaper = Shaper {
            profiles: vec![crate::config::shaper::tests::profile()],
        };
        let _ = replace_shaper(State(state.clone()), Json(shaper.clone()))
            .await
            .unwrap();
        let saved = fixture.store.get().await;
        assert_eq!(saved.shaper, shaper);
        assert_eq!(saved.interfaces, original.interfaces);
        assert_eq!(saved.firewall, original.firewall);
        assert!(fixture.store.get_applied().await.shaper.profiles.is_empty());
        let mut invalid = shaper;
        invalid.profiles[0].interface = "absent".into();
        assert!(replace_shaper(State(state), Json(invalid)).await.is_err());
        assert_eq!(fixture.store.get().await, saved);
    }
}
