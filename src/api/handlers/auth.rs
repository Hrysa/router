use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::server::AppState;
use crate::auth::{jwt, password};
use crate::config::ConfigStore;

/// GET /api/auth/status — check whether a password is configured.
pub async fn status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = state.config.get().await;
    Json(serde_json::json!({
        "password_configured": !config.auth.password_hash.is_empty()
    }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

/// POST /api/auth/login — authenticate and receive a JWT.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let config = state.config.get().await;

    if config.auth.password_hash.is_empty() {
        return Err(ApiError::Unauthorized);
    }

    if req.password.len() > 72 {
        return Err(ApiError::Unauthorized);
    }
    let hash = config.auth.password_hash.clone();
    let valid =
        tokio::task::spawn_blocking(move || password::verify_password(&req.password, &hash))
            .await
            .map_err(|error| ApiError::Internal(error.into()))??;

    if !valid {
        return Err(ApiError::Unauthorized);
    }

    let token = jwt::generate_token(&config.auth.jwt_secret).map_err(ApiError::Internal)?;

    Ok(Json(LoginResponse { token }))
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub password: String,
}

/// POST /api/auth/setup — set the admin password when none is configured.
/// This endpoint is unprotected and only works if password_hash is empty.
pub async fn setup(
    State(state): State<AppState>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _operation = state.config.lock_operation().await;
    let config = state.config.get().await;

    if !config.auth.password_hash.is_empty() {
        return Err(ApiError::Conflict("password is already configured".into()));
    }

    if req.password.is_empty() || req.password.len() > 72 {
        return Err(ApiError::BadRequest(
            "password must contain between 1 and 72 UTF-8 bytes".into(),
        ));
    }

    let hash = tokio::task::spawn_blocking(move || password::hash_password(&req.password))
        .await
        .map_err(|error| ApiError::Internal(error.into()))??;

    let mut new_config = config;
    new_config.auth.password_hash = hash;
    state
        .config
        .set(new_config)
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// Ensure the config has a JWT secret, generating one if missing.
pub async fn ensure_jwt_secret(config_store: &ConfigStore) -> anyhow::Result<()> {
    let _operation = config_store.lock_operation().await;
    let config = config_store.get().await;
    if !config.auth.jwt_secret.is_empty() {
        return Ok(());
    }

    let secret = uuid::Uuid::new_v4().to_string();
    let mut new_config = config;
    new_config.auth.jwt_secret = secret.clone();
    config_store.set(new_config).await?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::middleware::auth::AuthState;
    use crate::config::store::tests::TestStore;

    pub(crate) fn state(config: std::sync::Arc<ConfigStore>) -> AppState {
        AppState {
            config: config.clone(),
            config_path: std::path::PathBuf::from("unused"),
            auth: AuthState { config },
            metrics: crate::metrics::RouterdMetrics::new(),
        }
    }

    #[tokio::test]
    async fn unconfigured_password_cannot_issue_tokens() {
        let fixture = TestStore::new();
        ensure_jwt_secret(&fixture.store).await.unwrap();
        let result = login(
            State(state(fixture.store.clone())),
            Json(LoginRequest {
                password: String::new(),
            }),
        )
        .await;
        assert!(matches!(result, Err(ApiError::Unauthorized)));
    }

    #[tokio::test]
    async fn simultaneous_setup_only_allows_one_password() {
        let fixture = TestStore::new();
        ensure_jwt_secret(&fixture.store).await.unwrap();
        let application = state(fixture.store.clone());
        let (first, second) = tokio::join!(
            setup(
                State(application.clone()),
                Json(SetupRequest {
                    password: "first".into()
                })
            ),
            setup(
                State(application),
                Json(SetupRequest {
                    password: "second".into()
                })
            ),
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(
            matches!(first, Err(ApiError::Conflict(_)))
                || matches!(second, Err(ApiError::Conflict(_)))
        );
    }
}
