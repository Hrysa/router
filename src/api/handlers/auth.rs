use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

    // If no password is configured, authentication is disabled.
    if config.auth.password_hash.is_empty() {
        let token = jwt::generate_token(&config.auth.jwt_secret)
            .map_err(|e| ApiError::Internal(e.into()))?;
        return Ok(Json(LoginResponse { token }));
    }

    let valid = password::verify_password(&req.password,
        &config.auth.password_hash,
    )
    .map_err(|e| ApiError::Internal(e.into()))?;

    if !valid {
        return Err(ApiError::Unauthorized);
    }

    let token = jwt::generate_token(&config.auth.jwt_secret)
        .map_err(|e| ApiError::Internal(e.into()))?;

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
    let config = state.config.get().await;

    if !config.auth.password_hash.is_empty() {
        return Err(ApiError::Conflict("password is already configured".into()));
    }

    if req.password.is_empty() {
        return Err(ApiError::BadRequest("password cannot be empty".into()));
    }

    let hash = password::hash_password(&req.password)
        .map_err(|e| ApiError::Internal(e.into()))?;

    let mut new_config = config;
    new_config.auth.password_hash = hash;
    state.config.set(new_config).await
        .map_err(|e| ApiError::Internal(e.into()))?;

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// Ensure the config has a JWT secret, generating one if missing.
pub async fn ensure_jwt_secret(config_store: &ConfigStore) -> anyhow::Result<Arc<String>> {
    let config = config_store.get().await;
    if !config.auth.jwt_secret.is_empty() {
        return Ok(Arc::new(config.auth.jwt_secret.clone()));
    }

    let secret = uuid::Uuid::new_v4().to_string();
    let mut new_config = config;
    new_config.auth.jwt_secret = secret.clone();
    config_store.set(new_config).await?;

    Ok(Arc::new(secret))
}
