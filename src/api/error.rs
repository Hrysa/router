use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Unified API error type.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("validation failed")]
    Validation(Vec<ValidationError>),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match &self {
            ApiError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone(), Value::Null)
            }
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                msg.clone(),
                Value::Null,
            ),
            ApiError::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "validation failed".into(),
                json!(errors),
            ),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone(), Value::Null),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "unauthorized".into(),
                Value::Null,
            ),
            ApiError::Internal(err) => {
                tracing::error!("internal error: {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "internal server error".into(),
                    Value::Null,
                )
            }
        };

        let body = json!({
            "error": {
                "code": code,
                "message": message,
                "details": details,
            }
        });

        (status, Json(body)).into_response()
    }
}

/// Convert config validation errors to API validation errors.
impl From<Vec<crate::config::validator::ValidationError>> for ApiError {
    fn from(errors: Vec<crate::config::validator::ValidationError>) -> Self {
        ApiError::Validation(
            errors
                .into_iter()
                .map(|e| ValidationError {
                    field: e.field,
                    message: e.message,
                })
                .collect(),
        )
    }
}
