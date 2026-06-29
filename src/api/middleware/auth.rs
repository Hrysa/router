use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::auth::jwt::validate_token;

/// Shared authentication state.
#[derive(Clone)]
pub struct AuthState {
    pub jwt_secret: Arc<String>,
}

/// Axum middleware that validates the `Authorization: Bearer <token>` header.
pub async fn require_auth(
    State(state): State<AuthState>,
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            validate_token(token, &state.jwt_secret).map_err(|_| AuthError::Unauthorized)?;
            Ok(next.run(req).await)
        }
        _ => Err(AuthError::Unauthorized),
    }
}

/// Error type for authentication failures.
pub enum AuthError {
    Unauthorized,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Body::from(r#"{"error":"unauthorized"}"#),
            ),
        };
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap()
    }
}
