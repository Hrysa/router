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
    pub config: Arc<crate::config::ConfigStore>,
}

/// Axum middleware that validates the `Authorization: Bearer <token>` header.
pub async fn require_auth(
    State(state): State<AuthState>,
    req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let config = state.config.get().await;
    if config.auth.password_hash.is_empty() || config.auth.jwt_secret.is_empty() {
        return Err(AuthError::Unauthorized);
    }
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            validate_token(token, &config.auth.jwt_secret).map_err(|_| AuthError::Unauthorized)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::get, Router};
    use crate::auth::jwt::generate_token;
    use crate::config::store::tests::TestStore;

    #[tokio::test]
    async fn authentication_uses_current_secret_and_requires_setup() {
        let fixture = TestStore::new();
        let mut config = fixture.store.get().await;
        config.auth.jwt_secret = "first-secret".into();
        fixture.store.set(config.clone()).await.unwrap();
        let auth = AuthState { config: fixture.store.clone() };
        let app = Router::new().route("/protected", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(auth, require_auth));
        let server = axum_test::TestServer::new(app).unwrap();
        let first_token = generate_token("first-secret").unwrap();
        let first_header = format!("Bearer {}", first_token);
        server.get("/protected").add_header(header::AUTHORIZATION, first_header.clone()).await.assert_status_unauthorized();
        config.auth.password_hash = "configured".into();
        fixture.store.set(config.clone()).await.unwrap();
        server.get("/protected").add_header(header::AUTHORIZATION, first_header.clone()).await.assert_status_ok();
        config.auth.jwt_secret = "second-secret".into();
        fixture.store.set(config).await.unwrap();
        server.get("/protected").add_header(header::AUTHORIZATION, first_header).await.assert_status_unauthorized();
        let second_token = generate_token("second-secret").unwrap();
        server.get("/protected").add_header(header::AUTHORIZATION, format!("Bearer {}", second_token)).await.assert_status_ok();
    }
}
