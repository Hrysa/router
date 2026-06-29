use anyhow::{Context, Result};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims for authenticated sessions.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
}

/// Generate a JWT for the admin user.
pub fn generate_token(secret: &str) -> Result<String> {
    let now = chrono::Utc::now();
    let claims = Claims {
        sub: "admin".into(),
        iat: now.timestamp(),
        exp: (now + chrono::Duration::hours(24)).timestamp(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .context("failed to generate jwt")
}

/// Validate a JWT and return its claims.
pub fn validate_token(token: &str, secret: &str) -> Result<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .context("invalid or expired token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_validate() {
        let secret = "test-secret";
        let token = generate_token(secret).unwrap();
        let claims = validate_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "admin");
    }

    #[test]
    fn test_validate_wrong_secret() {
        let token = generate_token("secret-a").unwrap();
        assert!(validate_token(&token, "secret-b").is_err());
    }
}
