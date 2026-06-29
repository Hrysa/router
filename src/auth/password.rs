use anyhow::{Context, Result};

/// Hash a plaintext password using bcrypt.
pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).context("failed to hash password")
}

/// Verify a plaintext password against a bcrypt hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash).context("failed to verify password")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "secret123";
        let hash = hash_password(password).unwrap();
        assert_ne!(hash, password);
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }
}
