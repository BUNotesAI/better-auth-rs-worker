#![cfg(not(feature = "password-argon2"))]

use better_auth_core::{AuthError, hash_password};

#[tokio::test]
async fn worker_password_hashing_rejects_unsafe_defaults() {
    let error = hash_password(None, "Password123!")
        .await
        .expect_err("no-default builds require an injected password hasher");

    match error {
        AuthError::PasswordHash(message) => {
            assert!(
                message.contains("password-argon2") && message.contains("PasswordHasher"),
                "error should name the disabled native default and injected hasher requirement"
            );
        }
        other => panic!("expected PasswordHash error, got {other:?}"),
    }
}
