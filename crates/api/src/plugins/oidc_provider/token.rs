//! Opaque access-token generation and hashing, plus authorization-code /
//! access-token TTL policy.
//!
//! Access tokens are high-entropy opaque values drawn from the injected
//! [`SecureRandom`] port. Only their hash is ever persisted (`token_hash`); the
//! raw value is returned once to the client and never stored. The same hash
//! function is used at userinfo time to look the token up by hash.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use better_auth_core::{AccessToken, AccessTokenHash, AuthResult, SecureRandom};

/// Default authorization-code lifetime in seconds.
pub const DEFAULT_CODE_TTL_SECONDS: i64 = 60;
/// Default opaque access-token lifetime in seconds.
pub const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: i64 = 600;

/// Entropy drawn from `SecureRandom` for an opaque access token.
const ACCESS_TOKEN_ENTROPY_BYTES: usize = 32;

/// Generates a high-entropy opaque access token and its at-rest hash.
///
/// Preconditions:
/// - `secure_random` is the injected runtime entropy source.
///
/// Effects:
/// 1. Draws [`ACCESS_TOKEN_ENTROPY_BYTES`] from `secure_random`.
///
/// Returns the raw opaque token (to send once to the client) and its hash (to
/// persist). The raw token is never persisted.
pub fn generate_access_token(
    secure_random: &dyn SecureRandom,
) -> AuthResult<(AccessToken, AccessTokenHash)> {
    let mut bytes = [0u8; ACCESS_TOKEN_ENTROPY_BYTES];
    secure_random.fill_bytes(&mut bytes)?;
    let token = AccessToken::from_raw(URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_access_token(&token);
    Ok((token, hash))
}

/// Computes the at-rest hash of an opaque access token (SHA-256, base64url).
#[must_use]
pub fn hash_access_token(token: &AccessToken) -> AccessTokenHash {
    AccessTokenHash::from_hash(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_str().as_bytes())))
}

/// Computes the at-rest hash of a client secret (SHA-256, base64url).
///
/// Client secrets are high-entropy machine-generated values, so a fast hash is
/// sufficient (unlike user passwords, which use argon2).
#[must_use]
pub fn hash_client_secret(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

/// Computes an expiry instant from the issuing clock and a lifetime.
#[must_use]
pub fn expires_at(now: DateTime<Utc>, ttl: Duration) -> DateTime<Utc> {
    now + ttl
}

/// Returns whether `expires_at` is at or before `now` (i.e. expired).
#[must_use]
pub fn is_expired(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> bool {
    expires_at <= now
}
