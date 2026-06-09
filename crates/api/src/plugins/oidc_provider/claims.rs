//! Pure projection from granted scopes to standard OIDC claims.
//!
//! The host populates [`SubjectClaims`] from the authenticated better-auth user;
//! this function decides which claims the granted scopes expose. It performs no
//! I/O and never reads claims for scopes that were not granted.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

use better_auth_core::{ClientId, Issuer, Scope, ScopeSet};

use super::decide::TokenGrant;

/// Standard claim values for a subject, populated by the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectClaims {
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

/// Projects the standard claims allowed by the granted scopes.
///
/// `profile` exposes `name`; `email` exposes `email` and `email_verified`.
/// Claims for scopes that were not granted are always omitted.
#[must_use]
pub fn project_claims(granted: &ScopeSet, source: &SubjectClaims) -> Map<String, Value> {
    let mut claims = Map::new();
    if granted.contains(Scope::PROFILE)
        && let Some(name) = &source.name
    {
        claims.insert("name".to_string(), Value::String(name.clone()));
    }
    if granted.contains(Scope::EMAIL) {
        if let Some(email) = &source.email {
            claims.insert("email".to_string(), Value::String(email.clone()));
        }
        if let Some(verified) = source.email_verified {
            claims.insert("email_verified".to_string(), Value::Bool(verified));
        }
    }
    claims
}

/// The id_token claim set (OIDC Core).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// Builds the id_token claims (pure).
///
/// `iss` is the configured issuer, `sub` the subject, `aud` the client id,
/// `exp = now + ttl`, `iat = now`, `auth_time` from the session, `nonce` echoed
/// from the request, and profile/email claims included only for granted scopes.
#[must_use]
pub fn build_id_token_claims(
    issuer: &Issuer,
    client_id: &ClientId,
    grant: &TokenGrant,
    source: &SubjectClaims,
    now: DateTime<Utc>,
    ttl: Duration,
) -> IdTokenClaims {
    let projected = project_claims(&grant.scope, source);
    IdTokenClaims {
        iss: issuer.as_str().to_string(),
        sub: grant.subject.as_str().to_string(),
        aud: client_id.as_str().to_string(),
        exp: (now + ttl).timestamp(),
        iat: now.timestamp(),
        auth_time: grant.auth_time.timestamp(),
        nonce: grant.nonce.as_ref().map(|n| n.as_str().to_string()),
        name: projected
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        email: projected
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_string),
        email_verified: projected.get("email_verified").and_then(Value::as_bool),
    }
}
