//! Pure projection from granted scopes to standard OIDC claims.
//!
//! The host populates [`SubjectClaims`] from the authenticated better-auth user;
//! this function decides which claims the granted scopes expose. It performs no
//! I/O and never reads claims for scopes that were not granted.

use better_auth_core::{Scope, ScopeSet};
use serde_json::{Map, Value};

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
