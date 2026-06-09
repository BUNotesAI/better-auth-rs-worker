//! Pure OAuth2 / OIDC protocol rules.
//!
//! Each rule is a pure function over typed value objects and returns a typed
//! [`OAuthError`] on failure. No time, randomness, I/O, or database access.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use better_auth_core::{
    ClientType, CodeChallenge, CodeChallengeMethod, CodeVerifier, OAuthClient, RedirectUri,
    ResponseType, ScopeSet,
};

use super::error::OAuthError;

/// Verifies a PKCE `code_verifier` against the stored S256 `code_challenge`.
///
/// `plain` is rejected earlier by [`CodeChallengeMethod::parse`], so only `S256`
/// reaches here. A mismatched verifier fails with `invalid_grant`.
pub fn verify_pkce(
    challenge: &CodeChallenge,
    method: CodeChallengeMethod,
    verifier: &CodeVerifier,
) -> Result<(), OAuthError> {
    match method {
        CodeChallengeMethod::S256 => {
            if s256_code_challenge(verifier.as_str()) == challenge.as_str() {
                Ok(())
            } else {
                Err(OAuthError::invalid_grant("PKCE verification failed"))
            }
        }
    }
}

/// Computes `base64url(SHA-256(verifier))`, the S256 PKCE challenge transform.
fn s256_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Validates the requested redirect URI by exact match against the client's
/// registered set. Never redirects on failure (open-redirect guard).
pub fn validate_redirect_uri(
    client: &OAuthClient,
    requested: &str,
) -> Result<RedirectUri, OAuthError> {
    client
        .redirect_uris
        .iter()
        .find(|uri| uri.as_str() == requested)
        .cloned()
        .ok_or_else(|| {
            OAuthError::invalid_request("redirect_uri does not exactly match a registered URI")
        })
}

/// Parses the `response_type`, rejecting anything other than `code`.
pub fn parse_response_type(raw: &str) -> Result<ResponseType, OAuthError> {
    ResponseType::parse(raw)
        .map_err(|_| OAuthError::unsupported_response_type("only response_type=code is supported"))
}

/// Parses the requested scope string, enforcing the `openid` requirement.
pub fn parse_requested_scopes(raw: &str) -> Result<ScopeSet, OAuthError> {
    ScopeSet::parse(raw).map_err(|_| OAuthError::invalid_scope("the openid scope is required"))
}

/// Enforces that every requested scope is registered for the client.
///
/// A registered client may only request scopes within its `allowed_scopes`;
/// requesting any other scope is `invalid_scope`. This stops a client from
/// escalating beyond its registered scope set (and thus from obtaining
/// claims it was never granted).
pub fn validate_allowed_scopes(
    client: &OAuthClient,
    requested: &ScopeSet,
) -> Result<(), OAuthError> {
    for scope in requested.iter() {
        if !client.allowed_scopes.contains(scope.as_str()) {
            return Err(OAuthError::invalid_scope(format!(
                "scope is not allowed for this client: {}",
                scope.as_str()
            )));
        }
    }
    Ok(())
}

/// Enforces that public clients present a PKCE challenge at the authorize step.
pub fn require_pkce_at_authorize(
    client: &OAuthClient,
    code_challenge: Option<&CodeChallenge>,
) -> Result<(), OAuthError> {
    match client.client_type {
        ClientType::Public if code_challenge.is_none() => {
            Err(OAuthError::invalid_request("public clients must use PKCE"))
        }
        _ => Ok(()),
    }
}
