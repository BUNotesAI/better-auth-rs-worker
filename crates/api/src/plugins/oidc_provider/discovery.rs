//! Pure OIDC discovery document assembly (RFC 8414 / OpenID Discovery).
//!
//! This is a pure projection from the issuer and endpoint layout to the
//! advertised metadata. The P0 phase covers the pure assembly only; the
//! `/.well-known/openid-configuration` route contract is closed in a later phase
//! when the plugin exposes the endpoint.

use better_auth_core::Issuer;
use serde::Serialize;

/// Endpoint path suffixes (relative to the issuer base) for the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoints {
    pub authorization: String,
    pub token: String,
    pub userinfo: String,
    pub jwks: String,
}

/// The advertised OIDC provider metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// Assembles the discovery document for the issuer and endpoint layout.
#[must_use]
pub fn build_discovery_document(
    issuer: &Issuer,
    endpoints: &ProviderEndpoints,
) -> DiscoveryDocument {
    let base = issuer.as_str();
    let endpoint = |suffix: &str| format!("{base}{suffix}");
    DiscoveryDocument {
        issuer: base.to_string(),
        authorization_endpoint: endpoint(&endpoints.authorization),
        token_endpoint: endpoint(&endpoints.token),
        userinfo_endpoint: endpoint(&endpoints.userinfo),
        jwks_uri: endpoint(&endpoints.jwks),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        id_token_signing_alg_values_supported: vec!["ES256".to_string(), "RS256".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
    }
}
