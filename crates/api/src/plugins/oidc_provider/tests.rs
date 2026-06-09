//! P0 pure unit/contract tests for the OIDC provider domain rules.
//!
//! Test names match the spec scenario filters. PKCE uses the RFC 7636 Appendix B
//! reference vector so the test never recomputes the production hash.

use better_auth_core::{
    ClientId, ClientType, CodeChallenge, CodeChallengeMethod, CodeVerifier, GrantType, Issuer,
    OAuthClient, RedirectUri, ResponseType, Scope, ScopeSet, TokenEndpointAuthMethod,
};
use serde_json::Value;

use super::claims::{SubjectClaims, project_claims};
use super::discovery::{ProviderEndpoints, build_discovery_document};
use super::error::{OAuthError, OAuthErrorCode};
use super::rules::{
    parse_requested_scopes, parse_response_type, require_pkce_at_authorize, validate_redirect_uri,
    verify_pkce,
};

/// RFC 7636 Appendix B reference PKCE pair.
const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC7636_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn public_client() -> OAuthClient {
    OAuthClient {
        client_id: ClientId::parse("public-app").unwrap(),
        client_type: ClientType::Public,
        redirect_uris: vec![RedirectUri::parse("https://app.example/cb").unwrap()],
        allowed_scopes: ScopeSet::parse("openid profile email").unwrap(),
        allowed_grant_types: vec![GrantType::AuthorizationCode],
        secret_hash: None,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
    }
}

#[test]
fn oidc_pkce_s256_required_and_verified() {
    let challenge = CodeChallenge::parse(RFC7636_CHALLENGE).unwrap();
    let verifier = CodeVerifier::parse(RFC7636_VERIFIER).unwrap();

    // A verifier whose S256 matches the stored challenge succeeds.
    assert!(verify_pkce(&challenge, CodeChallengeMethod::S256, &verifier).is_ok());

    // A mismatched verifier fails with invalid_grant.
    let wrong = CodeVerifier::parse("a".repeat(50)).unwrap();
    let err = verify_pkce(&challenge, CodeChallengeMethod::S256, &wrong).unwrap_err();
    assert_eq!(err.code(), &OAuthErrorCode::InvalidGrant);

    // The `plain` challenge method is rejected (only S256 is representable).
    assert!(CodeChallengeMethod::parse("plain").is_err());

    // A public client without PKCE at authorize fails with invalid_request.
    let err = require_pkce_at_authorize(&public_client(), None).unwrap_err();
    assert_eq!(err.code(), &OAuthErrorCode::InvalidRequest);

    // A public client with a PKCE challenge at authorize is accepted.
    let challenge = CodeChallenge::parse(RFC7636_CHALLENGE).unwrap();
    assert!(require_pkce_at_authorize(&public_client(), Some(&challenge)).is_ok());
}

#[test]
fn oidc_redirect_uri_exact_match_no_open_redirect() {
    let client = public_client();

    // Exact registered match is accepted.
    let matched = validate_redirect_uri(&client, "https://app.example/cb").unwrap();
    assert_eq!(matched.as_str(), "https://app.example/cb");

    // A different host is rejected with a direct error (no redirect to it).
    let err = validate_redirect_uri(&client, "https://evil.example/cb").unwrap_err();
    assert_eq!(err.code(), &OAuthErrorCode::InvalidRequest);

    // A near-miss on the path is also rejected.
    let err = validate_redirect_uri(&client, "https://app.example/cb/extra").unwrap_err();
    assert_eq!(err.code(), &OAuthErrorCode::InvalidRequest);
}

#[test]
fn oidc_scope_openid_required_and_claims_mapping() {
    // A scope set without openid is rejected.
    assert!(parse_requested_scopes("profile email").is_err());

    // openid present is accepted.
    let scopes = parse_requested_scopes("openid profile email").unwrap();
    assert!(scopes.contains(Scope::OPENID));

    let source = SubjectClaims {
        name: Some("Ada Lovelace".to_string()),
        email: Some("ada@example.com".to_string()),
        email_verified: Some(true),
    };

    // profile + email granted -> standard claims exposed.
    let claims = project_claims(&scopes, &source);
    assert_eq!(claims.get("name").and_then(Value::as_str), Some("Ada Lovelace"));
    assert_eq!(
        claims.get("email").and_then(Value::as_str),
        Some("ada@example.com")
    );
    assert_eq!(
        claims.get("email_verified").and_then(Value::as_bool),
        Some(true)
    );

    // openid only -> profile/email claims omitted.
    let minimal = ScopeSet::parse("openid").unwrap();
    let claims = project_claims(&minimal, &source);
    assert!(claims.get("name").is_none());
    assert!(claims.get("email").is_none());
    assert!(claims.get("email_verified").is_none());
}

#[test]
fn oidc_response_type_code_only() {
    assert_eq!(parse_response_type("code").unwrap(), ResponseType::Code);

    let err = parse_response_type("token").unwrap_err();
    assert_eq!(err.code(), &OAuthErrorCode::UnsupportedResponseType);

    let err = parse_response_type("id_token").unwrap_err();
    assert_eq!(err.code(), &OAuthErrorCode::UnsupportedResponseType);
}

#[test]
fn discovery_document_pure_assembly_advertises_standard_metadata() {
    let issuer = Issuer::parse("https://idp.example").unwrap();
    let endpoints = ProviderEndpoints {
        authorization: "/oauth2/authorize".to_string(),
        token: "/oauth2/token".to_string(),
        userinfo: "/oauth2/userinfo".to_string(),
        jwks: "/oauth2/jwks".to_string(),
    };

    let doc = build_discovery_document(&issuer, &endpoints);

    assert_eq!(doc.issuer, "https://idp.example");
    assert_eq!(
        doc.authorization_endpoint,
        "https://idp.example/oauth2/authorize"
    );
    assert_eq!(doc.jwks_uri, "https://idp.example/oauth2/jwks");
    assert_eq!(doc.response_types_supported, vec!["code".to_string()]);
    assert_eq!(doc.code_challenge_methods_supported, vec!["S256".to_string()]);
    assert!(
        doc.id_token_signing_alg_values_supported
            .contains(&"ES256".to_string())
    );
    assert!(doc.scopes_supported.contains(&"openid".to_string()));
}

#[test]
fn oauth_error_maps_to_standard_response_shape() {
    let invalid_token = OAuthError::invalid_token("token expired");
    assert_eq!(invalid_token.code_str(), "invalid_token");
    assert_eq!(invalid_token.http_status(), 401);
    let body = invalid_token.to_body();
    assert_eq!(body.get("error").and_then(Value::as_str), Some("invalid_token"));
    assert_eq!(
        body.get("error_description").and_then(Value::as_str),
        Some("token expired")
    );
    assert!(invalid_token.www_authenticate().is_some());

    let invalid_grant = OAuthError::invalid_grant("code already used");
    assert_eq!(invalid_grant.http_status(), 400);
    assert!(invalid_grant.www_authenticate().is_none());
}
