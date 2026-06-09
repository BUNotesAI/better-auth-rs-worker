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

// ===== P1: pure decisions + JWS/token logic =====

use better_auth_core::{
    AuthResult, AuthorizationCode, AuthorizationCodeRecord, JwtSigner, KeyId, Nonce, SecureRandom,
    SigningAlg, State, SubjectId,
};
use chrono::{DateTime, Duration, TimeZone, Utc};

use super::claims::build_id_token_claims;
use super::decide::{
    AuthorizeDecision, TokenGrant, authenticate_client, decide_authorization, decide_token_grant,
};
use super::jws::sign_id_token;
use super::requests::{
    AuthenticatedSubject, AuthorizationRequest, PromptMode, TokenRequest, parse_prompt,
};
use super::token::{
    DEFAULT_ACCESS_TOKEN_TTL_SECONDS, DEFAULT_CODE_TTL_SECONDS, expires_at, generate_access_token,
    hash_access_token, hash_client_secret, is_expired,
};

fn fixed_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap()
}

fn confidential_client() -> OAuthClient {
    OAuthClient {
        client_id: ClientId::parse("conf-app").unwrap(),
        client_type: ClientType::Confidential,
        redirect_uris: vec![RedirectUri::parse("https://app.example/cb").unwrap()],
        allowed_scopes: ScopeSet::parse("openid profile email").unwrap(),
        allowed_grant_types: vec![GrantType::AuthorizationCode],
        secret_hash: Some(hash_client_secret("s3cr3t-value-123")),
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
    }
}

fn authz_request(prompt: PromptMode) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: ClientId::parse("public-app").unwrap(),
        redirect_uri: RedirectUri::parse("https://app.example/cb").unwrap(),
        scope: ScopeSet::parse("openid profile email").unwrap(),
        code_challenge: CodeChallenge::parse(RFC7636_CHALLENGE).unwrap(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: Some(Nonce::new("n-123".to_string())),
        state: Some(State::new("st-abc".to_string())),
        prompt,
    }
}

fn code_record(expires_at: DateTime<Utc>) -> AuthorizationCodeRecord {
    AuthorizationCodeRecord {
        code: AuthorizationCode::from_raw("code-xyz".to_string()),
        client_id: ClientId::parse("public-app").unwrap(),
        subject: SubjectId::parse("user-1").unwrap(),
        redirect_uri: RedirectUri::parse("https://app.example/cb").unwrap(),
        scope: ScopeSet::parse("openid profile email").unwrap(),
        code_challenge: CodeChallenge::parse(RFC7636_CHALLENGE).unwrap(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: Some(Nonce::new("n-123".to_string())),
        auth_time: fixed_now(),
        expires_at,
    }
}

fn token_request(verifier: Option<&str>, secret: Option<&str>) -> TokenRequest {
    TokenRequest {
        client_id: ClientId::parse("public-app").unwrap(),
        code: AuthorizationCode::from_raw("code-xyz".to_string()),
        redirect_uri: RedirectUri::parse("https://app.example/cb").unwrap(),
        code_verifier: verifier.map(|v| CodeVerifier::parse(v).unwrap()),
        client_secret: secret.map(str::to_string),
    }
}

struct FakeSigner {
    kid: KeyId,
    alg: SigningAlg,
    captured: std::sync::Mutex<Option<String>>,
}

#[cfg_attr(feature = "local-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait::async_trait)]
impl JwtSigner for FakeSigner {
    fn active_key(&self) -> AuthResult<(KeyId, SigningAlg)> {
        Ok((self.kid.clone(), self.alg))
    }

    async fn sign(
        &self,
        _kid: &KeyId,
        _alg: SigningAlg,
        signing_input: &[u8],
    ) -> AuthResult<Vec<u8>> {
        *self.captured.lock().unwrap() = Some(String::from_utf8(signing_input.to_vec()).unwrap());
        Ok(vec![0xABu8; 64])
    }
}

struct FakeRandom(u8);

impl SecureRandom for FakeRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
        dest.fill(self.0);
        Ok(())
    }
}

#[test]
fn oidc_authorize_prompt_consent_matrix() {
    let now = fixed_now();
    let ttl = Duration::seconds(DEFAULT_CODE_TTL_SECONDS);
    let sub = AuthenticatedSubject {
        subject: SubjectId::parse("user-1").unwrap(),
        auth_time: now,
    };

    // session + default prompt -> issue code (trusted implicit consent)
    match decide_authorization(&authz_request(PromptMode::Default), Some(&sub), false, now, ttl) {
        AuthorizeDecision::IssueCode(grant) => {
            assert_eq!(grant.subject.as_str(), "user-1");
            assert_eq!(grant.expires_at, now + ttl);
            assert_eq!(grant.state.as_ref().map(State::as_str), Some("st-abc"));
        }
        other => panic!("expected IssueCode, got {other:?}"),
    }

    // session + prompt=none -> issue code
    assert!(matches!(
        decide_authorization(&authz_request(PromptMode::None), Some(&sub), false, now, ttl),
        AuthorizeDecision::IssueCode(_)
    ));

    // session + prompt=login + host hook -> re-authenticate
    assert!(matches!(
        decide_authorization(&authz_request(PromptMode::Login), Some(&sub), true, now, ttl),
        AuthorizeDecision::RequireLogin
    ));

    // session + prompt=login + no hook -> login_required, state echoed
    match decide_authorization(&authz_request(PromptMode::Login), Some(&sub), false, now, ttl) {
        AuthorizeDecision::Deny { error, state, .. } => {
            assert_eq!(error.code(), &OAuthErrorCode::LoginRequired);
            assert_eq!(state.as_ref().map(State::as_str), Some("st-abc"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }

    // raw prompt parsing: known values map; an unsupported value is invalid_request
    assert_eq!(parse_prompt(None).unwrap(), PromptMode::Default);
    assert_eq!(parse_prompt(Some("none")).unwrap(), PromptMode::None);
    assert_eq!(parse_prompt(Some("login")).unwrap(), PromptMode::Login);
    assert_eq!(
        parse_prompt(Some("consent")).unwrap_err().code(),
        &OAuthErrorCode::InvalidRequest
    );
}

#[test]
fn oidc_unauthenticated_authorize_contract() {
    let now = fixed_now();
    let ttl = Duration::seconds(DEFAULT_CODE_TTL_SECONDS);

    // no session + default + hook -> delegate to host login UI
    assert!(matches!(
        decide_authorization(&authz_request(PromptMode::Default), None, true, now, ttl),
        AuthorizeDecision::RequireLogin
    ));

    // no session + default + no hook -> login_required via validated redirect, state echoed
    match decide_authorization(&authz_request(PromptMode::Default), None, false, now, ttl) {
        AuthorizeDecision::Deny {
            error,
            redirect_uri,
            state,
        } => {
            assert_eq!(error.code(), &OAuthErrorCode::LoginRequired);
            assert_eq!(redirect_uri.as_str(), "https://app.example/cb");
            assert_eq!(state.as_ref().map(State::as_str), Some("st-abc"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }

    // no session + prompt=none -> login_required (cannot interact), even with a hook
    match decide_authorization(&authz_request(PromptMode::None), None, true, now, ttl) {
        AuthorizeDecision::Deny { error, .. } => {
            assert_eq!(error.code(), &OAuthErrorCode::LoginRequired);
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn oidc_token_exchange_failure_ordering() {
    let now = fixed_now();
    let future = now + Duration::seconds(60);
    let conf = confidential_client();
    let public = public_client();

    // step 1 client auth: confidential wrong/missing secret -> invalid_client
    assert_eq!(
        authenticate_client(&conf, Some("wrong")).unwrap_err().code(),
        &OAuthErrorCode::InvalidClient
    );
    assert_eq!(
        authenticate_client(&conf, None).unwrap_err().code(),
        &OAuthErrorCode::InvalidClient
    );
    assert!(authenticate_client(&conf, Some("s3cr3t-value-123")).is_ok());
    // public client: no secret ok; secret present -> invalid_client
    assert!(authenticate_client(&public, None).is_ok());
    assert_eq!(
        authenticate_client(&public, Some("x")).unwrap_err().code(),
        &OAuthErrorCode::InvalidClient
    );

    let req = token_request(Some(RFC7636_VERIFIER), None);

    // step 2 missing code -> invalid_grant
    assert_eq!(
        decide_token_grant(&req, &public, None, now).unwrap_err().code(),
        &OAuthErrorCode::InvalidGrant
    );

    // step 2b code issued to a different client -> invalid_grant (ordered before
    // redirect/PKCE; protects the grant->client binding)
    let mut wrong_client = code_record(future);
    wrong_client.client_id = ClientId::parse("a-different-client").unwrap();
    assert_eq!(
        decide_token_grant(&req, &public, Some(&wrong_client), now)
            .unwrap_err()
            .code(),
        &OAuthErrorCode::InvalidGrant
    );

    // step 3 redirect mismatch -> invalid_grant (before PKCE)
    let mut wrong_redirect = code_record(future);
    wrong_redirect.redirect_uri = RedirectUri::parse("https://app.example/other").unwrap();
    assert_eq!(
        decide_token_grant(&req, &public, Some(&wrong_redirect), now)
            .unwrap_err()
            .code(),
        &OAuthErrorCode::InvalidGrant
    );

    // step 4 PKCE mismatch -> invalid_grant
    let bad = token_request(Some(&"b".repeat(50)), None);
    assert_eq!(
        decide_token_grant(&bad, &public, Some(&code_record(future)), now)
            .unwrap_err()
            .code(),
        &OAuthErrorCode::InvalidGrant
    );

    // all checks pass -> a token grant
    let grant = decide_token_grant(&req, &public, Some(&code_record(future)), now).unwrap();
    assert_eq!(grant.subject.as_str(), "user-1");
    assert!(grant.scope.contains(Scope::OPENID));
}

#[test]
fn oidc_id_token_claims_contract() {
    let now = fixed_now();
    let ttl = Duration::seconds(DEFAULT_ACCESS_TOKEN_TTL_SECONDS);
    let issuer = Issuer::parse("https://idp.example").unwrap();
    let client_id = ClientId::parse("rp-1").unwrap();
    let grant = TokenGrant {
        client_id: client_id.clone(),
        subject: SubjectId::parse("user-42").unwrap(),
        scope: ScopeSet::parse("openid profile email").unwrap(),
        nonce: Some(Nonce::new("nonce-xyz".to_string())),
        auth_time: now - Duration::seconds(30),
    };
    let source = SubjectClaims {
        name: Some("Grace".to_string()),
        email: Some("g@example.com".to_string()),
        email_verified: Some(true),
    };

    let claims = build_id_token_claims(&issuer, &grant, &source, now, ttl);
    assert_eq!(claims.iss, "https://idp.example");
    assert_eq!(claims.sub, "user-42");
    assert_eq!(claims.aud, "rp-1");
    assert_eq!(claims.iat, now.timestamp());
    assert_eq!(claims.exp, (now + ttl).timestamp());
    assert_eq!(claims.auth_time, (now - Duration::seconds(30)).timestamp());
    assert_eq!(claims.nonce.as_deref(), Some("nonce-xyz"));
    assert_eq!(claims.name.as_deref(), Some("Grace"));
    assert_eq!(claims.email.as_deref(), Some("g@example.com"));
    assert_eq!(claims.email_verified, Some(true));

    // openid-only -> profile/email claims omitted
    let minimal = TokenGrant {
        scope: ScopeSet::parse("openid").unwrap(),
        ..grant.clone()
    };
    let claims = build_id_token_claims(&issuer, &minimal, &source, now, ttl);
    assert!(claims.name.is_none());
    assert!(claims.email.is_none());
}

#[tokio::test]
async fn oidc_jws_assembly_owns_serialization() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let payload = br#"{"sub":"user-1","iss":"https://idp.example"}"#;
    let signer = FakeSigner {
        kid: KeyId::new("key-1"),
        alg: SigningAlg::Es256,
        captured: std::sync::Mutex::new(None),
    };

    let jws = sign_id_token(payload, &signer).await.unwrap();

    // the signer only ever saw the encoded signing_input = header "." payload
    let signing_input = signer
        .captured
        .lock()
        .unwrap()
        .clone()
        .expect("signer was called");
    let parts: Vec<&str> = signing_input.split('.').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(URL_SAFE_NO_PAD.decode(parts[1]).unwrap(), payload);
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header.get("alg").and_then(Value::as_str), Some("ES256"));
    assert_eq!(header.get("kid").and_then(Value::as_str), Some("key-1"));
    assert_eq!(header.get("typ").and_then(Value::as_str), Some("JWT"));

    // the core assembled the compact JWS = signing_input "." base64url(signature)
    let expected_sig = URL_SAFE_NO_PAD.encode([0xABu8; 64]);
    assert_eq!(jws, format!("{signing_input}.{expected_sig}"));
    // `alg: none` is unrepresentable — SigningAlg has only Es256/Rs256.
}

#[test]
fn oidc_access_token_entropy_and_hash_at_rest() {
    let (token_a, hash_a) = generate_access_token(&FakeRandom(7)).unwrap();
    let (token_b, _hash_b) = generate_access_token(&FakeRandom(9)).unwrap();

    // the token is produced from SecureRandom: different entropy -> different token
    assert_ne!(token_a.as_str(), token_b.as_str());
    // the stored value is a hash, never the raw token
    assert_ne!(token_a.as_str(), hash_a.as_str());
    // the stored hash equals the hash of the issued token (userinfo lookup path)
    assert_eq!(hash_access_token(&token_a).as_str(), hash_a.as_str());
}

#[test]
fn oidc_token_and_code_ttls() {
    let now = fixed_now();

    assert_eq!(DEFAULT_CODE_TTL_SECONDS, 60);
    assert_eq!(DEFAULT_ACCESS_TOKEN_TTL_SECONDS, 600);

    // expiry computed from the injected clock
    assert_eq!(
        expires_at(now, Duration::seconds(60)),
        now + Duration::seconds(60)
    );
    assert!(is_expired(now, now - Duration::seconds(1)));
    assert!(!is_expired(now, now + Duration::seconds(1)));

    // an expired authorization code fails token exchange with invalid_grant,
    // expiry decided by the injected clock rather than database NOW()
    let expired = code_record(now - Duration::seconds(1));
    let req = token_request(Some(RFC7636_VERIFIER), None);
    assert_eq!(
        decide_token_grant(&req, &public_client(), Some(&expired), now)
            .unwrap_err()
            .code(),
        &OAuthErrorCode::InvalidGrant
    );
}
