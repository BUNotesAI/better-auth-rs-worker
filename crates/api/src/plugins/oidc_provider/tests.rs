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

// ===== P3: endpoint contracts over the memory adapter =====

#[cfg(test)]
mod endpoints_p3 {
    use std::sync::Arc;

    use chrono::{DateTime, Duration, Utc};
    use serde_json::Value;

    use better_auth_core::adapters::{MemoryDatabaseAdapter, UserOps};
    use better_auth_core::entity::AuthUser;
    use better_auth_core::{
        AccessToken, AccessTokenOps, AuthConfig, AuthContext, AuthPlugin, AuthRequest, AuthResponse,
        AuthResult, AuthorizationCode, AuthorizationCodeOps, ClientId, Clock, CodeChallenge,
        CodeChallengeMethod, CreateUser, HttpMethod, Issuer, JwkSet, JwksProvider, KeyId,
        NewAccessToken, NewAuthorizationCode, RedirectUri, ScopeSet, SigningAlg, SubjectId,
    };

    use super::super::token::hash_access_token;
    use super::super::{OidcProviderConfig, OidcProviderPlugin};
    use super::{
        FakeRandom, FakeSigner, RFC7636_CHALLENGE, RFC7636_VERIFIER, confidential_client, fixed_now,
        public_client,
    };

    /// Deterministic clock so issued/consumed expiries are stable across a test.
    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// Minimal JWKS port: the route contract only checks the endpoint serializes
    /// the provider's set; the real verification smoke is a P4 concern.
    struct FakeJwks;
    impl JwksProvider for FakeJwks {
        fn jwks(&self) -> AuthResult<JwkSet> {
            Ok(JwkSet::default())
        }
    }

    fn issuer() -> Issuer {
        Issuer::parse("https://issuer.example").unwrap()
    }

    fn plugin() -> OidcProviderPlugin {
        OidcProviderPlugin::new(OidcProviderConfig::new(issuer()))
    }

    /// Builds a context whose runtime ports are the deterministic test fakes.
    fn context_at(now: DateTime<Utc>) -> AuthContext<MemoryDatabaseAdapter> {
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        config.runtime.clock = Arc::new(FixedClock(now));
        config.runtime.secure_random = Arc::new(FakeRandom(0x11));
        config.runtime.jwt_signer = Arc::new(FakeSigner {
            kid: KeyId::new("key-1"),
            alg: SigningAlg::Es256,
            captured: std::sync::Mutex::new(None),
        });
        config.runtime.jwks_provider = Arc::new(FakeJwks);
        AuthContext::new(Arc::new(config), Arc::new(MemoryDatabaseAdapter::new()))
    }

    async fn seed_user(ctx: &AuthContext<MemoryDatabaseAdapter>) -> String {
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email("alice@example.com")
                    .with_name("Alice")
                    .with_email_verified(true),
            )
            .await
            .unwrap();
        user.id().to_string()
    }

    fn body_json(resp: &AuthResponse) -> Value {
        serde_json::from_slice(&resp.body).unwrap()
    }

    fn location_param(resp: &AuthResponse, key: &str) -> Option<String> {
        let location = resp.headers.get("Location")?;
        let (_, query) = location.split_once('?')?;
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }

    fn form_request(path: &str, pairs: &[(&str, &str)]) -> AuthRequest {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            serializer.append_pair(key, value);
        }
        let mut req = AuthRequest::new(HttpMethod::Post, path);
        req.body = Some(serializer.finish().into_bytes());
        req.headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        req
    }

    fn authorize_request(session_token: &str) -> AuthRequest {
        let mut req = AuthRequest::new(HttpMethod::Get, "/oauth2/authorize");
        req.headers
            .insert("authorization".to_string(), format!("Bearer {session_token}"));
        let params = [
            ("response_type", "code"),
            ("client_id", "public-app"),
            ("redirect_uri", "https://app.example/cb"),
            ("scope", "openid profile email"),
            ("code_challenge", RFC7636_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "st-xyz"),
            ("nonce", "n-1"),
        ];
        req.query = params
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        req
    }

    #[tokio::test]
    async fn oidc_discovery_document_contract() {
        let ctx = context_at(fixed_now());
        let req = AuthRequest::new(HttpMethod::Get, "/.well-known/openid-configuration");

        let resp = plugin().on_request(&req, &ctx).await.unwrap().unwrap();

        assert_eq!(resp.status, 200);
        let doc = body_json(&resp);
        assert_eq!(doc["issuer"], "https://issuer.example");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://issuer.example/oauth2/authorize"
        );
        assert_eq!(doc["token_endpoint"], "https://issuer.example/oauth2/token");
        assert_eq!(
            doc["userinfo_endpoint"],
            "https://issuer.example/oauth2/userinfo"
        );
        assert_eq!(doc["jwks_uri"], "https://issuer.example/oauth2/jwks");
        assert_eq!(doc["response_types_supported"][0], "code");
        assert_eq!(doc["grant_types_supported"][0], "authorization_code");
        assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    }

    #[tokio::test]
    async fn oidc_jwks_route_serves_provider_set() {
        let ctx = context_at(fixed_now());
        let req = AuthRequest::new(HttpMethod::Get, "/oauth2/jwks");

        let resp = plugin().on_request(&req, &ctx).await.unwrap().unwrap();

        assert_eq!(resp.status, 200);
        assert!(body_json(&resp).get("keys").is_some());
    }

    #[tokio::test]
    async fn oidc_authorization_code_flow_happy_path() {
        let now = fixed_now();
        let ctx = context_at(now);
        ctx.database.seed_oauth_client(public_client());
        let user_id = seed_user(&ctx).await;
        let session = ctx
            .session_manager()
            .create_session(
                &ctx.database.get_user_by_id(&user_id).await.unwrap().unwrap(),
                None,
                None,
            )
            .await
            .unwrap();

        // authorize -> 302 redirect carrying code + echoed state
        let authorize = plugin()
            .on_request(&authorize_request(&session.token), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authorize.status, 302);
        assert_eq!(location_param(&authorize, "state").as_deref(), Some("st-xyz"));
        let code = location_param(&authorize, "code").expect("authorize must return a code");

        // token -> 200 with a signed id_token + opaque access token
        let token = plugin()
            .on_request(
                &form_request(
                    "/oauth2/token",
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", &code),
                        ("redirect_uri", "https://app.example/cb"),
                        ("client_id", "public-app"),
                        ("code_verifier", RFC7636_VERIFIER),
                    ],
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.status, 200);
        let token_body = body_json(&token);
        assert_eq!(token_body["token_type"], "Bearer");
        assert_eq!(
            token_body["id_token"]
                .as_str()
                .unwrap()
                .split('.')
                .count(),
            3,
            "id_token must be a compact JWS with 3 segments"
        );
        let access_token = token_body["access_token"].as_str().unwrap().to_string();

        // userinfo -> 200 with the granted claims bound to the subject
        let userinfo = plugin()
            .on_request(&bearer_get("/oauth2/userinfo", &access_token), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(userinfo.status, 200);
        let claims = body_json(&userinfo);
        assert_eq!(claims["sub"], user_id);
        assert_eq!(claims["email"], "alice@example.com");
        assert_eq!(claims["name"], "Alice");
    }

    fn bearer_get(path: &str, token: &str) -> AuthRequest {
        let mut req = AuthRequest::new(HttpMethod::Get, path);
        req.headers
            .insert("authorization".to_string(), format!("Bearer {token}"));
        req
    }

    async fn seed_code(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        code: &str,
        client_id: &str,
        now: DateTime<Utc>,
    ) {
        ctx.database
            .create_authorization_code(NewAuthorizationCode {
                code: AuthorizationCode::from_raw(code.to_string()),
                client_id: ClientId::parse(client_id).unwrap(),
                subject: SubjectId::parse("user-1").unwrap(),
                redirect_uri: RedirectUri::parse("https://app.example/cb").unwrap(),
                scope: ScopeSet::parse("openid profile email").unwrap(),
                code_challenge: CodeChallenge::parse(RFC7636_CHALLENGE).unwrap(),
                code_challenge_method: CodeChallengeMethod::S256,
                nonce: None,
                auth_time: now,
                expires_at: now + Duration::seconds(300),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oidc_authorization_code_single_use() {
        let now = fixed_now();
        let ctx = context_at(now);
        ctx.database.seed_oauth_client(public_client());
        seed_code(&ctx, "seed-code-1", "public-app", now).await;

        // owned request per call; the plugin is stateless
        let token_form = || {
            form_request(
                "/oauth2/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", "seed-code-1"),
                    ("redirect_uri", "https://app.example/cb"),
                    ("client_id", "public-app"),
                    ("code_verifier", RFC7636_VERIFIER),
                ],
            )
        };

        let first = plugin().on_request(&token_form(), &ctx).await.unwrap().unwrap();
        assert_eq!(first.status, 200);

        // second redemption of the same code is rejected (atomic single-use)
        let second = plugin().on_request(&token_form(), &ctx).await.unwrap().unwrap();
        assert_eq!(second.status, 400);
        assert_eq!(body_json(&second)["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn oidc_client_auth_public_vs_confidential() {
        let now = fixed_now();
        let ctx = context_at(now);
        ctx.database.seed_oauth_client(confidential_client());
        seed_code(&ctx, "conf-code", "conf-app", now).await;

        // confidential client with a missing secret: invalid_client, BEFORE consume
        let no_secret = plugin()
            .on_request(
                &form_request(
                    "/oauth2/token",
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", "conf-code"),
                        ("redirect_uri", "https://app.example/cb"),
                        ("client_id", "conf-app"),
                        ("code_verifier", RFC7636_VERIFIER),
                    ],
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(no_secret.status, 401);
        assert_eq!(body_json(&no_secret)["error"], "invalid_client");

        // the code must NOT have been consumed by the failed client auth: a
        // subsequent correct exchange still succeeds.
        let with_secret = plugin()
            .on_request(
                &form_request(
                    "/oauth2/token",
                    &[
                        ("grant_type", "authorization_code"),
                        ("code", "conf-code"),
                        ("redirect_uri", "https://app.example/cb"),
                        ("client_id", "conf-app"),
                        ("client_secret", "s3cr3t-value-123"),
                        ("code_verifier", RFC7636_VERIFIER),
                    ],
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(with_secret.status, 200, "code must survive a failed client auth");
    }

    #[tokio::test]
    async fn oidc_userinfo_bearer_claims_and_invalid_token() {
        let now = fixed_now();
        let ctx = context_at(now);
        let user_id = seed_user(&ctx).await;
        ctx.database
            .create_access_token(NewAccessToken {
                token_hash: hash_access_token(&AccessToken::from_raw("good-token".to_string())),
                client_id: ClientId::parse("public-app").unwrap(),
                subject: SubjectId::parse(&user_id).unwrap(),
                scope: ScopeSet::parse("openid profile email").unwrap(),
                expires_at: now + Duration::seconds(600),
                created_at: now,
            })
            .await
            .unwrap();

        // valid bearer token -> granted claims
        let ok = plugin()
            .on_request(&bearer_get("/oauth2/userinfo", "good-token"), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(body_json(&ok)["sub"], user_id);
        assert_eq!(body_json(&ok)["email"], "alice@example.com");

        // unknown token -> 401 invalid_token with a bearer challenge
        let bad = plugin()
            .on_request(&bearer_get("/oauth2/userinfo", "nope"), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bad.status, 401);
        assert_eq!(body_json(&bad)["error"], "invalid_token");
        assert!(bad.headers.contains_key("WWW-Authenticate"));

        // missing Authorization header -> 401 invalid_token
        let missing = plugin()
            .on_request(&AuthRequest::new(HttpMethod::Get, "/oauth2/userinfo"), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(missing.status, 401);
        assert_eq!(body_json(&missing)["error"], "invalid_token");
    }

    #[tokio::test]
    async fn oidc_authorize_rejects_scope_outside_client_registration() {
        let now = fixed_now();
        let ctx = context_at(now);
        // the client is registered for `openid` only
        let mut client = public_client();
        client.allowed_scopes = ScopeSet::parse("openid").unwrap();
        ctx.database.seed_oauth_client(client);
        let user_id = seed_user(&ctx).await;
        let session = ctx
            .session_manager()
            .create_session(
                &ctx.database.get_user_by_id(&user_id).await.unwrap().unwrap(),
                None,
                None,
            )
            .await
            .unwrap();

        // requesting `email` (not registered) must NOT issue a code; it is
        // returned as invalid_scope via the validated redirect URI.
        let mut req = authorize_request(&session.token);
        req.query
            .insert("scope".to_string(), "openid email".to_string());
        let resp = plugin().on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 302);
        assert_eq!(location_param(&resp, "error").as_deref(), Some("invalid_scope"));
        assert_eq!(location_param(&resp, "state").as_deref(), Some("st-xyz"));
        assert!(
            location_param(&resp, "code").is_none(),
            "no authorization code may be issued for an unregistered scope"
        );
    }

    #[tokio::test]
    async fn oidc_provider_isolated_from_social_oauth_client() {
        let plugin = plugin();
        // the provider owns only its own routes; none overlap the social-login
        // client plugin's `/oauth/**` or `/callback/**` surface.
        let routes: Vec<String> = AuthPlugin::<MemoryDatabaseAdapter>::routes(&plugin)
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert!(routes.iter().all(|p| p.starts_with("/oauth2/") || p.starts_with("/.well-known/")));
        assert!(!routes.iter().any(|p| p.starts_with("/callback")));
        assert_eq!(AuthPlugin::<MemoryDatabaseAdapter>::name(&plugin), "oidc-provider");

        // a social-login callback path is not handled by the provider.
        let ctx = context_at(fixed_now());
        let passthrough = plugin
            .on_request(
                &AuthRequest::new(HttpMethod::Get, "/callback/google"),
                &ctx,
            )
            .await
            .unwrap();
        assert!(passthrough.is_none());
    }
}
