use async_trait::async_trait;
use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps, VerificationOps};
use better_auth_core::types::{CreateSession, CreateUser, Session};
use better_auth_core::{
    AuthError, AuthPlugin, AuthRequest, AuthResult, AuthRuntimeCapabilities, Clock,
    CreateVerification, HttpMethod, IdGenerator, IdKind, OAuthHttpClient, OAuthHttpRequest,
    OAuthHttpResponse, SecureRandom, SessionTokenGenerator,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::handlers::{link_social_core, social_sign_in_core};
use super::providers::{OAuthConfig, OAuthProvider};
use super::types::{LinkSocialRequest, SocialSignInRequest};
use crate::plugins::test_helpers;

#[derive(Debug)]
struct FixedClock(DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Debug)]
struct FixedRandom;

impl SecureRandom for FixedRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
        for (idx, byte) in dest.iter_mut().enumerate() {
            *byte = b'a' + (idx % 26) as u8;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SequencedIds {
    values: Mutex<Vec<String>>,
}

impl SequencedIds {
    fn new(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            values: Mutex::new(values.into_iter().map(Into::into).collect()),
        }
    }
}

impl IdGenerator for SequencedIds {
    fn generate_id(&self, _kind: IdKind) -> AuthResult<String> {
        let mut values = self.values.lock().unwrap();
        if values.is_empty() {
            return Err(AuthError::internal("test id sequence exhausted"));
        }
        Ok(values.remove(0))
    }
}

#[derive(Debug)]
struct FixedSessionTokens;

impl SessionTokenGenerator for FixedSessionTokens {
    fn generate_session_token(&self) -> AuthResult<String> {
        Ok("session_oauth_runtime".to_string())
    }
}

#[derive(Debug, Default)]
struct RecordingOAuthHttp {
    requests: Mutex<Vec<OAuthHttpRequest>>,
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl OAuthHttpClient for RecordingOAuthHttp {
    async fn send(&self, request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
        self.requests.lock().unwrap().push(request.clone());

        if request.url == "https://provider.test/token" {
            assert_eq!(request.method, HttpMethod::Post);
            assert_eq!(
                request.headers.get("Accept").map(String::as_str),
                Some("application/json")
            );
            assert_eq!(
                request.headers.get("Content-Type").map(String::as_str),
                Some("application/x-www-form-urlencoded")
            );

            let body = String::from_utf8(request.body)
                .expect("token request body should be utf-8 form data");
            assert!(body.contains("grant_type=authorization_code"));
            assert!(body.contains("code=callback-code"));
            assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.test%2Fcallback%2Fgoogle"));
            assert!(body.contains("client_id=test-client-id"));
            assert!(body.contains("client_secret=test-client-secret"));
            assert!(body.contains("code_verifier=verifier-from-state"));

            return Ok(OAuthHttpResponse::new(
                200,
                r#"{"access_token":"access-from-port","refresh_token":"refresh-from-port","expires_in":3600,"scope":"openid email"}"#,
            ));
        }

        if request.url == "https://provider.test/userinfo" {
            assert_eq!(request.method, HttpMethod::Get);
            assert_eq!(
                request.headers.get("Accept").map(String::as_str),
                Some("application/json")
            );
            assert_eq!(
                request.headers.get("Authorization").map(String::as_str),
                Some("Bearer access-from-port")
            );

            return Ok(OAuthHttpResponse::new(
                200,
                r#"{"sub":"provider-user-1","email":"oauth@test.com","name":"OAuth User","email_verified":true}"#,
            ));
        }

        Err(AuthError::internal(format!(
            "unexpected OAuth HTTP request to {}",
            request.url
        )))
    }
}

fn runtime_with_oauth_http(
    now: DateTime<Utc>,
    http: Arc<RecordingOAuthHttp>,
) -> AuthRuntimeCapabilities {
    AuthRuntimeCapabilities::new(
        Arc::new(FixedClock(now)),
        Arc::new(FixedRandom),
        Arc::new(SequencedIds::new([
            "oauth-user-from-runtime",
            "oauth-session-from-runtime",
        ])),
        Arc::new(FixedSessionTokens),
        http,
    )
}

fn test_oauth_config_with_google() -> OAuthConfig {
    let mut cfg = OAuthConfig::default();
    cfg.providers.insert(
        "google".to_string(),
        OAuthProvider::google("test-client-id", "test-client-secret"),
    );
    cfg
}

#[tokio::test]
async fn sign_in_social_rejects_untrusted_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("https://evil.example.com/cb".to_string()),
        scopes: None,
    };

    let err = social_sign_in_core(&body, &oauth, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn sign_in_social_rejects_relative_callback_url() {
    // OAuth `redirect_uri` must be absolute; a relative path would pass
    // any general redirect trust check but fail at token exchange.
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("/oauth/callback".to_string()),
        scopes: None,
    };

    let err = social_sign_in_core(&body, &oauth, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn sign_in_social_allows_trusted_origin_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context_with_trusted_origins(&["https://admin.test.com"]);

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("https://admin.test.com/oauth/cb".to_string()),
        scopes: None,
    };

    let response = social_sign_in_core(&body, &oauth, &ctx).await.unwrap();
    assert!(response.redirect);
}

#[tokio::test]
async fn sign_in_social_defaults_when_no_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: None,
        scopes: None,
    };

    let response = social_sign_in_core(&body, &oauth, &ctx).await.unwrap();
    assert!(response.redirect);
}

#[tokio::test]
async fn oauth_callback_uses_runtime_http_client_and_session_manager() {
    let now = DateTime::parse_from_rfc3339("2035-03-04T05:06:07Z")
        .unwrap()
        .with_timezone(&Utc);
    let http = Arc::new(RecordingOAuthHttp::default());
    let config = test_helpers::create_test_config()
        .base_url("https://app.test")
        .runtime_capabilities(runtime_with_oauth_http(now, http.clone()));
    let ctx = test_helpers::create_test_context_with_config(config);

    let mut oauth = OAuthConfig::default();
    let google_mapper = OAuthProvider::google("ignored-client", "ignored-secret").map_user_info;
    oauth.providers.insert(
        "google".to_string(),
        OAuthProvider {
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            auth_url: "https://provider.test/auth".to_string(),
            token_url: "https://provider.test/token".to_string(),
            user_info_url: "https://provider.test/userinfo".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            map_user_info: google_mapper,
        },
    );

    ctx.database
        .create_verification(CreateVerification {
            identifier: "oauth:state-from-worker".to_string(),
            value: serde_json::json!({
                "provider": "google",
                "callback_url": "https://app.test/callback/google",
                "code_verifier": "verifier-from-state",
                "link_user_id": null,
                "scopes": "openid email",
            })
            .to_string(),
            expires_at: now + Duration::minutes(10),
        })
        .await
        .unwrap();

    let mut query = HashMap::new();
    query.insert("code".to_string(), "callback-code".to_string());
    query.insert("state".to_string(), "state-from-worker".to_string());
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/callback/google".to_string(),
        HashMap::new(),
        None,
        query,
    );

    let plugin = super::OAuthPlugin::with_config(oauth);
    let response = plugin
        .on_request(&req, &ctx)
        .await
        .unwrap()
        .expect("OAuth callback should be handled");

    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["token"], "session_oauth_runtime");

    let user = ctx
        .database
        .get_user_by_email("oauth@test.com")
        .await
        .unwrap()
        .expect("OAuth callback should create user");
    assert_eq!(user.id, "oauth-user-from-runtime");

    let session = ctx
        .database
        .get_session("session_oauth_runtime")
        .await
        .unwrap()
        .expect("OAuth callback should create session");
    assert_eq!(session.id, "oauth-session-from-runtime");
    assert_eq!(session.user_id, user.id);

    assert_eq!(http.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn sign_in_social_rejects_backslash_authority_bypass() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();

    let body = SocialSignInRequest {
        provider: "google".to_string(),
        callback_url: Some("/\\evil.example.com".to_string()),
        scopes: None,
    };

    let err = social_sign_in_core(&body, &oauth, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);
}

async fn seed_session(ctx: &better_auth_core::AuthContext<MemoryDatabaseAdapter>) -> Session {
    let user = ctx
        .database
        .create_user(
            CreateUser::new()
                .with_email("link@test.com")
                .with_name("Link"),
        )
        .await
        .unwrap();
    ctx.database
        .create_session(CreateSession {
            id: None,
            token: None,
            user_id: user.id.clone(),
            created_at: None,
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn link_social_rejects_untrusted_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context();
    let session = seed_session(&ctx).await;

    let body = LinkSocialRequest {
        provider: "google".to_string(),
        callback_url: Some("https://evil.example.com/cb".to_string()),
        scopes: None,
    };

    let err = link_social_core(&body, &session, &oauth, &ctx)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), 400);
}

#[tokio::test]
async fn link_social_allows_trusted_origin_callback_url() {
    let oauth = test_oauth_config_with_google();
    let ctx = test_helpers::create_test_context_with_trusted_origins(&["https://admin.test.com"]);
    let session = seed_session(&ctx).await;

    let body = LinkSocialRequest {
        provider: "google".to_string(),
        callback_url: Some("https://admin.test.com/oauth/cb".to_string()),
        scopes: None,
    };

    let response = link_social_core(&body, &session, &oauth, &ctx)
        .await
        .unwrap();
    assert!(response.redirect);
}
