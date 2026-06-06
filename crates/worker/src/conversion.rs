use std::collections::HashMap;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, HttpMethod,
};
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub struct WorkerRequestParts {
    method: HttpMethod,
    url_or_path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

impl WorkerRequestParts {
    pub fn new(method: HttpMethod, url_or_path: impl Into<String>) -> Self {
        Self {
            method,
            url_or_path: url_or_path.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn method(&self) -> &HttpMethod {
        &self.method
    }

    pub fn url_or_path(&self) -> &str {
        &self.url_or_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerResponseParts {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl WorkerResponseParts {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

pub fn auth_request_from_worker_parts(parts: WorkerRequestParts) -> AuthRequest {
    let (path, query) = split_path_and_query(&parts.url_or_path);
    let headers = parts
        .headers
        .into_iter()
        .map(|(name, value)| (normalize_header_name(&name), value))
        .collect::<HashMap<_, _>>();

    AuthRequest::from_parts(parts.method, path, headers, parts.body, query)
}

pub fn worker_response_from_auth_response(response: AuthResponse) -> WorkerResponseParts {
    let headers = response.headers.into_iter().collect::<Vec<_>>();

    WorkerResponseParts {
        status: response.status,
        headers,
        body: response.body,
    }
}

/// Executes one Worker request through one auth plugin.
///
/// Preconditions:
/// - `parts` contains the Worker request data for the auth route being probed.
/// - `plugin` is the production plugin that owns the route.
/// - `ctx` contains the configured database and runtime capabilities.
///
/// Effects:
/// 1. Converts Worker request data into [`AuthRequest`].
/// 2. Executes `plugin.on_request`.
/// 3. Converts a handled [`AuthResponse`] into [`WorkerResponseParts`].
///
/// Does not:
/// - Dispatch across multiple plugins.
/// - Catch or translate [`better_auth_core::AuthError`] values into HTTP responses.
/// - Touch Worker bindings directly.
///
/// Idempotency:
/// - Depends on the plugin route and database/runtime capabilities.
pub async fn handle_worker_plugin_request<DB, P>(
    plugin: &P,
    parts: WorkerRequestParts,
    ctx: &AuthContext<DB>,
) -> AuthResult<Option<WorkerResponseParts>>
where
    DB: DatabaseAdapter,
    P: AuthPlugin<DB>,
{
    let request = auth_request_from_worker_parts(parts);
    plugin
        .on_request(&request, ctx)
        .await
        .map(|response| response.map(worker_response_from_auth_response))
}

fn split_path_and_query(url_or_path: &str) -> (String, HashMap<String, String>) {
    if let Ok(url) = Url::parse(url_or_path) {
        let query = query_pairs_to_map(url.query_pairs());
        return (normalize_path(url.path()), query);
    }

    let (path, raw_query) = url_or_path
        .split_once('?')
        .map_or((url_or_path, ""), |(path, query)| (path, query));

    let query = url::form_urlencoded::parse(raw_query.as_bytes())
        .into_owned()
        .collect::<HashMap<_, _>>();

    (normalize_path(path), query)
}

fn query_pairs_to_map<'a>(pairs: url::form_urlencoded::Parse<'a>) -> HashMap<String, String> {
    pairs.into_owned().collect()
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }

    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn normalize_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::AuthResponse;
    use serde_json::json;

    #[test]
    fn worker_request_response_round_trip() {
        let request = WorkerRequestParts::new(
            HttpMethod::Post,
            "https://auth.example.test/sign-in/email?redirect=true&callbackURL=%2Fdashboard",
        )
        .with_header("Content-Type", "application/json")
        .with_header("Cookie", "better-auth.session_token=abc")
        .with_body(br#"{"email":"a@example.com","password":"secret"}"#.to_vec());

        let auth_request = auth_request_from_worker_parts(request);

        assert_eq!(auth_request.method, HttpMethod::Post);
        assert_eq!(auth_request.path, "/sign-in/email");
        assert_eq!(
            auth_request.header("content-type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(
            auth_request.header("cookie"),
            Some(&"better-auth.session_token=abc".to_string())
        );
        assert_eq!(
            auth_request.query.get("redirect"),
            Some(&"true".to_string())
        );
        assert_eq!(
            auth_request.query.get("callbackURL"),
            Some(&"/dashboard".to_string())
        );
        assert_eq!(
            auth_request.body.as_deref(),
            Some(&br#"{"email":"a@example.com","password":"secret"}"#[..])
        );

        let response = AuthResponse::json(302, &json!({ "ok": true }))
            .unwrap()
            .with_header("location", "/dashboard")
            .with_header("Set-Cookie", "better-auth.session_token=next; HttpOnly");

        let worker_response = worker_response_from_auth_response(response);

        assert_eq!(worker_response.status(), 302);
        assert_eq!(worker_response.header("location"), Some("/dashboard"));
        assert_eq!(
            worker_response.header("set-cookie"),
            Some("better-auth.session_token=next; HttpOnly")
        );
        assert_eq!(worker_response.body(), br#"{"ok":true}"#);
    }

    #[cfg(feature = "api-route-tests")]
    mod route_round_trip {
        use std::sync::{Arc, Mutex};

        use async_trait::async_trait;
        use better_auth_api::EmailPasswordPlugin;
        use better_auth_core::adapters::MemoryDatabaseAdapter;
        use better_auth_core::{
            AuthConfig, AuthContext, AuthError, AuthPlugin, AuthResult, AuthRuntimeCapabilities,
            Clock, IdGenerator, IdKind, OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse,
            PasswordHasher, SecureRandom, SessionTokenGenerator, SharedClock, SharedIdGenerator,
            SharedOAuthHttpClient, SharedPasswordHasher, SharedSecureRandom,
            SharedSessionTokenGenerator,
        };
        use chrono::{DateTime, TimeZone, Utc};
        use serde_json::json;

        use super::*;

        #[derive(Clone)]
        struct FixedClock(DateTime<Utc>);

        impl Clock for FixedClock {
            fn now(&self) -> DateTime<Utc> {
                self.0
            }
        }

        struct SequencedIds {
            values: Mutex<Vec<String>>,
        }

        impl SequencedIds {
            fn new(values: Vec<&str>) -> Self {
                Self {
                    values: Mutex::new(values.into_iter().map(str::to_string).rev().collect()),
                }
            }
        }

        impl IdGenerator for SequencedIds {
            fn generate_id(&self, _kind: IdKind) -> AuthResult<String> {
                self.values
                    .lock()
                    .expect("test ID lock is not poisoned")
                    .pop()
                    .ok_or_else(|| AuthError::internal("test ID generator exhausted"))
            }
        }

        struct FixedRandom;

        impl SecureRandom for FixedRandom {
            fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
                dest.fill(7);
                Ok(())
            }
        }

        struct FixedSessionTokens;

        impl SessionTokenGenerator for FixedSessionTokens {
            fn generate_session_token(&self) -> AuthResult<String> {
                Ok("session_worker_route".to_string())
            }
        }

        struct FixedOAuthHttp;

        #[cfg_attr(feature = "local-futures", async_trait(?Send))]
        #[cfg_attr(not(feature = "local-futures"), async_trait)]
        impl OAuthHttpClient for FixedOAuthHttp {
            async fn send(&self, _request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
                Ok(OAuthHttpResponse::new(200, Vec::new()))
            }
        }

        struct PrefixHasher;

        #[cfg_attr(feature = "local-futures", async_trait(?Send))]
        #[cfg_attr(not(feature = "local-futures"), async_trait)]
        impl PasswordHasher for PrefixHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("worker-hash:{password}"))
            }

            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                Ok(hash == format!("worker-hash:{password}"))
            }
        }

        #[cfg(feature = "local-futures")]
        fn shared_clock(value: FixedClock) -> SharedClock {
            std::rc::Rc::new(value)
        }

        #[cfg(not(feature = "local-futures"))]
        fn shared_clock(value: FixedClock) -> SharedClock {
            Arc::new(value)
        }

        #[cfg(feature = "local-futures")]
        fn shared_secure_random(value: FixedRandom) -> SharedSecureRandom {
            std::rc::Rc::new(value)
        }

        #[cfg(not(feature = "local-futures"))]
        fn shared_secure_random(value: FixedRandom) -> SharedSecureRandom {
            Arc::new(value)
        }

        #[cfg(feature = "local-futures")]
        fn shared_id_generator(value: SequencedIds) -> SharedIdGenerator {
            std::rc::Rc::new(value)
        }

        #[cfg(not(feature = "local-futures"))]
        fn shared_id_generator(value: SequencedIds) -> SharedIdGenerator {
            Arc::new(value)
        }

        #[cfg(feature = "local-futures")]
        fn shared_session_tokens(value: FixedSessionTokens) -> SharedSessionTokenGenerator {
            std::rc::Rc::new(value)
        }

        #[cfg(not(feature = "local-futures"))]
        fn shared_session_tokens(value: FixedSessionTokens) -> SharedSessionTokenGenerator {
            Arc::new(value)
        }

        #[cfg(feature = "local-futures")]
        fn shared_oauth_http(value: FixedOAuthHttp) -> SharedOAuthHttpClient {
            std::rc::Rc::new(value)
        }

        #[cfg(not(feature = "local-futures"))]
        fn shared_oauth_http(value: FixedOAuthHttp) -> SharedOAuthHttpClient {
            Arc::new(value)
        }

        #[cfg(feature = "local-futures")]
        fn shared_password_hasher(value: PrefixHasher) -> SharedPasswordHasher {
            std::rc::Rc::new(value)
        }

        #[cfg(not(feature = "local-futures"))]
        fn shared_password_hasher(value: PrefixHasher) -> SharedPasswordHasher {
            Arc::new(value)
        }

        fn runtime() -> AuthRuntimeCapabilities {
            AuthRuntimeCapabilities::new(
                shared_clock(FixedClock(
                    Utc.with_ymd_and_hms(2026, 6, 7, 0, 0, 0).unwrap(),
                )),
                shared_secure_random(FixedRandom),
                shared_id_generator(SequencedIds::new(vec![
                    "worker-route-user",
                    "worker-route-session",
                ])),
                shared_session_tokens(FixedSessionTokens),
                shared_oauth_http(FixedOAuthHttp),
            )
        }

        fn context() -> AuthContext<MemoryDatabaseAdapter> {
            let config = AuthConfig {
                runtime: runtime(),
                ..AuthConfig::new("test-secret-key-at-least-32-chars-long")
            };

            AuthContext::new(Arc::new(config), Arc::new(MemoryDatabaseAdapter::new()))
        }

        #[tokio::test(flavor = "current_thread")]
        async fn worker_request_response_route_round_trip_handles_success_and_error() {
            let ctx = context();
            let plugin =
                EmailPasswordPlugin::new().password_hasher(shared_password_hasher(PrefixHasher));

            let signup_request = WorkerRequestParts::new(
                HttpMethod::Post,
                "https://auth.example.test/sign-up/email?callbackURL=%2Fdashboard",
            )
            .with_header("Content-Type", "application/json")
            .with_header("Cookie", "visitor=abc")
            .with_body(
                json!({
                    "name": "Worker User",
                    "email": "worker@example.com",
                    "password": "Password123!"
                })
                .to_string()
                .into_bytes(),
            );

            let auth_request = auth_request_from_worker_parts(signup_request);
            let auth_response = plugin
                .on_request(&auth_request, &ctx)
                .await
                .expect("plugin request succeeds")
                .expect("email-password route handles sign-up");
            let worker_response = worker_response_from_auth_response(auth_response);

            assert_eq!(worker_response.status(), 200);
            let cookie = worker_response
                .header("set-cookie")
                .expect("route sets session cookie");
            assert!(cookie.contains("better-auth.session-token=session_worker_route"));
            assert!(cookie.contains("HttpOnly"));
            assert!(cookie.contains("Path=/"));
            let body: serde_json::Value = serde_json::from_slice(worker_response.body())
                .expect("successful route body is JSON");
            assert_eq!(body["token"], "session_worker_route");
            assert_eq!(body["user"]["id"], "worker-route-user");

            let error_request = WorkerRequestParts::new(
                HttpMethod::Post,
                "https://auth.example.test/sign-up/email",
            )
            .with_header("Content-Type", "application/json")
            .with_body(
                json!({ "email": "invalid@example.com" })
                    .to_string()
                    .into_bytes(),
            );

            let error_auth_request = auth_request_from_worker_parts(error_request);
            let error_auth_response = plugin
                .on_request(&error_auth_request, &ctx)
                .await
                .expect("plugin error response is represented as AuthResponse")
                .expect("email-password route handles validation error");
            let worker_error_response = worker_response_from_auth_response(error_auth_response);

            assert_eq!(worker_error_response.status(), 400);
            assert_eq!(
                worker_error_response.header("content-type"),
                Some("application/json")
            );
            let error_body: serde_json::Value =
                serde_json::from_slice(worker_error_response.body())
                    .expect("error route body is JSON");
            assert!(
                error_body["message"].is_string(),
                "error response contains a message"
            );
        }
    }
}
