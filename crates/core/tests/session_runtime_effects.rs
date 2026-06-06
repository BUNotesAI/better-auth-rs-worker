use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
use better_auth_core::capabilities::AuthRuntimeCapabilities;
use better_auth_core::{
    AuthConfig, AuthResult, AuthSession, Clock, CreateUser, IdGenerator, IdKind, OAuthHttpClient,
    OAuthHttpRequest, OAuthHttpResponse, SecureRandom, SessionConfig, SessionManager,
    SessionTokenGenerator,
};
use chrono::{DateTime, Duration, Utc};

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("test timestamp parses")
        .with_timezone(&Utc)
}

#[derive(Clone)]
struct MutableClock {
    now: Arc<Mutex<DateTime<Utc>>>,
}

impl MutableClock {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            now: Arc::new(Mutex::new(now)),
        }
    }

    fn set(&self, now: DateTime<Utc>) {
        *self.now.lock().expect("test clock lock is not poisoned") = now;
    }
}

impl Clock for MutableClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().expect("test clock lock is not poisoned")
    }
}

struct FixedIds;

impl IdGenerator for FixedIds {
    fn generate_id(&self, kind: IdKind) -> AuthResult<String> {
        Ok(format!("test-{kind:?}-id").to_lowercase())
    }
}

struct FixedSessionTokens;

impl SessionTokenGenerator for FixedSessionTokens {
    fn generate_session_token(&self) -> AuthResult<String> {
        Ok("session_test_token".to_string())
    }
}

struct UnusedRandom;

impl SecureRandom for UnusedRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
        dest.fill(7);
        Ok(())
    }
}

struct UnusedOAuthHttp;

#[async_trait]
impl OAuthHttpClient for UnusedOAuthHttp {
    async fn send(&self, _request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
        Ok(OAuthHttpResponse::new(200, Vec::new()))
    }
}

fn runtime(clock: MutableClock) -> AuthRuntimeCapabilities {
    AuthRuntimeCapabilities::new(
        Arc::new(clock),
        Arc::new(UnusedRandom),
        Arc::new(FixedIds),
        Arc::new(FixedSessionTokens),
        Arc::new(UnusedOAuthHttp),
    )
}

#[tokio::test]
async fn session_uses_configured_runtime_effects() {
    let initial_now = timestamp("2035-01-01T00:00:00Z");
    let clock = MutableClock::new(initial_now);
    let config = Arc::new(AuthConfig {
        session: SessionConfig {
            expires_in: Duration::hours(1),
            update_age: None,
            ..SessionConfig::default()
        },
        runtime: runtime(clock.clone()),
        ..AuthConfig::default()
    });
    let db = Arc::new(MemoryDatabaseAdapter::new());
    let user = db
        .create_user(CreateUser {
            id: Some("user-runtime".to_string()),
            email: Some("runtime@example.com".to_string()),
            name: Some("Runtime User".to_string()),
            ..CreateUser::default()
        })
        .await
        .expect("user creates through real memory adapter");
    let manager = SessionManager::new(config, db.clone());

    let session = manager
        .create_session(&user, None, None)
        .await
        .expect("session creates through real session manager");

    assert_eq!(session.id(), "test-session-id");
    assert_eq!(session.token(), "session_test_token");
    assert_eq!(session.created_at(), initial_now);
    assert_eq!(session.expires_at(), initial_now + Duration::hours(1));

    clock.set(initial_now + Duration::hours(2));
    let expired = manager
        .get_session(session.token())
        .await
        .expect("expired session lookup succeeds");
    assert!(expired.is_none(), "configured clock should drive expiry");
    assert!(
        db.get_session(session.token())
            .await
            .expect("database lookup succeeds")
            .is_none(),
        "expired session should be removed through the real adapter"
    );
}
