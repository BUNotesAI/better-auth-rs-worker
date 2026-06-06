#![cfg(feature = "local-futures")]

use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use better_auth_core::HttpMethod;
use better_auth_core::{
    AuthError, AuthResult, CacheAdapter, Clock, CreateUser, IdGenerator, IdKind, ListUsersParams,
    LocalRuntimeCapabilitiesDyn, OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse,
    RuntimeCapabilities, SecureRandom, SessionTokenGenerator, UpdateUser, User, UserOps,
};
use chrono::{DateTime, Duration, Utc};

fn fixed_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-06-07T00:00:00Z")
        .expect("fixed test timestamp parses")
        .with_timezone(&Utc)
}

fn user_from_create(input: CreateUser) -> User {
    let now = fixed_time();
    User {
        id: input.id.unwrap_or_else(|| "local-user".to_string()),
        name: input.name,
        email: input.email,
        email_verified: input.email_verified.unwrap_or(false),
        image: input.image,
        created_at: now,
        updated_at: now,
        username: input.username,
        display_username: input.display_username,
        two_factor_enabled: false,
        role: input.role,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        metadata: input.metadata.unwrap_or_else(|| serde_json::json!({})),
    }
}

#[derive(Clone, Default)]
struct LocalUserStore {
    users: Rc<RefCell<Vec<User>>>,
}

#[async_trait(?Send)]
impl UserOps for LocalUserStore {
    type User = User;

    async fn create_user(&self, user: CreateUser) -> AuthResult<Self::User> {
        let users = self.users.clone();
        core::future::ready(()).await;

        let user = user_from_create(user);
        users.borrow_mut().push(user.clone());
        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<Self::User>> {
        let users = self.users.clone();
        core::future::ready(()).await;

        Ok(users.borrow().iter().find(|user| user.id == id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<Self::User>> {
        let users = self.users.clone();
        core::future::ready(()).await;

        Ok(users
            .borrow()
            .iter()
            .find(|user| user.email.as_deref() == Some(email))
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<Self::User>> {
        let users = self.users.clone();
        core::future::ready(()).await;

        Ok(users
            .borrow()
            .iter()
            .find(|user| user.username.as_deref() == Some(username))
            .cloned())
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<Self::User> {
        let users = self.users.clone();
        core::future::ready(()).await;

        let mut users = users.borrow_mut();
        let user = users
            .iter_mut()
            .find(|user| user.id == id)
            .ok_or_else(|| AuthError::not_found("User"))?;

        if let Some(email) = update.email {
            user.email = Some(email);
        }
        if let Some(name) = update.name {
            user.name = Some(name);
        }
        user.updated_at = fixed_time();
        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let users = self.users.clone();
        core::future::ready(()).await;

        users.borrow_mut().retain(|user| user.id != id);
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<Self::User>, usize)> {
        let users = self.users.clone();
        core::future::ready(()).await;

        let users = users.borrow().clone();
        let total = users.len();
        Ok((users, total))
    }
}

#[derive(Clone, Default)]
struct LocalCache {
    value: Rc<RefCell<Option<String>>>,
}

#[async_trait(?Send)]
impl CacheAdapter for LocalCache {
    async fn set(&self, _key: &str, value: &str, _expires_in: Duration) -> AuthResult<()> {
        let slot = self.value.clone();
        core::future::ready(()).await;

        *slot.borrow_mut() = Some(value.to_string());
        Ok(())
    }

    async fn get(&self, _key: &str) -> AuthResult<Option<String>> {
        let slot = self.value.clone();
        core::future::ready(()).await;

        Ok(slot.borrow().clone())
    }

    async fn delete(&self, _key: &str) -> AuthResult<()> {
        let slot = self.value.clone();
        core::future::ready(()).await;

        *slot.borrow_mut() = None;
        Ok(())
    }

    async fn exists(&self, _key: &str) -> AuthResult<bool> {
        let slot = self.value.clone();
        core::future::ready(()).await;

        Ok(slot.borrow().is_some())
    }

    async fn expire(&self, _key: &str, _expires_in: Duration) -> AuthResult<()> {
        let slot = self.value.clone();
        core::future::ready(()).await;

        let _ = slot.borrow();
        Ok(())
    }

    async fn clear(&self) -> AuthResult<()> {
        let slot = self.value.clone();
        core::future::ready(()).await;

        *slot.borrow_mut() = None;
        Ok(())
    }
}

fn assert_user_ops<T: UserOps<User = User>>(_: &T) {}

fn assert_cache_adapter<T: CacheAdapter>(_: &T) {}

#[derive(Clone)]
struct LocalClock {
    now: Rc<RefCell<DateTime<Utc>>>,
}

impl Clock for LocalClock {
    fn now(&self) -> DateTime<Utc> {
        self.now.borrow().to_owned()
    }
}

#[derive(Clone)]
struct LocalRandom {
    bytes: Rc<RefCell<Vec<u8>>>,
}

impl SecureRandom for LocalRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
        let bytes = self.bytes.borrow();
        for (idx, byte) in dest.iter_mut().enumerate() {
            *byte = bytes[idx % bytes.len()];
        }
        Ok(())
    }
}

#[derive(Clone)]
struct LocalIds {
    counter: Rc<RefCell<u64>>,
}

impl IdGenerator for LocalIds {
    fn generate_id(&self, kind: IdKind) -> AuthResult<String> {
        let mut counter = self.counter.borrow_mut();
        *counter += 1;
        Ok(format!("{kind:?}-{}", *counter))
    }
}

#[derive(Clone)]
struct LocalSessionTokens {
    counter: Rc<RefCell<u64>>,
}

impl SessionTokenGenerator for LocalSessionTokens {
    fn generate_session_token(&self) -> AuthResult<String> {
        let mut counter = self.counter.borrow_mut();
        *counter += 1;
        Ok(format!("session_local_{}", *counter))
    }
}

#[derive(Clone, Default)]
struct LocalOAuthHttp {
    last_url: Rc<RefCell<Option<String>>>,
}

#[async_trait(?Send)]
impl OAuthHttpClient for LocalOAuthHttp {
    async fn send(&self, request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
        let last_url = self.last_url.clone();
        core::future::ready(()).await;

        *last_url.borrow_mut() = Some(request.url);
        Ok(OAuthHttpResponse::new(200, br#"{"ok":true}"#.to_vec()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn portable_traits_accept_non_send_worker_adapters() {
    let users = LocalUserStore::default();
    let cache = LocalCache::default();

    assert_user_ops(&users);
    assert_cache_adapter(&cache);

    let user = users
        .create_user(CreateUser {
            id: Some("worker-user".to_string()),
            email: Some("worker@example.com".to_string()),
            name: Some("Worker User".to_string()),
            image: None,
            email_verified: Some(true),
            password: None,
            username: Some("worker".to_string()),
            display_username: None,
            role: None,
            metadata: None,
        })
        .await
        .expect("local user store creates a user");

    assert_eq!(user.id, "worker-user");
    assert!(
        users
            .get_user_by_email("worker@example.com")
            .await
            .expect("local user lookup succeeds")
            .is_some()
    );

    cache
        .set("session", "token", Duration::seconds(60))
        .await
        .expect("local cache set succeeds");
    assert_eq!(
        cache
            .get("session")
            .await
            .expect("local cache get succeeds"),
        Some("token".to_string())
    );

    let capabilities: LocalRuntimeCapabilitiesDyn = RuntimeCapabilities::new(
        Box::new(LocalClock {
            now: Rc::new(RefCell::new(fixed_time())),
        }),
        Box::new(LocalRandom {
            bytes: Rc::new(RefCell::new(vec![1, 2, 3, 4])),
        }),
        Box::new(LocalIds {
            counter: Rc::new(RefCell::new(0)),
        }),
        Box::new(LocalSessionTokens {
            counter: Rc::new(RefCell::new(0)),
        }),
        Box::new(LocalOAuthHttp::default()),
    );

    assert_eq!(capabilities.clock.now(), fixed_time());

    let mut bytes = [0; 6];
    capabilities
        .secure_random
        .fill_bytes(&mut bytes)
        .expect("local secure random fills bytes");
    assert_eq!(bytes, [1, 2, 3, 4, 1, 2]);

    assert_eq!(
        capabilities
            .id_generator
            .generate_id(IdKind::User)
            .expect("local ID generator succeeds"),
        "User-1"
    );
    assert_eq!(
        capabilities
            .session_tokens
            .generate_session_token()
            .expect("local session token generator succeeds"),
        "session_local_1"
    );

    let response = capabilities
        .oauth_http
        .send(OAuthHttpRequest::new(
            HttpMethod::Get,
            "https://provider.example/userinfo",
        ))
        .await
        .expect("local OAuth HTTP client succeeds");
    assert_eq!(response.status, 200);
}
