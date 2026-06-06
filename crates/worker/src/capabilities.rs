use better_auth_core::{
    AuthError, AuthResult, AuthRuntimeCapabilities, SharedClock, SharedIdGenerator,
    SharedOAuthHttpClient, SharedSecureRandom, SharedSessionTokenGenerator,
};

/// Worker-facing wrapper around core runtime capabilities.
///
/// This type is only a construction boundary. It does not implement concrete
/// Worker time, entropy, ID, token, or fetch effects.
#[derive(Clone)]
pub struct WorkerRuntimeCapabilities {
    inner: AuthRuntimeCapabilities,
}

impl WorkerRuntimeCapabilities {
    pub fn new(inner: AuthRuntimeCapabilities) -> Self {
        Self { inner }
    }

    pub fn builder() -> WorkerRuntimeCapabilitiesBuilder {
        WorkerRuntimeCapabilitiesBuilder::new()
    }

    pub fn as_auth_runtime(&self) -> &AuthRuntimeCapabilities {
        &self.inner
    }

    pub fn into_auth_runtime(self) -> AuthRuntimeCapabilities {
        self.inner
    }
}

#[derive(Clone, Default)]
pub struct WorkerRuntimeCapabilitiesBuilder {
    clock: Option<SharedClock>,
    secure_random: Option<SharedSecureRandom>,
    id_generator: Option<SharedIdGenerator>,
    session_tokens: Option<SharedSessionTokenGenerator>,
    oauth_http: Option<SharedOAuthHttpClient>,
}

impl WorkerRuntimeCapabilitiesBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clock(mut self, clock: SharedClock) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn secure_random(mut self, secure_random: SharedSecureRandom) -> Self {
        self.secure_random = Some(secure_random);
        self
    }

    pub fn id_generator(mut self, id_generator: SharedIdGenerator) -> Self {
        self.id_generator = Some(id_generator);
        self
    }

    pub fn session_tokens(mut self, session_tokens: SharedSessionTokenGenerator) -> Self {
        self.session_tokens = Some(session_tokens);
        self
    }

    pub fn oauth_http(mut self, oauth_http: SharedOAuthHttpClient) -> Self {
        self.oauth_http = Some(oauth_http);
        self
    }

    pub fn build(self) -> AuthResult<WorkerRuntimeCapabilities> {
        let clock = self.clock.ok_or_else(|| missing("clock"))?;
        let secure_random = self.secure_random.ok_or_else(|| missing("secure_random"))?;
        let id_generator = self.id_generator.ok_or_else(|| missing("id_generator"))?;
        let session_tokens = self
            .session_tokens
            .ok_or_else(|| missing("session_tokens"))?;
        let oauth_http = self.oauth_http.ok_or_else(|| missing("oauth_http"))?;

        Ok(WorkerRuntimeCapabilities::new(
            AuthRuntimeCapabilities::new(
                clock,
                secure_random,
                id_generator,
                session_tokens,
                oauth_http,
            ),
        ))
    }
}

fn missing(capability: &str) -> AuthError {
    AuthError::config(format!(
        "Worker runtime capabilities require an explicit {capability} capability"
    ))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use better_auth_core::{
        Clock, IdGenerator, IdKind, OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse,
        SecureRandom, SessionTokenGenerator,
    };
    use chrono::{TimeZone, Utc};

    use super::*;

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 6, 7, 0, 0, 0).unwrap()
        }
    }

    #[derive(Debug)]
    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
            dest.fill(7);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FixedIds;

    impl IdGenerator for FixedIds {
        fn generate_id(&self, kind: IdKind) -> AuthResult<String> {
            Ok(format!("worker-{kind:?}"))
        }
    }

    #[derive(Debug)]
    struct FixedSessionTokens;

    impl SessionTokenGenerator for FixedSessionTokens {
        fn generate_session_token(&self) -> AuthResult<String> {
            Ok("session_worker_test".to_string())
        }
    }

    #[derive(Debug)]
    struct FixedOAuthHttp;

    #[cfg_attr(feature = "local-futures", async_trait(?Send))]
    #[cfg_attr(not(feature = "local-futures"), async_trait)]
    impl OAuthHttpClient for FixedOAuthHttp {
        async fn send(&self, _request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
            Ok(OAuthHttpResponse::new(200, br#"{"sub":"worker"}"#.to_vec()))
        }
    }

    #[cfg(feature = "local-futures")]
    fn shared_clock() -> SharedClock {
        std::rc::Rc::new(FixedClock)
    }

    #[cfg(not(feature = "local-futures"))]
    fn shared_clock() -> SharedClock {
        std::sync::Arc::new(FixedClock)
    }

    #[cfg(feature = "local-futures")]
    fn shared_secure_random() -> SharedSecureRandom {
        std::rc::Rc::new(FixedRandom)
    }

    #[cfg(not(feature = "local-futures"))]
    fn shared_secure_random() -> SharedSecureRandom {
        std::sync::Arc::new(FixedRandom)
    }

    #[cfg(feature = "local-futures")]
    fn shared_id_generator() -> SharedIdGenerator {
        std::rc::Rc::new(FixedIds)
    }

    #[cfg(not(feature = "local-futures"))]
    fn shared_id_generator() -> SharedIdGenerator {
        std::sync::Arc::new(FixedIds)
    }

    #[cfg(feature = "local-futures")]
    fn shared_session_tokens() -> SharedSessionTokenGenerator {
        std::rc::Rc::new(FixedSessionTokens)
    }

    #[cfg(not(feature = "local-futures"))]
    fn shared_session_tokens() -> SharedSessionTokenGenerator {
        std::sync::Arc::new(FixedSessionTokens)
    }

    #[cfg(feature = "local-futures")]
    fn shared_oauth_http() -> SharedOAuthHttpClient {
        std::rc::Rc::new(FixedOAuthHttp)
    }

    #[cfg(not(feature = "local-futures"))]
    fn shared_oauth_http() -> SharedOAuthHttpClient {
        std::sync::Arc::new(FixedOAuthHttp)
    }

    #[test]
    fn worker_runtime_capabilities_require_explicit_ports() {
        let err = match WorkerRuntimeCapabilities::builder().build() {
            Ok(_) => panic!("expected missing capability error"),
            Err(err) => err,
        };
        let AuthError::Config(message) = err else {
            panic!("expected config error");
        };

        assert!(message.contains("clock"));
    }

    #[test]
    fn worker_runtime_capabilities_build_from_explicit_ports() {
        let runtime = WorkerRuntimeCapabilities::builder()
            .clock(shared_clock())
            .secure_random(shared_secure_random())
            .id_generator(shared_id_generator())
            .session_tokens(shared_session_tokens())
            .oauth_http(shared_oauth_http())
            .build()
            .unwrap()
            .into_auth_runtime();

        assert_eq!(
            runtime.clock.now(),
            Utc.with_ymd_and_hms(2026, 6, 7, 0, 0, 0).unwrap()
        );
        assert_eq!(
            runtime.id_generator.generate_id(IdKind::User).unwrap(),
            "worker-User"
        );
        assert_eq!(
            runtime.session_tokens.generate_session_token().unwrap(),
            "session_worker_test"
        );
    }
}
