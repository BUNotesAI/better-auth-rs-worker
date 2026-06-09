pub mod account_management;
#[cfg(feature = "admin")]
pub mod admin;
#[cfg(feature = "api-key")]
pub mod api_key;
#[cfg(feature = "device-authorization")]
pub mod device_authorization;
pub mod email_password;
#[cfg(feature = "email-verification")]
pub mod email_verification;
pub mod helpers;
pub mod oauth;
#[cfg(feature = "oidc-provider")]
pub mod oidc_provider;
#[cfg(feature = "organization")]
pub mod organization;
#[cfg(feature = "passkey")]
pub mod passkey;
#[cfg(feature = "password-management")]
pub mod password_management;
pub mod session_management;
#[cfg(feature = "two-factor")]
pub mod two_factor;
#[cfg(feature = "user-management")]
pub mod user_management;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusResponse {
    status: bool,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)] // Exception: pre-existing test_helpers ordering, refactor outside task_6f08dbb6 scope.
pub(crate) mod test_helpers {
    use better_auth_core::adapters::{MemoryDatabaseAdapter, SessionOps, UserOps};
    use better_auth_core::config::AuthConfig;
    use better_auth_core::{
        AuthContext, AuthRequest, CreateSession, CreateUser, HttpMethod, Session, User,
    };
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    pub fn create_test_config() -> AuthConfig {
        AuthConfig::new("test-secret-key-at-least-32-chars-long")
    }

    pub fn create_test_context() -> AuthContext<MemoryDatabaseAdapter> {
        create_test_context_with_config(create_test_config())
    }

    pub fn create_test_context_with_config(
        config: AuthConfig,
    ) -> AuthContext<MemoryDatabaseAdapter> {
        let config = Arc::new(config);
        let database = Arc::new(MemoryDatabaseAdapter::new());
        AuthContext::new(config, database)
    }

    /// Test context whose `trusted_origins` accepts the given absolute
    /// origins. Use in tests that exercise `is_redirect_target_trusted`
    /// happy-path handling for callbackURLs under a custom origin.
    pub fn create_test_context_with_trusted_origins(
        origins: &[&str],
    ) -> AuthContext<MemoryDatabaseAdapter> {
        let mut config = create_test_config();
        config.trusted_origins = origins.iter().map(|s| (*s).to_string()).collect();
        create_test_context_with_config(config)
    }

    pub async fn create_user(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        create_user: CreateUser,
    ) -> User {
        ctx.database.create_user(create_user).await.unwrap()
    }

    pub async fn create_session(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        user_id: String,
        expires_in: Duration,
    ) -> Session {
        let create_session = CreateSession {
            id: None,
            token: None,
            user_id,
            created_at: None,
            expires_at: Utc::now() + expires_in,
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            impersonated_by: None,
            active_organization_id: None,
        };
        ctx.database.create_session(create_session).await.unwrap()
    }

    pub async fn create_user_and_session(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        user_data: CreateUser,
        session_expires_in: Duration,
    ) -> (User, Session) {
        let user = create_user(ctx, user_data).await;
        let session = create_session(ctx, user.id.clone(), session_expires_in).await;
        (user, session)
    }

    pub async fn create_test_context_with_user(
        create_user: CreateUser,
        session_expires_in: Duration,
    ) -> (AuthContext<MemoryDatabaseAdapter>, User, Session) {
        let ctx = create_test_context();
        let (user, session) = create_user_and_session(&ctx, create_user, session_expires_in).await;
        (ctx, user, session)
    }

    pub fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }

        AuthRequest::from_parts(method, path.to_string(), headers, body, query)
    }

    pub fn create_auth_request_no_query(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> AuthRequest {
        create_auth_request(method, path, token, body, HashMap::new())
    }

    pub fn create_auth_json_request_no_query(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        create_auth_json_request(method, path, token, body, HashMap::new())
    }

    pub fn create_auth_json_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut req = create_auth_request(
            method,
            path,
            token,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
            query,
        );
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        req
    }
}

pub use account_management::AccountManagementPlugin;
#[cfg(feature = "admin")]
pub use admin::{AdminConfig, AdminPlugin};
#[cfg(feature = "api-key")]
pub use api_key::{ApiKeyConfig, ApiKeyPlugin};
pub use better_auth_core::PasswordHasher;
#[cfg(feature = "device-authorization")]
pub use device_authorization::{DeviceAuthorizationConfig, DeviceAuthorizationPlugin};
pub use email_password::{EmailPasswordConfig, EmailPasswordPlugin};
#[cfg(feature = "email-verification")]
pub use email_verification::{
    EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin, SendVerificationEmail,
};
#[cfg(feature = "organization")]
pub use organization::{OrganizationConfig, OrganizationPlugin};
#[cfg(feature = "passkey")]
pub use passkey::{PasskeyConfig, PasskeyPlugin};
#[cfg(feature = "password-management")]
pub use password_management::{
    PasswordManagementConfig, PasswordManagementPlugin, SendResetPassword,
};
pub use session_management::SessionManagementPlugin;
#[cfg(feature = "two-factor")]
pub use two_factor::{TwoFactorConfig, TwoFactorPlugin};
#[cfg(feature = "user-management")]
pub use user_management::{
    ChangeEmailConfig, DeleteUserConfig, UserManagementConfig, UserManagementPlugin,
};
