//! OIDC provider storage ports.
//!
//! These traits are defined in `better-auth-core` (not merged into
//! [`crate::adapters::DatabaseAdapter`]) so that the SQLx adapter (core) and the
//! D1 adapter (worker) can implement them under the `oidc-provider` feature
//! while satisfying Rust's orphan rule and the crate dependency direction. The
//! memory adapter implements them for contract tests.
//!
//! The plugin is generic over `DB: DatabaseAdapter + OidcProviderStore`. Expiry
//! decisions use an injected [`chrono::DateTime<Utc>`] supplied by the runtime
//! `Clock`, never a database `NOW()`, so native and Worker behavior match.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::AuthResult;
use crate::threading::RuntimeSendSync;

use super::model::{
    AccessTokenHash, AccessTokenRecord, AuthorizationCode, AuthorizationCodeRecord, ClientId,
    NewAccessToken, NewAuthorizationCode, OAuthClient,
};

/// Registered OAuth2 / OIDC client lookups.
#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
pub trait OAuthClientOps: RuntimeSendSync + 'static {
    /// Looks up a registered client by id.
    ///
    /// Preconditions:
    /// - `id` is a parsed [`ClientId`].
    ///
    /// Effects:
    /// 1. Reads one client row.
    ///
    /// Does not:
    /// - Create or mutate clients.
    /// - Verify client secrets (that is a pure rule on the returned record).
    ///
    /// Idempotency:
    /// - Idempotent read.
    async fn get_client(&self, id: &ClientId) -> AuthResult<Option<OAuthClient>>;
}

/// Authorization-code persistence and single-use consume.
#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
pub trait AuthorizationCodeOps: RuntimeSendSync + 'static {
    /// Persists a freshly issued authorization code.
    ///
    /// Preconditions:
    /// - `code.code` is unique and high-entropy.
    ///
    /// Effects:
    /// 1. Inserts one authorization-code row.
    ///
    /// Does not:
    /// - Issue tokens.
    ///
    /// Idempotency:
    /// - Not idempotent; a duplicate code is a storage error.
    async fn create_authorization_code(&self, input: NewAuthorizationCode) -> AuthResult<()>;

    /// Atomically consumes an unexpired authorization code, returning the row.
    ///
    /// Preconditions:
    /// - `now` is the injected runtime clock instant.
    ///
    /// Effects:
    /// 1. Deletes the matching row in a single statement when `expires_at > now`
    ///    and returns it. Implementations must use a single `DELETE ...
    ///    RETURNING` (or equivalent) so two racing redemptions cannot both win.
    ///
    /// Does not:
    /// - Verify PKCE, redirect URI, or client authentication (pure rules do).
    ///
    /// Idempotency:
    /// - Effectively idempotent after the first success: a replay returns
    ///   `None` because the row was already removed.
    async fn consume_authorization_code(
        &self,
        code: &AuthorizationCode,
        now: DateTime<Utc>,
    ) -> AuthResult<Option<AuthorizationCodeRecord>>;

    /// Removes authorization codes whose `expires_at` is at or before `now`.
    ///
    /// Returns the number of removed rows.
    async fn delete_expired_authorization_codes(&self, now: DateTime<Utc>) -> AuthResult<usize>;
}

/// Opaque access-token persistence (hash at rest) and lookup.
#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
pub trait AccessTokenOps: RuntimeSendSync + 'static {
    /// Persists a freshly issued access token by its hash.
    ///
    /// Preconditions:
    /// - `input.token_hash` is the hash of the opaque token; the raw token is
    ///   never passed here.
    ///
    /// Effects:
    /// 1. Inserts one access-token row keyed by `token_hash`.
    ///
    /// Does not:
    /// - Store the raw token value.
    ///
    /// Idempotency:
    /// - Not idempotent; a duplicate hash is a storage error.
    async fn create_access_token(&self, input: NewAccessToken) -> AuthResult<()>;

    /// Looks up an access token by its hash.
    ///
    /// Effects:
    /// 1. Reads one access-token row by `token_hash`.
    ///
    /// Does not:
    /// - Decide expiry; the caller compares `expires_at` to the injected clock.
    ///
    /// Idempotency:
    /// - Idempotent read.
    async fn get_access_token_by_hash(
        &self,
        hash: &AccessTokenHash,
    ) -> AuthResult<Option<AccessTokenRecord>>;

    /// Removes access tokens whose `expires_at` is at or before `now`.
    ///
    /// Returns the number of removed rows.
    async fn delete_expired_access_tokens(&self, now: DateTime<Utc>) -> AuthResult<usize>;
}

/// Aggregate storage port required by the OIDC provider plugin.
///
/// Any adapter implementing all three operation sets is an `OidcProviderStore`
/// via the blanket implementation, so the plugin bound
/// `DB: DatabaseAdapter + OidcProviderStore` is satisfied without merging these
/// operations into the core `DatabaseAdapter` composition.
pub trait OidcProviderStore:
    OAuthClientOps + AuthorizationCodeOps + AccessTokenOps + RuntimeSendSync + 'static
{
}

impl<T> OidcProviderStore for T where
    T: OAuthClientOps + AuthorizationCodeOps + AccessTokenOps + RuntimeSendSync + 'static
{
}
