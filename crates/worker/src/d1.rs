use std::collections::BTreeMap;

use async_trait::async_trait;
use better_auth_core::adapters::{
    AccountOps, ApiKeyOps, InvitationOps, MemberOps, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};
use better_auth_core::threading::RuntimeSendSync;
use better_auth_core::types_org::{Invitation, Member, Organization};
use better_auth_core::{
    Account, ApiKey, AuthError, AuthResult, AuthRuntimeCapabilities, CreateAccount, CreateApiKey,
    CreateInvitation, CreateMember, CreateOrganization, CreatePasskey, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, DatabaseError, IdKind, InvitationStatus,
    ListUsersParams, Passkey, Session, TwoFactor, UpdateAccount, UpdateApiKey, UpdateOrganization,
    UpdateUser, User, Verification,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value as JsonValue;

use crate::WorkerRuntimeCapabilities;

pub const D1_MIGRATIONS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations/d1");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D1StatementMethod {
    Run,
    First,
    All,
}

#[derive(Debug, Clone, PartialEq)]
pub enum D1Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Boolean(bool),
}

impl From<&str> for D1Value {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

impl From<String> for D1Value {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&String> for D1Value {
    fn from(value: &String) -> Self {
        Self::Text(value.clone())
    }
}

impl From<i64> for D1Value {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<bool> for D1Value {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl<T> From<Option<T>> for D1Value
where
    T: Into<D1Value>,
{
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

#[derive(Debug, Clone)]
pub struct D1PreparedStatement {
    sql: &'static str,
    bindings: Vec<D1Value>,
    method: D1StatementMethod,
}

impl D1PreparedStatement {
    pub fn new(sql: &'static str) -> Self {
        Self {
            sql,
            bindings: Vec::new(),
            method: D1StatementMethod::Run,
        }
    }

    pub fn bind(mut self, value: impl Into<D1Value>) -> Self {
        self.bindings.push(value.into());
        self
    }

    pub fn run(mut self) -> Self {
        self.method = D1StatementMethod::Run;
        self
    }

    pub fn first(mut self) -> Self {
        self.method = D1StatementMethod::First;
        self
    }

    pub fn all(mut self) -> Self {
        self.method = D1StatementMethod::All;
        self
    }

    pub fn sql(&self) -> &'static str {
        self.sql
    }

    pub fn bindings(&self) -> &[D1Value] {
        &self.bindings
    }

    pub fn method(&self) -> D1StatementMethod {
        self.method
    }
}

#[derive(Debug, Clone, Default)]
pub struct D1QueryResult {
    rows: Vec<D1Row>,
    rows_affected: usize,
}

impl D1QueryResult {
    pub fn new(rows: Vec<D1Row>, rows_affected: usize) -> Self {
        Self {
            rows,
            rows_affected,
        }
    }

    pub fn into_first(mut self) -> Option<D1Row> {
        self.rows.drain(..).next()
    }

    pub fn into_rows(self) -> Vec<D1Row> {
        self.rows
    }

    pub fn rows_affected(&self) -> usize {
        self.rows_affected
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct D1Row {
    values: BTreeMap<String, D1Value>,
}

impl D1Row {
    pub fn new(values: BTreeMap<String, D1Value>) -> Self {
        Self { values }
    }

    fn required_text(&self, column: &str) -> AuthResult<String> {
        match self.values.get(column) {
            Some(D1Value::Text(value)) => Ok(value.clone()),
            Some(D1Value::Null) | None => Err(row_error(format!("missing text column {column}"))),
            Some(other) => Err(row_error(format!(
                "expected text column {column}, got {other:?}"
            ))),
        }
    }

    fn optional_text(&self, column: &str) -> AuthResult<Option<String>> {
        match self.values.get(column) {
            Some(D1Value::Text(value)) => Ok(Some(value.clone())),
            Some(D1Value::Null) | None => Ok(None),
            Some(other) => Err(row_error(format!(
                "expected optional text column {column}, got {other:?}"
            ))),
        }
    }

    fn required_i64(&self, column: &str) -> AuthResult<i64> {
        match self.values.get(column) {
            Some(D1Value::Integer(value)) => Ok(*value),
            Some(D1Value::Boolean(value)) => Ok(i64::from(*value)),
            Some(D1Value::Null) | None => {
                Err(row_error(format!("missing integer column {column}")))
            }
            Some(other) => Err(row_error(format!(
                "expected integer column {column}, got {other:?}"
            ))),
        }
    }

    fn optional_i64(&self, column: &str) -> AuthResult<Option<i64>> {
        match self.values.get(column) {
            Some(D1Value::Integer(value)) => Ok(Some(*value)),
            Some(D1Value::Boolean(value)) => Ok(Some(i64::from(*value))),
            Some(D1Value::Null) | None => Ok(None),
            Some(other) => Err(row_error(format!(
                "expected optional integer column {column}, got {other:?}"
            ))),
        }
    }

    fn required_bool(&self, column: &str) -> AuthResult<bool> {
        Ok(self.required_i64(column)? != 0)
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
pub trait D1Database: RuntimeSendSync + 'static {
    async fn execute(&self, statement: D1PreparedStatement) -> AuthResult<D1QueryResult>;
}

#[derive(Clone)]
pub struct D1DatabaseAdapter<D> {
    database: D,
    runtime: AuthRuntimeCapabilities,
}

impl<D> D1DatabaseAdapter<D> {
    /// Creates a D1 adapter backed by a Worker-compatible prepared-statement executor.
    ///
    /// Preconditions:
    /// - `database` executes statements through a Worker D1-compatible `prepare().bind()` boundary.
    /// - The D1 core migration set has already been applied.
    /// - `runtime` contains explicit Worker clock, ID, and session-token capabilities.
    ///
    /// Effects:
    /// 1. Stores the D1 executor and runtime capabilities for later adapter calls.
    ///
    /// Does not:
    /// - Open a SQLx/PostgreSQL pool.
    /// - Apply migrations.
    /// - Read time, randomness, or IDs during construction.
    ///
    /// Idempotency:
    /// - Construction is idempotent; persistence methods are not.
    pub fn new(database: D, runtime: WorkerRuntimeCapabilities) -> Self {
        Self::from_auth_runtime(database, runtime.into_auth_runtime())
    }

    pub fn from_auth_runtime(database: D, runtime: AuthRuntimeCapabilities) -> Self {
        Self { database, runtime }
    }
}

pub fn lint_d1_migration_sql(name: &str, sql: &str) -> AuthResult<()> {
    const FORBIDDEN: &[&str] = &[
        "$1",
        "TIMESTAMPTZ",
        "JSONB",
        "NOW()",
        "::",
        "CREATE EXTENSION",
        "ALTER TYPE",
        "USING gin",
        "PgPool",
        "sqlx::",
    ];

    let upper = sql.to_ascii_uppercase();
    for pattern in FORBIDDEN {
        if upper.contains(&pattern.to_ascii_uppercase()) {
            return Err(AuthError::config(format!(
                "D1 migration {name} contains forbidden syntax: {pattern}"
            )));
        }
    }

    if upper.contains("BEGIN TRANSACTION") || upper.contains("COMMIT;") {
        return Err(AuthError::config(format!(
            "D1 migration {name} must not wrap statements in an explicit transaction"
        )));
    }

    Ok(())
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> UserOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type User = User;

    async fn create_user(&self, create: CreateUser) -> AuthResult<Self::User> {
        let id = create
            .id
            .clone()
            .map_or_else(|| self.runtime.id_generator.generate_id(IdKind::User), Ok)?;
        let now = self.runtime.clock.now();
        let metadata = create
            .metadata
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let metadata_text = serde_json::to_string(&metadata)?;

        self.execute(
            D1PreparedStatement::new(
                "INSERT INTO users \
                 (id, name, email, email_verified, image, username, display_username, \
                  two_factor_enabled, role, banned, ban_reason, ban_expires, metadata, \
                  created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(create.name.as_ref())
            .bind(create.email.as_ref())
            .bind(create.email_verified.unwrap_or(false))
            .bind(create.image.as_ref())
            .bind(create.username.as_ref())
            .bind(create.display_username.as_ref())
            .bind(false)
            .bind(create.role.as_ref())
            .bind(false)
            .bind(D1Value::Null)
            .bind(D1Value::Null)
            .bind(metadata_text)
            .bind(datetime_to_ms(now))
            .bind(datetime_to_ms(now))
            .run(),
        )
        .await?;

        self.get_user_by_id(&id)
            .await?
            .ok_or_else(|| row_error("inserted user was not found"))
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<Self::User>> {
        self.query_user(
            D1PreparedStatement::new(
                "SELECT id, name, email, email_verified, image, username, display_username, \
                 two_factor_enabled, role, banned, ban_reason, ban_expires, metadata, \
                 created_at, updated_at \
                 FROM users WHERE id = ? LIMIT 1",
            )
            .bind(id)
            .first(),
        )
        .await
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<Self::User>> {
        self.query_user(
            D1PreparedStatement::new(
                "SELECT id, name, email, email_verified, image, username, display_username, \
                 two_factor_enabled, role, banned, ban_reason, ban_expires, metadata, \
                 created_at, updated_at \
                 FROM users WHERE email = ? LIMIT 1",
            )
            .bind(email)
            .first(),
        )
        .await
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<Self::User>> {
        self.query_user(
            D1PreparedStatement::new(
                "SELECT id, name, email, email_verified, image, username, display_username, \
                 two_factor_enabled, role, banned, ban_reason, ban_expires, metadata, \
                 created_at, updated_at \
                 FROM users WHERE username = ? LIMIT 1",
            )
            .bind(username)
            .first(),
        )
        .await
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<Self::User> {
        let existing = self
            .get_user_by_id(id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let now = self.runtime.clock.now();
        let email = update.email.or(existing.email);
        let name = update.name.or(existing.name);
        let image = update.image.or(existing.image);
        let username = update.username.or(existing.username);
        let display_username = update.display_username.or(existing.display_username);
        let role = update.role.or(existing.role);
        let metadata = update.metadata.unwrap_or(existing.metadata);
        let metadata_text = serde_json::to_string(&metadata)?;

        self.execute(
            D1PreparedStatement::new(
                "UPDATE users SET \
                 name = ?, email = ?, email_verified = ?, image = ?, username = ?, \
                 display_username = ?, two_factor_enabled = ?, role = ?, banned = ?, \
                 ban_reason = ?, ban_expires = ?, metadata = ?, updated_at = ? \
                 WHERE id = ?",
            )
            .bind(name.as_ref())
            .bind(email.as_ref())
            .bind(update.email_verified.unwrap_or(existing.email_verified))
            .bind(image.as_ref())
            .bind(username.as_ref())
            .bind(display_username.as_ref())
            .bind(
                update
                    .two_factor_enabled
                    .unwrap_or(existing.two_factor_enabled),
            )
            .bind(role.as_ref())
            .bind(update.banned.unwrap_or(existing.banned))
            .bind(update.ban_reason.as_ref().or(existing.ban_reason.as_ref()))
            .bind(optional_datetime_ms(
                update.ban_expires.or(existing.ban_expires),
            ))
            .bind(metadata_text)
            .bind(datetime_to_ms(now))
            .bind(id)
            .run(),
        )
        .await?;

        self.get_user_by_id(id)
            .await?
            .ok_or(AuthError::UserNotFound)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.execute(
            D1PreparedStatement::new("DELETE FROM users WHERE id = ?")
                .bind(id)
                .run(),
        )
        .await?;
        Ok(())
    }

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<Self::User>, usize)> {
        let rows = self
            .execute(
                D1PreparedStatement::new(
                    "SELECT id, name, email, email_verified, image, username, display_username, \
                     two_factor_enabled, role, banned, ban_reason, ban_expires, metadata, \
                     created_at, updated_at \
                     FROM users ORDER BY created_at DESC",
                )
                .all(),
            )
            .await?
            .into_rows();
        let mut users = rows
            .into_iter()
            .map(row_to_user)
            .collect::<AuthResult<Vec<_>>>()?;

        apply_user_filters(&mut users, &params);

        let total = users.len();
        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);
        Ok((users.into_iter().skip(offset).take(limit).collect(), total))
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> SessionOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Session = Session;

    async fn create_session(&self, create: CreateSession) -> AuthResult<Self::Session> {
        let id = create.id.clone().map_or_else(
            || self.runtime.id_generator.generate_id(IdKind::Session),
            Ok,
        )?;
        let token = create
            .token
            .clone()
            .map_or_else(|| self.runtime.session_tokens.generate_session_token(), Ok)?;
        let now = create
            .created_at
            .unwrap_or_else(|| self.runtime.clock.now());

        self.execute(
            D1PreparedStatement::new(
                "INSERT INTO sessions \
                 (id, expires_at, token, created_at, updated_at, ip_address, user_agent, user_id, \
                  impersonated_by, active_organization_id, active) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(datetime_to_ms(create.expires_at))
            .bind(&token)
            .bind(datetime_to_ms(now))
            .bind(datetime_to_ms(now))
            .bind(create.ip_address.as_ref())
            .bind(create.user_agent.as_ref())
            .bind(&create.user_id)
            .bind(create.impersonated_by.as_ref())
            .bind(create.active_organization_id.as_ref())
            .bind(true)
            .run(),
        )
        .await?;

        self.get_session(&token)
            .await?
            .ok_or_else(|| row_error("inserted session was not found"))
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Self::Session>> {
        self.query_session(
            D1PreparedStatement::new(
                "SELECT id, expires_at, token, created_at, updated_at, ip_address, user_agent, \
                 user_id, impersonated_by, active_organization_id, active \
                 FROM sessions WHERE token = ? LIMIT 1",
            )
            .bind(token)
            .first(),
        )
        .await
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Self::Session>> {
        self.execute(
            D1PreparedStatement::new(
                "SELECT id, expires_at, token, created_at, updated_at, ip_address, user_agent, \
                 user_id, impersonated_by, active_organization_id, active \
                 FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
            )
            .bind(user_id)
            .all(),
        )
        .await?
        .into_rows()
        .into_iter()
        .map(row_to_session)
        .collect()
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let now = self.runtime.clock.now();
        self.execute(
            D1PreparedStatement::new(
                "UPDATE sessions SET expires_at = ?, updated_at = ? WHERE token = ?",
            )
            .bind(datetime_to_ms(expires_at))
            .bind(datetime_to_ms(now))
            .bind(token)
            .run(),
        )
        .await?;
        Ok(())
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.execute(
            D1PreparedStatement::new("DELETE FROM sessions WHERE token = ?")
                .bind(token)
                .run(),
        )
        .await?;
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.execute(
            D1PreparedStatement::new("DELETE FROM sessions WHERE user_id = ?")
                .bind(user_id)
                .run(),
        )
        .await?;
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now_ms = datetime_to_ms(self.runtime.clock.now());
        let result = self
            .execute(
                D1PreparedStatement::new("DELETE FROM sessions WHERE expires_at <= ?")
                    .bind(now_ms)
                    .run(),
            )
            .await?;
        Ok(result.rows_affected())
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Self::Session> {
        let now = self.runtime.clock.now();
        self.execute(
            D1PreparedStatement::new(
                "UPDATE sessions SET active_organization_id = ?, updated_at = ? WHERE token = ?",
            )
            .bind(organization_id)
            .bind(datetime_to_ms(now))
            .bind(token)
            .run(),
        )
        .await?;

        self.get_session(token)
            .await?
            .ok_or(AuthError::SessionNotFound)
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> AccountOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Account = Account;

    async fn create_account(&self, create: CreateAccount) -> AuthResult<Self::Account> {
        let id = self.runtime.id_generator.generate_id(IdKind::Account)?;
        let now = self.runtime.clock.now();

        self.execute(
            D1PreparedStatement::new(
                "INSERT INTO accounts \
                 (id, account_id, provider_id, user_id, access_token, refresh_token, id_token, \
                  access_token_expires_at, refresh_token_expires_at, scope, password, \
                  created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&create.account_id)
            .bind(&create.provider_id)
            .bind(&create.user_id)
            .bind(create.access_token.as_ref())
            .bind(create.refresh_token.as_ref())
            .bind(create.id_token.as_ref())
            .bind(optional_datetime_ms(create.access_token_expires_at))
            .bind(optional_datetime_ms(create.refresh_token_expires_at))
            .bind(create.scope.as_ref())
            .bind(create.password.as_ref())
            .bind(datetime_to_ms(now))
            .bind(datetime_to_ms(now))
            .run(),
        )
        .await?;

        self.query_account_by_id(&id)
            .await?
            .ok_or_else(|| row_error("inserted account was not found"))
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<Self::Account>> {
        self.query_account(
            D1PreparedStatement::new(
                "SELECT id, account_id, provider_id, user_id, access_token, refresh_token, \
                 id_token, access_token_expires_at, refresh_token_expires_at, scope, password, \
                 created_at, updated_at \
                 FROM accounts WHERE provider_id = ? AND account_id = ? LIMIT 1",
            )
            .bind(provider)
            .bind(provider_account_id)
            .first(),
        )
        .await
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<Self::Account>> {
        self.execute(
            D1PreparedStatement::new(
                "SELECT id, account_id, provider_id, user_id, access_token, refresh_token, \
                 id_token, access_token_expires_at, refresh_token_expires_at, scope, password, \
                 created_at, updated_at \
                 FROM accounts WHERE user_id = ? ORDER BY created_at DESC",
            )
            .bind(user_id)
            .all(),
        )
        .await?
        .into_rows()
        .into_iter()
        .map(row_to_account)
        .collect()
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<Self::Account> {
        let existing = self
            .query_account_by_id(id)
            .await?
            .ok_or_else(|| AuthError::not_found("Account not found"))?;
        let now = self.runtime.clock.now();
        let access_token = update.access_token.or(existing.access_token);
        let refresh_token = update.refresh_token.or(existing.refresh_token);
        let id_token = update.id_token.or(existing.id_token);
        let scope = update.scope.or(existing.scope);
        let password = update.password.or(existing.password);

        self.execute(
            D1PreparedStatement::new(
                "UPDATE accounts SET access_token = ?, refresh_token = ?, id_token = ?, \
                 access_token_expires_at = ?, refresh_token_expires_at = ?, scope = ?, \
                 password = ?, updated_at = ? WHERE id = ?",
            )
            .bind(access_token.as_ref())
            .bind(refresh_token.as_ref())
            .bind(id_token.as_ref())
            .bind(optional_datetime_ms(
                update
                    .access_token_expires_at
                    .or(existing.access_token_expires_at),
            ))
            .bind(optional_datetime_ms(
                update
                    .refresh_token_expires_at
                    .or(existing.refresh_token_expires_at),
            ))
            .bind(scope.as_ref())
            .bind(password.as_ref())
            .bind(datetime_to_ms(now))
            .bind(id)
            .run(),
        )
        .await?;

        self.query_account_by_id(id)
            .await?
            .ok_or_else(|| AuthError::not_found("Account not found"))
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.execute(
            D1PreparedStatement::new("DELETE FROM accounts WHERE id = ?")
                .bind(id)
                .run(),
        )
        .await?;
        Ok(())
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> VerificationOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Verification = Verification;

    async fn create_verification(
        &self,
        create: CreateVerification,
    ) -> AuthResult<Self::Verification> {
        let id = self
            .runtime
            .id_generator
            .generate_id(IdKind::Verification)?;
        let now = self.runtime.clock.now();

        self.execute(
            D1PreparedStatement::new(
                "INSERT INTO verifications \
                 (id, identifier, value, expires_at, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&create.identifier)
            .bind(&create.value)
            .bind(datetime_to_ms(create.expires_at))
            .bind(datetime_to_ms(now))
            .bind(datetime_to_ms(now))
            .run(),
        )
        .await?;

        self.query_verification_by_id(&id)
            .await?
            .ok_or_else(|| row_error("inserted verification was not found"))
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        self.query_verification(
            D1PreparedStatement::new(
                "SELECT id, identifier, value, expires_at, created_at, updated_at \
                 FROM verifications WHERE identifier = ? AND value = ? LIMIT 1",
            )
            .bind(identifier)
            .bind(value)
            .first(),
        )
        .await
    }

    async fn get_verification_by_value(
        &self,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        self.query_verification(
            D1PreparedStatement::new(
                "SELECT id, identifier, value, expires_at, created_at, updated_at \
                 FROM verifications WHERE value = ? LIMIT 1",
            )
            .bind(value)
            .first(),
        )
        .await
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        self.query_verification(
            D1PreparedStatement::new(
                "SELECT id, identifier, value, expires_at, created_at, updated_at \
                 FROM verifications WHERE identifier = ? LIMIT 1",
            )
            .bind(identifier)
            .first(),
        )
        .await
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<Self::Verification>> {
        self.query_verification(
            D1PreparedStatement::new(
                "DELETE FROM verifications \
                 WHERE identifier = ? AND value = ? \
                 RETURNING id, identifier, value, expires_at, created_at, updated_at",
            )
            .bind(identifier)
            .bind(value)
            .first(),
        )
        .await
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        self.execute(
            D1PreparedStatement::new("DELETE FROM verifications WHERE id = ?")
                .bind(id)
                .run(),
        )
        .await?;
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let result = self
            .execute(
                D1PreparedStatement::new("DELETE FROM verifications WHERE expires_at <= ?")
                    .bind(datetime_to_ms(self.runtime.clock.now()))
                    .run(),
            )
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> OrganizationOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Organization = Organization;

    async fn create_organization(
        &self,
        _org: CreateOrganization,
    ) -> AuthResult<Self::Organization> {
        unsupported("organization")
    }
    async fn get_organization_by_id(&self, _id: &str) -> AuthResult<Option<Self::Organization>> {
        unsupported("organization")
    }
    async fn get_organization_by_slug(
        &self,
        _slug: &str,
    ) -> AuthResult<Option<Self::Organization>> {
        unsupported("organization")
    }
    async fn update_organization(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Self::Organization> {
        unsupported("organization")
    }
    async fn delete_organization(&self, _id: &str) -> AuthResult<()> {
        unsupported("organization")
    }
    async fn list_user_organizations(&self, _user_id: &str) -> AuthResult<Vec<Self::Organization>> {
        unsupported("organization")
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> MemberOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Member = Member;

    async fn create_member(&self, _member: CreateMember) -> AuthResult<Self::Member> {
        unsupported("organization member")
    }
    async fn get_member(
        &self,
        _organization_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<Self::Member>> {
        unsupported("organization member")
    }
    async fn get_member_by_id(&self, _id: &str) -> AuthResult<Option<Self::Member>> {
        unsupported("organization member")
    }
    async fn update_member_role(&self, _member_id: &str, _role: &str) -> AuthResult<Self::Member> {
        unsupported("organization member")
    }
    async fn delete_member(&self, _member_id: &str) -> AuthResult<()> {
        unsupported("organization member")
    }
    async fn list_organization_members(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Vec<Self::Member>> {
        unsupported("organization member")
    }
    async fn count_organization_members(&self, _organization_id: &str) -> AuthResult<usize> {
        unsupported("organization member")
    }
    async fn count_organization_owners(&self, _organization_id: &str) -> AuthResult<usize> {
        unsupported("organization member")
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> InvitationOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Invitation = Invitation;

    async fn create_invitation(
        &self,
        _invitation: CreateInvitation,
    ) -> AuthResult<Self::Invitation> {
        unsupported("invitation")
    }
    async fn get_invitation_by_id(&self, _id: &str) -> AuthResult<Option<Self::Invitation>> {
        unsupported("invitation")
    }
    async fn get_pending_invitation(
        &self,
        _organization_id: &str,
        _email: &str,
    ) -> AuthResult<Option<Self::Invitation>> {
        unsupported("invitation")
    }
    async fn update_invitation_status(
        &self,
        _id: &str,
        _status: InvitationStatus,
    ) -> AuthResult<Self::Invitation> {
        unsupported("invitation")
    }
    async fn list_organization_invitations(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Vec<Self::Invitation>> {
        unsupported("invitation")
    }
    async fn list_user_invitations(&self, _email: &str) -> AuthResult<Vec<Self::Invitation>> {
        unsupported("invitation")
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> TwoFactorOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type TwoFactor = TwoFactor;

    async fn create_two_factor(&self, _two_factor: CreateTwoFactor) -> AuthResult<Self::TwoFactor> {
        unsupported("two-factor")
    }
    async fn get_two_factor_by_user_id(
        &self,
        _user_id: &str,
    ) -> AuthResult<Option<Self::TwoFactor>> {
        unsupported("two-factor")
    }
    async fn update_two_factor_backup_codes(
        &self,
        _user_id: &str,
        _backup_codes: &str,
    ) -> AuthResult<Self::TwoFactor> {
        unsupported("two-factor")
    }
    async fn delete_two_factor(&self, _user_id: &str) -> AuthResult<()> {
        unsupported("two-factor")
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> ApiKeyOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type ApiKey = ApiKey;

    async fn create_api_key(&self, _input: CreateApiKey) -> AuthResult<Self::ApiKey> {
        unsupported("api-key")
    }
    async fn get_api_key_by_id(&self, _id: &str) -> AuthResult<Option<Self::ApiKey>> {
        unsupported("api-key")
    }
    async fn get_api_key_by_hash(&self, _hash: &str) -> AuthResult<Option<Self::ApiKey>> {
        unsupported("api-key")
    }
    async fn list_api_keys_by_user(&self, _user_id: &str) -> AuthResult<Vec<Self::ApiKey>> {
        unsupported("api-key")
    }
    async fn update_api_key(&self, _id: &str, _update: UpdateApiKey) -> AuthResult<Self::ApiKey> {
        unsupported("api-key")
    }
    async fn delete_api_key(&self, _id: &str) -> AuthResult<()> {
        unsupported("api-key")
    }
    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        unsupported("api-key")
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<D> PasskeyOps for D1DatabaseAdapter<D>
where
    D: D1Database,
{
    type Passkey = Passkey;

    async fn create_passkey(&self, _input: CreatePasskey) -> AuthResult<Self::Passkey> {
        unsupported("passkey")
    }
    async fn get_passkey_by_id(&self, _id: &str) -> AuthResult<Option<Self::Passkey>> {
        unsupported("passkey")
    }
    async fn get_passkey_by_credential_id(
        &self,
        _credential_id: &str,
    ) -> AuthResult<Option<Self::Passkey>> {
        unsupported("passkey")
    }
    async fn list_passkeys_by_user(&self, _user_id: &str) -> AuthResult<Vec<Self::Passkey>> {
        unsupported("passkey")
    }
    async fn update_passkey_counter(&self, _id: &str, _counter: u64) -> AuthResult<Self::Passkey> {
        unsupported("passkey")
    }
    async fn update_passkey_name(&self, _id: &str, _name: &str) -> AuthResult<Self::Passkey> {
        unsupported("passkey")
    }
    async fn delete_passkey(&self, _id: &str) -> AuthResult<()> {
        unsupported("passkey")
    }
}

impl<D> D1DatabaseAdapter<D>
where
    D: D1Database,
{
    async fn execute(&self, statement: D1PreparedStatement) -> AuthResult<D1QueryResult> {
        self.database.execute(statement).await
    }

    async fn query_user(&self, statement: D1PreparedStatement) -> AuthResult<Option<User>> {
        self.execute(statement)
            .await?
            .into_first()
            .map(row_to_user)
            .transpose()
    }

    async fn query_session(&self, statement: D1PreparedStatement) -> AuthResult<Option<Session>> {
        self.execute(statement)
            .await?
            .into_first()
            .map(row_to_session)
            .transpose()
    }

    async fn query_account(&self, statement: D1PreparedStatement) -> AuthResult<Option<Account>> {
        self.execute(statement)
            .await?
            .into_first()
            .map(row_to_account)
            .transpose()
    }

    async fn query_account_by_id(&self, id: &str) -> AuthResult<Option<Account>> {
        self.query_account(
            D1PreparedStatement::new(
                "SELECT id, account_id, provider_id, user_id, access_token, refresh_token, \
                 id_token, access_token_expires_at, refresh_token_expires_at, scope, password, \
                 created_at, updated_at \
                 FROM accounts WHERE id = ? LIMIT 1",
            )
            .bind(id)
            .first(),
        )
        .await
    }

    async fn query_verification(
        &self,
        statement: D1PreparedStatement,
    ) -> AuthResult<Option<Verification>> {
        self.execute(statement)
            .await?
            .into_first()
            .map(row_to_verification)
            .transpose()
    }

    async fn query_verification_by_id(&self, id: &str) -> AuthResult<Option<Verification>> {
        self.query_verification(
            D1PreparedStatement::new(
                "SELECT id, identifier, value, expires_at, created_at, updated_at \
                 FROM verifications WHERE id = ? LIMIT 1",
            )
            .bind(id)
            .first(),
        )
        .await
    }
}

fn row_to_user(row: D1Row) -> AuthResult<User> {
    let metadata_text = row.required_text("metadata")?;
    Ok(User {
        id: row.required_text("id")?,
        name: row.optional_text("name")?,
        email: row.optional_text("email")?,
        email_verified: row.required_bool("email_verified")?,
        image: row.optional_text("image")?,
        created_at: ms_to_datetime(row.required_i64("created_at")?)?,
        updated_at: ms_to_datetime(row.required_i64("updated_at")?)?,
        username: row.optional_text("username")?,
        display_username: row.optional_text("display_username")?,
        two_factor_enabled: row.required_bool("two_factor_enabled")?,
        role: row.optional_text("role")?,
        banned: row.required_bool("banned")?,
        ban_reason: row.optional_text("ban_reason")?,
        ban_expires: row
            .optional_i64("ban_expires")?
            .map(ms_to_datetime)
            .transpose()?,
        metadata: serde_json::from_str::<JsonValue>(&metadata_text)?,
    })
}

fn row_to_session(row: D1Row) -> AuthResult<Session> {
    Ok(Session {
        id: row.required_text("id")?,
        expires_at: ms_to_datetime(row.required_i64("expires_at")?)?,
        token: row.required_text("token")?,
        created_at: ms_to_datetime(row.required_i64("created_at")?)?,
        updated_at: ms_to_datetime(row.required_i64("updated_at")?)?,
        ip_address: row.optional_text("ip_address")?,
        user_agent: row.optional_text("user_agent")?,
        user_id: row.required_text("user_id")?,
        impersonated_by: row.optional_text("impersonated_by")?,
        active_organization_id: row.optional_text("active_organization_id")?,
        active: row.required_bool("active")?,
    })
}

fn row_to_account(row: D1Row) -> AuthResult<Account> {
    Ok(Account {
        id: row.required_text("id")?,
        account_id: row.required_text("account_id")?,
        provider_id: row.required_text("provider_id")?,
        user_id: row.required_text("user_id")?,
        access_token: row.optional_text("access_token")?,
        refresh_token: row.optional_text("refresh_token")?,
        id_token: row.optional_text("id_token")?,
        access_token_expires_at: row
            .optional_i64("access_token_expires_at")?
            .map(ms_to_datetime)
            .transpose()?,
        refresh_token_expires_at: row
            .optional_i64("refresh_token_expires_at")?
            .map(ms_to_datetime)
            .transpose()?,
        scope: row.optional_text("scope")?,
        password: row.optional_text("password")?,
        created_at: ms_to_datetime(row.required_i64("created_at")?)?,
        updated_at: ms_to_datetime(row.required_i64("updated_at")?)?,
    })
}

fn row_to_verification(row: D1Row) -> AuthResult<Verification> {
    Ok(Verification {
        id: row.required_text("id")?,
        identifier: row.required_text("identifier")?,
        value: row.required_text("value")?,
        expires_at: ms_to_datetime(row.required_i64("expires_at")?)?,
        created_at: ms_to_datetime(row.required_i64("created_at")?)?,
        updated_at: ms_to_datetime(row.required_i64("updated_at")?)?,
    })
}

fn apply_user_filters(users: &mut Vec<User>, params: &ListUsersParams) {
    if let Some(search_value) = &params.search_value {
        let field = params.search_field.as_deref().unwrap_or("email");
        let op = params.search_operator.as_deref().unwrap_or("contains");
        let value = search_value.to_lowercase();
        users.retain(|user| {
            let field_value = match field {
                "name" => user.name.as_deref().unwrap_or("").to_lowercase(),
                "username" => user.username.as_deref().unwrap_or("").to_lowercase(),
                "role" => user.role.as_deref().unwrap_or("").to_lowercase(),
                _ => user.email.as_deref().unwrap_or("").to_lowercase(),
            };
            matches_filter(&field_value, op, &value)
        });
    }

    if let Some(filter_value) = &params.filter_value {
        let field = params.filter_field.as_deref().unwrap_or("email");
        let op = params.filter_operator.as_deref().unwrap_or("eq");
        let value = filter_value.to_lowercase();
        users.retain(|user| {
            let field_value = match field {
                "name" => user.name.as_deref().unwrap_or("").to_lowercase(),
                "username" => user.username.as_deref().unwrap_or("").to_lowercase(),
                "role" => user.role.as_deref().unwrap_or("").to_lowercase(),
                _ => user.email.as_deref().unwrap_or("").to_lowercase(),
            };
            matches_filter(&field_value, op, &value)
        });
    }

    if let Some(sort_by) = &params.sort_by {
        let desc = params.sort_direction.as_deref() == Some("desc");
        users.sort_by(|a, b| {
            let left = match sort_by.as_str() {
                "name" => a.name.as_deref().unwrap_or("").to_string(),
                "username" => a.username.as_deref().unwrap_or("").to_string(),
                "createdAt" => a.created_at.to_rfc3339(),
                _ => a.email.as_deref().unwrap_or("").to_string(),
            };
            let right = match sort_by.as_str() {
                "name" => b.name.as_deref().unwrap_or("").to_string(),
                "username" => b.username.as_deref().unwrap_or("").to_string(),
                "createdAt" => b.created_at.to_rfc3339(),
                _ => b.email.as_deref().unwrap_or("").to_string(),
            };
            if desc {
                right.cmp(&left)
            } else {
                left.cmp(&right)
            }
        });
    }
}

fn matches_filter(value: &str, operator: &str, expected: &str) -> bool {
    match operator {
        "starts_with" => value.starts_with(expected),
        "ends_with" => value.ends_with(expected),
        "ne" => value != expected,
        "contains" => value.contains(expected),
        _ => value == expected,
    }
}

fn datetime_to_ms(value: DateTime<Utc>) -> i64 {
    value.timestamp_millis()
}

fn optional_datetime_ms(value: Option<DateTime<Utc>>) -> D1Value {
    value.map_or(D1Value::Null, |value| {
        D1Value::Integer(datetime_to_ms(value))
    })
}

fn ms_to_datetime(value: i64) -> AuthResult<DateTime<Utc>> {
    Utc.timestamp_millis_opt(value)
        .single()
        .ok_or_else(|| row_error(format!("invalid epoch milliseconds: {value}")))
}

fn unsupported<T>(feature: &str) -> AuthResult<T> {
    Err(AuthError::not_implemented(format!(
        "Worker v1 D1 adapter does not implement {feature}"
    )))
}

fn row_error(message: impl Into<String>) -> AuthError {
    AuthError::Database(DatabaseError::Query(message.into()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;

    use better_auth_core::{
        Clock, IdGenerator, OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse, SecureRandom,
        SessionTokenGenerator,
    };
    use chrono::Duration;
    use rusqlite::types::{Value, ValueRef};
    use rusqlite::{Connection, params_from_iter};

    use super::*;

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 6, 7, 1, 2, 3).unwrap()
        }
    }

    #[derive(Debug)]
    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
            dest.fill(42);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FixedIds;

    impl IdGenerator for FixedIds {
        fn generate_id(&self, kind: IdKind) -> AuthResult<String> {
            let suffix = match kind {
                IdKind::User => "user",
                IdKind::Session => "session",
                IdKind::Account => "account",
                IdKind::Verification => "verification",
                other => return Ok(format!("d1-{other:?}")),
            };
            Ok(format!("d1-{suffix}"))
        }
    }

    #[derive(Debug)]
    struct FixedSessionTokens;

    impl SessionTokenGenerator for FixedSessionTokens {
        fn generate_session_token(&self) -> AuthResult<String> {
            Ok("d1-session-token".to_string())
        }
    }

    #[derive(Debug)]
    struct FixedOAuthHttp;

    #[cfg_attr(feature = "local-futures", async_trait(?Send))]
    #[cfg_attr(not(feature = "local-futures"), async_trait)]
    impl OAuthHttpClient for FixedOAuthHttp {
        async fn send(&self, _request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
            Ok(OAuthHttpResponse::new(200, br#"{"ok":true}"#.to_vec()))
        }
    }

    #[derive(Debug)]
    struct SqliteD1 {
        connection: Mutex<Connection>,
    }

    impl SqliteD1 {
        fn migrated() -> Self {
            let connection = Connection::open_in_memory().unwrap();
            for migration in migration_files() {
                let sql = fs::read_to_string(&migration).unwrap();
                lint_d1_migration_sql(migration.to_str().unwrap(), &sql).unwrap();
                connection.execute_batch(&sql).unwrap();
            }
            Self {
                connection: Mutex::new(connection),
            }
        }

        fn execute_sync(&self, statement: D1PreparedStatement) -> AuthResult<D1QueryResult> {
            let connection = self.connection.lock().unwrap();
            let bindings = statement
                .bindings()
                .iter()
                .map(sqlite_value)
                .collect::<Vec<_>>();

            match statement.method() {
                D1StatementMethod::Run => {
                    let affected = connection
                        .execute(statement.sql(), params_from_iter(bindings.iter()))
                        .map_err(sqlite_error)?;
                    Ok(D1QueryResult::new(Vec::new(), affected))
                }
                D1StatementMethod::First | D1StatementMethod::All => {
                    let mut prepared = connection.prepare(statement.sql()).map_err(sqlite_error)?;
                    let rows = prepared
                        .query_map(params_from_iter(bindings.iter()), sqlite_row)
                        .map_err(sqlite_error)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(sqlite_error)?;
                    let rows = if statement.method() == D1StatementMethod::First {
                        rows.into_iter().take(1).collect()
                    } else {
                        rows
                    };
                    Ok(D1QueryResult::new(rows, 0))
                }
            }
        }
    }

    #[cfg_attr(feature = "local-futures", async_trait(?Send))]
    #[cfg_attr(not(feature = "local-futures"), async_trait)]
    impl D1Database for SqliteD1 {
        async fn execute(&self, statement: D1PreparedStatement) -> AuthResult<D1QueryResult> {
            self.execute_sync(statement)
        }
    }

    fn runtime() -> WorkerRuntimeCapabilities {
        WorkerRuntimeCapabilities::builder()
            .clock(shared(FixedClock))
            .secure_random(shared(FixedRandom))
            .id_generator(shared(FixedIds))
            .session_tokens(shared(FixedSessionTokens))
            .oauth_http(shared(FixedOAuthHttp))
            .build()
            .unwrap()
    }

    #[cfg(not(feature = "local-futures"))]
    fn shared<T>(value: T) -> std::sync::Arc<T> {
        std::sync::Arc::new(value)
    }

    #[cfg(feature = "local-futures")]
    fn shared<T>(value: T) -> std::rc::Rc<T> {
        std::rc::Rc::new(value)
    }

    #[test]
    fn d1_migrations_are_sqlite_and_wrangler_compatible() {
        let migrations = migration_files();
        assert!(!migrations.is_empty(), "expected D1 migrations");

        let connection = Connection::open_in_memory().unwrap();
        for migration in migrations {
            let sql = fs::read_to_string(&migration).unwrap();
            lint_d1_migration_sql(migration.to_str().unwrap(), &sql).unwrap();
            connection.execute_batch(&sql).unwrap();
        }

        assert_column_type(&connection, "users", "created_at", "INTEGER");
        assert_column_type(&connection, "users", "metadata", "TEXT");
        assert_column_type(&connection, "sessions", "expires_at", "INTEGER");
        assert_column_type(
            &connection,
            "accounts",
            "access_token_expires_at",
            "INTEGER",
        );
        assert_column_type(&connection, "verifications", "expires_at", "INTEGER");
    }

    #[tokio::test]
    async fn d1_adapter_persists_core_auth_records() {
        let adapter = D1DatabaseAdapter::new(SqliteD1::migrated(), runtime());
        let now = Utc.with_ymd_and_hms(2026, 6, 7, 1, 2, 3).unwrap();

        let user = adapter
            .create_user(CreateUser {
                id: None,
                email: Some("d1@example.com".to_string()),
                name: Some("D1 User".to_string()),
                image: None,
                email_verified: Some(true),
                password: None,
                username: Some("d1-user".to_string()),
                display_username: Some("D1".to_string()),
                role: Some("user".to_string()),
                metadata: Some(serde_json::json!({ "password_hash": "hash", "plan": "free" })),
            })
            .await
            .unwrap();

        assert_eq!(user.id, "d1-user");
        assert_eq!(user.created_at, now);
        assert_eq!(
            adapter
                .get_user_by_email("d1@example.com")
                .await
                .unwrap()
                .unwrap()
                .metadata["plan"],
            "free"
        );

        let updated = adapter
            .update_user(
                &user.id,
                UpdateUser {
                    name: Some("Updated D1 User".to_string()),
                    metadata: Some(serde_json::json!({ "password_hash": "hash2" })),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name.as_deref(), Some("Updated D1 User"));
        assert_eq!(updated.metadata["password_hash"], "hash2");

        let account = adapter
            .create_account(CreateAccount {
                user_id: user.id.clone(),
                account_id: "provider-user".to_string(),
                provider_id: "github".to_string(),
                access_token: Some("access-1".to_string()),
                refresh_token: Some("refresh-1".to_string()),
                id_token: None,
                access_token_expires_at: Some(now + Duration::hours(1)),
                refresh_token_expires_at: None,
                scope: Some("read:user".to_string()),
                password: None,
            })
            .await
            .unwrap();
        assert_eq!(
            adapter
                .get_account("github", "provider-user")
                .await
                .unwrap()
                .unwrap()
                .access_token
                .as_deref(),
            Some("access-1")
        );

        let updated_account = adapter
            .update_account(
                &account.id,
                UpdateAccount {
                    access_token: Some("access-2".to_string()),
                    scope: Some("read:org".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated_account.access_token.as_deref(), Some("access-2"));
        assert_eq!(adapter.get_user_accounts(&user.id).await.unwrap().len(), 1);
        adapter.delete_account(&account.id).await.unwrap();
        assert!(
            adapter
                .get_account("github", "provider-user")
                .await
                .unwrap()
                .is_none()
        );

        let verification = adapter
            .create_verification(CreateVerification {
                identifier: "email:d1@example.com".to_string(),
                value: "verify-token".to_string(),
                expires_at: now + Duration::minutes(10),
            })
            .await
            .unwrap();
        assert_eq!(
            adapter
                .get_verification_by_value("verify-token")
                .await
                .unwrap()
                .unwrap()
                .id,
            verification.id
        );
        assert!(
            adapter
                .consume_verification("email:d1@example.com", "verify-token")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            adapter
                .get_verification("email:d1@example.com", "verify-token")
                .await
                .unwrap()
                .is_none()
        );

        adapter
            .create_verification(CreateVerification {
                identifier: "expired".to_string(),
                value: "expired-token".to_string(),
                expires_at: now - Duration::milliseconds(1),
            })
            .await
            .unwrap();
        assert_eq!(adapter.delete_expired_verifications().await.unwrap(), 1);

        let session = adapter
            .create_session(CreateSession {
                id: None,
                token: None,
                user_id: user.id.clone(),
                created_at: None,
                expires_at: now + Duration::hours(1),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("d1-test".to_string()),
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        assert_eq!(session.token, "d1-session-token");
        assert_eq!(adapter.get_user_sessions(&user.id).await.unwrap().len(), 1);

        adapter
            .update_session_active_organization(&session.token, Some("org-1"))
            .await
            .unwrap();
        adapter
            .update_session_expiry(&session.token, now - Duration::milliseconds(1))
            .await
            .unwrap();
        assert_eq!(adapter.delete_expired_sessions().await.unwrap(), 1);
        assert!(
            adapter
                .get_session("d1-session-token")
                .await
                .unwrap()
                .is_none()
        );

        adapter.delete_user(&user.id).await.unwrap();
        assert!(adapter.get_user_by_id(&user.id).await.unwrap().is_none());
    }

    #[cfg(feature = "api-route-tests")]
    mod route_smoke {
        use std::sync::{Arc, Mutex};

        use async_trait::async_trait;
        use better_auth_api::plugins::oauth::{OAuthConfig, OAuthProvider, OAuthUserInfo};
        use better_auth_api::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
        use better_auth_core::adapters::{AccountOps, SessionOps, UserOps, VerificationOps};
        use better_auth_core::{
            AuthConfig, AuthContext, AuthPlugin, AuthResult, AuthRuntimeCapabilities,
            CreateVerification, HttpMethod, IdGenerator, OAuthHttpClient, OAuthHttpRequest,
            OAuthHttpResponse, PasswordHasher, SessionTokenGenerator, SharedOAuthHttpClient,
            SharedPasswordHasher,
        };
        use serde_json::json;

        use crate::{WorkerRequestParts, WorkerResponseParts, handle_worker_plugin_request};

        use super::*;

        #[derive(Clone)]
        struct RecordingD1 {
            inner: Arc<SqliteD1>,
            statements: Arc<Mutex<Vec<&'static str>>>,
        }

        impl RecordingD1 {
            fn migrated() -> Self {
                Self {
                    inner: Arc::new(SqliteD1::migrated()),
                    statements: Arc::new(Mutex::new(Vec::new())),
                }
            }

            fn executed_sql(&self) -> Vec<&'static str> {
                self.statements
                    .lock()
                    .expect("test D1 statement log is not poisoned")
                    .clone()
            }
        }

        #[cfg_attr(feature = "local-futures", async_trait(?Send))]
        #[cfg_attr(not(feature = "local-futures"), async_trait)]
        impl D1Database for RecordingD1 {
            async fn execute(&self, statement: D1PreparedStatement) -> AuthResult<D1QueryResult> {
                self.statements
                    .lock()
                    .expect("test D1 statement log is not poisoned")
                    .push(statement.sql());
                self.inner.as_ref().execute(statement).await
            }
        }

        type WorkerD1Context = AuthContext<D1DatabaseAdapter<RecordingD1>>;

        struct WorkerD1Harness {
            ctx: WorkerD1Context,
            d1: RecordingD1,
        }

        #[derive(Debug, Default)]
        struct IndexedIds {
            user: Mutex<usize>,
            session: Mutex<usize>,
            account: Mutex<usize>,
            verification: Mutex<usize>,
            oauth_state: Mutex<usize>,
            other: Mutex<usize>,
        }

        impl IndexedIds {
            fn next(prefix: &str, counter: &Mutex<usize>) -> AuthResult<String> {
                let mut value = counter.lock().expect("test ID lock is not poisoned");
                let id = format!("{prefix}-{}", *value);
                *value += 1;
                Ok(id)
            }
        }

        impl IdGenerator for IndexedIds {
            fn generate_id(&self, kind: IdKind) -> AuthResult<String> {
                match kind {
                    IdKind::User => Self::next("p7-user", &self.user),
                    IdKind::Session => Self::next("p7-session", &self.session),
                    IdKind::Account => Self::next("p7-account", &self.account),
                    IdKind::Verification => Self::next("p7-verification", &self.verification),
                    IdKind::OAuthState => Self::next("p7-oauth-state", &self.oauth_state),
                    _ => Self::next("p7-other", &self.other),
                }
            }
        }

        #[derive(Debug)]
        struct SequencedSessionTokens {
            prefix: &'static str,
            counter: Mutex<usize>,
        }

        impl SequencedSessionTokens {
            fn new(prefix: &'static str) -> Self {
                Self {
                    prefix,
                    counter: Mutex::new(0),
                }
            }
        }

        impl SessionTokenGenerator for SequencedSessionTokens {
            fn generate_session_token(&self) -> AuthResult<String> {
                let mut value = self
                    .counter
                    .lock()
                    .expect("test session-token lock is not poisoned");
                let token = format!("{}-{}", self.prefix, *value);
                *value += 1;
                Ok(token)
            }
        }

        #[derive(Debug)]
        struct PrefixHasher;

        #[cfg_attr(feature = "local-futures", async_trait(?Send))]
        #[cfg_attr(not(feature = "local-futures"), async_trait)]
        impl PasswordHasher for PrefixHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("worker-d1-hash:{password}"))
            }

            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                Ok(hash == format!("worker-d1-hash:{password}"))
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
                self.requests
                    .lock()
                    .expect("test OAuth HTTP lock is not poisoned")
                    .push(request.clone());

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
                    assert!(body.contains("code=worker-callback-code"));
                    assert!(body.contains(
                        "redirect_uri=https%3A%2F%2Fauth.example.test%2Fcallback%2Fgoogle"
                    ));
                    assert!(body.contains("client_id=worker-client-id"));
                    assert!(body.contains("client_secret=worker-client-secret"));
                    assert!(body.contains("code_verifier="));

                    return Ok(OAuthHttpResponse::new(
                        200,
                        r#"{"access_token":"worker-access-token","refresh_token":"worker-refresh-token","expires_in":3600,"scope":"openid email"}"#,
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
                        Some("Bearer worker-access-token")
                    );

                    return Ok(OAuthHttpResponse::new(
                        200,
                        r#"{"sub":"worker-provider-user","email":"worker-oauth@example.com","name":"Worker OAuth User","email_verified":true}"#,
                    ));
                }

                Err(AuthError::internal(format!(
                    "unexpected OAuth HTTP request to {}",
                    request.url
                )))
            }
        }

        fn worker_config(runtime: AuthRuntimeCapabilities) -> AuthConfig {
            AuthConfig::new("test-secret-key-at-least-32-chars-long")
                .base_url("https://auth.example.test")
                .runtime_capabilities(runtime)
        }

        fn runtime_with_oauth_http(
            oauth_http: SharedOAuthHttpClient,
            session_token_prefix: &'static str,
        ) -> AuthRuntimeCapabilities {
            AuthRuntimeCapabilities::new(
                shared(FixedClock),
                shared(FixedRandom),
                shared(IndexedIds::default()),
                shared(SequencedSessionTokens::new(session_token_prefix)),
                oauth_http,
            )
        }

        fn context(
            oauth_http: SharedOAuthHttpClient,
            session_token_prefix: &'static str,
        ) -> WorkerD1Harness {
            let runtime = runtime_with_oauth_http(oauth_http, session_token_prefix);
            let config = worker_config(runtime.clone());
            let d1 = RecordingD1::migrated();
            let adapter = D1DatabaseAdapter::from_auth_runtime(d1.clone(), runtime);
            let ctx = AuthContext::new(Arc::new(config), Arc::new(adapter));
            WorkerD1Harness { ctx, d1 }
        }

        fn prefix_hasher() -> SharedPasswordHasher {
            shared(PrefixHasher)
        }

        async fn route<P>(
            plugin: &P,
            request: WorkerRequestParts,
            ctx: &WorkerD1Context,
        ) -> WorkerResponseParts
        where
            P: AuthPlugin<D1DatabaseAdapter<RecordingD1>>,
        {
            handle_worker_plugin_request(plugin, request, ctx)
                .await
                .expect("worker route succeeds")
                .expect("plugin handles worker request")
        }

        #[tokio::test(flavor = "current_thread")]
        async fn worker_email_password_session_flow_uses_explicit_effects() {
            let harness = context(shared(FixedOAuthHttp), "p7-email-session");
            let ctx = &harness.ctx;
            let email_plugin = EmailPasswordPlugin::new().password_hasher(prefix_hasher());
            let session_plugin = SessionManagementPlugin::new();

            let signup_response = route(
                &email_plugin,
                WorkerRequestParts::new(
                    HttpMethod::Post,
                    "https://auth.example.test/sign-up/email?callbackURL=%2Fdashboard",
                )
                .with_header("Content-Type", "application/json")
                .with_body(
                    json!({
                        "name": "Worker D1 User",
                        "email": "worker-d1@example.com",
                        "password": "Password123!"
                    })
                    .to_string()
                    .into_bytes(),
                ),
                &ctx,
            )
            .await;
            assert_eq!(signup_response.status(), 200);
            assert!(
                signup_response
                    .header("set-cookie")
                    .expect("sign-up sets a session cookie")
                    .contains("better-auth.session-token=p7-email-session-0")
            );
            let signup_body: serde_json::Value =
                serde_json::from_slice(signup_response.body()).unwrap();
            assert_eq!(signup_body["token"], "p7-email-session-0");
            assert_eq!(signup_body["user"]["id"], "p7-user-0");

            let error_response = route(
                &email_plugin,
                WorkerRequestParts::new(HttpMethod::Post, "/sign-up/email")
                    .with_header("Content-Type", "application/json")
                    .with_body(json!({ "email": "missing-fields@example.com" }).to_string()),
                &ctx,
            )
            .await;
            assert_eq!(error_response.status(), 400);
            assert_eq!(
                error_response.header("content-type"),
                Some("application/json")
            );
            let error_body: serde_json::Value =
                serde_json::from_slice(error_response.body()).unwrap();
            assert!(error_body["message"].is_string());

            let signin_response = route(
                &email_plugin,
                WorkerRequestParts::new(HttpMethod::Post, "/sign-in/email")
                    .with_header("Content-Type", "application/json")
                    .with_body(
                        json!({
                            "email": "worker-d1@example.com",
                            "password": "Password123!"
                        })
                        .to_string(),
                    ),
                &ctx,
            )
            .await;
            assert_eq!(signin_response.status(), 200);
            let signin_body: serde_json::Value =
                serde_json::from_slice(signin_response.body()).unwrap();
            assert_eq!(signin_body["token"], "p7-email-session-1");

            let get_session_response = route(
                &session_plugin,
                WorkerRequestParts::new(HttpMethod::Get, "/get-session")
                    .with_header("Authorization", "Bearer p7-email-session-1"),
                &ctx,
            )
            .await;
            assert_eq!(get_session_response.status(), 200);
            let session_body: serde_json::Value =
                serde_json::from_slice(get_session_response.body()).unwrap();
            assert_eq!(session_body["session"]["token"], "p7-email-session-1");
            assert_eq!(session_body["user"]["email"], "worker-d1@example.com");

            let verification = ctx
                .database
                .create_verification(CreateVerification {
                    identifier: "oauth:p7-consume-watch".to_string(),
                    value: "watch-value".to_string(),
                    expires_at: ctx.config.runtime.clock.now() + Duration::minutes(10),
                })
                .await
                .unwrap();
            let consumed = ctx
                .database
                .consume_verification("oauth:p7-consume-watch", "watch-value")
                .await
                .unwrap()
                .expect("verification consume returns the deleted row");
            assert_eq!(consumed.id, verification.id);
            assert!(
                ctx.database
                    .get_verification("oauth:p7-consume-watch", "watch-value")
                    .await
                    .unwrap()
                    .is_none()
            );

            let signout_response = route(
                &session_plugin,
                WorkerRequestParts::new(HttpMethod::Post, "/sign-out")
                    .with_header("Authorization", "Bearer p7-email-session-1")
                    .with_body("{}"),
                &ctx,
            )
            .await;
            assert_eq!(signout_response.status(), 200);
            assert!(
                signout_response
                    .header("set-cookie")
                    .expect("sign-out clears the session cookie")
                    .contains("better-auth.session-token=")
            );
            assert!(
                ctx.database
                    .get_session("p7-email-session-1")
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn worker_oauth_uses_fetch_port_and_userinfo() {
            let http = shared(RecordingOAuthHttp::default());
            let harness = context(http.clone(), "p7-oauth-session");
            let ctx = &harness.ctx;
            let plugin = OAuthPlugin::with_config(oauth_config());

            let sign_in_response = route(
                &plugin,
                WorkerRequestParts::new(HttpMethod::Post, "/sign-in/social")
                    .with_header("Content-Type", "application/json")
                    .with_body(
                        json!({
                            "provider": "google",
                            "callback_url": "https://auth.example.test/callback/google"
                        })
                        .to_string(),
                    ),
                &ctx,
            )
            .await;
            assert_eq!(sign_in_response.status(), 200);
            let sign_in_body: serde_json::Value =
                serde_json::from_slice(sign_in_response.body()).unwrap();
            let authorization_url = sign_in_body["url"]
                .as_str()
                .expect("sign-in response includes authorization URL");
            assert!(authorization_url.contains("https://provider.test/auth"));
            assert!(authorization_url.contains("state=p7-oauth-state-0"));

            let callback_response = route(
                &plugin,
                WorkerRequestParts::new(
                    HttpMethod::Get,
                    "/callback/google?code=worker-callback-code&state=p7-oauth-state-0",
                ),
                &ctx,
            )
            .await;
            assert_eq!(callback_response.status(), 200);
            assert!(
                callback_response
                    .header("set-cookie")
                    .expect("OAuth callback sets a session cookie")
                    .contains("better-auth.session-token=p7-oauth-session-0")
            );
            let callback_body: serde_json::Value =
                serde_json::from_slice(callback_response.body()).unwrap();
            assert_eq!(callback_body["token"], "p7-oauth-session-0");

            let user = ctx
                .database
                .get_user_by_email("worker-oauth@example.com")
                .await
                .unwrap()
                .expect("OAuth callback creates a user");
            assert_eq!(user.id, "p7-user-0");

            let account = ctx
                .database
                .get_account("google", "worker-provider-user")
                .await
                .unwrap()
                .expect("OAuth callback links provider account");
            assert_eq!(account.user_id, user.id);

            let session = ctx
                .database
                .get_session("p7-oauth-session-0")
                .await
                .unwrap()
                .expect("OAuth callback creates a session");
            assert_eq!(session.user_id, user.id);

            assert!(
                ctx.database
                    .get_verification_by_identifier("oauth:p7-oauth-state-0")
                    .await
                    .unwrap()
                    .is_none(),
                "OAuth callback removes consumed D1 state"
            );
            assert!(
                harness.d1.executed_sql().iter().any(|sql| {
                    sql.contains("DELETE FROM verifications") && sql.contains("RETURNING")
                }),
                "OAuth callback consumes D1 state through consume_verification"
            );
            assert_eq!(
                http.requests
                    .lock()
                    .expect("test OAuth HTTP lock is not poisoned")
                    .len(),
                2
            );
        }

        fn oauth_config() -> OAuthConfig {
            let mut config = OAuthConfig::default();
            config.providers.insert(
                "google".to_string(),
                OAuthProvider {
                    client_id: "worker-client-id".to_string(),
                    client_secret: "worker-client-secret".to_string(),
                    auth_url: "https://provider.test/auth".to_string(),
                    token_url: "https://provider.test/token".to_string(),
                    user_info_url: "https://provider.test/userinfo".to_string(),
                    scopes: vec!["openid".to_string(), "email".to_string()],
                    map_user_info: map_google_user_info,
                },
            );
            config
        }

        fn map_google_user_info(value: serde_json::Value) -> Result<OAuthUserInfo, String> {
            Ok(OAuthUserInfo {
                id: value["sub"].as_str().ok_or("missing sub")?.to_string(),
                email: value["email"].as_str().ok_or("missing email")?.to_string(),
                name: value["name"].as_str().map(String::from),
                image: value["picture"].as_str().map(String::from),
                email_verified: value["email_verified"].as_bool().unwrap_or(false),
            })
        }
    }

    fn migration_files() -> Vec<std::path::PathBuf> {
        let mut migrations = fs::read_dir(Path::new(D1_MIGRATIONS_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
            .collect::<Vec<_>>();
        migrations.sort();
        migrations
    }

    fn assert_column_type(connection: &Connection, table: &str, column: &str, expected: &str) {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let actual = columns
            .iter()
            .find_map(|(name, ty)| (name == column).then_some(ty.as_str()))
            .unwrap_or_else(|| panic!("missing column {table}.{column}"));
        assert_eq!(actual, expected);
    }

    fn sqlite_value(value: &D1Value) -> Value {
        match value {
            D1Value::Null => Value::Null,
            D1Value::Integer(value) => Value::Integer(*value),
            D1Value::Real(value) => Value::Real(*value),
            D1Value::Text(value) => Value::Text(value.clone()),
            D1Value::Boolean(value) => Value::Integer(i64::from(*value)),
        }
    }

    fn sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<D1Row> {
        let mut values = BTreeMap::new();
        let row_ref = row.as_ref();
        for index in 0..row_ref.column_count() {
            let name = row_ref.column_name(index)?.to_string();
            let value = match row.get_ref(index)? {
                ValueRef::Null => D1Value::Null,
                ValueRef::Integer(value) => D1Value::Integer(value),
                ValueRef::Real(value) => D1Value::Real(value),
                ValueRef::Text(value) => D1Value::Text(String::from_utf8_lossy(value).to_string()),
                ValueRef::Blob(_) => D1Value::Null,
            };
            values.insert(name, value);
        }
        Ok(D1Row::new(values))
    }

    fn sqlite_error(error: rusqlite::Error) -> AuthError {
        AuthError::Database(DatabaseError::Query(error.to_string()))
    }
}
