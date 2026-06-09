//! Pure OIDC provider domain types: value objects and persistence records.
//!
//! These types are framework-agnostic and contain no time, randomness, I/O, or
//! database access. They are gated behind the `oidc-provider` feature and are
//! shared by the OIDC provider plugin (rules and decisions) and by the storage
//! adapters that implement [`crate::oidc::store::OidcProviderStore`].
//!
//! Value objects validate their structural and domain invariants in `parse`
//! constructors and keep their inner representation private, so callers cannot
//! build an invalid value. Protocol error codes (`invalid_scope`,
//! `invalid_request`, ...) are decided by the provider plugin, not here; these
//! constructors only report whether a value is structurally valid.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{AuthError, AuthResult};

/// Registered OAuth2 / OIDC client identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId(String);

impl ClientId {
    /// Parses a non-empty client identifier.
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        if raw.trim().is_empty() {
            return Err(AuthError::validation("client_id must not be empty"));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authenticated end-user subject identifier (`sub`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectId(String);

impl SubjectId {
    /// Parses a non-empty subject identifier.
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(AuthError::validation("subject id must not be empty"));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// OIDC issuer identifier, derived from the configured base URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(String);

impl Issuer {
    /// Parses an absolute issuer URL with no trailing slash.
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        let parsed = url::Url::parse(&raw)
            .map_err(|e| AuthError::validation(format!("issuer must be an absolute URL: {e}")))?;
        if parsed.cannot_be_a_base() {
            return Err(AuthError::validation("issuer must be an absolute URL"));
        }
        Ok(Self(raw.trim_end_matches('/').to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Absolute redirect URI registered with a client.
///
/// Matching at the authorization endpoint is exact (RFC 6749 §3.1.2.3 simple
/// string comparison); this type therefore preserves the original string and
/// compares by value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// Parses an absolute redirect URI (must have a scheme and not be relative).
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        let parsed = url::Url::parse(&raw).map_err(|e| {
            AuthError::validation(format!("redirect_uri must be an absolute URI: {e}"))
        })?;
        if parsed.cannot_be_a_base() {
            return Err(AuthError::validation("redirect_uri must be absolute"));
        }
        if parsed.fragment().is_some() {
            return Err(AuthError::validation("redirect_uri must not contain a fragment"));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A single OAuth2 scope token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Scope(String);

impl Scope {
    /// The mandatory OIDC scope.
    pub const OPENID: &'static str = "openid";
    /// Standard profile-claims scope.
    pub const PROFILE: &'static str = "profile";
    /// Standard email-claims scope.
    pub const EMAIL: &'static str = "email";

    /// Parses a single non-empty scope token (no internal whitespace).
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        if raw.is_empty() || raw.split_whitespace().count() != 1 {
            return Err(AuthError::validation("scope token must be a single word"));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated set of requested or granted scopes.
///
/// Invariant: the set always contains `openid`. Tokens are stored sorted and
/// de-duplicated so serialization is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSet(Vec<Scope>);

impl ScopeSet {
    /// Parses a space-delimited scope string, enforcing the `openid` invariant.
    pub fn parse(raw: &str) -> AuthResult<Self> {
        let mut scopes: Vec<Scope> = raw
            .split_whitespace()
            .map(Scope::parse)
            .collect::<AuthResult<Vec<_>>>()?;
        scopes.sort();
        scopes.dedup();
        Self::from_scopes(scopes)
    }

    /// Builds a scope set from already-parsed scopes, enforcing `openid`.
    pub fn from_scopes(mut scopes: Vec<Scope>) -> AuthResult<Self> {
        scopes.sort();
        scopes.dedup();
        if !scopes.iter().any(|s| s.as_str() == Scope::OPENID) {
            return Err(AuthError::validation("scope must include openid"));
        }
        Ok(Self(scopes))
    }

    /// Returns whether the set contains the given scope token.
    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|s| s.as_str() == scope)
    }

    /// Iterates the scope tokens in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }

    /// Renders the set as a space-delimited scope string.
    #[must_use]
    pub fn as_space_delimited(&self) -> String {
        self.0
            .iter()
            .map(Scope::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// PKCE code challenge (base64url of the SHA-256 of the verifier, for S256).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// Parses a non-empty code challenge.
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(AuthError::validation("code_challenge must not be empty"));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// PKCE code verifier presented at the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeVerifier(String);

impl CodeVerifier {
    /// Parses a code verifier within the RFC 7636 length bounds (43..=128).
    pub fn parse(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        let len = raw.len();
        if !(43..=128).contains(&len) {
            return Err(AuthError::validation(
                "code_verifier length must be between 43 and 128 characters",
            ));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// PKCE challenge method. v1 supports `S256` only; `plain` is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// SHA-256 challenge transformation.
    S256,
}

impl CodeChallengeMethod {
    /// Parses a challenge method, rejecting `plain` and unknown values.
    pub fn parse(raw: &str) -> AuthResult<Self> {
        match raw {
            "S256" => Ok(Self::S256),
            other => Err(AuthError::validation(format!(
                "unsupported code_challenge_method: {other}"
            ))),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::S256 => "S256",
        }
    }
}

/// OAuth2 response type. v1 supports the authorization-code flow only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// Authorization code grant.
    Code,
}

impl ResponseType {
    /// Parses a response type, rejecting anything other than `code`.
    pub fn parse(raw: &str) -> AuthResult<Self> {
        match raw {
            "code" => Ok(Self::Code),
            other => Err(AuthError::validation(format!(
                "unsupported response_type: {other}"
            ))),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Code => "code",
        }
    }
}

/// OAuth2 grant type supported by the provider in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    /// `authorization_code` grant.
    AuthorizationCode,
}

impl GrantType {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::AuthorizationCode => "authorization_code",
        }
    }

    /// Parses a stored grant type string.
    pub fn parse(raw: &str) -> AuthResult<Self> {
        match raw {
            "authorization_code" => Ok(Self::AuthorizationCode),
            other => Err(AuthError::validation(format!("unknown grant_type: {other}"))),
        }
    }
}

/// Client confidentiality classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientType {
    /// Public client; authenticated by PKCE, holds no secret.
    Public,
    /// Confidential client; authenticated by a client secret.
    Confidential,
}

impl ClientType {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Public => "public",
            Self::Confidential => "confidential",
        }
    }

    /// Parses a stored client type string.
    pub fn parse(raw: &str) -> AuthResult<Self> {
        match raw {
            "public" => Ok(Self::Public),
            "confidential" => Ok(Self::Confidential),
            other => Err(AuthError::validation(format!("unknown client_type: {other}"))),
        }
    }
}

/// Token endpoint client authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenEndpointAuthMethod {
    /// HTTP Basic with client_id/client_secret.
    ClientSecretBasic,
    /// client_id/client_secret in the request body.
    ClientSecretPost,
    /// No client authentication (public clients).
    None,
}

impl TokenEndpointAuthMethod {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::None => "none",
        }
    }

    /// Parses a stored token endpoint auth method string.
    pub fn parse(raw: &str) -> AuthResult<Self> {
        match raw {
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "none" => Ok(Self::None),
            other => Err(AuthError::validation(format!(
                "unknown token_endpoint_auth_method: {other}"
            ))),
        }
    }
}

/// Issued opaque access token (the secret returned to the client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken(String);

impl AccessToken {
    /// Wraps an already-generated opaque token value.
    #[must_use]
    pub fn from_raw(raw: String) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Hash of an access token, the only form persisted at rest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessTokenHash(String);

impl AccessTokenHash {
    /// Wraps an already-computed token hash.
    #[must_use]
    pub fn from_hash(hash: String) -> Self {
        Self(hash)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Issued opaque authorization code.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
    /// Wraps an already-generated authorization code value.
    #[must_use]
    pub fn from_raw(raw: String) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque `nonce` echoed into the id_token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce(String);

impl Nonce {
    /// Wraps a client-supplied nonce value.
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque `state` round-tripped back to the client redirect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State(String);

impl State {
    /// Wraps a client-supplied state value.
    #[must_use]
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// OAuth2 token type. v1 issues bearer tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// `Bearer` token type.
    Bearer,
}

impl TokenType {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Bearer => "Bearer",
        }
    }
}

/// A registered OAuth2 / OIDC client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    pub client_id: ClientId,
    pub client_type: ClientType,
    pub redirect_uris: Vec<RedirectUri>,
    pub allowed_scopes: ScopeSet,
    pub allowed_grant_types: Vec<GrantType>,
    /// Present only for confidential clients; stores a hash, never a raw secret.
    pub secret_hash: Option<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
}

/// Input for persisting a freshly issued authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuthorizationCode {
    pub code: AuthorizationCode,
    pub client_id: ClientId,
    pub subject: SubjectId,
    pub redirect_uri: RedirectUri,
    pub scope: ScopeSet,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: Option<Nonce>,
    pub auth_time: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A stored authorization code returned by an atomic consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRecord {
    pub code: AuthorizationCode,
    pub client_id: ClientId,
    pub subject: SubjectId,
    pub redirect_uri: RedirectUri,
    pub scope: ScopeSet,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: Option<Nonce>,
    pub auth_time: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Input for persisting a freshly issued access token (hash at rest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccessToken {
    pub token_hash: AccessTokenHash,
    pub client_id: ClientId,
    pub subject: SubjectId,
    pub scope: ScopeSet,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// A stored access token, looked up by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    pub token_hash: AccessTokenHash,
    pub client_id: ClientId,
    pub subject: SubjectId,
    pub scope: ScopeSet,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
