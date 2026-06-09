//! Validated request value objects for the authorize and token endpoints.
//!
//! These represent the post-parse, typed form of an incoming request. Raw query
//! and body parsing happens in the handler (P3); the pure decisions in
//! [`super::decide`] operate only on these typed values.

use chrono::{DateTime, Utc};

use better_auth_core::{
    AuthorizationCode, ClientId, CodeChallenge, CodeChallengeMethod, CodeVerifier, Nonce,
    RedirectUri, ScopeSet, State, SubjectId,
};

use super::error::OAuthError;

/// The v1 `prompt` parameter modes. `Default` represents an absent parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptMode {
    Default,
    None,
    Login,
}

/// Parses the optional `prompt` parameter, rejecting unsupported values.
pub fn parse_prompt(raw: Option<&str>) -> Result<PromptMode, OAuthError> {
    match raw {
        None => Ok(PromptMode::Default),
        Some("none") => Ok(PromptMode::None),
        Some("login") => Ok(PromptMode::Login),
        Some(other) => Err(OAuthError::invalid_request(format!(
            "unsupported prompt value: {other}"
        ))),
    }
}

/// An authenticated end-user subject derived from the better-auth session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSubject {
    pub subject: SubjectId,
    /// Session creation time, exposed as the id_token `auth_time`.
    pub auth_time: DateTime<Utc>,
}

/// A validated authorize request. `redirect_uri` is already exact-match validated
/// against the client (P0 rule) before a decision is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub client_id: ClientId,
    pub redirect_uri: RedirectUri,
    pub scope: ScopeSet,
    pub code_challenge: CodeChallenge,
    pub code_challenge_method: CodeChallengeMethod,
    pub nonce: Option<Nonce>,
    pub state: Option<State>,
    pub prompt: PromptMode,
}

/// A validated token endpoint request for the `authorization_code` grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRequest {
    pub client_id: ClientId,
    pub code: AuthorizationCode,
    pub redirect_uri: RedirectUri,
    pub code_verifier: Option<CodeVerifier>,
    /// Present for confidential clients authenticating by secret.
    pub client_secret: Option<String>,
}
