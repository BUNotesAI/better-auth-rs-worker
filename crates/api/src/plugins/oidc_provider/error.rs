//! Typed OAuth2 / OIDC provider errors and their standard response mapping.
//!
//! Replaces the stringly `AuthError::bad_request("invalid_grant")` style with a
//! typed error whose wire `error` code, HTTP status, `error_description`, and
//! `WWW-Authenticate` challenge are all derived from the variant. The exhaustive
//! mapping means a new error code cannot be added without also deciding its
//! response shape.

use serde_json::{Value, json};

/// Standard OAuth2 / OIDC error codes (RFC 6749 §4.1.2.1 / §5.2, OIDC Core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    AccessDenied,
    LoginRequired,
    InvalidToken,
    ServerError,
}

impl OAuthErrorCode {
    /// The wire `error` value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::InvalidToken => "invalid_token",
            Self::ServerError => "server_error",
        }
    }

    /// HTTP status for a direct (non-redirect) error response.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest
            | Self::InvalidGrant
            | Self::UnauthorizedClient
            | Self::UnsupportedGrantType
            | Self::UnsupportedResponseType
            | Self::InvalidScope => 400,
            Self::InvalidClient | Self::LoginRequired | Self::InvalidToken => 401,
            Self::AccessDenied => 403,
            Self::ServerError => 500,
        }
    }
}

/// A typed provider error carrying a standard code and a human description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    code: OAuthErrorCode,
    description: String,
}

impl OAuthError {
    /// Builds an error from a code and description.
    #[must_use]
    pub fn new(code: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }

    /// The error code.
    #[must_use]
    pub fn code(&self) -> &OAuthErrorCode {
        &self.code
    }

    /// The wire `error` value.
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// The human-readable `error_description`.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// HTTP status for a direct (non-redirect) error response.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    /// The standard `{error, error_description}` JSON body.
    #[must_use]
    pub fn to_body(&self) -> Value {
        json!({
            "error": self.code.as_str(),
            "error_description": self.description,
        })
    }

    /// The `WWW-Authenticate` challenge for bearer-token failures, if any.
    #[must_use]
    pub fn www_authenticate(&self) -> Option<String> {
        match self.code {
            OAuthErrorCode::InvalidToken => Some(format!(
                "Bearer error=\"{}\", error_description=\"{}\"",
                self.code.as_str(),
                self.description
            )),
            _ => None,
        }
    }
}

macro_rules! oauth_error_ctors {
    ($($ctor:ident => $variant:ident),+ $(,)?) => {
        impl OAuthError {
            $(
                #[doc = concat!("Builds an `", stringify!($variant), "` error.")]
                #[must_use]
                pub fn $ctor(description: impl Into<String>) -> Self {
                    Self::new(OAuthErrorCode::$variant, description)
                }
            )+
        }
    };
}

oauth_error_ctors! {
    invalid_request => InvalidRequest,
    invalid_client => InvalidClient,
    invalid_grant => InvalidGrant,
    unauthorized_client => UnauthorizedClient,
    unsupported_grant_type => UnsupportedGrantType,
    unsupported_response_type => UnsupportedResponseType,
    invalid_scope => InvalidScope,
    access_denied => AccessDenied,
    login_required => LoginRequired,
    invalid_token => InvalidToken,
    server_error => ServerError,
}
