#![warn(clippy::too_many_lines)]
//! # Better Auth API
//!
//! Plugin implementations for the Better Auth authentication framework.

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!(
    "features `native-tls` and `rustls` are mutually exclusive. \
     Enable exactly one of them: \
     for `native-tls` (default), remove the `rustls` feature; \
     for `rustls`, set `default-features = false, features = [\"rustls\"]`."
);

pub mod plugins;

pub use plugins::account_management::AccountManagementPlugin;
#[cfg(feature = "api-key")]
pub use plugins::api_key::{ApiKeyConfig, ApiKeyPlugin};
#[cfg(feature = "device-authorization")]
pub use plugins::device_authorization::{DeviceAuthorizationConfig, DeviceAuthorizationPlugin};
pub use plugins::email_password::EmailPasswordPlugin;
#[cfg(feature = "email-verification")]
pub use plugins::email_verification::EmailVerificationPlugin;
pub use plugins::oauth::OAuthPlugin;
#[cfg(feature = "oidc-provider")]
pub use plugins::oidc_provider::{LoginRedirectHook, OidcProviderConfig, OidcProviderPlugin};
#[cfg(feature = "passkey")]
pub use plugins::passkey::{PasskeyConfig, PasskeyPlugin};
#[cfg(feature = "password-management")]
pub use plugins::password_management::PasswordManagementPlugin;
pub use plugins::session_management::SessionManagementPlugin;
#[cfg(feature = "two-factor")]
pub use plugins::two_factor::TwoFactorPlugin;
