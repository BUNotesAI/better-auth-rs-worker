//! OpenID Connect provider plugin (provider side / authorization server).
//!
//! Pure protocol logic gated behind the `oidc-provider` feature. The domain
//! value objects, persistence records, and storage ports live in
//! `better-auth-core` (`oidc` module). This plugin owns the protocol rules,
//! error mapping, claims projection, and discovery document assembly. Later
//! phases add the pure authorize/token decisions, the endpoint handlers, and the
//! hand-written `AuthPlugin` implementation generic over
//! `DB: DatabaseAdapter + OidcProviderStore`.
//!
//! This provider plugin is intentionally isolated from the social-login OAuth
//! client plugin (`crate::plugins::oauth`): the two share no request, handler,
//! or config types.

pub mod claims;
pub mod decide;
pub mod discovery;
pub mod error;
pub mod jws;
pub mod requests;
pub mod rules;
pub mod token;

#[cfg(test)]
mod tests;
