//! OpenID Connect provider domain model and storage ports.
//!
//! Gated behind the `oidc-provider` feature. Holds the pure value objects and
//! persistence records ([`model`]) and the storage port traits ([`store`]) that
//! the OIDC provider plugin and the SQLx / D1 / memory adapters build on. The
//! signing effect ports (`JwtSigner`, `JwksProvider`) live in
//! [`crate::capabilities`] because they are always-present runtime capabilities
//! with `Unavailable*` defaults, like the other effect ports.

pub mod model;
pub mod store;

pub use model::{
    AccessToken, AccessTokenHash, AccessTokenRecord, AuthorizationCode, AuthorizationCodeRecord,
    ClientId, ClientType, CodeChallenge, CodeChallengeMethod, CodeVerifier, GrantType, Issuer,
    NewAccessToken, NewAuthorizationCode, Nonce, OAuthClient, RedirectUri, ResponseType, Scope,
    ScopeSet, State, SubjectId, TokenEndpointAuthMethod, TokenType,
};
pub use store::{
    AccessTokenOps, AuthorizationCodeOps, OAuthClientOps, OidcProviderStore,
};
