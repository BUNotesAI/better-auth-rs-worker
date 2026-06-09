#![warn(clippy::too_many_lines)]
//! # Better Auth Core
//!
//! Core abstractions for the Better Auth authentication framework.
//! Contains traits, types, configuration, and error handling.

#[cfg(all(feature = "axum", feature = "local-futures"))]
compile_error!(
    "`axum` requires Send futures and is mutually exclusive with `local-futures`; build native Axum and Worker local-futures targets separately"
);

pub mod adapters;
pub mod capabilities;
pub mod config;
pub mod email;
pub mod entity;
pub mod error;
#[cfg(all(feature = "axum", not(feature = "local-futures")))]
pub mod extractors;
pub mod hooks;
pub mod middleware;
#[cfg(feature = "oidc-provider")]
pub mod oidc;
pub mod openapi;
pub mod plugin;
pub mod session;
pub mod threading;
pub mod types;
pub mod types_impls;
pub mod types_org;
pub mod utils;

// Re-export derive macros when the `derive` feature is enabled
#[cfg(feature = "derive")]
pub use better_auth_derive::*;

// Re-export commonly used items
pub use adapters::{
    AccountOps, ApiKeyOps, CacheAdapter, DatabaseAdapter, InvitationOps, MemberOps, MemoryAccount,
    MemoryApiKey, MemoryCacheAdapter, MemoryDatabaseAdapter, MemoryInvitation, MemoryMember,
    MemoryOrganization, MemoryPasskey, MemorySession, MemoryTwoFactor, MemoryUser,
    MemoryVerification, NativeDatabaseAdapter, OrganizationOps, PasskeyOps, SessionOps,
    TwoFactorOps, UserOps, VerificationOps,
};
#[cfg(feature = "sqlx-postgres")]
pub use adapters::{SqlxAdapter, SqlxEntity};
pub use capabilities::{
    AuthRuntimeCapabilities, Clock, DynClock, DynIdGenerator, DynJwksProvider, DynJwtSigner,
    DynOAuthHttpClient, DynSecureRandom, DynSessionTokenGenerator, IdGenerator, IdKind, Jwk, JwkSet,
    JwksProvider, JwtSigner, KeyId, LocalRuntimeCapabilitiesDyn, NativeDynClock,
    NativeDynIdGenerator, NativeDynJwksProvider, NativeDynJwtSigner, NativeDynOAuthHttpClient,
    NativeDynSecureRandom, NativeDynSessionTokenGenerator, NativeRuntimeCapabilitiesDyn,
    OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse, RuntimeCapabilities, SecureRandom,
    SessionTokenGenerator, SharedClock, SharedIdGenerator, SharedJwksProvider, SharedJwtSigner,
    SharedOAuthHttpClient, SharedSecureRandom, SharedSessionTokenGenerator, SigningAlg,
    StaticJwksProvider,
};
#[cfg(feature = "oidc-provider")]
pub use oidc::{
    AccessToken, AccessTokenHash, AccessTokenOps, AccessTokenRecord, AuthorizationCode,
    AuthorizationCodeOps, AuthorizationCodeRecord, ClientId, ClientType, CodeChallenge,
    CodeChallengeMethod, CodeVerifier, GrantType, Issuer, NewAccessToken, NewAuthorizationCode,
    Nonce, OAuthClient, OAuthClientOps, OidcProviderStore, RedirectUri, ResponseType, Scope,
    ScopeSet, State, SubjectId, TokenEndpointAuthMethod, TokenType,
};
#[cfg(feature = "p256-signer")]
pub use oidc::P256JwtSigner;
pub use config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, Argon2Config,
    AuthConfig, CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride,
    CrossSubDomainConfig, IpAddressConfig, JwtConfig, PasswordConfig, SameSite, SessionConfig,
    core_paths, extract_origin,
};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthAccountMeta, AuthApiKey, AuthApiKeyMeta, AuthInvitation, AuthInvitationMeta,
    AuthMember, AuthMemberMeta, AuthOrganization, AuthOrganizationMeta, AuthPasskey,
    AuthPasskeyMeta, AuthSession, AuthSessionMeta, AuthTwoFactor, AuthTwoFactorMeta, AuthUser,
    AuthUserMeta, AuthVerification, AuthVerificationMeta, MemberUserView, PASSWORD_HASH_KEY,
};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
#[cfg(all(feature = "axum", not(feature = "local-futures")))]
pub use extractors::{
    AdminRole, AdminSession, AuthRequestExt, AxumAuthResponse, CurrentSession, OptionalSession,
    Pending2faToken, ValidatedJson,
};
pub use hooks::{DatabaseHooks, HookedDatabaseAdapter, NativeDatabaseHooks};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitMiddleware,
};
pub use openapi::{OpenApiBuilder, OpenApiInfo, OpenApiOperation, OpenApiResponse, OpenApiSpec};
#[cfg(all(feature = "axum", not(feature = "local-futures")))]
pub use plugin::AxumPlugin;
pub use plugin::{
    AuthContext, AuthPlugin, AuthRoute, AuthState, BeforeRequestAction, NativeAuthPlugin,
};
pub use session::SessionManager;
pub use types::{
    Account, ApiKey, AuthRequest, AuthResponse, CodeMessageResponse, CreateAccount, CreateApiKey,
    CreateInvitation, CreateMember, CreateOrganization, CreatePasskey, CreateSession,
    CreateTwoFactor, CreateUser, CreateVerification, ErrorMessageResponse, HealthCheckResponse,
    HttpMethod, Invitation, InvitationStatus, ListUsersParams, OkResponse, Passkey,
    RateLimitErrorResponse, Session, StatusMessageResponse, StatusResponse, SuccessMessageResponse,
    SuccessResponse, TwoFactor, UpdateAccount, UpdateApiKey, UpdateOrganization, UpdatePasskey,
    UpdateUser, UpdateUserRequest, UpdateUserResponse, User, ValidationErrorResponse, Verification,
};
pub use utils::password::{PasswordHasher, SharedPasswordHasher, hash_password, verify_password};
