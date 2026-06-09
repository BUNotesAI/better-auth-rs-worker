//! Endpoint handlers and the hand-written [`AuthPlugin`] assembly.
//!
//! The handlers are thin adapters: they parse the raw request (query / form /
//! headers) into the typed value objects from [`super::requests`], run the P0
//! rules and P1 decisions, execute the resulting effects through the injected
//! runtime ports (`clock`, `secure_random`, `jwt_signer`, `jwks_provider`) and
//! the [`OidcProviderStore`] bound, then serialize the response. No protocol
//! decision lives here.
//!
//! The [`AuthPlugin`] implementation is written by hand (not via
//! `impl_auth_plugin!`) because the macro only emits `DB: DatabaseAdapter`,
//! whereas the provider needs the stronger `DB: DatabaseAdapter +
//! OidcProviderStore` bound to reach the storage ports.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::threading::RuntimeSendSync;
use better_auth_core::{
    AccessToken, AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthorizationCode, ClientId, CodeChallenge, CodeChallengeMethod, CodeVerifier,
    HttpMethod, Issuer, NewAccessToken, NewAuthorizationCode, Nonce, OAuthClient, OidcProviderStore,
    RedirectUri, ScopeSet, State, SubjectId,
};

use super::claims::{SubjectClaims, build_id_token_claims, project_claims};
use super::decide::{
    AuthorizeDecision, TokenGrant, authenticate_client, decide_authorization, decide_token_grant,
};
use super::discovery::{ProviderEndpoints, build_discovery_document};
use super::error::OAuthError;
use super::jws::sign_id_token;
use super::requests::{
    AuthenticatedSubject, AuthorizationRequest, PromptMode, TokenRequest, parse_prompt,
};
use super::rules::{
    parse_requested_scopes, parse_response_type, require_pkce_at_authorize, validate_allowed_scopes,
    validate_redirect_uri,
};
use super::token::{
    DEFAULT_ACCESS_TOKEN_TTL_SECONDS, DEFAULT_CODE_TTL_SECONDS, generate_access_token,
    generate_authorization_code, hash_access_token, is_expired,
};

/// Host hook used to delegate to a login UI when authorization requires login.
///
/// The provider stays decoupled from any specific login flow: when
/// [`decide_authorization`] returns `RequireLogin`, the handler asks the hook to
/// build the URL to redirect the user-agent to. `return_to` is the authorize URL
/// the host should send the user back to once authenticated.
pub trait LoginRedirectHook: RuntimeSendSync + 'static {
    /// Builds the login URL for the given post-login return target.
    fn login_url(&self, return_to: &str) -> String;
}

/// Static configuration for the OIDC provider plugin.
///
/// `issuer` is the externally reachable base URL; endpoint suffixes are both the
/// locally matched route paths and the suffixes advertised (as `issuer + suffix`)
/// in the discovery document, so the two cannot diverge.
#[derive(Clone)]
pub struct OidcProviderConfig {
    pub issuer: Issuer,
    pub endpoints: ProviderEndpoints,
    pub discovery_path: String,
    pub code_ttl: Duration,
    pub access_token_ttl: Duration,
    pub id_token_ttl: Duration,
    pub login_hook: Option<Arc<dyn LoginRedirectHook>>,
}

impl OidcProviderConfig {
    /// Builds a config for `issuer` with the default endpoint layout and TTLs.
    #[must_use]
    pub fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            endpoints: ProviderEndpoints {
                authorization: "/oauth2/authorize".to_string(),
                token: "/oauth2/token".to_string(),
                userinfo: "/oauth2/userinfo".to_string(),
                jwks: "/oauth2/jwks".to_string(),
            },
            discovery_path: "/.well-known/openid-configuration".to_string(),
            code_ttl: Duration::seconds(DEFAULT_CODE_TTL_SECONDS),
            access_token_ttl: Duration::seconds(DEFAULT_ACCESS_TOKEN_TTL_SECONDS),
            id_token_ttl: Duration::seconds(DEFAULT_ACCESS_TOKEN_TTL_SECONDS),
            login_hook: None,
        }
    }

    /// Installs a login-redirect hook, enabling the `RequireLogin` decision path.
    #[must_use]
    pub fn with_login_hook(mut self, hook: Arc<dyn LoginRedirectHook>) -> Self {
        self.login_hook = Some(hook);
        self
    }

    /// Overrides the endpoint layout (and thus both routing and discovery URLs).
    #[must_use]
    pub fn with_endpoints(mut self, endpoints: ProviderEndpoints) -> Self {
        self.endpoints = endpoints;
        self
    }
}

/// OpenID Connect provider plugin (authorization server).
pub struct OidcProviderPlugin {
    config: OidcProviderConfig,
}

impl OidcProviderPlugin {
    /// Builds the plugin from its static configuration.
    #[must_use]
    pub fn new(config: OidcProviderConfig) -> Self {
        Self { config }
    }

    /// The plugin configuration.
    #[must_use]
    pub fn config(&self) -> &OidcProviderConfig {
        &self.config
    }

    /// `GET {discovery_path}` — serves the discovery document (pure projection).
    fn handle_discovery(&self) -> AuthResult<AuthResponse> {
        let doc = build_discovery_document(&self.config.issuer, &self.config.endpoints);
        Ok(AuthResponse::json(200, &doc)?)
    }

    /// `GET {jwks}` — serves the public JWKS from the injected provider port.
    fn handle_jwks<DB: DatabaseAdapter + OidcProviderStore>(
        &self,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let jwks = ctx.config.runtime.jwks_provider.jwks()?;
        Ok(AuthResponse::json(200, &jwks)?)
    }

    /// `GET {authorization}` — the authorization-code authorize endpoint.
    ///
    /// Effects (in order):
    /// 1. Reads the client and validates the redirect URI (never redirects on a
    ///    bad/unknown redirect URI).
    /// 2. On `IssueCode`, draws an opaque code from `SecureRandom` and persists it.
    /// 3. Redirects to the validated redirect URI (or the login hook).
    async fn handle_authorize<DB: DatabaseAdapter + OidcProviderStore>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        // Unknown client / missing client_id: cannot trust any redirect target.
        let client_id_raw =
            query(req, "client_id").ok_or_else(|| AuthError::bad_request("client_id is required"))?;
        let client_id = ClientId::parse(client_id_raw)
            .map_err(|_| AuthError::bad_request("invalid client_id"))?;
        let client = ctx
            .database
            .get_client(&client_id)
            .await?
            .ok_or_else(|| AuthError::bad_request("unknown client"))?;

        // Open-redirect guard: exact-match the redirect URI before any redirect.
        let redirect_raw = query(req, "redirect_uri")
            .ok_or_else(|| AuthError::bad_request("redirect_uri is required"))?;
        let redirect_uri = validate_redirect_uri(&client, redirect_raw)
            .map_err(|_| AuthError::bad_request("redirect_uri does not match a registered URI"))?;

        // From here the redirect URI is trusted: protocol errors go back via it.
        let state = query(req, "state").map(|s| State::new(s.to_string()));

        let params = match parse_authorize_params(req, &client) {
            Ok(params) => params,
            Err(e) => return Ok(redirect_error_response(&redirect_uri, state.as_ref(), &e)),
        };

        let request = AuthorizationRequest {
            client_id,
            redirect_uri,
            scope: params.scope,
            code_challenge: params.code_challenge,
            code_challenge_method: params.code_challenge_method,
            nonce: params.nonce,
            state,
            prompt: params.prompt,
        };

        let subject = self.authenticated_subject(req, ctx).await?;
        let now = ctx.config.runtime.clock.now();
        let decision = decide_authorization(
            &request,
            subject.as_ref(),
            self.config.login_hook.is_some(),
            now,
            self.config.code_ttl,
        );

        match decision {
            AuthorizeDecision::IssueCode(grant) => {
                let code = generate_authorization_code(&*ctx.config.runtime.secure_random)?;
                ctx.database
                    .create_authorization_code(NewAuthorizationCode {
                        code: code.clone(),
                        client_id: grant.client_id,
                        subject: grant.subject,
                        redirect_uri: grant.redirect_uri.clone(),
                        scope: grant.scope,
                        code_challenge: grant.code_challenge,
                        code_challenge_method: grant.code_challenge_method,
                        nonce: grant.nonce,
                        auth_time: grant.auth_time,
                        expires_at: grant.expires_at,
                    })
                    .await?;
                Ok(redirect_code_response(
                    &grant.redirect_uri,
                    code.as_str(),
                    grant.state.as_ref(),
                ))
            }
            AuthorizeDecision::RequireLogin => {
                let hook = self
                    .config
                    .login_hook
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("login hook is required for RequireLogin"))?;
                let location = hook.login_url(&authorize_return_to(req));
                Ok(AuthResponse::new(302).with_header("Location", location))
            }
            AuthorizeDecision::Deny {
                error,
                redirect_uri,
                state,
            } => Ok(redirect_error_response(&redirect_uri, state.as_ref(), &error)),
        }
    }

    /// `POST {token}` — the authorization-code token endpoint.
    ///
    /// Failure order is enforced here: the client is authenticated **before** the
    /// authorization code is consumed, so a client-auth failure never burns a
    /// valid code.
    async fn handle_token<DB: DatabaseAdapter + OidcProviderStore>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let form = parse_form(req);

        if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
            return oauth_error_response(&OAuthError::unsupported_grant_type(
                "only the authorization_code grant is supported",
            ));
        }

        let (client_id_raw, client_secret) = match client_credentials(req, &form) {
            Ok(creds) => creds,
            Err(e) => return oauth_error_response(&e),
        };
        let client_id = match ClientId::parse(client_id_raw.as_str()) {
            Ok(c) => c,
            Err(_) => return oauth_error_response(&OAuthError::invalid_client("invalid client_id")),
        };
        let client = match ctx.database.get_client(&client_id).await? {
            Some(c) => c,
            None => return oauth_error_response(&OAuthError::invalid_client("unknown client")),
        };

        // Step 1: authenticate the client BEFORE consuming the code.
        if let Err(e) = authenticate_client(&client, client_secret.as_deref()) {
            return oauth_error_response(&e);
        }

        let Some(code_raw) = form.get("code") else {
            return oauth_error_response(&OAuthError::invalid_request("code is required"));
        };
        let code = AuthorizationCode::from_raw(code_raw.clone());
        let Some(redirect_raw) = form.get("redirect_uri") else {
            return oauth_error_response(&OAuthError::invalid_request("redirect_uri is required"));
        };
        let redirect_uri = match RedirectUri::parse(redirect_raw) {
            Ok(u) => u,
            Err(_) => return oauth_error_response(&OAuthError::invalid_request("invalid redirect_uri")),
        };
        let code_verifier = match form
            .get("code_verifier")
            .map(String::as_str)
            .map(CodeVerifier::parse)
            .transpose()
        {
            Ok(v) => v,
            Err(_) => return oauth_error_response(&OAuthError::invalid_grant("invalid code_verifier")),
        };

        let token_request = TokenRequest {
            client_id,
            code: code.clone(),
            redirect_uri,
            code_verifier,
            client_secret,
        };

        // Step 2: atomic single-use consume (effect), then the pure grant decision.
        let now = ctx.config.runtime.clock.now();
        let consumed = ctx.database.consume_authorization_code(&code, now).await?;
        let grant = match decide_token_grant(&token_request, &client, consumed.as_ref(), now) {
            Ok(g) => g,
            Err(e) => return oauth_error_response(&e),
        };

        self.issue_tokens(ctx, &grant, now).await
    }

    /// Issues the signed id_token and a fresh opaque access token (hash at rest).
    ///
    /// Effects (in order):
    /// 1. Signs the id_token through the `jwt_signer` port.
    /// 2. Draws an opaque access token from `secure_random`.
    /// 3. Persists the access token by hash (the raw token is never stored).
    async fn issue_tokens<DB: DatabaseAdapter + OidcProviderStore>(
        &self,
        ctx: &AuthContext<DB>,
        grant: &TokenGrant,
        now: DateTime<Utc>,
    ) -> AuthResult<AuthResponse> {
        let source = match ctx.database.get_user_by_id(grant.subject.as_str()).await? {
            Some(user) => subject_claims_from_user(&user),
            None => SubjectClaims::default(),
        };
        let id_claims =
            build_id_token_claims(&self.config.issuer, grant, &source, now, self.config.id_token_ttl);
        let id_token =
            sign_id_token(&serde_json::to_vec(&id_claims)?, &*ctx.config.runtime.jwt_signer).await?;

        let (access_token, token_hash) = generate_access_token(&*ctx.config.runtime.secure_random)?;
        ctx.database
            .create_access_token(NewAccessToken {
                token_hash,
                client_id: grant.client_id.clone(),
                subject: grant.subject.clone(),
                scope: grant.scope.clone(),
                expires_at: now + self.config.access_token_ttl,
                created_at: now,
            })
            .await?;

        Ok(AuthResponse::json(
            200,
            &TokenResponse {
                access_token: access_token.as_str().to_string(),
                token_type: "Bearer",
                expires_in: self.config.access_token_ttl.num_seconds(),
                id_token,
                scope: grant.scope.as_space_delimited(),
            },
        )?)
    }

    /// `GET`/`POST {userinfo}` — returns the granted claims for a bearer token.
    async fn handle_userinfo<DB: DatabaseAdapter + OidcProviderStore>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let Some(token) = bearer_token(req) else {
            return oauth_error_response(&OAuthError::invalid_token(
                "a bearer access token is required",
            ));
        };
        let hash = hash_access_token(&AccessToken::from_raw(token.to_string()));
        let Some(record) = ctx.database.get_access_token_by_hash(&hash).await? else {
            return oauth_error_response(&OAuthError::invalid_token("the access token is invalid"));
        };
        let now = ctx.config.runtime.clock.now();
        if is_expired(now, record.expires_at) {
            return oauth_error_response(&OAuthError::invalid_token("the access token has expired"));
        }
        let Some(user) = ctx.database.get_user_by_id(record.subject.as_str()).await? else {
            return oauth_error_response(&OAuthError::invalid_token(
                "the access token subject no longer exists",
            ));
        };

        let mut claims = project_claims(&record.scope, &subject_claims_from_user(&user));
        claims.insert(
            "sub".to_string(),
            serde_json::Value::String(record.subject.as_str().to_string()),
        );
        Ok(AuthResponse::json(200, &serde_json::Value::Object(claims))?)
    }

    /// Resolves the better-auth session into an OIDC subject, if authenticated.
    async fn authenticated_subject<DB: DatabaseAdapter + OidcProviderStore>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthenticatedSubject>> {
        match ctx.require_session(req).await {
            Ok((user, session)) => Ok(Some(AuthenticatedSubject {
                subject: SubjectId::parse(user.id())
                    .map_err(|_| AuthError::internal("session user id is not a valid subject"))?,
                auth_time: session.created_at(),
            })),
            Err(AuthError::Unauthenticated) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl<DB: DatabaseAdapter + OidcProviderStore> AuthPlugin<DB> for OidcProviderPlugin {
    fn name(&self) -> &'static str {
        "oidc-provider"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let e = &self.config.endpoints;
        vec![
            AuthRoute::get(self.config.discovery_path.clone(), "oidc_discovery"),
            AuthRoute::get(e.jwks.clone(), "oidc_jwks"),
            AuthRoute::get(e.authorization.clone(), "oidc_authorize"),
            AuthRoute::post(e.token.clone(), "oidc_token"),
            AuthRoute::get(e.userinfo.clone(), "oidc_userinfo"),
            AuthRoute::post(e.userinfo.clone(), "oidc_userinfo_post"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        let method = req.method();
        let path = req.path();
        let e = &self.config.endpoints;

        let response = if method == &HttpMethod::Get && path == self.config.discovery_path {
            self.handle_discovery()?
        } else if method == &HttpMethod::Get && path == e.jwks {
            self.handle_jwks(ctx)?
        } else if method == &HttpMethod::Get && path == e.authorization {
            self.handle_authorize(req, ctx).await?
        } else if method == &HttpMethod::Post && path == e.token {
            self.handle_token(req, ctx).await?
        } else if (method == &HttpMethod::Get || method == &HttpMethod::Post) && path == e.userinfo {
            self.handle_userinfo(req, ctx).await?
        } else {
            return Ok(None);
        };
        Ok(Some(response))
    }
}

/// The OAuth2 token endpoint success response.
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: String,
}

/// The authorize-request fields parsed after the redirect URI is validated.
struct AuthorizeParams {
    scope: ScopeSet,
    code_challenge: CodeChallenge,
    code_challenge_method: CodeChallengeMethod,
    nonce: Option<Nonce>,
    prompt: PromptMode,
}

/// Parses and validates the authorize parameters that, on failure, are reported
/// back via the (already validated) redirect URI.
///
/// Returns a typed [`OAuthError`] so the caller can render it as a redirect.
fn parse_authorize_params(
    req: &AuthRequest,
    client: &OAuthClient,
) -> Result<AuthorizeParams, OAuthError> {
    parse_response_type(query(req, "response_type").unwrap_or_default())?;
    let scope = parse_requested_scopes(query(req, "scope").unwrap_or_default())?;
    validate_allowed_scopes(client, &scope)?;
    let code_challenge = query(req, "code_challenge")
        .map(CodeChallenge::parse)
        .transpose()
        .map_err(|_| OAuthError::invalid_request("invalid code_challenge"))?;
    require_pkce_at_authorize(client, code_challenge.as_ref())?;
    let code_challenge =
        code_challenge.ok_or_else(|| OAuthError::invalid_request("code_challenge is required"))?;
    let code_challenge_method =
        CodeChallengeMethod::parse(query(req, "code_challenge_method").unwrap_or("S256")).map_err(
            |_| OAuthError::invalid_request("only the S256 code_challenge_method is supported"),
        )?;
    let prompt = parse_prompt(query(req, "prompt"))?;
    Ok(AuthorizeParams {
        scope,
        code_challenge,
        code_challenge_method,
        nonce: query(req, "nonce").map(|n| Nonce::new(n.to_string())),
        prompt,
    })
}

/// Reads a query parameter as a string slice.
fn query<'a>(req: &'a AuthRequest, key: &str) -> Option<&'a str> {
    req.query.get(key).map(String::as_str)
}

/// Parses an `application/x-www-form-urlencoded` request body into a map.
fn parse_form(req: &AuthRequest) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(body) = &req.body {
        for (key, value) in url::form_urlencoded::parse(body) {
            map.insert(key.into_owned(), value.into_owned());
        }
    }
    map
}

/// Extracts client credentials, preferring HTTP Basic over form parameters.
///
/// Returns `(client_id, client_secret)`. A public client presents no secret.
///
/// v1 treats `client_secret_basic` and `client_secret_post` as the same
/// confidential-secret authentication class: a confidential client may present
/// its secret via either transport, and the registered
/// [`TokenEndpointAuthMethod`](better_auth_core::TokenEndpointAuthMethod) is
/// advertised in discovery but not strictly enforced per-method. Strict
/// per-method enforcement is a deliberate future enhancement.
fn client_credentials(
    req: &AuthRequest,
    form: &HashMap<String, String>,
) -> Result<(String, Option<String>), OAuthError> {
    if let Some(encoded) = req
        .header("authorization")
        .and_then(|h| h.strip_prefix("Basic ").or_else(|| h.strip_prefix("basic ")))
    {
        let decoded = STANDARD
            .decode(encoded.trim())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| OAuthError::invalid_client("malformed Basic authorization header"))?;
        let (id, secret) = decoded
            .split_once(':')
            .ok_or_else(|| OAuthError::invalid_client("malformed Basic authorization header"))?;
        return Ok((id.to_string(), Some(secret.to_string())));
    }
    let id = form
        .get("client_id")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_client("client authentication is required"))?;
    Ok((id, form.get("client_secret").cloned()))
}

/// Extracts a bearer token from the `Authorization` header.
fn bearer_token(req: &AuthRequest) -> Option<&str> {
    let header = req.header("authorization")?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?;
    Some(token.trim())
}

/// Builds the standard OAuth2 error response (JSON body + bearer challenge).
fn oauth_error_response(err: &OAuthError) -> AuthResult<AuthResponse> {
    let mut response = AuthResponse::json(err.http_status(), &err.to_body())?;
    if let Some(challenge) = err.www_authenticate() {
        response = response.with_header("WWW-Authenticate", challenge);
    }
    Ok(response)
}

/// Builds a 302 redirect carrying the issued `code` (and echoed `state`).
fn redirect_code_response(
    redirect_uri: &RedirectUri,
    code: &str,
    state: Option<&State>,
) -> AuthResponse {
    let mut params = vec![("code", code.to_string())];
    if let Some(state) = state {
        params.push(("state", state.as_str().to_string()));
    }
    redirect_with_params(redirect_uri, &params)
}

/// Builds a 302 redirect carrying the OAuth2 `error` (and echoed `state`).
fn redirect_error_response(
    redirect_uri: &RedirectUri,
    state: Option<&State>,
    err: &OAuthError,
) -> AuthResponse {
    let mut params = vec![
        ("error", err.code_str().to_string()),
        ("error_description", err.description().to_string()),
    ];
    if let Some(state) = state {
        params.push(("state", state.as_str().to_string()));
    }
    redirect_with_params(redirect_uri, &params)
}

/// Appends URL-encoded params to the redirect URI and returns a 302 response.
fn redirect_with_params(redirect_uri: &RedirectUri, params: &[(&str, String)]) -> AuthResponse {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    let base = redirect_uri.as_str();
    let separator = if base.contains('?') { '&' } else { '?' };
    let location = format!("{base}{separator}{}", serializer.finish());
    AuthResponse::new(302).with_header("Location", location)
}

/// Reconstructs the authorize URL (path + query) for a post-login return target.
fn authorize_return_to(req: &AuthRequest) -> String {
    if req.query.is_empty() {
        return req.path().to_string();
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in &req.query {
        serializer.append_pair(key, value);
    }
    format!("{}?{}", req.path(), serializer.finish())
}

/// Projects a better-auth user into the OIDC claim source.
fn subject_claims_from_user<U: AuthUser>(user: &U) -> SubjectClaims {
    SubjectClaims {
        name: user.name().map(str::to_string),
        email: user.email().map(str::to_string),
        email_verified: Some(user.email_verified()),
    }
}
