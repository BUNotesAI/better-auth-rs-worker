use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher as Argon2PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use better_auth_api::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthResult, Clock, DatabaseError, HttpMethod, IdGenerator,
    IdKind, OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse, PasswordHasher, SecureRandom,
    SessionTokenGenerator, SharedPasswordHasher,
};
use better_auth_worker::{
    D1Database as BetterAuthD1Database, D1DatabaseAdapter, D1PreparedStatement, D1QueryResult,
    D1Row, D1StatementMethod, D1Value, WorkerRequestParts, WorkerResponseParts,
    WorkerRuntimeCapabilities, WorkerV1Config, handle_worker_plugin_request,
    worker_response_from_auth_response,
};
use chrono::{DateTime, TimeZone, Utc};
use js_sys::Uint8Array;
use serde_json::Value as JsonValue;
use wasm_bindgen::JsValue;
use worker::{
    Context, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result as WorkerResult,
    event,
};

const AUTH_BASE_PATH: &str = "/api/auth";
const DB_BINDING: &str = "better_auth_rs_worker";
const SECRET_BINDING: &str = "BETTER_AUTH_SECRET";
const MAX_JS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[event(fetch, respond_with_errors)]
pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> WorkerResult<Response> {
    match handle_request(&mut req, &env).await {
        Ok(response) => Ok(response),
        Err(error) => auth_error_to_worker_response(error),
    }
}

async fn handle_request(req: &mut Request, env: &Env) -> AuthResult<Response> {
    let url = req.url().map_err(worker_error)?;
    let Some(auth_url) = auth_plugin_url(&url) else {
        return Response::error("Not found", 404).map_err(worker_error);
    };

    let base_url = request_origin(&url);
    let context = build_auth_context(env, base_url)?;
    let request_parts = worker_request_parts(req, auth_url).await?;

    let response_parts = dispatch_auth(request_parts, &context).await?;
    worker_response_parts_to_response(response_parts).map_err(worker_error)
}

type WorkerAuthContext = AuthContext<D1DatabaseAdapter<WorkerD1Database>>;

fn build_auth_context(env: &Env, base_url: String) -> AuthResult<WorkerAuthContext> {
    WorkerV1Config::new()
        .with_injected_password_hasher()
        .validate()?;

    let secret = env
        .secret(SECRET_BINDING)
        .map_err(worker_error)?
        .to_string();
    let runtime = worker_runtime()?;
    let auth_runtime = runtime.clone().into_auth_runtime();
    let d1 = env.d1(DB_BINDING).map_err(worker_error)?;
    let database = D1DatabaseAdapter::new(WorkerD1Database::new(d1), runtime);

    let config = AuthConfig::new(secret)
        .base_url(base_url.clone())
        .base_path(AUTH_BASE_PATH)
        .trusted_origin(base_url)
        .runtime_capabilities(auth_runtime);

    Ok(AuthContext::new(Arc::new(config), Arc::new(database)))
}

fn worker_runtime() -> AuthResult<WorkerRuntimeCapabilities> {
    WorkerRuntimeCapabilities::builder()
        .clock(Rc::new(WorkerClock))
        .secure_random(Rc::new(WorkerSecureRandom))
        .id_generator(Rc::new(WorkerIds))
        .session_tokens(Rc::new(WorkerSessionTokens))
        .oauth_http(Rc::new(WorkerFetchOAuthHttp))
        .build()
}

async fn dispatch_auth(
    request_parts: WorkerRequestParts,
    context: &WorkerAuthContext,
) -> AuthResult<WorkerResponseParts> {
    let email_password = EmailPasswordPlugin::new()
        .enable_signup(true)
        .password_hasher(shared_password_hasher());

    if let Some(response) =
        handle_worker_plugin_request(&email_password, request_parts.clone(), context).await?
    {
        return Ok(response);
    }

    let sessions = SessionManagementPlugin::new();
    if let Some(response) = handle_worker_plugin_request(&sessions, request_parts, context).await? {
        return Ok(response);
    }

    Ok(worker_response_from_auth_response(
        AuthError::not_found("Auth route not found").into_response(),
    ))
}

fn shared_password_hasher() -> SharedPasswordHasher {
    Rc::new(WorkerArgon2PasswordHasher)
}

async fn worker_request_parts(
    req: &mut Request,
    auth_url: String,
) -> AuthResult<WorkerRequestParts> {
    let method = core_method(req.method())?;
    let mut parts = WorkerRequestParts::new(method, auth_url);

    for (name, value) in req.headers().entries() {
        parts = parts.with_header(name, value);
    }

    let body = req.bytes().await.map_err(worker_error)?;
    if !body.is_empty() {
        parts = parts.with_body(body);
    }

    Ok(parts)
}

fn worker_response_parts_to_response(parts: WorkerResponseParts) -> WorkerResult<Response> {
    let headers = Headers::new();
    for (name, value) in parts.headers() {
        headers.set(name, value)?;
    }

    Ok(Response::builder()
        .with_status(parts.status())
        .with_headers(headers)
        .fixed(parts.body().to_vec()))
}

fn auth_error_to_worker_response(error: AuthError) -> WorkerResult<Response> {
    worker_response_parts_to_response(worker_response_from_auth_response(error.into_response()))
}

fn auth_plugin_url(url: &url::Url) -> Option<String> {
    let plugin_path = auth_plugin_path(url.path())?;
    let mut auth_url = url.clone();
    auth_url.set_path(&plugin_path);
    Some(auth_url.to_string())
}

fn auth_plugin_path(path: &str) -> Option<String> {
    if path == AUTH_BASE_PATH {
        return Some("/".to_string());
    }

    path.strip_prefix("/api/auth/")
        .map(|rest| format!("/{rest}"))
}

fn request_origin(url: &url::Url) -> String {
    let mut origin = url.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    origin.as_str().trim_end_matches('/').to_string()
}

struct WorkerD1Database {
    inner: worker::D1Database,
}

impl WorkerD1Database {
    fn new(inner: worker::D1Database) -> Self {
        Self { inner }
    }
}

#[async_trait(?Send)]
impl BetterAuthD1Database for WorkerD1Database {
    async fn execute(&self, statement: D1PreparedStatement) -> AuthResult<D1QueryResult> {
        let bindings = statement
            .bindings()
            .iter()
            .map(d1_value_to_js_value)
            .collect::<AuthResult<Vec<_>>>()?;
        let prepared = self
            .inner
            .prepare(statement.sql())
            .bind(&bindings)
            .map_err(worker_error)?;

        match statement.method() {
            D1StatementMethod::Run => {
                let result = prepared.run().await.map_err(worker_error)?;
                Ok(D1QueryResult::new(Vec::new(), rows_affected(&result)?))
            }
            D1StatementMethod::First => {
                let row = prepared
                    .first::<BTreeMap<String, JsonValue>>(None)
                    .await
                    .map_err(worker_error)?
                    .map(json_row_to_d1_row);
                Ok(D1QueryResult::new(row.into_iter().collect(), 0))
            }
            D1StatementMethod::All => {
                let result = prepared.all().await.map_err(worker_error)?;
                let rows = result
                    .results::<BTreeMap<String, JsonValue>>()
                    .map_err(worker_error)?
                    .into_iter()
                    .map(json_row_to_d1_row)
                    .collect();
                Ok(D1QueryResult::new(rows, rows_affected(&result)?))
            }
        }
    }
}

fn rows_affected(result: &worker::D1Result) -> AuthResult<usize> {
    Ok(result
        .meta()
        .map_err(worker_error)?
        .and_then(|meta| meta.changes)
        .unwrap_or(0))
}

fn d1_value_to_js_value(value: &D1Value) -> AuthResult<JsValue> {
    match value {
        D1Value::Null => Ok(JsValue::NULL),
        D1Value::Integer(value) => {
            if !(-MAX_JS_SAFE_INTEGER..=MAX_JS_SAFE_INTEGER).contains(value) {
                return Err(AuthError::Database(DatabaseError::Query(format!(
                    "D1 integer binding {value} exceeds JavaScript safe integer range"
                ))));
            }
            Ok(JsValue::from_f64(*value as f64))
        }
        D1Value::Real(value) => Ok(JsValue::from_f64(*value)),
        D1Value::Text(value) => Ok(JsValue::from_str(value)),
        D1Value::Boolean(value) => Ok(JsValue::from_bool(*value)),
    }
}

fn json_row_to_d1_row(row: BTreeMap<String, JsonValue>) -> D1Row {
    D1Row::new(
        row.into_iter()
            .map(|(column, value)| (column, json_value_to_d1_value(value)))
            .collect(),
    )
}

fn json_value_to_d1_value(value: JsonValue) -> D1Value {
    match value {
        JsonValue::Null => D1Value::Null,
        JsonValue::Bool(value) => D1Value::Boolean(value),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                D1Value::Integer(value)
            } else if let Some(value) = value.as_u64() {
                if value <= i64::MAX as u64 {
                    D1Value::Integer(value as i64)
                } else {
                    D1Value::Real(value as f64)
                }
            } else {
                D1Value::Real(value.as_f64().unwrap_or_default())
            }
        }
        JsonValue::String(value) => D1Value::Text(value),
        other => D1Value::Text(other.to_string()),
    }
}

struct WorkerClock;

impl Clock for WorkerClock {
    fn now(&self) -> DateTime<Utc> {
        let millis = js_sys::Date::now() as i64;
        Utc.timestamp_millis_opt(millis)
            .single()
            .unwrap_or_else(unix_epoch)
    }
}

struct WorkerSecureRandom;

impl SecureRandom for WorkerSecureRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> AuthResult<()> {
        fill_secure_bytes(dest)
    }
}

struct WorkerIds;

impl IdGenerator for WorkerIds {
    fn generate_id(&self, kind: IdKind) -> AuthResult<String> {
        let mut bytes = [0_u8; 16];
        fill_secure_bytes(&mut bytes)?;
        Ok(format!("{}_{}", id_prefix(kind), hex_encode(&bytes)))
    }
}

struct WorkerSessionTokens;

impl SessionTokenGenerator for WorkerSessionTokens {
    fn generate_session_token(&self) -> AuthResult<String> {
        let mut bytes = [0_u8; 32];
        fill_secure_bytes(&mut bytes)?;
        Ok(format!("ba_{}", hex_encode(&bytes)))
    }
}

struct WorkerFetchOAuthHttp;

#[async_trait(?Send)]
impl OAuthHttpClient for WorkerFetchOAuthHttp {
    async fn send(&self, request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
        let mut init = RequestInit::new();
        init.with_method(worker_method(&request.method));

        let headers = Headers::new();
        for (name, value) in &request.headers {
            headers.set(name, value).map_err(worker_error)?;
        }
        init.with_headers(headers);

        if !request.body.is_empty() {
            init.with_body(Some(Uint8Array::from(request.body.as_slice()).into()));
        }

        let outbound = Request::new_with_init(&request.url, &init).map_err(worker_error)?;
        let mut response = Fetch::Request(outbound)
            .send()
            .await
            .map_err(worker_error)?;

        let headers = response.headers().entries().collect::<HashMap<_, _>>();
        let status = response.status_code();
        let body = response.bytes().await.map_err(worker_error)?;

        Ok(OAuthHttpResponse {
            status,
            headers,
            body,
        })
    }
}

struct WorkerArgon2PasswordHasher;

#[async_trait(?Send)]
impl PasswordHasher for WorkerArgon2PasswordHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        let mut salt = [0_u8; 16];
        fill_secure_bytes(&mut salt)?;
        let salt = SaltString::encode_b64(&salt)
            .map_err(|error| AuthError::PasswordHash(format!("Failed to encode salt: {error}")))?;

        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| AuthError::PasswordHash(format!("Failed to hash password: {error}")))
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        let parsed = PasswordHash::new(hash)
            .map_err(|error| AuthError::PasswordHash(format!("Invalid password hash: {error}")))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

fn fill_secure_bytes(dest: &mut [u8]) -> AuthResult<()> {
    getrandom::getrandom(dest)
        .map_err(|error| AuthError::config(format!("Worker secure random failed: {error}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn id_prefix(kind: IdKind) -> &'static str {
    match kind {
        IdKind::User => "user",
        IdKind::Session => "session",
        IdKind::Account => "account",
        IdKind::Verification => "verification",
        IdKind::Organization => "organization",
        IdKind::Member => "member",
        IdKind::Invitation => "invitation",
        IdKind::TwoFactor => "two_factor",
        IdKind::ApiKey => "api_key",
        IdKind::Passkey => "passkey",
        IdKind::OAuthState => "oauth_state",
    }
}

fn core_method(method: Method) -> AuthResult<HttpMethod> {
    match method {
        Method::Get => Ok(HttpMethod::Get),
        Method::Post => Ok(HttpMethod::Post),
        Method::Put => Ok(HttpMethod::Put),
        Method::Delete => Ok(HttpMethod::Delete),
        Method::Patch => Ok(HttpMethod::Patch),
        Method::Options => Ok(HttpMethod::Options),
        Method::Head => Ok(HttpMethod::Head),
        other => Err(AuthError::bad_request(format!(
            "Unsupported auth method: {other}"
        ))),
    }
}

fn worker_method(method: &HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::Get,
        HttpMethod::Post => Method::Post,
        HttpMethod::Put => Method::Put,
        HttpMethod::Delete => Method::Delete,
        HttpMethod::Patch => Method::Patch,
        HttpMethod::Options => Method::Options,
        HttpMethod::Head => Method::Head,
    }
}

fn worker_error(error: worker::Error) -> AuthError {
    AuthError::internal(format!("{error:?}"))
}

fn unix_epoch() -> DateTime<Utc> {
    Utc.timestamp_millis_opt(0)
        .single()
        .expect("Unix epoch timestamp is valid")
}
