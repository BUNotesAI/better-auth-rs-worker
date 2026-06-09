#![cfg(all(feature = "sqlx-postgres", feature = "oidc-provider"))]
//! SQLx real-path test for the OIDC provider store, closing
//! `oidc_sqlx_store_atomic_consume_and_token_lookup`.
//!
//! Gated on a live PostgreSQL via `DATABASE_URL`. When unset, the test skips
//! with a note (so it runs in CI / with a database but does not fail in
//! environments without one). It exercises the real SQL path: the atomic
//! single-statement `DELETE ... RETURNING` consume under a race, and access-token
//! lookup by hash with delete-expired.

use better_auth_core::adapters::SqlxAdapter;
use better_auth_core::oidc::{
    AccessTokenHash, AccessTokenOps, AuthorizationCode, AuthorizationCodeOps, ClientId,
    CodeChallenge, CodeChallengeMethod, NewAccessToken, NewAuthorizationCode, RedirectUri,
    ScopeSet, SubjectId,
};
use chrono::{Duration, Utc};

const MIGRATION: &str = include_str!("../../../migrations/006_create_oidc_provider_tables.sql");

#[tokio::test]
async fn oidc_sqlx_store_atomic_consume_and_token_lookup() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!(
            "SKIP oidc_sqlx_store_atomic_consume_and_token_lookup: DATABASE_URL unset \
             (requires a live PostgreSQL)"
        );
        return;
    };

    let adapter = SqlxAdapter::new(&database_url)
        .await
        .expect("connect to postgres");
    sqlx::raw_sql(MIGRATION)
        .execute(adapter.pool())
        .await
        .expect("apply OIDC migration");

    let now = Utc::now();
    let future = now + Duration::seconds(60);
    let unique = now.timestamp_micros();
    let code = AuthorizationCode::from_raw(format!("code-{unique}"));

    // Seed a registered client (v1 has no dynamic registration).
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_type, redirect_uris, allowed_scopes, \
         allowed_grant_types, token_endpoint_auth_method, created_at, updated_at) \
         VALUES ($1, 'public', '[\"https://app.example/cb\"]'::jsonb, 'openid profile', \
         '[\"authorization_code\"]'::jsonb, 'none', $2, $2) \
         ON CONFLICT (client_id) DO NOTHING",
    )
    .bind("sqlx-app")
    .bind(now)
    .execute(adapter.pool())
    .await
    .expect("seed client");

    adapter
        .create_authorization_code(NewAuthorizationCode {
            code: code.clone(),
            client_id: ClientId::parse("sqlx-app").unwrap(),
            subject: SubjectId::parse("user-1").unwrap(),
            redirect_uri: RedirectUri::parse("https://app.example/cb").unwrap(),
            scope: ScopeSet::parse("openid profile").unwrap(),
            code_challenge: CodeChallenge::parse("a-challenge").unwrap(),
            code_challenge_method: CodeChallengeMethod::S256,
            nonce: None,
            auth_time: now,
            expires_at: future,
        })
        .await
        .expect("create code");

    // Two consumers race for the same code; the atomic DELETE..RETURNING ensures
    // exactly one redeems it.
    let (first, second) = tokio::join!(
        adapter.consume_authorization_code(&code, now),
        adapter.consume_authorization_code(&code, now),
    );
    let winners = [first.unwrap(), second.unwrap()]
        .into_iter()
        .filter(Option::is_some)
        .count();
    assert_eq!(winners, 1, "exactly one consumer redeems the code");

    // Access token: create, look up by hash, delete-expired keeps the unexpired one.
    let live = AccessTokenHash::from_hash(format!("hash-{unique}"));
    adapter
        .create_access_token(NewAccessToken {
            token_hash: live.clone(),
            client_id: ClientId::parse("sqlx-app").unwrap(),
            subject: SubjectId::parse("user-1").unwrap(),
            scope: ScopeSet::parse("openid").unwrap(),
            expires_at: future,
            created_at: now,
        })
        .await
        .expect("create token");
    let fetched = adapter
        .get_access_token_by_hash(&live)
        .await
        .expect("lookup token");
    assert_eq!(fetched.unwrap().subject.as_str(), "user-1");
    adapter
        .delete_expired_access_tokens(now)
        .await
        .expect("delete expired tokens");
    assert!(adapter.get_access_token_by_hash(&live).await.unwrap().is_some());
}
