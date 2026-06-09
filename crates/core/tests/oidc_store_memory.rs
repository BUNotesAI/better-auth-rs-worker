#![cfg(feature = "oidc-provider")]
//! Memory-tier contract tests for `OidcProviderStore`.
//!
//! These exercise the atomic single-use consume, hash lookup, and delete-expired
//! semantics at the in-memory tier, so the store contract logic is covered
//! without a database. The SQLx real-path equivalent
//! (`oidc_sqlx_store_atomic_consume_and_token_lookup`) runs the same contract
//! against PostgreSQL and is gated on `DATABASE_URL`.

use better_auth_core::adapters::MemoryDatabaseAdapter;
use better_auth_core::oidc::{
    AccessTokenHash, AccessTokenOps, AuthorizationCode, AuthorizationCodeOps, ClientId, ClientType,
    CodeChallenge, CodeChallengeMethod, GrantType, NewAccessToken, NewAuthorizationCode,
    OAuthClient, OAuthClientOps, RedirectUri, ScopeSet, SubjectId, TokenEndpointAuthMethod,
};
use chrono::{DateTime, Duration, TimeZone, Utc};

fn ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap()
}

fn client() -> OAuthClient {
    OAuthClient {
        client_id: ClientId::parse("app-1").unwrap(),
        client_type: ClientType::Public,
        redirect_uris: vec![RedirectUri::parse("https://app.example/cb").unwrap()],
        allowed_scopes: ScopeSet::parse("openid profile").unwrap(),
        allowed_grant_types: vec![GrantType::AuthorizationCode],
        secret_hash: None,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
    }
}

fn new_code(code: &str, expires_at: DateTime<Utc>) -> NewAuthorizationCode {
    NewAuthorizationCode {
        code: AuthorizationCode::from_raw(code.to_string()),
        client_id: ClientId::parse("app-1").unwrap(),
        subject: SubjectId::parse("user-1").unwrap(),
        redirect_uri: RedirectUri::parse("https://app.example/cb").unwrap(),
        scope: ScopeSet::parse("openid profile").unwrap(),
        code_challenge: CodeChallenge::parse("a-challenge").unwrap(),
        code_challenge_method: CodeChallengeMethod::S256,
        nonce: None,
        auth_time: ts(),
        expires_at,
    }
}

fn new_token(hash: &str, expires_at: DateTime<Utc>) -> NewAccessToken {
    NewAccessToken {
        token_hash: AccessTokenHash::from_hash(hash.to_string()),
        client_id: ClientId::parse("app-1").unwrap(),
        subject: SubjectId::parse("user-1").unwrap(),
        scope: ScopeSet::parse("openid").unwrap(),
        expires_at,
        created_at: ts(),
    }
}

#[tokio::test]
async fn oidc_memory_store_atomic_consume_and_token_lookup() {
    let store = MemoryDatabaseAdapter::new();
    let now = ts();
    let future = now + Duration::seconds(60);

    // client lookup
    store.seed_oauth_client(client());
    let found = store
        .get_client(&ClientId::parse("app-1").unwrap())
        .await
        .unwrap();
    assert_eq!(found.unwrap().client_id.as_str(), "app-1");
    assert!(
        store
            .get_client(&ClientId::parse("missing").unwrap())
            .await
            .unwrap()
            .is_none()
    );

    // atomic single-use consume: first succeeds, replay returns None
    store.create_authorization_code(new_code("c1", future)).await.unwrap();
    let consumed = store
        .consume_authorization_code(&AuthorizationCode::from_raw("c1".to_string()), now)
        .await
        .unwrap();
    assert_eq!(consumed.unwrap().subject.as_str(), "user-1");
    assert!(
        store
            .consume_authorization_code(&AuthorizationCode::from_raw("c1".to_string()), now)
            .await
            .unwrap()
            .is_none()
    );

    // expired code: consume returns None (not removed); delete-expired cleans it
    store
        .create_authorization_code(new_code("c2", now - Duration::seconds(1)))
        .await
        .unwrap();
    assert!(
        store
            .consume_authorization_code(&AuthorizationCode::from_raw("c2".to_string()), now)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.delete_expired_authorization_codes(now).await.unwrap(), 1);

    // access token: create, look up by hash, and delete-expired keeps unexpired
    let live = AccessTokenHash::from_hash("hash-live".to_string());
    store.create_access_token(new_token("hash-live", future)).await.unwrap();
    store.create_access_token(new_token("hash-old", now - Duration::seconds(1))).await.unwrap();
    assert_eq!(
        store.get_access_token_by_hash(&live).await.unwrap().unwrap().subject.as_str(),
        "user-1"
    );
    assert_eq!(store.delete_expired_access_tokens(now).await.unwrap(), 1);
    assert!(store.get_access_token_by_hash(&live).await.unwrap().is_some());
}
