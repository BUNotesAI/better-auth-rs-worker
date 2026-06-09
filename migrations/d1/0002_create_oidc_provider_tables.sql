-- Better Auth Worker D1 (SQLite) OIDC provider tables. Parity with the native
-- PostgreSQL migrations/006_create_oidc_provider_tables.sql. No PostgreSQL-only
-- syntax: epoch INTEGER timestamps (set by the injected clock, not NOW()), TEXT
-- for JSON, no TIMESTAMPTZ/JSONB/$1 placeholders.

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_type TEXT NOT NULL,
    client_secret_hash TEXT,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    allowed_scopes TEXT NOT NULL,
    allowed_grant_types TEXT NOT NULL DEFAULT '[]',
    token_endpoint_auth_method TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Authorization codes are single-use: consumed by a single-statement atomic
-- DELETE ... RETURNING. Expiry compares against an injected clock epoch, not a
-- database time function.
CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce TEXT,
    auth_time INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires_at
    ON oidc_authorization_codes (expires_at);

-- Access tokens are opaque and stored only as a hash (token_hash); the raw token
-- value is never persisted. Lookup at userinfo time is by token_hash.
CREATE TABLE IF NOT EXISTS oidc_access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_user_id
    ON oidc_access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires_at
    ON oidc_access_tokens (expires_at);
