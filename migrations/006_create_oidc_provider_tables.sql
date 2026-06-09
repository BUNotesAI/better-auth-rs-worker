-- Better Auth: OIDC provider tables (oauth_clients, oidc_authorization_codes, oidc_access_tokens)
-- Native (PostgreSQL) schema. The D1 (SQLite) parity migration lives under migrations/d1/.
-- Gated by the `oidc-provider` capability; not applied unless the provider is used.

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_type TEXT NOT NULL,
    client_secret_hash TEXT,
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    allowed_scopes TEXT NOT NULL,
    allowed_grant_types JSONB NOT NULL DEFAULT '[]',
    token_endpoint_auth_method TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authorization codes are single-use: consumed by a single-statement atomic
-- DELETE ... RETURNING. Expiry is compared against an injected clock instant,
-- not database NOW(), so native and Worker behavior match.
CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce TEXT,
    auth_time TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oidc_authorization_codes_expires_at
    ON oidc_authorization_codes (expires_at);

-- Access tokens are opaque and stored only as a hash (token_hash). The raw token
-- value is never persisted. Lookup at userinfo time is by token_hash.
CREATE TABLE IF NOT EXISTS oidc_access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_user_id
    ON oidc_access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_access_tokens_expires_at
    ON oidc_access_tokens (expires_at);
