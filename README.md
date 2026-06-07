# Better Auth RS Worker Fork

A Cloudflare Worker + D1 focused public fork of Better Auth RS. The project keeps the upstream Rust authentication API and adds edge-runtime boundaries for Cloudflare deployments.

> [!IMPORTANT]
> This repository is forked from [better-auth-rs/better-auth-rs](https://github.com/better-auth-rs/better-auth-rs). This fork is maintained at [BUNotesAI/better-auth-rs-worker](https://github.com/BUNotesAI/better-auth-rs-worker) (`git@github.com:BUNotesAI/better-auth-rs-worker.git`).

> [!NOTE]
> **v1 ([`v1`](https://github.com/better-auth-rs/better-auth-rs/tree/v1) branch, alpha):** complete rewrite with app-owned schema and full compatibility with [`better-auth@1.4.19`](https://www.npmjs.com/package/better-auth/v/1.4.19).

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/better-auth.svg)](LICENSE-MIT)
[![better-auth compatibility](https://img.shields.io/badge/better--auth-v1.4.19-blue?logo=typescript&logoColor=white)](https://www.npmjs.com/package/better-auth/v/1.4.19)

## Fork Highlights

- **Cloudflare Worker crate** — `better-auth-worker` bridges `worker::Request` / `worker::Response` with Better Auth route handling
- **D1 persistence boundary** — `D1DatabaseAdapter` maps core auth records onto Cloudflare D1 prepared statements
- **Runnable Worker example** — [`examples/cloudflare-worker/`](examples/cloudflare-worker/) includes Wrangler config, D1 binding, local secrets template, route wiring, and deployment steps
- **Worker runtime capabilities** — clock, secure random, IDs, session tokens, and OAuth HTTP are injected explicitly so Worker builds avoid native runtime assumptions
- **Public-repo hygiene** — real D1 ids, `.dev.vars`, `.wrangler/`, generated Worker builds, local Wrangler configs, IDE state, and harness-local files are ignored

## Features

- **Plugin Architecture** — compose only the auth features you need
- **Type Safety** — leverages Rust's type system for compile-time guarantees
- **Async First** — built on Tokio with full async/await support
- **Database Agnostic** — in-memory for development, PostgreSQL for production
- **Framework Integration** — first-class Axum support with session extractors
- **Cloudflare Worker Boundary** — Wasm-friendly Worker adapter and D1 persistence boundary
- **OpenAPI** — auto-generated API specification
- **Middleware** — CSRF, CORS, rate limiting, body size limits
- **Database Hooks** — intercept create/update/delete operations

## Quick Start

```toml
[dependencies]
better-auth = "0.8"
```

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = BetterAuth::new(
            AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
                .base_url("http://localhost:3000"),
        )
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;

    // Mount as an Axum router (requires `axum` feature)
    // let app = auth.axum_router();

    Ok(())
}
```

> See the [Quick Start guide](docs/content/docs/quick-start.mdx) for a complete walkthrough including sign-up, sign-in, and session usage.

## Cloudflare Worker + D1

Worker support lives in the `better-auth-worker` crate. It provides:

- Worker request/response conversion through `WorkerRequestParts` and `WorkerResponseParts`
- explicit Worker runtime capability injection for clock, secure random, IDs, session tokens, and OAuth HTTP
- a D1 database adapter boundary through `D1DatabaseAdapter`
- D1 core schema migrations in [`migrations/d1/`](migrations/d1/)

The host-tested Worker v1 path covers email/password, sessions, core D1 auth records, and the runtime ports required by OAuth flows. The standalone Worker example currently wires email/password and sessions; social-login provider wiring still needs a dedicated copy-paste example and live Worker validation before it should be treated as a ready deployment path. The first Worker release intentionally defers api-key, passkey, two-factor, organization, Durable Objects, and durable rate limiting until those paths have Worker/D1 runtime evidence.

See [`examples/cloudflare-worker/`](examples/cloudflare-worker/) for a standalone Worker project that wires `worker::Request`, `worker::Response`, `Env.DB`, prepared D1 bindings, runtime capabilities, an injected Argon2 password hasher, email/password routes, and session routes.

### 1. Configure Worker-compatible dependencies

Do not use the root crate's default native feature set for Worker builds. Use the core/API/Worker crates without default native transport features and opt in to `local-futures`:

```toml
[dependencies]
better-auth-core = { version = "0.10", default-features = false, features = ["local-futures"] }
better-auth-api = { version = "0.10", default-features = false, features = ["local-futures"] }
better-auth-worker = { version = "0.10", default-features = false, features = ["local-futures"] }
async-trait = "0.1"
serde_json = "1"
```

The example already uses this dependency shape.

### 2. Build the example

Install the Worker build prerequisites and run the Wasm check:

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.8.3
export PATH="$HOME/.cargo/bin:$PATH"
command -v worker-build
cargo check --manifest-path examples/cloudflare-worker/Cargo.toml --target wasm32-unknown-unknown
```

### 3. Create and migrate the D1 database

Create your own D1 database. Do not commit a real production `database_id` into a public repository; keep it in a private Wrangler config or a local-only edit.

```bash
cd examples/cloudflare-worker
npx wrangler d1 create better-auth-rs-worker
cp wrangler.toml wrangler.local.toml
cp .dev.vars.example .dev.vars
npx wrangler d1 migrations apply better-auth-rs-worker --local --config wrangler.local.toml
```

Paste the returned `database_id` into `wrangler.local.toml`, then replace the local `.dev.vars` secret before running `wrangler dev`. The checked-in example [`wrangler.toml`](examples/cloudflare-worker/wrangler.toml) keeps a placeholder `database_id` and points `migrations_dir` at [`migrations/d1/`](migrations/d1/). Private `wrangler.local.toml`, `.dev.vars`, `.wrangler/`, and generated `build/` paths are ignored by git.

The names are intentionally separate:

- Worker script name: `better-auth-rs-cloudflare-worker`
- D1 database name: `better-auth-rs-worker`
- D1 binding name: `better_auth_rs_worker`

### 4. Run locally

```bash
cd examples/cloudflare-worker
export PATH="$HOME/.cargo/bin:$PATH"
npx wrangler dev --config wrangler.local.toml
curl -i http://localhost:8787/api/auth/sign-up/email \
  -H 'content-type: application/json' \
  -d '{"name":"Worker User","email":"worker@example.com","password":"Password123!"}'
```

Use `/api/auth/sign-in/email` to sign in and pass the returned `better-auth.session-token` cookie to `/api/auth/get-session`.

### 5. Deploy to Cloudflare

Use the private Wrangler config with the real D1 `database_id`, apply remote migrations, deploy the Worker, then add the remote secret:

```bash
cd examples/cloudflare-worker
export PATH="$HOME/.cargo/bin:$PATH"
npx wrangler d1 migrations apply better-auth-rs-worker --remote --config wrangler.local.toml
npx wrangler deploy --config wrangler.local.toml
npx wrangler secret put BETTER_AUTH_SECRET --config wrangler.local.toml
```

Verify the deployed Worker:

```bash
curl -i https://better-auth-rs-cloudflare-worker.<your-subdomain>.workers.dev/api/auth/sign-up/email \
  -H 'content-type: application/json' \
  -d '{"name":"Worker User","email":"worker@example.com","password":"Password123!"}'
```

If `wrangler secret put` says the Worker does not exist, run `wrangler deploy` first. For local dev, use `.dev.vars` instead of `wrangler secret put`.

### 6. Verify Worker gates

```bash
cargo check -p better-auth-worker --target wasm32-unknown-unknown --no-default-features
cargo check -p better-auth-worker --target wasm32-unknown-unknown --features local-futures
cargo test -p better-auth-worker --features api-route-tests --lib
cargo check --manifest-path examples/cloudflare-worker/Cargo.toml --target wasm32-unknown-unknown
```

## Plugins

Better Auth RS ships with a rich set of plugins. Enable only what you need:

| Plugin | Description |
|--------|-------------|
| **Email/Password** | Sign up/sign in with email & password, username support |
| **Session Management** | Session listing, revocation, and token refresh |
| **Password Management** | Password reset, change, and set flows |
| **Email Verification** | Email verification workflows |
| **Account Management** | Account linking and unlinking |
| **OAuth** | Social sign-in via OAuth 2.0 providers |
| **Two-Factor** | TOTP-based 2FA with backup codes |
| **Organization** | Multi-tenant organizations with RBAC |
| **Admin** | User management and administrative operations |
| **API Key** | API key generation, rotation, and revocation |
| **Passkey** | WebAuthn passkey authentication |
| **Device Authorization** | Device flow for TVs, consoles, CLIs, and other input-constrained clients |

> See the [Plugins documentation](docs/content/docs/concepts/plugins.mdx) for usage details.

## Feature Flags

| Feature | Description |
|---------|-------------|
| `axum` | Axum web framework integration |
| `derive` | Derive macros for custom entity types (`AuthUser`, `MemoryUser`, etc.) |
| `local-futures` | Worker-style local futures using `Rc` / `?Send`; build separately from `axum` |
| `sqlx-postgres` | PostgreSQL database support via SQLx |

The `better-auth-worker` crate has its own feature flags:

| Feature | Description |
|---------|-------------|
| `local-futures` | Enables Worker-local `?Send` futures and `Rc` runtime capability ports |
| `api-route-tests` | Internal test-only feature for route smoke tests with `better-auth-api` |

## Crate Structure

| Crate | Description |
|-------|-------------|
| [`better-auth`](https://crates.io/crates/better-auth) | Main crate — re-exports and framework integration |
| [`better-auth-core`](https://crates.io/crates/better-auth-core) | Core abstractions: traits, config, middleware, error handling |
| [`better-auth-api`](https://crates.io/crates/better-auth-api) | Plugin implementations |
| [`better-auth-derive`](https://crates.io/crates/better-auth-derive) | Derive macros for custom entity types |
| [`better-auth-worker`](crates/worker) | Cloudflare Worker request/response, runtime capability, and D1 adapter boundary |

## Documentation

Detailed guides and API reference are available in the [`docs/`](docs/) directory:

- [Installation](docs/content/docs/installation.mdx)
- [Quick Start](docs/content/docs/quick-start.mdx)
- **Authentication** — [Email/Password](docs/content/docs/authentication/email-password.mdx) · [Sessions](docs/content/docs/authentication/sessions.mdx) · [Email Verification](docs/content/docs/authentication/email-verification.mdx)
- **Concepts** — [Configuration](docs/content/docs/concepts/configuration.mdx) · [Database](docs/content/docs/concepts/database.mdx) · [Plugins](docs/content/docs/concepts/plugins.mdx) · [Middleware](docs/content/docs/concepts/middleware.mdx) · [Hooks](docs/content/docs/concepts/hooks.mdx)
- **Plugins** — [OAuth](docs/content/docs/plugins/oauth.mdx) · [Two-Factor](docs/content/docs/plugins/two-factor.mdx) · [Organization](docs/content/docs/plugins/organization.mdx) · [Admin](docs/content/docs/plugins/admin.mdx) · [API Key](docs/content/docs/plugins/api-key.mdx) · [Passkey](docs/content/docs/plugins/passkey.mdx) · [Device Authorization](docs/content/docs/plugins/device-authorization.mdx)
- **Reference** — [API Routes](docs/content/docs/reference/api-routes.mdx) · [Configuration Options](docs/content/docs/reference/configuration-options.mdx) · [Errors](docs/content/docs/reference/errors.mdx) · [Security](docs/content/docs/reference/security.mdx) · [OpenAPI](docs/content/docs/reference/openapi.mdx)
- **Integrations** — [Axum](docs/content/docs/integrations/axum.mdx)

## Examples

```bash
# Basic usage (in-memory)
cargo run --example basic_usage

# Axum web server
cargo run --example axum_server --features axum

# PostgreSQL
cargo run --example postgres_usage --features sqlx-postgres

# Custom entity types with derive macros
cargo run --example custom_entities --features derive

# Custom ORM adapter
cargo run --example custom_orm_adapter

# Full-stack (better-auth frontend + better-auth-rs backend)
cargo run --manifest-path examples/fullstack/backend/Cargo.toml

# Worker adapter and D1 route smoke tests
cargo test -p better-auth-worker --features api-route-tests --lib
```

> See [examples/README.md](examples/README.md) for detailed documentation on each example.

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
