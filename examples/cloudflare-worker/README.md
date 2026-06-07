# Cloudflare Worker + D1 example

This standalone example wires `better-auth-worker` to real Cloudflare Worker bindings:

- `worker::Request` / `worker::Response` conversion
- `Env.DB` D1 prepared statements
- Worker runtime capabilities for clock, entropy, IDs, session tokens, and OAuth fetch
- email/password sign-up and sign-in
- session routes such as `/api/auth/get-session` and `/api/auth/sign-out`

## Prerequisites

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.8.3
export PATH="$HOME/.cargo/bin:$PATH"
command -v worker-build
npm install --global wrangler
```

## Configure D1

Create a D1 database and copy the checked-in config to a private local config.

```bash
cd examples/cloudflare-worker
npx wrangler d1 create better-auth-rs-worker
cp wrangler.toml wrangler.local.toml
```

Keep these names distinct:

- Worker script name: `better-auth-rs-cloudflare-worker`
- D1 database name: `better-auth-rs-worker`
- D1 binding name: `better_auth_rs_worker`

Paste the returned `database_id` into `wrangler.local.toml`. `wrangler.toml` is safe to commit only with the checked-in placeholder `database_id`. For a public repository, keep real D1 database ids in a private config, a local-only edit, or deployment automation that is not committed. The D1 binding name must stay `better_auth_rs_worker` unless you also change `DB_BINDING` in `src/lib.rs`.

## Set the auth secret

For local development, copy `.dev.vars.example` to `.dev.vars` and replace the value with at least 32 random characters.
The `.dev.vars`, `.wrangler/`, `wrangler.local.toml`, `wrangler.deploy.toml`, and generated `build/` paths are ignored by git.

Use `wrangler secret put` only for deployed Workers. For local dev, keep using `.dev.vars`; the full remote sequence is in the deploy section below.

## Apply local migrations

```bash
npx wrangler d1 migrations apply better-auth-rs-worker --local --config wrangler.local.toml
```

The migration directory is `../../migrations/d1`, which points at the D1 schema shipped by the repository.

## Run locally

```bash
export PATH="$HOME/.cargo/bin:$PATH"
npx wrangler dev --config wrangler.local.toml
```

If Wrangler reports `/bin/sh: worker-build: command not found`, run the `export PATH="$HOME/.cargo/bin:$PATH"` command in the same terminal before `npx wrangler dev`. Wrangler inherits the PATH from the terminal that starts it.

The Worker exposes auth routes under `/api/auth`.

```bash
curl -i http://localhost:8787/api/auth/sign-up/email \
  -H 'content-type: application/json' \
  -d '{"name":"Worker User","email":"worker@example.com","password":"Password123!"}'

curl -i http://localhost:8787/api/auth/sign-in/email \
  -H 'content-type: application/json' \
  -d '{"email":"worker@example.com","password":"Password123!"}'
```

Use the `Set-Cookie` value from sign-in when calling session routes:

```bash
curl -i http://localhost:8787/api/auth/get-session \
  -H 'cookie: better-auth.session-token=<token>'
```

## Deploy to Cloudflare

Use `wrangler.local.toml` or another private Wrangler config that contains the real D1 `database_id`.

```bash
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

If `wrangler secret put` says there is no Worker named `better-auth-rs-cloudflare-worker`, deploy first. For local dev, keep using `.dev.vars`.

## Verify the Rust build

```bash
cargo check --manifest-path Cargo.toml --target wasm32-unknown-unknown
```

Run the command from `examples/cloudflare-worker`.
