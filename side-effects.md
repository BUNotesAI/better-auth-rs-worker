# Side-Effect Matrix

Every write operation must be listed here.

| Write operation | Resource | Effect | Test coverage |
|---|---|---|---|
| `SessionManager::create_session` | Session table / adapter session store | Creates a session using configured runtime ID, session-token, and clock capabilities before delegating persistence to the adapter. | `cargo test -p better-auth-core session_uses_configured_runtime_effects -- --nocapture` |
| `SessionManager::get_session` | Session table / adapter session store | Reads a session and deletes it when the configured runtime clock marks it expired. | `cargo test -p better-auth-core session_uses_configured_runtime_effects -- --nocapture` |
| `EmailPasswordPlugin::sign_up_core` | User table / session table / response cookie | Creates a user with a runtime-generated user ID, stores password metadata through the injected hasher, creates an auto sign-in session through `SessionManager`, and emits the session cookie. | `cargo test -p better-auth-api email_password_signup_uses_runtime_effect_ports -- --nocapture` |
| `EmailPasswordPlugin::sign_in_with_user_core` two-factor pending branch | Verification table | Creates a pending two-factor verification token using the configured runtime ID generator and clock. Worker v1 still excludes two-factor; this keeps the existing branch from using hidden native effects. | Covered by existing email/password sign-in route tests; residual Worker-v1 exclusion recorded in P3 Quality Evidence. |
| `hash_password(None, ...)` in no-default builds | Password hashing runtime policy | Rejects unsafe native default password hashing when no `password-argon2` feature or injected hasher is present. | `cargo test -p better-auth-core --no-default-features worker_password_hashing_rejects_unsafe_defaults -- --nocapture` |

## Update Rules

- Add a row when a new write operation is introduced.
- Update a row when the side-effect scope changes.
- Review this matrix during task close.
