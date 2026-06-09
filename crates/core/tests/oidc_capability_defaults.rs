//! Capability-default contract for the OIDC signing ports.
//!
//! The `oidc-provider` feature adds `jwt_signer` / `jwks_provider` to the runtime
//! capability set, but a default (non-OIDC, or Worker) assembly must NOT be
//! forced to inject them: the defaults are `Unavailable` stubs that error when
//! used. This keeps the feature additive and safe to compile in everywhere.

use better_auth_core::AuthRuntimeCapabilities;

#[test]
fn oidc_capability_defaults_are_unavailable_stubs() {
    let caps = AuthRuntimeCapabilities::default();

    assert!(
        caps.jwks_provider.jwks().is_err(),
        "the default JWKS provider must be the Unavailable stub"
    );
    assert!(
        caps.jwt_signer.active_key().is_err(),
        "the default JWT signer must be the Unavailable stub"
    );
}
