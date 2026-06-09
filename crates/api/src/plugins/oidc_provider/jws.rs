//! Pure JOSE assembly for OIDC id_tokens.
//!
//! The pure core owns all serialization: the protected header, the payload, the
//! base64url encoding, the `signing_input`, and the final compact JWS. The
//! [`JwtSigner`] port produces only the raw signature bytes over the already
//! encoded `signing_input`. `alg: none` is unrepresentable because [`SigningAlg`]
//! has no such variant.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use better_auth_core::{AuthResult, JwtSigner, KeyId, SigningAlg};

/// JOSE protected header for a signed id_token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    kid: &'a str,
    typ: &'a str,
}

/// Builds `base64url(header) "." base64url(payload)` (pure, no signing).
pub fn build_signing_input(
    kid: &KeyId,
    alg: SigningAlg,
    payload_json: &[u8],
) -> AuthResult<String> {
    let header = ProtectedHeader {
        alg: alg.as_str(),
        kid: kid.as_str(),
        typ: "JWT",
    };
    let header_json = serde_json::to_vec(&header)?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json),
        URL_SAFE_NO_PAD.encode(payload_json)
    ))
}

/// Assembles the compact JWS from the signing input and the raw signature (pure).
#[must_use]
pub fn assemble_compact_jws(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Signs a serialized id_token payload into a compact JWS.
///
/// The core builds the header/payload/`signing_input` and assembles the final
/// JWS; the signer is asked only for the raw signature over `signing_input`.
pub async fn sign_id_token(payload_json: &[u8], signer: &dyn JwtSigner) -> AuthResult<String> {
    let (kid, alg) = signer.active_key()?;
    let signing_input = build_signing_input(&kid, alg, payload_json)?;
    let signature = signer.sign(&kid, alg, signing_input.as_bytes()).await?;
    Ok(assemble_compact_jws(&signing_input, &signature))
}
