//! Portable ES256 signing for the OIDC [`JwtSigner`](crate::capabilities::JwtSigner) port.
//!
//! Pure-Rust ECDSA P-256 (the `p256` crate), so a single signer works on **both**
//! native and wasm/Worker targets with no `ring`/`openssl` dependency and no
//! WebCrypto plumbing. Signing is deterministic (RFC 6979), so it needs no
//! runtime RNG. The signer returns only the raw JOSE `r || s` signature; the pure
//! core owns header/payload/compact-JWS assembly.
//!
//! The matching public JWK (kid/crv/x/y) is derived from the signing key via
//! [`P256JwtSigner::public_jwk`] / [`P256JwtSigner::jwks`] and published through
//! [`StaticJwksProvider`](crate::capabilities::StaticJwksProvider), so the same
//! key that signs id_tokens is the one a relying party verifies against.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

use crate::capabilities::{Jwk, JwkSet, JwtSigner, KeyId, SigningAlg};
use crate::error::{AuthError, AuthResult};

/// A portable ES256 [`JwtSigner`] backed by a pure-Rust P-256 key.
///
/// Works unchanged on native and wasm/Worker; no `ring`/`openssl`/WebCrypto.
pub struct P256JwtSigner {
    kid: KeyId,
    signing_key: SigningKey,
}

impl P256JwtSigner {
    /// Builds a signer from a PKCS#8 DER-encoded P-256 private key.
    pub fn from_pkcs8_der(kid: KeyId, der: &[u8]) -> AuthResult<Self> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| AuthError::config(format!("invalid P-256 PKCS#8 DER key: {e}")))?;
        Ok(Self { kid, signing_key })
    }

    /// Builds a signer from a PKCS#8 PEM-encoded P-256 private key.
    pub fn from_pkcs8_pem(kid: KeyId, pem: &str) -> AuthResult<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| AuthError::config(format!("invalid P-256 PKCS#8 PEM key: {e}")))?;
        Ok(Self { kid, signing_key })
    }

    /// The public JWK (EC P-256) for this signer's key, for JWKS publication.
    ///
    /// `x` / `y` are the base64url-encoded affine coordinates of the public key,
    /// matching what a relying party uses to verify issued id_tokens.
    #[must_use]
    pub fn public_jwk(&self) -> Jwk {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        // Uncompressed SEC1 point is `0x04 || X(32) || Y(32)`; x()/y() yield the
        // 32-byte coordinates for a non-compressed point.
        let x = point.x().map(|x| URL_SAFE_NO_PAD.encode(x)).unwrap_or_default();
        let y = point.y().map(|y| URL_SAFE_NO_PAD.encode(y)).unwrap_or_default();
        Jwk::Ec {
            use_: "sig".to_string(),
            kid: self.kid.as_str().to_string(),
            alg: SigningAlg::Es256.as_str().to_string(),
            crv: "P-256".to_string(),
            x,
            y,
        }
    }

    /// The single-key JWK set to publish at the JWKS endpoint.
    #[must_use]
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public_jwk()],
        }
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl JwtSigner for P256JwtSigner {
    fn active_key(&self) -> AuthResult<(KeyId, SigningAlg)> {
        Ok((self.kid.clone(), SigningAlg::Es256))
    }

    async fn sign(
        &self,
        _kid: &KeyId,
        alg: SigningAlg,
        signing_input: &[u8],
    ) -> AuthResult<Vec<u8>> {
        match alg {
            SigningAlg::Es256 => {
                // Deterministic ECDSA (RFC 6979) over SHA-256(signing_input).
                // `Signature::to_bytes()` is the fixed 64-byte JOSE `r || s` form.
                let signature: Signature = self
                    .signing_key
                    .try_sign(signing_input)
                    .map_err(|e| AuthError::internal(format!("ES256 signing failed: {e}")))?;
                Ok(signature.to_bytes().to_vec())
            }
            SigningAlg::Rs256 => Err(AuthError::config(
                "P256JwtSigner supports ES256 only; RS256 requires an RSA signer",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{JwksProvider, StaticJwksProvider};
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    // Test-only EC P-256 PKCS#8 key pair (openssl-generated, shared with native_signer tests).
    const TEST_EC_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzLAeyXrnD1fnAn7i\n5W/CFsHd6Xzz7BSNxzoZPAayY+ahRANCAAQzfPIndcIPl6+RCid5qyXDrE0N1Itr\nXqAv8uZjyAPV5FOXFobP+tomsWNyFI5TXrbC6nXwfIPIkKxvVdnHqRBI\n-----END PRIVATE KEY-----\n";

    fn verifying_key_from_jwk_xy(x_b64: &str, y_b64: &str) -> VerifyingKey {
        let x = URL_SAFE_NO_PAD.decode(x_b64).unwrap();
        let y = URL_SAFE_NO_PAD.decode(y_b64).unwrap();
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1).unwrap()
    }

    #[tokio::test]
    async fn p256_signer_verifies_under_published_jwk_and_is_deterministic() {
        let signer =
            P256JwtSigner::from_pkcs8_pem(KeyId::new("p256-key-1"), TEST_EC_PKCS8_PEM).unwrap();

        let (kid, alg) = signer.active_key().unwrap();
        assert_eq!(kid.as_str(), "p256-key-1");
        assert_eq!(alg, SigningAlg::Es256);

        let signing_input = b"eyJhbGciOiJFUzI1NiIsImtpZCI6InAyNTYta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ1c2VyLTEifQ";
        let sig = signer.sign(&kid, alg, signing_input).await.unwrap();
        // ES256 raw JOSE signature is r || s = 64 bytes.
        assert_eq!(sig.len(), 64);

        // Reconstruct the verifying key from the PUBLISHED JWK (x/y) and verify:
        // this is the end-to-end "published JWKS verifies issued id_tokens" contract.
        let published = StaticJwksProvider::new(signer.jwks()).jwks().unwrap();
        let Jwk::Ec {
            crv, alg: jwk_alg, x, y, ..
        } = &published.keys[0]
        else {
            panic!("expected an EC jwk");
        };
        assert_eq!(crv, "P-256");
        assert_eq!(jwk_alg, "ES256");

        let verifying_key = verifying_key_from_jwk_xy(x, y);
        let signature = Signature::from_slice(&sig).unwrap();
        assert!(
            verifying_key.verify(signing_input, &signature).is_ok(),
            "issued id_token signature must verify under the published JWK"
        );
        // A tampered message must not verify.
        assert!(verifying_key.verify(b"tampered.payload", &signature).is_err());

        // Deterministic (RFC 6979): the same input yields the same signature.
        let sig_again = signer.sign(&kid, alg, signing_input).await.unwrap();
        assert_eq!(sig, sig_again, "ES256 signing must be deterministic (RFC 6979)");
    }

    #[tokio::test]
    async fn p256_signer_rejects_rs256() {
        let signer =
            P256JwtSigner::from_pkcs8_pem(KeyId::new("p256-key-1"), TEST_EC_PKCS8_PEM).unwrap();
        let (kid, _) = signer.active_key().unwrap();
        assert!(signer.sign(&kid, SigningAlg::Rs256, b"x").await.is_err());
    }
}
