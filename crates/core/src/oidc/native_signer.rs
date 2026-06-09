//! Native signing adapters for the OIDC [`JwtSigner`] / [`JwksProvider`] ports.
//!
//! Gated behind `jwt` + `oidc-provider`. The signer uses `jsonwebtoken`'s
//! `crypto::sign` over the pure-core `signing_input` and returns only the raw
//! signature bytes (ES256 JOSE `r||s`, RS256 PKCS#1 v1.5), honoring the port
//! contract that the pure core owns all JOSE serialization. `ring` (pulled in by
//! `jsonwebtoken`) is confined to this native, feature-gated adapter and never
//! enters the portable OIDC path.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey};

use crate::capabilities::{JwtSigner, KeyId, SigningAlg};
use crate::error::{AuthError, AuthResult};

fn jwt_algorithm(alg: SigningAlg) -> Algorithm {
    match alg {
        SigningAlg::Es256 => Algorithm::ES256,
        SigningAlg::Rs256 => Algorithm::RS256,
    }
}

/// A [`JwtSigner`] backed by a `jsonwebtoken` [`EncodingKey`].
pub struct NativeJwtSigner {
    kid: KeyId,
    alg: SigningAlg,
    key: EncodingKey,
}

impl NativeJwtSigner {
    /// Builds a native signer from a private-key PEM (EC for ES256, RSA for RS256).
    pub fn from_pem(kid: KeyId, alg: SigningAlg, pem: &[u8]) -> AuthResult<Self> {
        let key = match alg {
            SigningAlg::Es256 => EncodingKey::from_ec_pem(pem),
            SigningAlg::Rs256 => EncodingKey::from_rsa_pem(pem),
        }
        .map_err(|e| AuthError::config(format!("invalid OIDC signing key PEM: {e}")))?;
        Ok(Self { kid, alg, key })
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl JwtSigner for NativeJwtSigner {
    fn active_key(&self) -> AuthResult<(KeyId, SigningAlg)> {
        Ok((self.kid.clone(), self.alg))
    }

    async fn sign(
        &self,
        _kid: &KeyId,
        alg: SigningAlg,
        signing_input: &[u8],
    ) -> AuthResult<Vec<u8>> {
        // jsonwebtoken returns a base64url signature; the port returns raw bytes.
        let encoded = jsonwebtoken::crypto::sign(signing_input, &self.key, jwt_algorithm(alg))?;
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|e| AuthError::internal(format!("signature base64url decode: {e}")))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::DecodingKey;

    // Test-only EC P-256 key pair (generated with openssl for this test).
    const TEST_EC_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzLAeyXrnD1fnAn7i\n5W/CFsHd6Xzz7BSNxzoZPAayY+ahRANCAAQzfPIndcIPl6+RCid5qyXDrE0N1Itr\nXqAv8uZjyAPV5FOXFobP+tomsWNyFI5TXrbC6nXwfIPIkKxvVdnHqRBI\n-----END PRIVATE KEY-----\n";
    const TEST_EC_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM3zyJ3XCD5evkQoneaslw6xNDdSL\na16gL/LmY8gD1eRTlxaGz/raJrFjchSOU162wup18HyDyJCsb1XZx6kQSA==\n-----END PUBLIC KEY-----\n";

    #[tokio::test]
    async fn native_es256_signer_signs_and_round_trips() {
        let signer = NativeJwtSigner::from_pem(
            KeyId::new("test-key-1"),
            SigningAlg::Es256,
            TEST_EC_PKCS8_PEM.as_bytes(),
        )
        .unwrap();

        let (kid, alg) = signer.active_key().unwrap();
        assert_eq!(kid.as_str(), "test-key-1");
        assert_eq!(alg, SigningAlg::Es256);

        let signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ";
        let signature = signer.sign(&kid, alg, signing_input).await.unwrap();
        // ES256 raw JOSE signature is r||s = 64 bytes.
        assert_eq!(signature.len(), 64);

        // The raw signature verifies against the public key (native arm of the
        // P4 jwks_verify_smoke; full cross-adapter verify is closed in P4).
        let decoding = DecodingKey::from_ec_pem(TEST_EC_PUB_PEM.as_bytes()).unwrap();
        let verified = jsonwebtoken::crypto::verify(
            &URL_SAFE_NO_PAD.encode(&signature),
            signing_input,
            &decoding,
            Algorithm::ES256,
        )
        .unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn oidc_jwks_verify_smoke_native() {
        use crate::capabilities::{Jwk, JwkSet, JwksProvider, StaticJwksProvider};

        // The published JWK (x/y) for the test key. An OIDC relying party uses
        // exactly this JWKS output to verify issued id_tokens, so this is the
        // end-to-end contract: what the signer signs must verify under the
        // *published* JWK, not just the raw key. (Worker/WebCrypto arm carried
        // forward to wrangler/CI; the port is identical.)
        const JWK_X: &str = "M3zyJ3XCD5evkQoneaslw6xNDdSLa16gL_LmY8gD1eQ";
        const JWK_Y: &str = "U5cWhs_62iaxY3IUjlNetsLqdfB8g8iQrG9V2cepEEg";

        let signer = NativeJwtSigner::from_pem(
            KeyId::new("test-key-1"),
            SigningAlg::Es256,
            TEST_EC_PKCS8_PEM.as_bytes(),
        )
        .unwrap();
        let (kid, alg) = signer.active_key().unwrap();

        let jwks = StaticJwksProvider::new(JwkSet {
            keys: vec![Jwk::Ec {
                use_: "sig".to_string(),
                kid: kid.as_str().to_string(),
                alg: alg.as_str().to_string(),
                crv: "P-256".to_string(),
                x: JWK_X.to_string(),
                y: JWK_Y.to_string(),
            }],
        });

        let signing_input =
            b"eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ1c2VyLTEifQ";
        let signature = signer.sign(&kid, alg, signing_input).await.unwrap();

        // verify using the PUBLISHED JWK components (x/y), not the raw PEM key.
        let published = jwks.jwks().unwrap();
        let Jwk::Ec { x, y, .. } = &published.keys[0] else {
            panic!("expected an EC jwk");
        };
        let decoding = DecodingKey::from_ec_components(x, y).unwrap();
        let verified = jsonwebtoken::crypto::verify(
            &URL_SAFE_NO_PAD.encode(&signature),
            signing_input,
            &decoding,
            Algorithm::ES256,
        )
        .unwrap();
        assert!(
            verified,
            "issued id_token signature must verify under the published JWKS"
        );

        // a different message must not verify under the same JWK + signature.
        let tampered = jsonwebtoken::crypto::verify(
            &URL_SAFE_NO_PAD.encode(&signature),
            b"tampered.payload",
            &decoding,
            Algorithm::ES256,
        )
        .unwrap();
        assert!(!tampered, "a tampered token must not verify");
    }
}
