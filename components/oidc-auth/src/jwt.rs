//! id_token validation — done ONCE, at `/callback`. After this, the session is ours
//! and we never touch JWKS on the request path again.
//!
//! Two distinct checks (scope.md "Authn vs Authz"):
//!   * `verify_signature` + claim checks here = authentication (who).
//!   * the `groups`/admin-group check (in lib.rs middleware) = authorization (may they).

use crate::config::Config;
use crate::jwks::Jwk;
use crate::util::{b64url_decode, now_secs};
use anyhow::{anyhow, bail, Result};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: String,
    /// Accept `aud` as either a single string or an array (both are spec-legal).
    #[serde(default)]
    pub aud: Audience,
    pub iss: String,
    pub exp: u64,
    #[serde(default)]
    pub nonce: Option<String>,
    /// Group/role claim. Name is IdP-specific; `groups` is the common case (Keycloak,
    /// Okta custom authz server). Mapping is configurable in a real multi-IdP build.
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    None,
}

impl Audience {
    fn contains(&self, v: &str) -> bool {
        match self {
            Audience::One(a) => a == v,
            Audience::Many(xs) => xs.iter().any(|a| a == v),
            Audience::None => false,
        }
    }
}

/// The kid we need to fetch a signing key for (read from the header, no verification yet).
pub fn header_kid(id_token: &str) -> Result<Option<String>> {
    let header_b64 = id_token.split('.').next().ok_or_else(|| anyhow!("malformed JWT"))?;
    let header: Header = serde_json::from_slice(&b64url_decode(header_b64)?)?;
    Ok(header.kid)
}

/// Verify the signature against `jwk`, then validate `iss`/`aud`/`exp`/`nonce`.
/// Returns the validated claims on success.
pub fn validate(id_token: &str, jwk: &Jwk, cfg: &Config, expected_nonce: &str) -> Result<Claims> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        bail!("id_token is not a 3-part JWT");
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);
    let header: Header = serde_json::from_slice(&b64url_decode(header_b64)?)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = b64url_decode(sig_b64)?;

    verify_signature(&header.alg, &signing_input, &sig, jwk)?;

    let claims: Claims = serde_json::from_slice(&b64url_decode(payload_b64)?)?;

    // iss must match the configured issuer exactly.
    if claims.iss != cfg.issuer {
        bail!("issuer mismatch: token={} expected={}", claims.iss, cfg.issuer);
    }
    // aud: configured audience if set, else must contain our client_id.
    let expected_aud = if cfg.audience.is_empty() {
        &cfg.client_id
    } else {
        &cfg.audience
    };
    if !claims.aud.contains(expected_aud) {
        bail!("audience does not contain {expected_aud}");
    }
    // exp (small leeway for clock skew).
    if claims.exp + 60 < now_secs() {
        bail!("id_token expired");
    }
    // nonce: replay protection — must equal the one we stored at /login.
    match claims.nonce.as_deref() {
        Some(n) if n == expected_nonce => {}
        _ => bail!("nonce mismatch (possible replay)"),
    }
    Ok(claims)
}

fn verify_signature(alg: &str, signing_input: &str, sig: &[u8], jwk: &Jwk) -> Result<()> {
    match alg {
        "RS256" => verify_rs256(signing_input, sig, jwk),
        "ES256" => verify_es256(signing_input, sig, jwk),
        other => bail!("unsupported id_token alg: {other}"),
    }
}

fn verify_rs256(signing_input: &str, sig: &[u8], jwk: &Jwk) -> Result<()> {
    if jwk.kty != "RSA" {
        bail!("RS256 token but JWK kty={}", jwk.kty);
    }
    let n = jwk.n.as_ref().ok_or_else(|| anyhow!("JWK missing n"))?;
    let e = jwk.e.as_ref().ok_or_else(|| anyhow!("JWK missing e"))?;
    let n = BigUint::from_bytes_be(&b64url_decode(n)?);
    let e = BigUint::from_bytes_be(&b64url_decode(e)?);
    let key = RsaPublicKey::new(n, e).map_err(|e| anyhow!("bad RSA key: {e}"))?;

    let digest = Sha256::digest(signing_input.as_bytes());
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
        .map_err(|e| anyhow!("RS256 signature invalid: {e}"))
}

fn verify_es256(signing_input: &str, sig: &[u8], jwk: &Jwk) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    if jwk.kty != "EC" {
        bail!("ES256 token but JWK kty={}", jwk.kty);
    }
    let x = b64url_decode(jwk.x.as_ref().ok_or_else(|| anyhow!("JWK missing x"))?)?;
    let y = b64url_decode(jwk.y.as_ref().ok_or_else(|| anyhow!("JWK missing y"))?)?;
    if x.len() != 32 || y.len() != 32 {
        bail!("ES256 JWK coordinates must be 32 bytes (P-256)");
    }
    // SEC1 uncompressed point: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| anyhow!("bad EC key: {e}"))?;
    let sig = Signature::from_slice(sig).map_err(|e| anyhow!("bad ES256 sig: {e}"))?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|e| anyhow!("ES256 signature invalid: {e}"))
}
