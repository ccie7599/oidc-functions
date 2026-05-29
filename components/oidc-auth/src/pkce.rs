//! PKCE + state/nonce: the short-lived `pkce:{state}` KV record that ties a `/login`
//! to its `/callback`. Single-use — deleted the instant `/callback` reads it.

use crate::util::{b64url, now_secs, random_bytes, random_token};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spin_sdk::key_value::Store;

/// ~5 min: long enough for a human IdP login, short enough to bound replay.
const PKCE_TTL_SECS: u64 = 300;

#[derive(Serialize, Deserialize)]
pub struct PkceRecord {
    pub verifier: String,
    pub nonce: String,
    pub return_to: String,
    pub created: u64,
}

/// `code_challenge = BASE64URL(SHA256(verifier))` — only the challenge goes to the IdP.
pub fn challenge_s256(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    b64url(&h.finalize())
}

pub struct PkceStart {
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

/// Generate verifier/state/nonce, persist `pkce:{state}`, return what `/login` needs.
pub fn begin(store: &Store, return_to: &str) -> Result<PkceStart> {
    // RFC 7636: verifier is 43–128 chars. 32 random bytes -> 43 base64url chars.
    let verifier = b64url(&random_bytes(32)?);
    let state = random_token(24)?;
    let nonce = random_token(24)?;
    let code_challenge = challenge_s256(&verifier);

    let rec = PkceRecord {
        verifier,
        nonce: nonce.clone(),
        return_to: return_to.to_string(),
        created: now_secs(),
    };
    store.set(&pkce_key(&state), &serde_json::to_vec(&rec)?)?;
    Ok(PkceStart {
        state,
        nonce,
        code_challenge,
    })
}

/// Read-and-delete the PKCE record (single-use). Enforces the 5-min window in code,
/// since Spin's default KV has no native TTL (scope.md: "TTL is a backstop").
pub fn take(store: &Store, state: &str) -> Result<PkceRecord> {
    let key = pkce_key(state);
    let raw = store
        .get(&key)?
        .ok_or_else(|| anyhow!("unknown or expired state"))?;
    store.delete(&key)?; // single-use, regardless of what happens next
    let rec: PkceRecord = serde_json::from_slice(&raw)?;
    if now_secs().saturating_sub(rec.created) > PKCE_TTL_SECS {
        return Err(anyhow!("state expired"));
    }
    Ok(rec)
}

fn pkce_key(state: &str) -> String {
    format!("pkce:{state}")
}
