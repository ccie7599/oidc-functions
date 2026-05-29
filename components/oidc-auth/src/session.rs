//! Opaque server-side sessions in Spin KV. The session id is random (NOT derived
//! from the id_token), so the cookie reveals nothing and revocation == delete the key.
//!
//! After `/callback` validates the IdP signature once, the session is *ours*: our
//! opaque id, our stored claims subset, our own `exp`. No per-request JWKS work.

use crate::config::Config;
use crate::util::{now_secs, random_token};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use spin_sdk::key_value::Store;

pub const COOKIE_NAME: &str = "cp_session";

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
    pub idp_tenant: String,
    /// Our own expiry (unix secs). The authority — checked on every request.
    pub exp: u64,
    /// Kept server-side only (never sent to the client) so /logout can pass it as
    /// `id_token_hint` for clean RP-initiated logout without an IdP confirmation page.
    #[serde(default)]
    pub id_token: String,
}

/// Mint a fresh session, persist `sess:{id}`, return (id, session).
pub fn create(
    store: &Store,
    cfg: &Config,
    sub: String,
    email: String,
    groups: Vec<String>,
    id_token: String,
) -> Result<(String, Session)> {
    let id = random_token(32)?; // 256 bits of opaque id
    let sess = Session {
        sub,
        email,
        groups,
        idp_tenant: cfg.tenant.clone(),
        exp: now_secs() + cfg.session_ttl_secs,
        id_token,
    };
    store.set(&sess_key(&id), &serde_json::to_vec(&sess)?)?;
    Ok((id, sess))
}

/// Look up a session by opaque id. Expired sessions are deleted and treated as absent.
pub fn lookup(store: &Store, id: &str) -> Result<Option<Session>> {
    let key = sess_key(id);
    let Some(raw) = store.get(&key)? else {
        return Ok(None);
    };
    let sess: Session = serde_json::from_slice(&raw)?;
    if now_secs() >= sess.exp {
        store.delete(&key)?; // opportunistic GC; KV TTL is only a backstop
        return Ok(None);
    }
    Ok(Some(sess))
}

pub fn revoke(store: &Store, id: &str) -> Result<()> {
    store.delete(&sess_key(id)).map_err(|e| anyhow!("{e}"))
}

/// `Set-Cookie` value for a new session: HttpOnly + Secure + SameSite=Lax.
pub fn set_cookie(id: &str, ttl_secs: u64) -> String {
    format!(
        "{COOKIE_NAME}={id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={ttl_secs}"
    )
}

/// `Set-Cookie` value that clears the session cookie (logout).
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

fn sess_key(id: &str) -> String {
    format!("sess:{id}")
}
