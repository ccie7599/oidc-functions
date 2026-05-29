//! Discovery + JWKS fetch-through cache — the ONLY outward fetch in the system,
//! and never on the hot path (only at `/login`, `/callback`, or on a cache miss).
//!
//! One KV record per tenant (`jwks:{tenant}`) holds both the discovery endpoints
//! and the signing keys. Freshness is enforced from `Cache-Control: max-age`.
//! An unknown `kid` forces a refetch (handles IdP key rotation with no background
//! job) — but rate-capped by a negative-cache window so unknown-kid spam can't turn
//! into a JWKS DoS against the IdP. See scope.md "JWKS caching".

use crate::config::Config;
use crate::util::now_secs;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use spin_sdk::http::{send, Method, Request, Response};
use spin_sdk::key_value::Store;

/// Don't refetch JWKS more than once per this window when chasing an unknown kid.
const KID_MISS_REFETCH_COOLDOWN_SECS: u64 = 60;
/// Fallback freshness if the IdP sends no usable `Cache-Control: max-age`.
const DEFAULT_JWKS_MAX_AGE_SECS: u64 = 3600;

#[derive(Serialize, Deserialize, Clone)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    // RSA
    pub n: Option<String>,
    pub e: Option<String>,
    // EC (ES256)
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TenantMeta {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// RP-initiated logout endpoint (OIDC `end_session_endpoint`). Empty if the IdP
    /// doesn't advertise one — then logout is local-only.
    #[serde(default)]
    pub end_session_endpoint: String,
    pub jwks_uri: String,
    pub keys: Vec<Jwk>,
    pub fetched_at: u64,
    pub max_age: u64,
    /// Last time we refetched specifically because of an unknown kid (rate cap).
    pub last_kid_miss_fetch: u64,
}

impl TenantMeta {
    fn fresh(&self) -> bool {
        now_secs().saturating_sub(self.fetched_at) < self.max_age
    }
    fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            // No kid in the header => only unambiguous if there's exactly one key.
            None => (self.keys.len() == 1).then(|| &self.keys[0]),
            Some(kid) => self.keys.iter().find(|k| k.kid.as_deref() == Some(kid)),
        }
    }
}

fn meta_key(cfg: &Config) -> String {
    // Version suffix: bump when the cached TenantMeta shape changes, to force a fresh
    // discovery fetch instead of deserializing a stale record (e.g. adding
    // end_session_endpoint). v2: added end_session_endpoint.
    format!("jwks:v2:{}", cfg.tenant)
}

/// Return tenant metadata (endpoints + keys), refreshing from the IdP if stale/missing.
/// Used by `/login` (authorization_endpoint) and `/callback` (token_endpoint).
pub async fn get_meta(store: &Store, cfg: &Config) -> Result<TenantMeta> {
    if let Some(raw) = store.get(&meta_key(cfg))? {
        if let Ok(meta) = serde_json::from_slice::<TenantMeta>(&raw) {
            if meta.fresh() {
                return Ok(meta);
            }
        }
    }
    refresh(store, cfg).await
}

/// Resolve a signing key by `kid`, fetching through on a miss (key rotation),
/// but never more often than the negative-cache cooldown.
pub async fn signing_key(store: &Store, cfg: &Config, kid: Option<&str>) -> Result<Jwk> {
    let meta = get_meta(store, cfg).await?;
    if let Some(k) = meta.find(kid) {
        return Ok(k.clone());
    }
    // Unknown kid. Refetch only if we haven't just done so (DoS cap).
    if now_secs().saturating_sub(meta.last_kid_miss_fetch) < KID_MISS_REFETCH_COOLDOWN_SECS {
        bail!("unknown signing kid (refetch suppressed by negative-cache cooldown)");
    }
    let mut fresh = refresh(store, cfg).await?;
    if let Some(k) = fresh.find(kid) {
        return Ok(k.clone());
    }
    // Still missing after a real refetch => genuine signing failure. Stamp the cap.
    fresh.last_kid_miss_fetch = now_secs();
    store.set(&meta_key(cfg), &serde_json::to_vec(&fresh)?)?;
    bail!("no signing key for kid after refetch")
}

/// Fetch discovery + JWKS and persist the combined record.
async fn refresh(store: &Store, cfg: &Config) -> Result<TenantMeta> {
    let discovery_url = format!("{}/.well-known/openid-configuration", cfg.issuer);
    let (disc, _) = get_json(&discovery_url).await?;

    let issuer = str_field(&disc, "issuer")?;
    let authorization_endpoint = str_field(&disc, "authorization_endpoint")?;
    let token_endpoint = str_field(&disc, "token_endpoint")?;
    let jwks_uri = str_field(&disc, "jwks_uri")?;
    // Optional — not every IdP advertises it.
    let end_session_endpoint = disc
        .get("end_session_endpoint")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();

    let (jwks, max_age) = get_json(&jwks_uri).await?;
    let keys: Vec<Jwk> = serde_json::from_value(
        jwks.get("keys")
            .cloned()
            .ok_or_else(|| anyhow!("JWKS missing 'keys'"))?,
    )?;

    let meta = TenantMeta {
        issuer,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
        jwks_uri,
        keys,
        fetched_at: now_secs(),
        max_age: max_age.unwrap_or(DEFAULT_JWKS_MAX_AGE_SECS),
        last_kid_miss_fetch: 0,
    };
    store.set(&meta_key(cfg), &serde_json::to_vec(&meta)?)?;
    Ok(meta)
}

/// GET a URL and parse JSON, returning the body and any `Cache-Control: max-age`.
async fn get_json(url: &str) -> Result<(serde_json::Value, Option<u64>)> {
    let req = Request::builder().method(Method::Get).uri(url).body(()).build();
    let resp: Response = send(req).await.map_err(|e| anyhow!("GET {url}: {e}"))?;
    let status = *resp.status();
    if !(200..300).contains(&status) {
        bail!("GET {url} -> HTTP {status}");
    }
    let max_age = resp
        .header("cache-control")
        .and_then(|h| h.as_str())
        .and_then(parse_max_age);
    let value: serde_json::Value = serde_json::from_slice(resp.body())
        .map_err(|e| anyhow!("parse JSON from {url}: {e}"))?;
    Ok((value, max_age))
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control.split(',').find_map(|p| {
        let p = p.trim();
        p.strip_prefix("max-age=").and_then(|v| v.parse().ok())
    })
}

fn str_field(v: &serde_json::Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("discovery doc missing '{key}'"))
}
