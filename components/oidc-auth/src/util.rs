//! Small shared helpers: base64url, randomness, time, cookies, responses.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use spin_sdk::http::Response;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| anyhow!("base64url decode: {e}"))
}

/// `n` cryptographically-random bytes (wasi `random_get` via getrandom).
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow!("getrandom: {e}"))?;
    Ok(buf)
}

/// URL-safe random token of `n` bytes of entropy.
pub fn random_token(n: usize) -> Result<String> {
    Ok(b64url(&random_bytes(n)?))
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pull a single cookie value out of a `Cookie:` header.
pub fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == name).then(|| v.trim())
    })
}

pub fn redirect(location: &str) -> Result<Response> {
    Ok(Response::builder()
        .status(302)
        .header("location", location)
        .header("cache-control", "no-store")
        .body(())
        .build())
}

pub fn redirect_with_cookie(location: &str, set_cookie: &str) -> Result<Response> {
    Ok(Response::builder()
        .status(302)
        .header("location", location)
        .header("set-cookie", set_cookie)
        .header("cache-control", "no-store")
        .body(())
        .build())
}

pub fn text(status: u16, body: impl Into<String>) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(body.into())
        .build()
}
