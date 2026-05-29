//! oidc-auth — a self-contained Spin HTTP component that owns the full OIDC
//! authorization-code + PKCE flow and gates a downstream control-plane function.
//!
//! Routes (this component is mapped to `/...`):
//!   GET /login    -> build authorize URL (PKCE+state+nonce), 302 to IdP
//!   GET /callback -> validate state, exchange code, validate id_token, create session
//!   GET /logout   -> delete session (local), clear cookie
//!   *  (anything else, protected) -> cookie -> session -> exp -> group check -> forward to CP
//!
//! Only stateful dependency is Spin KV. See scope.md for the settled design.

mod config;
mod jwks;
mod jwt;
mod pkce;
mod session;
mod util;

use anyhow::{anyhow, bail, Result};
use config::Config;
use spin_sdk::http::{send, IntoResponse, Method, Request, Response};
use spin_sdk::http_component;
use spin_sdk::key_value::Store;
use util::{cookie_value, redirect, redirect_with_cookie, text};

#[http_component]
async fn handle(req: Request) -> Response {
    match dispatch(req).await {
        Ok(resp) => resp,
        // Surface the reason in the demo rather than an opaque 500.
        Err(e) => text(500, format!("auth component error: {e:#}")).into_response(),
    }
}

async fn dispatch(req: Request) -> Result<Response> {
    let cfg = Config::load()?;
    let store = Store::open_default()?;
    let path = req.path().to_string();

    match path.as_str() {
        "/login" => login(&req, &cfg, &store).await,
        "/callback" => callback(&req, &cfg, &store).await,
        "/logout" => logout(&req, &cfg, &store).await,
        _ => protected(&req, &cfg, &store).await,
    }
}

// ---------------------------------------------------------------------------
// /login
// ---------------------------------------------------------------------------
async fn login(req: &Request, cfg: &Config, store: &Store) -> Result<Response> {
    let return_to = query_param(req.query(), "return_to")
        .map(|s| sanitize_return_to(&s))
        .unwrap_or_else(|| "/".to_string());

    let meta = jwks::get_meta(store, cfg).await?;
    let start = pkce::begin(store, &return_to)?;

    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_uri)
        .append_pair("scope", &cfg.scopes)
        .append_pair("state", &start.state)
        .append_pair("nonce", &start.nonce)
        .append_pair("code_challenge", &start.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();

    redirect(&format!("{}?{}", meta.authorization_endpoint, query))
}

// ---------------------------------------------------------------------------
// /callback
// ---------------------------------------------------------------------------
async fn callback(req: &Request, cfg: &Config, store: &Store) -> Result<Response> {
    let q = req.query();
    if let Some(err) = query_param(q, "error") {
        let desc = query_param(q, "error_description").unwrap_or_default();
        return Ok(text(401, format!("IdP returned error: {err} {desc}")));
    }
    let code = query_param(q, "code").ok_or_else(|| anyhow!("missing code"))?;
    let state = query_param(q, "state").ok_or_else(|| anyhow!("missing state"))?;

    // Single-use: reading the PKCE record also deletes it.
    let pkce = pkce::take(store, &state)?;

    // Exchange the code for tokens (confidential client: secret + verifier).
    let meta = jwks::get_meta(store, cfg).await?;
    let id_token = exchange_code(cfg, &meta.token_endpoint, &code, &pkce.verifier).await?;

    // Validate id_token signature + claims (the one-time JWKS work).
    let kid = jwt::header_kid(&id_token)?;
    let jwk = jwks::signing_key(store, cfg, kid.as_deref()).await?;
    let claims = jwt::validate(&id_token, &jwk, cfg, &pkce.nonce)?;

    // Mint our own opaque session. We keep the id_token server-side (only) so /logout
    // can do clean RP-initiated logout via id_token_hint.
    let (sid, _sess) = session::create(
        store,
        cfg,
        claims.sub,
        claims.email,
        claims.groups,
        id_token,
    )?;

    redirect_with_cookie(
        &pkce.return_to,
        &session::set_cookie(&sid, cfg.session_ttl_secs),
    )
}

/// POST to the token endpoint, return the raw `id_token` string.
async fn exchange_code(
    cfg: &Config,
    token_endpoint: &str,
    code: &str,
    verifier: &str,
) -> Result<String> {
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &cfg.redirect_uri)
        .append_pair("client_id", &cfg.client_id)
        .append_pair("client_secret", &cfg.client_secret)
        .append_pair("code_verifier", verifier)
        .finish();

    let req = Request::builder()
        .method(Method::Post)
        .uri(token_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body)
        .build();

    let resp: Response = send(req).await.map_err(|e| anyhow!("token endpoint: {e}"))?;
    let status = *resp.status();
    if !(200..300).contains(&status) {
        bail!(
            "token endpoint -> HTTP {status}: {}",
            String::from_utf8_lossy(resp.body())
        );
    }
    let token: serde_json::Value = serde_json::from_slice(resp.body())?;
    token
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("token response has no id_token"))
}

// ---------------------------------------------------------------------------
// /logout — delete our session AND end the IdP SSO session (RP-initiated logout).
// Without the IdP hop, /login would silently re-authenticate from the IdP's SSO
// cookie and the user would never actually be logged out.
// ---------------------------------------------------------------------------
async fn logout(req: &Request, cfg: &Config, store: &Store) -> Result<Response> {
    // Look the session up first so we can hand the IdP an id_token_hint, then revoke it.
    let id_token_hint = match session_id(req) {
        Some(sid) => {
            let hint = session::lookup(store, &sid)?.map(|s| s.id_token);
            session::revoke(store, &sid)?;
            hint
        }
        None => None,
    };
    let clear = session::clear_cookie();

    // Send the browser to the IdP's end_session_endpoint so its SSO session ends too —
    // otherwise /login silently re-authenticates from the IdP's SSO cookie.
    let meta = jwks::get_meta(store, cfg).await?;
    if meta.end_session_endpoint.is_empty() {
        return redirect_with_cookie("/login", &clear); // IdP has no logout endpoint
    }
    // id_token_hint lets the IdP log out immediately (no confirmation prompt) and
    // validates the post_logout_redirect_uri against the token's client.
    let post_logout = format!("{}/login", app_base(cfg));
    let mut ser = form_urlencoded::Serializer::new(String::new());
    ser.append_pair("post_logout_redirect_uri", &post_logout);
    match &id_token_hint {
        Some(t) if !t.is_empty() => {
            ser.append_pair("id_token_hint", t);
        }
        _ => {
            ser.append_pair("client_id", &cfg.client_id);
        }
    }
    redirect_with_cookie(&format!("{}?{}", meta.end_session_endpoint, ser.finish()), &clear)
}

/// The app's public base URL, derived from `redirect_uri` (…/callback → …).
fn app_base(cfg: &Config) -> String {
    cfg.redirect_uri
        .strip_suffix("/callback")
        .unwrap_or(&cfg.redirect_uri)
        .to_string()
}

// ---------------------------------------------------------------------------
// protected middleware: authenticate (session) + authorize (group) + forward
// ---------------------------------------------------------------------------
async fn protected(req: &Request, cfg: &Config, store: &Store) -> Result<Response> {
    let Some(sid) = session_id(req) else {
        return login_redirect(req.path());
    };
    let Some(sess) = session::lookup(store, &sid)? else {
        // Missing/expired/revoked => re-auth.
        return login_redirect(req.path());
    };

    // Authorization: the group claim is what actually gates the control plane.
    if !sess.groups.iter().any(|g| g == &cfg.admin_group) {
        return Ok(text(
            403,
            format!(
                "403 Forbidden: '{}' is required to access the control plane.\n\
                 You are '{}' with groups {:?}.",
                cfg.admin_group, sess.email, sess.groups
            ),
        ));
    }

    forward_to_cp(cfg, &sess).await
}

/// Forward the request to the CP component via Spin local service chaining,
/// stamping the validated identity and the shared forwarding secret.
async fn forward_to_cp(cfg: &Config, sess: &session::Session) -> Result<Response> {
    let target = "http://cp-landing.spin.internal/__cp/";
    let out = Request::builder()
        .method(Method::Get)
        .uri(target)
        .header("x-cp-forward-secret", &cfg.cp_forward_secret)
        .header("x-auth-sub", &sess.sub)
        .header("x-auth-email", &sess.email)
        .header("x-auth-groups", sess.groups.join(","))
        .body(())
        .build();
    let resp: Response = send(out).await.map_err(|e| anyhow!("forward to CP: {e}"))?;
    Ok(resp)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
fn session_id(req: &Request) -> Option<String> {
    let cookie = req.header("cookie")?.as_str()?;
    cookie_value(cookie, session::COOKIE_NAME).map(|s| s.to_string())
}

fn login_redirect(path: &str) -> Result<Response> {
    let q = form_urlencoded::Serializer::new(String::new())
        .append_pair("return_to", path)
        .finish();
    redirect(&format!("/login?{q}"))
}

fn query_param(query: &str, key: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Only allow same-site absolute paths as return targets (open-redirect guard).
fn sanitize_return_to(v: &str) -> String {
    if v.starts_with('/') && !v.starts_with("//") && !v.starts_with("/\\") {
        v.to_string()
    } else {
        "/".to_string()
    }
}
