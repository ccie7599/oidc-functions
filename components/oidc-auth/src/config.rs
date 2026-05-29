//! Per-tenant OIDC configuration, read from Spin variables.
//!
//! Nothing is baked into the binary — every value comes from `[component.*.variables]`
//! in `spin.toml`, which in turn pull from runtime config / `SPIN_VARIABLE_*` env.
//! Keying these by tenant (here a single `tenant` slug) is what lets one component
//! serve multiple customers' IdPs. See scope.md "Per-tenant config".

use anyhow::Result;
use spin_sdk::variables;

#[derive(Debug, Clone)]
pub struct Config {
    /// Slug used to namespace KV records (`jwks:{tenant}`, etc.). One IdP == one tenant.
    pub tenant: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// Expected `aud`. Empty => fall back to requiring `aud` contains `client_id`.
    pub audience: String,
    /// Group/role claim value that gates the control plane (authorization).
    pub admin_group: String,
    pub scopes: String,
    pub session_ttl_secs: u64,
    /// Shared secret the auth component sends to the CP so the CP can reject any
    /// request that did not pass through auth (service-chaining guard).
    pub cp_forward_secret: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        Ok(Self {
            tenant: variables::get("tenant").unwrap_or_else(|_| "default".to_string()),
            issuer: trim_trailing_slash(variables::get("issuer")?),
            client_id: variables::get("client_id")?,
            client_secret: variables::get("client_secret")?,
            redirect_uri: variables::get("redirect_uri")?,
            audience: variables::get("audience").unwrap_or_default(),
            admin_group: variables::get("admin_group").unwrap_or_else(|_| "cp-admins".into()),
            scopes: variables::get("scopes")
                .unwrap_or_else(|_| "openid profile email groups".into()),
            session_ttl_secs: variables::get("session_ttl_secs")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            cp_forward_secret: variables::get("cp_forward_secret")?,
        })
    }
}

fn trim_trailing_slash(s: String) -> String {
    s.trim_end_matches('/').to_string()
}
