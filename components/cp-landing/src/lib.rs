//! cp-landing — the protected "control plane" behind the auth gate.
//!
//! It renders a landing page from the identity that oidc-auth forwarded. It does NOT
//! do any auth itself; it only trusts requests that carry the shared forwarding secret
//! that oidc-auth injects over Spin local service chaining. A direct external hit to
//! this component's route (`/__cp/...`) has no secret and is rejected 403.
//!
//! In a real deployment, replace this with the actual CP business logic, or compose it
//! as a WAC dependency of oidc-auth so it has no public route at all (see DECISIONS.md).

use spin_sdk::http::{IntoResponse, Request, Response};
use spin_sdk::http_component;
use spin_sdk::variables;

#[http_component]
fn handle(req: Request) -> Response {
    // Service-chaining guard: only oidc-auth knows this secret.
    let expected = variables::get("cp_forward_secret").unwrap_or_default();
    let presented = header(&req, "x-cp-forward-secret");
    if expected.is_empty() || presented.as_deref() != Some(expected.as_str()) {
        return Response::builder()
            .status(403)
            .header("content-type", "text/plain; charset=utf-8")
            .body("403: control plane is only reachable through the auth component")
            .build();
    }

    let sub = header(&req, "x-auth-sub").unwrap_or_else(|| "unknown".into());
    let email = header(&req, "x-auth-email").unwrap_or_default();
    let groups = header(&req, "x-auth-groups").unwrap_or_default();

    Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(landing_html(&sub, &email, &groups))
        .build()
        .into_response()
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.header(name).and_then(|h| h.as_str()).map(|s| s.to_string())
}

fn landing_html(sub: &str, email: &str, groups: &str) -> String {
    let groups_list = groups
        .split(',')
        .filter(|g| !g.is_empty())
        .map(|g| format!("<li><code>{}</code></li>", esc(g)))
        .collect::<String>();

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Control Plane</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 42rem; margin: 4rem auto; padding: 0 1.5rem; }}
    .badge {{ display:inline-block; background:#0a7f3f; color:#fff; padding:.15rem .6rem; border-radius:1rem; font-size:.8rem; letter-spacing:.02em; }}
    .card {{ border:1px solid color-mix(in srgb, currentColor 18%, transparent); border-radius:.75rem; padding:1.25rem 1.5rem; margin:1.5rem 0; }}
    dt {{ font-weight:600; }} dd {{ margin:0 0 .75rem; }}
    code {{ background: color-mix(in srgb, currentColor 10%, transparent); padding:.1rem .35rem; border-radius:.3rem; }}
    a.logout {{ display:inline-block; margin-top:1rem; }}
    footer {{ margin-top:2rem; font-size:.85rem; opacity:.7; }}
  </style>
</head>
<body>
  <p><span class="badge">AUTHENTICATED</span></p>
  <h1>Control Plane</h1>
  <p>You reached the protected function. The OIDC component authenticated you, checked
     your admin group, and forwarded your identity here.</p>
  <div class="card">
    <dl>
      <dt>Subject (<code>sub</code>)</dt><dd><code>{sub}</code></dd>
      <dt>Email</dt><dd>{email}</dd>
      <dt>Groups</dt><dd><ul>{groups_list}</ul></dd>
    </dl>
  </div>
  <a class="logout" href="/logout">Log out</a>
  <footer>Served by the <code>cp-landing</code> component, gated by <code>oidc-auth</code>.</footer>
</body>
</html>"#,
        sub = esc(sub),
        email = esc(email),
        groups_list = groups_list,
    )
}

/// Minimal HTML-escaping for the identity values we echo back.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
