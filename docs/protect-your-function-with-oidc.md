# Protect your Function with OIDC

**Audience:** you have an app or API running on Akamai Functions (FWF) / Fermyon Spin,
and you want to put real **OIDC login** in front of it — only authenticated, authorized
users get through. This guide shows how to do that by composing a ready-made auth
component in front of your function. No auth code in your app.

You get: authorization-code flow with **PKCE**, signature-verified **id_tokens**,
**group-based** access control, opaque sessions in **Spin KV**, and an IdP you can point
at **Keycloak, Okta, or PingOne** with config alone.

---

## The idea in one picture

```
  user ─▶ oidc-auth  (the gate — you add this in front)
            │  • not logged in?  → 302 to your IdP, do PKCE handshake
            │  • logged in?      → check group claim → forward
            ▼
          your function  (unchanged — receives the verified identity as headers)
```

`oidc-auth` is a standalone Spin component. You compose it in front of your function in
one `spin.toml`; it handles `/login`, `/callback`, `/logout`, and gates every other route.
Your function stays auth-free and just reads `x-auth-sub` / `x-auth-email` / `x-auth-groups`.

**Two checks, kept separate:**
- **Authentication** (*who are you*): id_token signature + `iss`/`aud`/`exp`/`nonce`, verified once at `/callback`.
- **Authorization** (*may you in*): a configurable **group claim** must contain your admin group — checked on every request.

---

## Live reference deployment

A working instance is deployed so you can see the flow end-to-end:

| Piece | URL |
|-------|-----|
| Protected app (on FWF) | `https://da1e3f2d-1db0-4b67-8105-58894c41c07b.fwf.app/` |
| IdP (Keycloak, presales LZ) | `https://keycloak.connected-cloud.io/realms/cp-demo` |
| Source | <https://github.com/ccie7599/oidc-functions> |

Try it: open the app URL → you're bounced to Keycloak → log in as **`admin-user` / `password`**
→ you land on the control-plane page showing your identity. Log in as **`plain-user` / `password`**
(not in the `cp-admins` group) → you authenticate but get **403** — that's authorization working.

---

## Adopt it for your own function

### 1. Add both components to your `spin.toml`

```toml
# Your function — unchanged business logic, on a private route.
[[trigger.http]]
route = "/__app/..."
component = "your-app"

# The gate — owns every user-facing route.
[[trigger.http]]
route = "/..."
component = "oidc-auth"
```

`oidc-auth` forwards authenticated requests to your function over Spin service chaining
(`http://your-app.spin.internal/...`) with a shared `cp_forward_secret`, so your function
is only reachable *through* the gate. (Grab the `oidc-auth` component from the repo above —
`components/oidc-auth`.)

### 2. Have your function trust the forwarded identity

Your function reads three headers the gate sets after a successful check:

```
x-auth-sub      the subject (stable user id)
x-auth-email    the user's email
x-auth-groups   comma-separated group claims
```

…and rejects any request missing the shared `cp_forward_secret` header (so nobody can hit
your function's route directly). See `components/cp-landing` for a ~40-line example.

### 3. Configure your IdP (per-tenant, via Spin variables)

| Variable | What | Example |
|----------|------|---------|
| `issuer` | OIDC issuer (discovery base) | `https://keycloak.connected-cloud.io/realms/cp-demo` |
| `client_id` | Confidential client id | `cp-oidc` |
| `client_secret` | Client secret *(secret)* | — |
| `redirect_uri` | **Your FWF app URL** + `/callback` | `https://<app>.fwf.app/callback` |
| `admin_group` | Group claim that grants access | `cp-admins` |
| `scopes` | Requested scopes | `openid profile email` |
| `session_ttl_secs` | Session lifetime | `3600` |
| `cp_forward_secret` | Shared gate→app secret *(secret)* | `$(openssl rand -hex 32)` |

### 4. Deploy to FWF

```bash
spin aka app deploy --build --create-name my-protected-app \
  --variable issuer=https://your-idp/... \
  --variable client_id=... \
  --variable client_secret=... \
  --variable redirect_uri=https://<the-app-url-fwf-prints>/callback \
  --variable cp_forward_secret=$(openssl rand -hex 32)
```

FWF prints your app URL on first deploy. Set `redirect_uri` to that URL + `/callback`,
register the same URL in your IdP's client, and redeploy. Done.

> **Chicken-and-egg tip:** deploy once to learn your `*.fwf.app` URL, register that
> `…/callback` in the IdP client, then redeploy with the real `redirect_uri`.

---

## Pointing at Okta or PingOne instead of Keycloak

Nothing in code changes — it's all `--variable`:

```bash
# Okta (custom authz server)
--variable issuer=https://your-org.okta.com/oauth2/<authzServerId>
--variable scopes="openid profile email groups"   # add the groups claim on the authz server
```

Okta: the `groups` claim must be added on the authorization server (org vs custom authz
server changes which claims appear). PingOne/PingFederate: the groups claim follows your
OAuth attribute contract. The component validates whatever OIDC-compliant id_token comes back.

---

## What it does and doesn't do

**Does:** PKCE (S256), RS256/ES256 signature verification against the IdP's JWKS (cached,
never on the hot path), `iss`/`aud`/`exp`/`nonce` validation, opaque KV sessions with
immediate revocation (`kv.delete`), group-based authorization, local logout.

**Doesn't (by design):** token refresh / `offline_access` (short sessions, re-auth on
expiry), IdP-side single-logout. See [`scope.md`](../scope.md) and [`DECISIONS.md`](../DECISIONS.md).

**KV at scale:** sessions live in Spin KV. On FWF the platform provides a backing store;
if you self-host Spin and scale out, that KV **must** be shared across instances or
sessions break on the second replica.
