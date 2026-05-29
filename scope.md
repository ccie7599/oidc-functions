# SCOPE: OIDC Auth Component for WASM Control Planes (Fermyon Spin / Akamai Functions)

## Goal

A standalone Spin HTTP component that owns the **full OIDC authorization-code flow with PKCE**
and gates access to a control-plane (CP) function. The component is **self-contained**: the only
stateful dependency is **Spin KV**. No external session store, no EdgeWorker auth termination,
no background refresh jobs.

It is designed to be **composed in front of** the CP business-logic component (Spin 2.0 component
model — exports `wasi:http/incoming-handler`, forwards on auth success), so it is reusable across
multiple WASM functions, not baked into one CP.

Supported IdPs: **Okta** and **PingFederate / PingOne** (any OIDC-compliant provider).

## Why this design (settled decisions)

- **Auth-code + PKCE, confidential client.** Not implicit flow. Function holds client secret.
- **Trust boundary inside the function.** The function does OIDC itself rather than trusting an
  edge-injected identity header. Correct for an admin CP — tight, self-contained trust boundary.
- **Stateful sessions in Spin KV** (not stateless self-signed JWT). Reason: admin CP requires
  *immediate revocation*; per-request KV lookup cost is irrelevant at admin-access volume.
- **IdP signature validated once, at callback.** After that the session is ours (opaque cookie +
  KV record + our own expiry). No per-request JWKS work on the hot path. The id_token is consumed
  and discarded — we do NOT store it, and we do NOT store the IdP refresh token.
- **No token refresh.** Short session lifetime (~1h); re-auth through IdP on expiry.

## Prior art (context — none is a drop-in)

- Fermyon "Composing Components with Spin 2.0" — **structural reference** (auth middleware component
  composed in front of business logic, exports incoming-handler). But it's GitHub OAuth, not OIDC:
  no id_token validation, no JWKS, no PKCE, no group claims. Borrow the *shape*, write the OIDC guts.
- Fermyon "JWT Token Validation with Wasm Functions" — the OPPOSITE architecture (EdgeWorker
  terminates, function only validates). Explicitly rejected here.
- Spin discussion #741 — maintainers: app-level auth is out of Spin's domain, app implements it.
  No framework primitive to lean on; the stateless-session-in-KV model is the part we're inventing.
- `openidconnect-rs` (Rust) — check `wasm32-wasi`/`wasm32-wasip1` compile. Built around a persistent
  client object, so use its discovery/JWKS/validation primitives, NOT its session model.
- Standard PKCE request/response shapes: Okta + Ory OIDC docs.

## Component shape

One Spin HTTP component, three route groups:

- `GET  /login`            → build authorize URL, set PKCE + state, 302 to IdP
- `GET  /callback`         → validate state, exchange code, validate id_token, create session, 302
- `*`   (protected)        → middleware: cookie → KV session lookup → exp check → group check → forward
- (admin/out-of-band)      → `kv.delete("sess:{id}")` to revoke

### Spin KV namespaces

| Key                  | Value                                         | TTL                  | Notes                          |
|----------------------|-----------------------------------------------|----------------------|--------------------------------|
| `pkce:{state}`       | `{verifier, nonce, return_to}`                | ~5 min               | single-use, delete on callback |
| `sess:{opaque_id}`   | `{sub, email, groups, exp, idp_tenant}`       | = session lifetime   | revoke = delete this key       |
| `jwks:{tenant}`      | cached JWKS doc + discovery endpoints         | from `Cache-Control` | fetch-through on miss/unknown kid |

## Flow detail

### `/login`
1. Generate `code_verifier` (random 43–128 chars). `code_challenge = BASE64URL(SHA256(verifier))`.
2. Generate `state` and `nonce` (CSRF + replay protection).
3. Store `pkce:{state}` → `{verifier, nonce, return_to}` with ~5 min TTL.
4. 302 to:
   `{issuer}/authorize?response_type=code&client_id=...&redirect_uri=...`
   `&scope=openid profile groups&state=...&code_challenge=...&code_challenge_method=S256`
   - Verifier never leaves KV; only the challenge goes to the IdP.

### `/callback`
1. Read `state` from query; look up `pkce:{state}`. Missing → reject (expired/forged).
   **Delete it immediately** (single-use).
2. POST to `{issuer}/token`: `grant_type=authorization_code`, `code`, `redirect_uri`,
   `client_id`, `client_secret`, `code_verifier`.
3. Receive `id_token` (+ access token). **Validate id_token**:
   - fetch-through JWKS by `kid`, verify RS256/ES256 signature
   - check `iss`, `aud`, `exp`, and `nonce` == stored nonce
4. Extract `sub`, `email`, `groups`. Generate opaque session id (random — NOT derived from token).
   Store `sess:{id}` with the needed subset + our own `exp`.
5. `Set-Cookie: cp_session={id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=...`. 302 to `return_to`.

### Protected middleware
1. Parse `cp_session` cookie. Missing → 302 `/login`.
2. KV lookup `sess:{id}`. Missing → expired/revoked → 302 `/login`.
3. Check stored `exp` (KV TTL is a backstop, not the authority — check the value too).
4. Check `groups` contains the admin group. Missing → **403**.
5. Forward to CP handler with identity (sub/email/groups).

## JWKS caching (the only outward fetch)

```
get_signing_key(kid, tenant):
  jwks = kv.get("jwks:{tenant}")
  if jwks and kid in jwks and not expired:
    return jwks[kid]
  # miss or unknown kid (rotation)
  doc      = http.get("{issuer}/.well-known/openid-configuration")   # cache this too
  jwks_uri = doc.jwks_uri
  fresh    = http.get(jwks_uri)
  kv.set("jwks:{tenant}", fresh, ttl=parse_cache_control(resp))
  return fresh[kid]   # still missing → reject (real signing failure)
```

- Unknown `kid` forces a refetch → handles IdP key rotation with no background job.
- **Cap the refetch rate**: short negative-cache on "just fetched, still no such kid" to prevent
  unknown-kid spam becoming a JWKS DoS against the IdP.
- Never fetch JWKS per-request on the hot path — only at callback / on cache miss.

## Crypto

- Needs RS256/ES256 signature verify + SHA256 (for PKCE challenge).
- Prefer **host crypto** via component model / `wasi-crypto` host bindings (faster, smaller guest).
- Fallback: pure-Rust (`ring` / `rsa` + `jsonwebtoken`) compiles to WASM fine; guest-side cost is
  irrelevant at admin volume. Don't over-optimize.

## Per-tenant config (Spin variables / runtime config — never baked in)

Key all of these by tenant so one component serves multiple customers' IdPs:

- `issuer` URL
- `client_id`
- `client_secret`
- allowed `audiences`
- admin group/role claim mapping (e.g. `groups` contains `cp-admins`)
- `redirect_uri`
- session lifetime

## Authn vs Authz (don't conflate)

- **Authentication** = signature + `iss`/`aud`/`exp`/`nonce` valid → tells you *who*.
- **Authorization** = group/role claim gates the CP → tells you *whether they may*.
- Validate the group claim on **every protected request** alongside session validity. The group
  claim is what actually gates the control plane.

## IdP specifics

### Okta
- OIDC discovery at `/.well-known/openid-configuration`, standard JWKS endpoint.
- `groups` claim must be added to the token via an authz-server claim config.
- **Org authz server vs custom authz server** matters for which claims you get — pin this down early.

### PingFederate / PingOne
- OIDC-compliant, but JWKS path + claim mapping depend on the **OAuth attribute contract**.
- PingOne = more turnkey. PingFederate = more control, but you specify the policy contract and how
  attributes flow into the token.

## Tradeoffs accepted (be explicit)

- **Horizontal scale requires shared KV.** If the Spin runtime scales out, Spin KV MUST be a shared
  backing store across instances, not per-instance local — otherwise sessions break on replica #2.
  **Verify the deployment's KV backing before building.**
- **Revocation = `kv.delete("sess:{id}")`.** Build a tiny admin endpoint or out-of-band tool for it.
- **No refresh tokens stored.** Re-login on expiry. Correct for an admin CP.

## Build tasks (suggested order for the code session)

1. Confirm Spin KV is shared/backed across instances in the target deployment.
2. Confirm language + crypto path: Rust + host crypto (preferred) vs `ring`/`jsonwebtoken` fallback.
   (Check `openidconnect-rs` wasm32-wasi compile if reusing its primitives.)
3. Scaffold Spin component, route dispatch (`/login`, `/callback`, protected `*`).
4. PKCE + state generation and `pkce:{state}` KV store/delete.
5. `/callback`: token exchange + id_token validation (iss/aud/exp/nonce).
6. JWKS fetch-through cache module (`jwks:{tenant}`) with negative-cache cap.
7. Session model: opaque id, `sess:{id}` store, cookie set.
8. Protected middleware: cookie → session → exp → group check → forward.
9. Per-tenant config wiring via Spin variables.
10. Compose in front of CP component (Spin 2.0 component model, export incoming-handler).
11. Revocation endpoint / tool.
12. Test against Okta (custom authz server) and PingOne.

## Out of scope (for now)

- Token refresh / offline_access.
- Edge-terminated auth (auth EdgeWorker injecting signed identity) — viable for fronting many
  functions, but rejected here for a single admin CP to keep the trust boundary tight.
- Logout from the IdP side (SLO) — local session delete only, unless added later.
