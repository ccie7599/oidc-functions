# OIDC Auth in Front of a WASM Function

A reference app: a self-contained **Spin HTTP component** that owns the full **OIDC
authorization-code flow with PKCE** and gates access to a downstream control-plane (CP)
function. Sessions live in **Spin KV** — no external session store, no edge auth
termination, no background refresh jobs.

The IdP signature is validated **once**, at `/callback`. After that the session is
ours (opaque cookie + KV record + our own expiry). No per-request JWKS work on the hot
path. The id_token is consumed and discarded — we never store it or any refresh token.

See [`scope.md`](scope.md) for the settled design and [`DECISIONS.md`](DECISIONS.md) for
the architecture decisions (and tradeoffs taken for this build).

## Architecture

```
                         ┌──────────────────────── Spin app ────────────────────────┐
  browser ──────────────►│  oidc-auth  (route /...)                                  │
        302 /login       │   • /login    → PKCE + state + nonce, 302 to IdP          │
        ◄────────────────│   • /callback → code exchange, id_token verify, session   │
                         │   • /logout   → delete session                            │
   ┌─────────────┐       │   • *         → cookie → KV session → exp → GROUP check ──┐│
   │  Keycloak   │◄──────│        (authenticate)            (authorize)             ││
   │  (or Okta/  │ JWKS  │                                                          ▼│
   │  PingOne)   │ token │  cp-landing (route /__cp/...) ── guarded by forward secret │
   └─────────────┘       │   renders landing page from forwarded identity headers     │
                         └────────────────────────────────────────────────────────────┘
                              Spin KV:  pkce:{state}   sess:{id}   jwks:{tenant}
```

- **Authentication** (who): id_token signature + `iss`/`aud`/`exp`/`nonce`, done once at `/callback`.
- **Authorization** (may they): the `groups` claim must contain the admin group — checked on **every** protected request.

## Quick start (local, no IdP account needed)

Prereqs: Docker, Rust + `rustup target add wasm32-wasip1`, and [Spin](https://developer.fermyon.com/spin).

```bash
make demo          # start Keycloak (imports the cp-demo realm), build, run on :3000
```

Then open <http://localhost:3000/> and log in with one of the seeded users:

| User         | Password   | In `cp-admins`? | Result                         |
|--------------|------------|-----------------|--------------------------------|
| `admin-user` | `password` | yes             | 200 — control-plane landing page |
| `plain-user` | `password` | no              | 403 — authenticated but not authorized |

Tear down with `make idp-down`. Run `make help` for all targets.

## Configuration (per-tenant, never baked in)

Every value is a Spin variable. Defaults target the local Keycloak realm; override any
with `SPIN_VARIABLE_<NAME>` (uppercase) — no manifest edit required.

| Variable            | Default (demo)                          | Purpose                                  |
|---------------------|-----------------------------------------|------------------------------------------|
| `issuer`            | `http://localhost:8080/realms/cp-demo`  | OIDC issuer (discovery base)             |
| `client_id`         | `cp-oidc`                               | Confidential client id                   |
| `client_secret`     | `cp-oidc-demo-secret` *(secret)*        | Client secret                            |
| `redirect_uri`      | `http://localhost:3000/callback`        | Must be registered at the IdP            |
| `audience`          | *(empty → require `aud` contains `client_id`)* | Expected `aud`                    |
| `admin_group`       | `cp-admins`                             | Group claim that gates the CP            |
| `scopes`            | `openid profile email`                  | Requested scopes                         |
| `session_ttl_secs`  | `3600`                                  | Our session lifetime                     |
| `cp_forward_secret` | `demo-…` *(secret)*                     | Shared secret guarding the CP component  |

### Point it at real Okta / PingOne

The component is OIDC-generic — switching IdPs is config only. See [`.env.example`](.env.example):

```bash
export SPIN_VARIABLE_ISSUER=https://your-org.okta.com/oauth2/<authzServerId>
export SPIN_VARIABLE_CLIENT_ID=0oa...
export SPIN_VARIABLE_CLIENT_SECRET=...
export SPIN_VARIABLE_SCOPES="openid profile email groups"
export SPIN_VARIABLE_CP_FORWARD_SECRET=$(openssl rand -hex 32)
spin up
```

> Okta: add the `groups` claim on your authorization server (org vs custom authz server
> changes which claims you get). PingOne/PingFederate: the groups claim depends on the
> OAuth attribute contract. See [`scope.md`](scope.md) → "IdP specifics".

## Project layout

```
spin.toml                     # 2-component app + per-tenant variables
components/oidc-auth/          # the auth component (Rust → wasm32-wasip1)
  src/{config,pkce,session,jwks,jwt,util}.rs + lib.rs (routes/flow)
components/cp-landing/         # protected CP: landing page from forwarded identity
keycloak/                      # docker-compose + cp-demo realm export (client/group/users)
Makefile  .env.example  scope.md  DECISIONS.md
```

## What's verified vs. projected

**Proven** (exercised end-to-end against Keycloak 26, single Spin instance, RS256):
auth-code + PKCE (S256), state/nonce replay protection, JWKS fetch-through + RS256
signature verify, `iss`/`aud`/`exp`/`nonce` validation, opaque KV session + cookie,
group-based 403, logout/revocation, forged-cookie handling, CP forward-secret guard.

**Implemented but not exercised here:** ES256 verification (Keycloak signs RS256 by
default), and IdP key-rotation refetch (the unknown-kid path).

**Projected, not tested:** horizontal scale. If the Spin runtime scales out, Spin KV
**must** be a shared backing store across instances or sessions break on replica #2
(see `scope.md` → "Tradeoffs accepted"). Default `spin up` uses a local SQLite KV.

## Out of scope (see `scope.md`)

Token refresh / `offline_access`; edge-terminated auth; IdP-side single-logout (SLO).
This build forwards via Spin **local service chaining** rather than WAC component-model
composition — same auth guts, different forwarding edge ([ADR-0004](DECISIONS.md)).
