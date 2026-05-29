# Deployment — live reference instance

This documents the deployed reference stack: the OIDC app on **Akamai Functions (FWF)**
and the **Keycloak** IdP on the **presales landing zone**. Verified end-to-end 2026-05-29.

## Live URLs

| Piece | URL |
|-------|-----|
| Protected app (FWF) | https://da1e3f2d-1db0-4b67-8105-58894c41c07b.fwf.app/ |
| FWF app name | `oidc-cp-demo` |
| IdP (Keycloak) | https://keycloak.connected-cloud.io/realms/cp-demo |
| Source repo | https://github.com/ccie7599/oidc-functions |
| Demo login (admin) | `admin-user` / `password` → 200 control-plane page |
| Demo login (denied) | `plain-user` / `password` → 403 (not in `cp-admins`) |

## Topology

```
 browser ─▶ FWF: oidc-cp-demo  (oidc-auth ▶ cp-landing, Spin KV)
                 │  issuer ─────────────────────────┐
                 │  outbound https (token + JWKS)     ▼
                 └──────────────────────────▶ keycloak.connected-cloud.io
                                              (LZ lke575271, demo-oidc-cp ns)
                                               nginx TLS sidecar ▶ Keycloak 26.1
                                               cert: LE DNS-01 (Akamai)
                                               secrets: Vault api/oidc-cp/config
```

## FWF (the app)

Deployed with `spin aka app deploy`. Config is passed as deploy-time variables (no
secrets in the repo):

```bash
spin aka app deploy --no-confirm \
  --variable issuer=https://keycloak.connected-cloud.io/realms/cp-demo \
  --variable redirect_uri=https://da1e3f2d-1db0-4b67-8105-58894c41c07b.fwf.app/callback \
  --variable client_secret=<from Vault api/oidc-cp/config> \
  --variable cp_forward_secret=<random; shared oidc-auth->cp-landing>
```

Verified on FWF: Spin **KV** (PKCE + sessions), **service chaining** (`*.spin.internal`
oidc-auth → cp-landing), outbound HTTPS to the IdP, RS256 id_token verification.

## Keycloak (the IdP) — presales LZ

Intake-compliant deploy into the shared cluster `lke575271`, namespace `demo-oidc-cp`:

- **Image**: mirrored to Harbor — `harbor.harbor.svc.cluster.local/presales/keycloak:26.1`
  (and `presales/nginx:alpine` for the TLS sidecar). Pull secret `harbor-creds` created
  out-of-band (not in the public repo).
- **Secrets in Vault**: `api/oidc-cp/config` → `admin_password`, `client_secret`. Injected
  via Vault Agent (`role: api`, SA `app-vault-access`) into `/vault/secrets/env`, sourced
  at container start. The realm's `__CLIENT_SECRET__` placeholder is rendered at startup.
- **GitOps**: Argo CD `Application` `oidc-cp-keycloak` → `k8s/` of the repo, `prune` +
  `selfHeal`. Apply once: `kubectl apply -f argocd/application.yaml`.
- **TLS**: nginx sidecar terminates 443 (house pattern), holding a cert-manager cert
  (`letsencrypt-prod`, **DNS-01 via Akamai**). LoadBalancer NodeBalancer in TCP passthrough.
- **DNS**: `keycloak.connected-cloud.io` A → NodeBalancer IP (`172.236.113.14`), Akamai Edge DNS.
- **Telemetry**: Prometheus scrape annotations on port 9000 (`/metrics`); scraped by the
  node-local OTel Agent (Keycloak `KC_METRICS_ENABLED=true`).
- **Catalog**: added to `demo-catalog-landingzone/data/demos.json` (id `oidc-functions`).

## Operational notes / known tech debt

- **Keycloak DB is H2 `dev-file` on an `emptyDir`** (no external Postgres). Fine for a demo
  IdP — the realm re-imports on every restart and our app sessions live in FWF KV, not
  Keycloak — but **not** production-grade: a pod restart drops Keycloak's own state and
  re-creates the bootstrap admin. Promote to Postgres + a PVC for anything beyond a demo.
- **Single replica** (`strategy: Recreate`) because H2 is single-writer.
- **Vault `api` role is shared** across many namespaces. When authorizing a new namespace,
  write `bound_service_account_namespaces` as a **comma-separated list** — a space-separated
  string collapses into a single element and silently breaks auth for *every* app on the
  role. (Hit and fixed during this deploy: 2026-05-29.)
- **harbor-creds / Vault secret are intentionally not in git** — the repo is public.

## Re-run the end-to-end check

```bash
FWF=https://da1e3f2d-1db0-4b67-8105-58894c41c07b.fwf.app
# 1) /login should 302 to https://keycloak.connected-cloud.io/.../auth with code_challenge
curl -sI "$FWF/login" | grep -i location
# 2) full browser flow: log in as admin-user/password -> control-plane page (200)
#    log in as plain-user/password -> 403 (authenticated, not authorized)
```
