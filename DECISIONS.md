# Architecture Decision Records

Records the choices behind this build. The auth-model decisions (ADR-0001/0002) are
restatements of the settled design in `scope.md`; ADR-0003/0004/0005 are decisions made
during the build session, with their tradeoffs.

---

## ADR-0001 — Auth-code + PKCE, confidential client, trust boundary inside the function

**Status:** Accepted (from `scope.md`).

The function performs OIDC itself rather than trusting an edge-injected identity header.
Authorization-code flow with PKCE (S256), confidential client holding the secret — not
implicit flow. Correct for an admin control plane: a tight, self-contained trust boundary.

---

## ADR-0002 — Opaque stateful sessions in Spin KV (not stateless JWT)

**Status:** Accepted (from `scope.md`).

After the IdP signature is validated once at `/callback`, we mint a random opaque session
id and store `sess:{id}` in KV with our own `exp`. The cookie reveals nothing; **revocation
is `kv.delete("sess:{id}")`**. Chosen over a stateless self-signed JWT because an admin CP
needs immediate revocation, and per-request KV lookup cost is irrelevant at admin volume.

**Note on TTL:** Spin's default KV has no native TTL, so expiry is enforced from the `exp`
value stored *inside* each record (and PKCE records carry a `created` timestamp). KV TTL,
where available, is only a backstop — the stored value is the authority.

---

## ADR-0003 — Pure-Rust crypto (`rsa` + `p256`), not `ring` or `wasi-crypto`

**Status:** Accepted (build-session decision).

**Decision:** Verify id_token signatures with pure-Rust RustCrypto (`rsa` for RS256,
`p256` for ES256, `sha2` for digests + PKCE challenge). RSA public keys are reconstructed
from the JWKS `n`/`e` components; EC keys from `x`/`y`.

**Why not `jsonwebtoken`/`ring`:** `ring` needs a C toolchain (`clang`) to build for
`wasm32-wasip1` — verified failing in this environment (`cc-rs: failed to find tool
"clang"`). **Why not host `wasi-crypto`:** more fragile to build and needs `cargo-component`
tooling that isn't installed. Per `scope.md`, guest-side crypto cost is irrelevant at admin
volume — so the pure-Rust path is the pragmatic, portable choice. The full stack compiles
clean to `wasm32-wasip1` in ~30s.

**Consequence:** RS256 and ES256 are both implemented; only RS256 is exercised end-to-end
here (Keycloak's default). ES256 is unverified against a live ES256 IdP.

---

## ADR-0004 — Forwarding via Spin local service chaining + a forwarding-secret guard

**Status:** Accepted with a documented tradeoff (build-session decision).

`scope.md` describes composing the auth component in front of the CP via the **Spin 2.0
component model** (auth imports the CP's `wasi:http/incoming-handler`, so the CP has no
public route). That requires `cargo-component` + `wac`, which are **not installed** in this
environment and add real build fragility.

**Decision:** Forward over **Spin local service chaining** instead — `oidc-auth` issues an
internal request to `http://cp-landing.spin.internal/__cp/`, injecting the validated
identity (`x-auth-sub/email/groups`) and a shared **forwarding secret**. The CP rejects any
request lacking that secret with 403, so a direct external hit to its `/__cp/...` route
cannot bypass auth.

**Why:** builds and runs reliably with plain `cargo` + `spin` — no extra component-model
tooling — which matches the priority of a runnable reference app.

**Tradeoff:** the CP still has an HTTP route (guarded), whereas true component-model
composition would give it no route at all. The auth guts are identical either way; only the
forwarding edge differs.

**Migration path to true composition:** `cargo install cargo-component wac-cli`; build
`cp-landing` as a component exporting `wasi:http/incoming-handler`; give `oidc-auth` a WIT
world that *imports* that handler and call it directly instead of the `.spin.internal`
request; `wac plug` the CP into the auth import; drop the `/__cp` trigger and the
forwarding-secret guard. (Reference: Fermyon "Composing Components with Spin 2.0".)

---

## ADR-0005 — Keycloak as the demo IdP (config-swappable to Okta / PingOne)

**Status:** Accepted (build-session decision).

**Context:** No Okta or PingOne account was available. The scope targets "any OIDC-compliant
provider."

**Decision:** Ship a local **Keycloak** (Docker) with a pre-imported `cp-demo` realm
(confidential client with enforced S256 PKCE, a `cp-admins` group, a group-membership mapper
emitting `groups`, and two seeded users). The whole demo runs offline with `make demo`.

**Why Keycloak over alternatives:** it's a genuinely OIDC-compliant IdP (discovery, JWKS,
RS256, PKCE) with first-class **group claims** — which the authorization model depends on —
and it's free and self-hosted. Auth0/Okta-dev free tiers are hosted (no offline demo);
Google-as-OIDC has no usable groups claim; Ory Hydra needs a separate login/consent app.

**Consequence:** none of the IdP coupling lives in code — switching to Okta/PingOne is
Spin-variable config only (`issuer`/`client_id`/`client_secret`/`scopes`/`admin_group`).
