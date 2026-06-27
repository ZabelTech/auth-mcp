# Spec: Refresh tokens for `mcp_oauth.auth_server`

Status: proposed · Branch: `spec/refresh-tokens` · Owner: ZabelTech

## 1. Problem

The self-hosted authorization server issues a single short-lived access token and **no
refresh token**. When the access token's `exp` passes, the resource-server gate
(`resource_server.py`) rejects it and the MCP client has no silent way to renew — it must
re-run the full interactive `authorization_code` login. With the default 8 h TTL that is a
login every workday; the operational workaround applied across the fleet was to stretch
`as_token_ttl` to 7 days (`ACTIVITIES_AS_TOKEN_TTL`, `VITALS_MCP_AS_TOKEN_TTL`,
`GENOSCOPE_AS_TOKEN_TTL` = `604800`). That trades the annoyance for a larger exposure
window: a leaked bearer token is valid for a week and there is no revocation.

The proper fix is OAuth 2.1 refresh tokens: keep the **access** token short-lived
(minutes–an hour) and issue a long-lived **refresh** token the client exchanges silently
for a new access token. This is the standard the MCP clients (Claude) already implement on
the client side — we only need the server half.

Today's relevant facts (all in `mcp_oauth/auth_server.py`):
- `grant_types_supported = ["authorization_code"]` (metadata, line 221).
- `/token` only accepts `grant_type=authorization_code` (line 302) and returns
  `{access_token, token_type, expires_in, scope}` with no `refresh_token` (line 315).
- Auth codes are **stateless** HS256 JWTs signed with a key derived from the RSA signing
  key (`_code_secret()`), single-use via an in-memory `_seen_jti` set (line 119).
- The deploy is single-machine, no DB (`auto_stop_machines=false`, `min_machines_running=1`).

## 2. Goals / Non-goals

**Goals**
- Add a `refresh_token` grant so clients renew access without re-login.
- Decouple access-token lifetime from re-login cadence: access tokens go back to short
  (default 1 h); refresh tokens carry the long lifetime (default 30 days).
- Support **refresh-token rotation** with reuse detection (OAuth 2.1 BCP).
- Stay within the package's constraints: host-injected config, no new runtime dependency
  beyond `pyjwt[crypto]` (stdlib `sqlite3` is acceptable for store option C), and **no new
  network service** — the rotation state lives in-process or in a local volume-backed file,
  never an external broker.
- Backwards compatible: a host that does not opt in behaves exactly as today.

**Non-goals**
- Dynamic client registration, multiple users/clients, or scopes (still single fixed
  subject, CIMD-only).
- A **multi-node / networked** token store (Redis, a shared DB service). The rotation-state
  store stays single-writer to match the single-machine deploy; the only durability choice
  on the table (§7 option C) is local SQLite on the Fly volume, not a separate service.
- Changing the resource-server verifier — access tokens are unchanged RS256 JWTs.

## 3. Token model

| Token | Alg / form | Lifetime (default) | New config accessor |
|---|---|---|---|
| Access | RS256 JWT (unchanged) | `as_access_ttl()` = 3600 s | new, replaces `as_token_ttl` for the access token |
| Refresh | HS256 JWT, `_refresh_secret()` derived from the signing key (same pattern as `_code_secret()`) | `as_refresh_ttl()` = 2592000 s (30 d) | new |

Keep `as_token_ttl()` as the access-token TTL for **back-compat**: `as_access_ttl()`
defaults to `as_token_ttl()` if a host doesn't define it, and the webapp **session cookie**
(`make_session`, `max_age` on the cookie) keeps using `as_token_ttl()` unchanged. So a host
that adds nothing keeps today's single-TTL behaviour and still gets no refresh token (the
grant is gated — see §6, `as_refresh_enabled()`).

### Refresh token claims (HS256, `_refresh_secret()`)
```
{ "typ": "refresh",
  "sub": <subject>,
  "res": <resource/audience the access token is bound to>,
  "sid": <session id: secrets.token_urlsafe(16), stable across one rotation chain>,
  "gen": <int, rotation generation, starts 0>,
  "jti": <secrets.token_urlsafe(12), unique per issued refresh token>,
  "iat": <now>,
  "exp": <now + as_refresh_ttl()> }
```
`sid` identifies a login session; `gen` increments on each rotation. The pair `(sid, gen)`
is what reuse-detection keys on.

## 4. Flows

### 4.1 Initial issuance (`grant_type=authorization_code`)
After the existing code → access-token mint, also mint a refresh token **iff**
`as_refresh_enabled()`. Response gains `refresh_token` and keeps `expires_in =
as_access_ttl()`:
```json
{ "access_token": "...", "token_type": "Bearer",
  "expires_in": 3600, "refresh_token": "...", "scope": "" }
```
`scope` unchanged (empty). Metadata `grant_types_supported` becomes
`["authorization_code", "refresh_token"]` when refresh is enabled.

### 4.2 Renewal (`grant_type=refresh_token`) — new branch in `token()`
1. Require `refresh_token` form field; decode + verify with `_refresh_secret()`, requiring
   `["exp", "jti", "typ", "sub", "sid", "gen"]`; reject if `typ != "refresh"`.
2. **Resource binding**: if the request sends `resource`, it must equal the token's `res`
   (RFC 8707), else `invalid_grant`.
3. **Reuse detection / rotation** (§5): accept only the newest generation of the chain;
   replay of a rotated-away token revokes the whole chain.
4. On success, mint a **new** access token (`_mint_access_token(sub, res)`) and a **new**
   refresh token with the same `sid`, `gen+1`, fresh `jti`/`iat`/`exp`. Return both.
   (Sliding expiry: each rotation issues a refresh token with a fresh 30-day window. A hard
   absolute cap is out of scope; note it in §7.)
5. PKCE does **not** apply to the refresh grant (no `code_verifier`).

`token_endpoint_auth_methods_supported` stays `["none"]` (public client); the refresh
token itself is the bearer credential for renewal.

## 5. Rotation & reuse detection (stateless baseline)

OAuth 2.1 requires rotation for public clients. We do it without a DB, exploiting the
single-machine deploy and the existing in-memory `jti` pattern.

Per-session state map (mirrors `_seen_jti`; lives for process lifetime):
```
_refresh_chain: dict[sid, {gen: int, token: str, rotated_at: int, exp: int}]
#                              ^highest issued  ^the current refresh token string (for
#                                                idempotent retry), ^when gen was last
#                                                bumped, ^newest token's expiry (for pruning)
```

- On `authorization_code` issuance: `sid = token_urlsafe(16)`, `gen = 0`, store the entry.
- On refresh, let `g` = presented `gen`:
  - **`sid` unknown** → predates this process / pruned → §7 restart policy (default: reject
    `invalid_grant`; client falls back to interactive login).
  - **`g == gen`** (current token) → valid. Rotate: issue `gen+1`, update the entry
    (`gen+1`, new token, `rotated_at=now`). Return new access + new refresh token.
  - **`g == gen - 1` within the rotation grace window** (`now - rotated_at <=
    REFRESH_GRACE`, default 30 s) → **benign retry**, not a breach: the client's previous
    rotation response was almost certainly lost in transit. Return the *cached current*
    token (`entry.token`) and a fresh access token — **idempotent**, do **not** rotate
    again and do **not** revoke. (We return the same successor we already minted rather than
    branching the chain, so the client converges on one valid token.)
  - **`g == gen - 1` after the grace window, or `g < gen - 1`** → **true reuse of a rotated
    token** → delete `sid` (revoke the chain), return `invalid_grant`. BCP breach response.
  - **`g > gen`** → impossible under our signing → `invalid_grant`.
- Bound memory: prune an entry lazily once `entry.exp` is in the past (checked on access /
  on a size threshold). Same growth concern as `_seen_jti`; document the bound.

The grace window closes the **rotation-retry race**: without it, any lost rotation response
(network blip, client crash mid-exchange, 5xx) would trip reuse detection and force a full
re-login — defeating the spec's purpose. The window is short enough that a genuinely stolen
predecessor token is still caught once the legitimate client rotates past it.

This gives correct rotation + reuse detection + retry-safety on a single machine with no
datastore. §7 covers what changes across a restart and for multi-node.

## 6. Config surface (additions to `ConfigProvider`)

All resolved per-call like the rest. New accessors, each with a back-compat default so
existing host adapters keep working until they opt in:

```python
def as_refresh_enabled(self) -> bool: ...   # default False  -> behaves exactly as today
def as_access_ttl(self) -> int: ...         # default: self.as_token_ttl()  (back-compat)
def as_refresh_ttl(self) -> int: ...        # default 2_592_000 (30 d)
```

Host env wiring (one row per service, mirroring the existing `*_AS_TOKEN_TTL`):

| Host | enable | access TTL | refresh TTL |
|---|---|---|---|
| activities-mcp | `ACTIVITIES_AS_REFRESH_ENABLED` | `ACTIVITIES_AS_ACCESS_TTL` | `ACTIVITIES_AS_REFRESH_TTL` |
| vitals-mcp | `VITALS_MCP_AS_REFRESH_ENABLED` | `VITALS_MCP_AS_ACCESS_TTL` | `VITALS_MCP_AS_REFRESH_TTL` |
| genoscope | `GENOSCOPE_AS_REFRESH_ENABLED` | `GENOSCOPE_AS_ACCESS_TTL` | `GENOSCOPE_AS_REFRESH_TTL` |

Because `mcp_oauth.config.ConfigProvider` is a `Protocol`, adding methods is source-compat;
hosts that don't yet define them must be given the defaults. **Implementation note:** since
the package calls `provider().as_refresh_enabled()` directly, provide the defaults via a
small shim in `mcp_oauth` (e.g. module-level helpers `refresh_enabled()/access_ttl()/
refresh_ttl()` that `getattr(provider(), name, default)()`), so an un-updated host adapter
doesn't `AttributeError`. This keeps the "host passes its config module directly" contract.
If policy **C** (§7) is chosen, add an `as_refresh_store_path() -> str | None` accessor
too (the volume-backed SQLite path; `None` selects the in-memory store, A/B).

## 7. Restart behaviour & the autodeploy interaction (the key decision)

The `_refresh_chain` map is **in-process**, matching today's `_seen_jti` and the
`min_machines_running=1`, no-scale deploy (`fly.toml`). A **process restart / redeploy
clears it**, so every still-valid refresh token hits the "`sid` unknown" path on its next
renewal.

**This matters more than it first appears, because these hosts now autodeploy on push to
`main`** (the CI → Fly pipeline added in `activities-mcp`, and the same pattern is intended
for the others). A redeploy on every merge means: with an in-memory store, *every merge
invalidates all refresh sessions*. Policy A below would then force an interactive re-login
after each deploy — quietly recreating much of the daily-login pain we set out to remove.
So the store-durability choice is **coupled to deploy cadence**, and is the main judgement
call this spec defers (see §11):

- **A. In-memory + reject on unknown `sid`** (safe, simplest, zero new infra): strict reuse
  detection; one interactive re-login per redeploy per active session. Fine if deploys are
  rare; **poor fit for frequent autodeploys.**
- **B. In-memory + trust-on-first-use**: accept an unknown `sid` once, seeding the entry at
  the presented `gen`, then enforce. Survives restarts without infra, but weakens reuse
  detection across a restart boundary (a predecessor token stolen just before a restart can
  be replayed once after).
- **C. Persist the chain on the Fly volume (SQLite)**: the hosts already mount a volume
  (e.g. activities `/data`, `ACTIVITIES_PLANS_DB`). A tiny `refresh_chains` table behind the
  same `get/set/delete(sid)` interface survives redeploys with **full** reuse detection and
  no extra service. Costs a small schema + the single-writer assumption (still one machine).
  **Best fit given autodeploy**, at the price of a little persistence code + tests.

Whichever is chosen, keep it behind one narrow interface (`chain_get/chain_put/chain_del`)
so A/B/C differ only in the backing store — the rotation logic in §5 is identical.

- **Multi-node / scale-out** still breaks A/B; only C (or Redis) survives it. Out of scope
  to *implement* multi-node, but choosing C now makes it a config swap later.
- **Absolute session cap**: sliding expiry means an actively-refreshed session never forces
  re-login. If a hard cap is desired, add `as_refresh_absolute_ttl()` and stamp an `iss_at`
  in the chain; out of scope for v1.

## 8. Security checklist (OAuth 2.1 BCP)

- [ ] Refresh token is rotated on every use; old generation invalidated.
- [ ] A benign retry of the immediately-previous generation **within** the grace window is
      idempotent (returns the current token, no rotation, no revoke); the **same** token
      presented **after** the window, or any older generation, revokes the chain.
- [ ] Reuse of a rotated token (outside grace) revokes the entire chain (`sid`).
- [ ] Refresh token bound to `resource` (`res` claim); audience-confused renewal rejected.
- [ ] Access TTL short (default 1 h) so a leaked **access** token expires fast.
- [ ] Refresh token is HS256 with a secret derived from the RSA signing key — rotating the
      signing key invalidates all refresh tokens and sessions (same blast radius as today).
- [ ] No refresh token logged; `/token` errors stay opaque (`invalid_grant`).
- [ ] `grant_types_supported` advertises `refresh_token` only when enabled.

## 9. Test plan (extend `tests/test_auth_server.py`)

1. **Issuance**: `authorization_code` exchange returns a `refresh_token` when enabled; none
   when disabled (back-compat). `expires_in == as_access_ttl()`.
2. **Renewal happy path**: `grant_type=refresh_token` returns a new access token and a new
   refresh token with `gen+1`, same `sid`.
3. **Rotation invalidates predecessor (true reuse)**: renew with `g`, then present `g` again
   *after the grace window* → `invalid_grant` **and** chain revoked (a later renew with the
   real current token also fails). Also test `g < gen-1` → immediate revoke.
4. **Benign retry within grace**: present the previous generation while `now - rotated_at <=
   REFRESH_GRACE` → returns the *current* refresh token unchanged (idempotent), a fresh
   access token, no rotation, chain **not** revoked. (Drive time via an injectable clock.)
5. **Expiry**: an expired refresh token → `invalid_grant`.
6. **Resource binding**: renewal with a mismatched `resource` → `invalid_grant`.
7. **Tampering**: refresh token signed with the wrong secret / altered claims → rejected.
8. **Metadata**: `grant_types_supported` includes `refresh_token` iff enabled.
9. **Back-compat**: a provider lacking the new accessors (old adapter) still works — access
   TTL falls back to `as_token_ttl()`, refresh disabled.
10. **Restart policy**: simulate a cleared chain store (unknown `sid`) → matches the chosen
    policy A/B/C (C: seed from the persisted row and succeed).

## 10. Rollout

1. Land this package change behind `as_refresh_enabled()` (default off) + tests. No host
   behaviour changes until opted in.
2. Tag a release; bump each host's `mcp-oauth` pin (`pip install "mcp-oauth @ git+...@<tag>"`).
3. Per host: add the three env accessors to its `config.py` + adapter, set
   `*_AS_REFRESH_ENABLED=1`, `*_AS_ACCESS_TTL=3600`, `*_AS_REFRESH_TTL=2592000` as Fly
   secrets, and **revert** the quick-fix `*_AS_TOKEN_TTL=604800` back to the short default
   (its only remaining use is the webapp session-cookie lifetime — pick a deliberate value
   there).
4. Verify: log in once, confirm the client silently renews after the access TTL elapses
   (token endpoint shows a `refresh_token` round-trip), and — for policies A/B — confirm a
   redeploy triggers at most one interactive re-login; for policy C, confirm renewal
   survives a redeploy with no re-login.

## 11. Open questions

- **Store durability (the main call) — A / B / C from §7.** Because these hosts autodeploy
  on push to `main`, an in-memory store (A/B) re-logs every active session on every merge.
  Recommendation: **C (SQLite on the existing Fly volume)** — full reuse detection that
  survives redeploys, no new service. A is acceptable only if we accept a re-login per
  deploy; B trades a sliver of reuse-detection strength to avoid persistence code.
- Do we want an absolute session cap (§7) now, or defer until there's a reason?
- Webapp **session cookie** lifetime: keep tying it to `as_token_ttl()`, or give it its own
  accessor so the access-token change doesn't silently shorten browser sessions? (Leaning:
  give it `as_session_ttl()` defaulting to `as_token_ttl()` to avoid coupling.)
