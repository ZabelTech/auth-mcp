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
- Support **refresh-token rotation** with reuse detection (OAuth 2.1 BCP) as a *configurable*
  posture (§5a / §11); a non-rotating static refresh token is the simpler alternative for a
  single-user deploy and the recommended starting point.
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

Back-compat without a footgun. `as_access_ttl()`'s default is **conditional on whether
refresh is enabled**:
- refresh **disabled** → defaults to `as_token_ttl()` — a non-opted host is byte-for-byte
  unchanged (access token = today's single TTL).
- refresh **enabled** but `as_access_ttl` unset → defaults to a hard **3600 s**, *not*
  `as_token_ttl()`. This matters because rollout (§10) leaves the quick-fix
  `*_AS_TOKEN_TTL=604800` (7 d) in place until a later step: if access TTL inherited that, an
  operator who enabled refresh but forgot to set `AS_ACCESS_TTL` would silently keep
  **7-day access tokens**, defeating the whole point. So once refresh is on, access tokens
  are short by default regardless of `as_token_ttl()`.

The webapp **session cookie** (`make_session`, `max_age`) keeps using `as_token_ttl()`
unchanged — it is the browser-session lifetime, independent of the access-token TTL (see
the §11 open question on giving it its own accessor). A host that adds nothing keeps today's
single-TTL behaviour and still gets no refresh token (the grant is gated — see §6,
`as_refresh_enabled()`).

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
0. **Gate**: if `as_refresh_enabled()` is false, return `unsupported_grant_type` (defense in
   depth — the metadata already omits the grant). Steps below run only when enabled.
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

## 5. Rotation & reuse detection (rotation-on path; in-memory, no DB)

This section specifies the **rotation-enabled** posture (`as_refresh_rotation() == True`);
§5a covers the simpler non-rotating alternative, and §11 is where the choice is made. OAuth
2.1 recommends rotation for public clients; we do it without a DB, exploiting the
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
  - **`sid` unknown** → predates this process / pruned (e.g. after a redeploy) →
    **trust-on-first-use** (§7, chosen policy **B**): accept once, seed the entry at the
    presented `gen`, and enforce rotation strictly from there. No interactive re-login.
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
  - **`g > gen`** → cannot happen under strict tracking, but **can** under policy B after a
    TOFU seed at a low generation (the client legitimately holds a higher-gen token it
    already had). Treat as a valid presentation: **re-seed upward** (set `gen = g`) and
    rotate normally. The token is validly signed by us, so this is consistent with B's
    first-presenter-trust posture and avoids a spurious re-login. (Under A/C this branch is
    unreachable; rejecting there is fine.)
- **Dedup is by `(sid, gen)` only — never by `jti`.** The `jti` claim exists for token
  *uniqueness* and logging, not single-use enforcement. Do **not** add an auth-code-style
  `_seen_jti` check for refresh tokens: the benign-retry path deliberately returns the
  **same cached token** (same `jti`), so a per-`jti` single-use check would reject exactly
  the idempotent retry the grace window is designed to allow.
- Bound memory: prune an entry lazily once `entry.exp` is in the past (checked on access /
  on a size threshold). Same growth concern as `_seen_jti`; document the bound.

**Load-bearing process model.** The in-memory store is correct *only* under the deploy's
actual runtime: a **single** uvicorn worker (the image's `CMD` is `uvicorn webapp:app` with
no `--workers`, so one process) on a **single-threaded asyncio** loop. Two constraints the
implementation must preserve:
- The read-modify-write of `_refresh_chain` (lookup → mint → store) must contain **no
  `await`**. Then it runs to completion without yielding the loop, so each rotation is atomic
  against concurrent refreshes — two parallel requests bearing the same token cannot both
  rotate (which would mint two divergent successors and leave an orphan). `jwt.encode` is
  synchronous, so this holds today; a future **async** store (e.g. aiosqlite under option C)
  reintroduces an `await` mid-section and then needs a per-`sid` `asyncio.Lock`. A
  *synchronous* `sqlite3` call keeps the section await-free and atomic.
- A second worker/process (`--workers N`, Gunicorn, scale-out) splits the map and breaks
  **both** refresh rotation and the existing `_seen_jti` auth-code single-use. This is
  already an implicit assumption of today's code; the refresh chain makes it load-bearing —
  assert single-worker in a startup comment, and treat multi-node as the trigger for option
  C/Redis (§7).

The grace window closes the **rotation-retry race**: without it, any lost rotation response
(network blip, client crash mid-exchange, 5xx) would trip reuse detection and force a full
re-login — defeating the spec's purpose.

Its cost, stated honestly: within `REFRESH_GRACE` the server cannot tell a legitimate retry
from a replay, so a **stolen predecessor token presented inside the window yields the
current token** (we must return it, or the genuine retrying client could never converge).
The exposure is bounded by `REFRESH_GRACE` (default 30 s) and by requiring the predecessor
to be stolen in the first place; outside the window any older generation revokes the chain.
`REFRESH_GRACE` is the knob that trades retry-robustness against this window — keep it as
small as real client/network latency allows.

### 5a. Non-rotating mode (`as_refresh_rotation() == False`)
All of the above — the chain map, generations, grace window, reuse detection — exists to
make **rotation** safe. Rotation is OAuth 2.1's BCP for public clients, but it is only sound
if the client reliably replaces its stored refresh token on every renewal; if it does not,
*every* renewal after the first replays a now-stale token and (under strict revocation)
forces a re-login — strictly worse than no refresh at all. Because that client behavior is
**unverified** here (see §10 steps 4–5 and the §11 posture decision), the spec makes rotation
a switch:
- **Rotation off — CHOSEN default (§11)** → `/token` mints a fresh **access** token on each
  refresh grant but returns **the same refresh token** (no new one), so there is no chain, no `_refresh_chain`
  map, no reuse detection, no grace window, and no false-revoke failure mode. The refresh
  token is a static bearer credential whose `exp` is fixed at login (30 d, *not* sliding —
  re-login once a month). Weaker (a stolen refresh token is usable until that `exp`,
  undetected), but mitigated by short access tokens and by signing-key rotation as the blunt
  revoke. Robust and simple — the natural starting posture for a single-user server.
- **Rotation on** → the full §5 machinery. Choose once the client is observed to honor
  rotated tokens.

The two share the issuance path (§4.1) and the access-token mint; they differ only in
whether step 4 of §4.2 issues a new refresh token and touches the chain map.

This gives correct rotation + reuse detection + retry-safety on a single machine with no
datastore (rotation on), or a simple robust static credential (rotation off). §7 covers what
changes across a restart and for multi-node.

## 6. Config surface (additions to `ConfigProvider`)

All resolved per-call like the rest. New accessors, each with a back-compat default so
existing host adapters keep working until they opt in:

```python
def as_refresh_enabled(self) -> bool: ...   # default False  -> behaves exactly as today
def as_access_ttl(self) -> int: ...         # default: 3600 if refresh enabled, else
                                            #          as_token_ttl()  (see §3 — avoids
                                            #          inheriting the 7-day quick-fix TTL)
def as_refresh_ttl(self) -> int: ...        # default 2_592_000 (30 d)
def as_refresh_rotation(self) -> bool: ...  # rotate + reuse-detect (True) vs static
                                            #   non-rotating refresh token (False).
                                            #   Deployed value: False (§11 decision); the
                                            #   accessor default may stay True (BCP) — hosts
                                            #   ship *_AS_REFRESH_ROTATION=0 explicitly.
```

Host env wiring (one row per service, mirroring the existing `*_AS_TOKEN_TTL`):

| Host | enable | access TTL | refresh TTL |
|---|---|---|---|
| activities-mcp | `ACTIVITIES_AS_REFRESH_ENABLED` | `ACTIVITIES_AS_ACCESS_TTL` | `ACTIVITIES_AS_REFRESH_TTL` |
| vitals-mcp | `VITALS_MCP_AS_REFRESH_ENABLED` | `VITALS_MCP_AS_ACCESS_TTL` | `VITALS_MCP_AS_REFRESH_TTL` |
| genoscope | `GENOSCOPE_AS_REFRESH_ENABLED` | `GENOSCOPE_AS_ACCESS_TTL` | `GENOSCOPE_AS_REFRESH_TTL` |

Plus `*_AS_REFRESH_ROTATION` (bool) per host, backing `as_refresh_rotation()` — value set by
the §11 posture decision (start `0`/off per §10).

Because `mcp_oauth.config.ConfigProvider` is a `Protocol`, adding methods is source-compat;
hosts that don't yet define them must be given the defaults. **Implementation note:** since
the package calls `provider().as_refresh_enabled()` directly, provide the defaults via a
small shim in `mcp_oauth` (e.g. module-level helpers `refresh_enabled()/access_ttl()/
refresh_ttl()` that `getattr(provider(), name, default)()`), so an un-updated host adapter
doesn't `AttributeError`. This keeps the "host passes its config module directly" contract.
(No store-path accessor is needed for the chosen policy **B** — the store is in-memory; a
future move to **C** would add `as_refresh_store_path() -> str | None`, the volume-backed
SQLite path.)

## 7. Restart behaviour & the autodeploy interaction (the key decision)

**Applies only under rotation-on (§5) — i.e. NOT the chosen initial posture (§11).** With
rotation off (§5a, the committed default) there is no chain map to persist: a static refresh
token verifies statelessly from its signature, so restarts and redeploys are a non-issue and
the A/B/C choice below is moot. This section (and its "Decision: policy B") is parked, taking
effect only if rotation is later enabled via the §10 gate.

The `_refresh_chain` map is **in-process**, matching today's `_seen_jti` and the
`min_machines_running=1`, no-scale deploy (`fly.toml`). A **process restart / redeploy
clears it**, so every still-valid refresh token hits the "`sid` unknown" path on its next
renewal.

**This matters more than it first appears, because these hosts now autodeploy on push to
`main`** (the CI → Fly pipeline added in `activities-mcp`, and the same pattern is intended
for the others). A redeploy on every merge means: with an in-memory store, *every merge
invalidates all refresh sessions*. Policy A below would then force an interactive re-login
after each deploy — quietly recreating much of the daily-login pain we set out to remove.
So the store-durability choice is **coupled to deploy cadence**. **Decision: policy B**
(in-memory + trust-on-first-use) — chosen for a single-user deploy where avoiding a
re-login on every autodeploy outweighs the narrow restart-window risk, and where adding
persistence isn't worth it yet. The three options considered:

- **A. In-memory + reject on unknown `sid`** (safe, simplest, zero new infra): strict reuse
  detection; one interactive re-login per redeploy per active session. Fine if deploys are
  rare; **poor fit for frequent autodeploys.**
- **B. In-memory + trust-on-first-use** — **CHOSEN**: on an unknown `sid`, accept once,
  seed the entry at the presented `gen`, then enforce rotation strictly. Survives restarts
  with no infra and no re-login. Trade-off: across a restart boundary reuse detection is
  weakened — a predecessor token stolen just before a restart can be redeemed once after,
  and the "who presents first" race is no longer adjudicated by server memory. Acceptable
  for a single-user, HTTPS-only, low-exposure surface; revisit if the threat model changes.
- **C. Persist the chain on the Fly volume (SQLite)** (not chosen now): the hosts already
  mount a volume (e.g. activities `/data`, `ACTIVITIES_PLANS_DB`). A tiny `refresh_chains`
  table behind the same interface survives redeploys with **full** reuse detection and no
  extra service. The natural upgrade from B if the restart-window weakness ever matters — it
  closes B's hole and needs no client change.

Keep the store behind one narrow interface (`chain_get/chain_put/chain_del`) so B → C is a
backing-store swap with the §5 rotation logic unchanged.

- **Multi-node / scale-out** still breaks B; only C (or Redis) survives it. Out of scope to
  *implement*; B → C is the migration path if scale-out is ever needed.
- **Absolute session cap**: sliding expiry means an actively-refreshed session never forces
  re-login. If a hard cap is desired, add `as_refresh_absolute_ttl()` and stamp an `iss_at`
  in the chain; out of scope for v1.

## 8. Security checklist (OAuth 2.1 BCP)

Items tagged **(rot)** apply only when rotation is enabled (§5a); in static mode they are
n/a and the relevant guarantee is "short access TTL + signing-key revocation" instead.

- [ ] **(rot)** Refresh token is rotated on every use; old generation invalidated.
- [ ] **(rot)** A benign retry of the immediately-previous generation **within** the grace
      window is idempotent (returns the current token, no rotation, no revoke); the **same**
      token presented **after** the window, or any older generation, revokes the chain.
- [ ] **(rot)** Reuse of a rotated token (outside grace) revokes the entire chain (`sid`).
- [ ] **(rot)** `REFRESH_GRACE` set above real client retry/backoff: a predecessor token
      replayed *inside* the window yields the current token (inherent grace-window exposure,
      §5) — tune deliberately against the false-revoke-vs-exposure trade.
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
10. **Restart policy (B / TOFU)**: simulate a cleared store (unknown `sid`) → the first
    refresh is **accepted** and seeds the chain at the presented `gen`; a *second* refresh
    with that same now-superseded `gen` (after rotation) is then rejected/revoked as normal —
    i.e. enforcement resumes immediately after the trust-on-first-use seed.
11. **TOFU reseed-upward**: after a cleared store, seed via a low-gen token, then present a
    higher-gen validly-signed token → **accepted**, chain re-seeds to that gen and rotates
    (no spurious `invalid_grant`).
12. **No jti single-use**: the idempotent grace retry returns a token whose `jti` was already
    seen → still accepted (guards against an accidental `_seen_jti` check on refresh tokens).
13. **Non-rotating mode** (`as_refresh_rotation() == False`, §5a): a refresh grant returns a
    fresh access token and the **same** refresh token (no new one); presenting that same
    refresh token repeatedly keeps working with **no** rotation and **no** revoke; an expired
    static refresh token → `invalid_grant`. (Tests 2–4/10–12, which assert rotation, are
    skipped/inapplicable in this mode.)

## 10. Rollout

1. Land this package change behind `as_refresh_enabled()` (default off) + tests. No host
   behaviour changes until opted in.
2. Tag a release; bump each host's `mcp-oauth` pin (`pip install "mcp-oauth @ git+...@<tag>"`).
3. Per host: add the env accessors to its `config.py` + adapter, set `*_AS_REFRESH_ENABLED=1`,
   `*_AS_ACCESS_TTL=3600`, `*_AS_REFRESH_TTL=2592000`, and `*_AS_REFRESH_ROTATION=0`
   (non-rotating — the §11 committed posture; no chain, no false-revoke failure mode).
   **Revert** the quick-fix `*_AS_TOKEN_TTL=604800` to a deliberate session-cookie value (its
   only remaining use).
4. Verify (rotation off): log in once, let the access token expire, confirm the client
   **silently renews** (a `refresh_token` grant round-trip, no interactive login) and keeps
   working across a redeploy.
5. **Future / optional — empirical rotation gate** (not part of the initial ship; only if
   later pursuing rotation-on): flip `*_AS_REFRESH_ROTATION=1`
   and watch several renewals — confirm the client presents a *new* (rotated) refresh token
   each time and never gets bounced to an interactive login (incl. across a redeploy, exercising
   §5 TOFU). If any unexpected re-login appears, the client isn't honoring rotation cleanly →
   set rotation back to `0`. This observation is the evidence the §11 posture decision needs;
   do not enable rotation fleet-wide on assumption.

## 11. Open questions

- ~~Refresh posture (rotation on/off), `as_refresh_rotation()`.~~ **Resolved: non-rotating
  (rotation OFF) for the initial deploy** (`as_refresh_rotation() == False`, §5a). Rationale:
  a false reuse-detection trip = the exact interactive re-login this spec exists to remove,
  and rotation's correctness depends on the real MCP client honoring rotated tokens — which is
  **unverified**. Rotation-on (full §5, incl. the store policy B in §7) remains a documented
  upgrade, adopted only **after** the §10 empirical gate observes clean client rotation. The
  three postures weighed:
  - **Static / rotation-off (§5a)** — **← CHOSEN.** Fresh access token each refresh, same
    long-lived refresh token; no chain, no false-revoke, monthly hard re-login at the refresh
    `exp`. Robust, simplest, BCP-noncompliant. Best fit for a single-user, HTTPS-only server,
    and consistent with the earlier "never re-login on deploy" priority.
  - **Rotate + reuse-detect (full §5)** — BCP-correct, ejects a stolen refresh token via the
    revoke tripwire, sliding expiry so an active session never re-logins. Cost: depends on
    client rotation behavior; a slow/lost retry past `REFRESH_GRACE` causes a false re-login.
    Adopt **after** the §10 step-5 empirical gate passes.
  - **Rotate + reject-stale-without-revoke** — middle ground; removes the false-revoke
    lockout but also removes the theft tripwire (and can still strand the victim under real
    theft), so it mostly combines the downsides. Listed for completeness; not recommended.
  Sub-decision if rotating: `REFRESH_GRACE` size (default 30 s) — set it above the client's
  real refresh retry/backoff, likely 1–5 min, to avoid false revokes.
- Do we want an absolute session cap (§7) now, or defer? (Note: rotation-**off** already
  imposes a natural ~monthly cap via the fixed refresh `exp`; rotation-**on** does not.)
- Webapp **session cookie** lifetime: keep tying it to `as_token_ttl()`, or give it its own
  accessor so the access-token change doesn't silently shorten browser sessions? (Leaning:
  give it `as_session_ttl()` defaulting to `as_token_ttl()` to avoid coupling.)
