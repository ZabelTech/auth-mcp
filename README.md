# auth-mcp — `mcp_oauth`

Shared OAuth 2.1 auth for an MCP HTTP surface — host-agnostic, dependency-injected.
Extracted from genoscope-mcp so it can be reused across services (genoscope-mcp,
activities-mcp) instead of being port-copied.

Two surfaces, both reusable across hosts:

- **`mcp_oauth.resource_server`** — the bearer-JWT gate (`JwksTokenVerifier`,
  `RequireAuthMiddleware`, `protected_resource_routes`) that protects the mounted `/mcp`
  app. A thin ASGI middleware rather than the SDK's `FastMCP(auth=...)`: the gate is
  *conditional* on `require_auth()` and adds a *single-subject* allowlist check on top of
  token validity.
- **`mcp_oauth.auth_server`** — a minimal self-hosted OAuth 2.1 authorization server that
  issues the RS256 JWTs the gate validates (CIMD-only, no DCR, single fixed credential),
  plus the first-party webapp session-cookie gate (`WebappSessionMiddleware`). Optionally
  issues **refresh tokens** (gated on `as_refresh_enabled()`) so a client renews a short
  access token without re-running the interactive login — static / non-rotating by default
  (`as_refresh_rotation()`); see `specs/refresh-tokens.spec.md`.

## Install

The repo is public; depend on it from git (pin to a tag or commit for reproducibility):

```
pip install "mcp-oauth @ git+https://github.com/ZabelTech/auth-mcp@<ref>"
```

Only `pyjwt[crypto]` is declared as a dependency. `mcp` / `starlette` / `pydantic` /
`cryptography` are intentionally **not** declared — every host already pins them (and
pins `starlette` transitively via FastAPI), so declaring them here would risk resolving a
different `starlette` out from under FastAPI.

## Wiring (host side)

The package has no opinion about *where* its settings come from. The host calls
`configure()` once at startup; the auth code then reads everything through `provider()`
and `branding()` (resolved per call, so an env change is picked up without a restart):

```python
import mcp_oauth
mcp_oauth.configure(my_config, service_name="my-mcp", session_cookie="my_session")
```

`my_config` is any object exposing the accessor methods in
`mcp_oauth.config.ConfigProvider`. A host whose accessor names already match passes its
`config` module directly; a host with different names passes a small adapter. A
resource-server-only host (no self-hosted AS) returns `as_enabled() -> False` and stubs
the rest of the AS accessors. See `mcp_oauth/config.py`.

### Setup helpers

```
python -m mcp_oauth.auth_server genkey       # print a fresh RSA private key (PEM)
python -m mcp_oauth.auth_server hash PW       # print a pbkdf2 hash for the AS password
```

## Tests

```
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```
