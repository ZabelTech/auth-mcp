"""Host-injected configuration for the shared OAuth package.

This package is auth logic with no opinion about *where* its settings come from. The
host application calls `configure(provider, ...)` once at import/startup; the auth code
then reads everything through `provider()` and `branding()`. Settings are resolved **per
call** (the provider's methods are invoked each time), so an env change is picked up
without a restart — the same lazy contract the host configs already use.

The provider is any object exposing the accessor methods below as callables. genoscope's
`mcp_server.config` module satisfies it directly (the names already match); activities-mcp
passes a small adapter that maps its own env names onto the same surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@runtime_checkable
class ConfigProvider(Protocol):
    """The settings surface the auth code depends on. Resource-server gate first, then
    the self-hosted authorization server. Every method is resolved per call."""

    # ── resource-server gate ────────────────────────────────────────────────
    def require_auth(self) -> bool: ...
    def oauth_issuer(self) -> str | None: ...
    def oauth_jwks_url(self) -> str | None: ...
    def oauth_resource_url(self) -> str | None: ...
    def allowed_subjects(self) -> set[str]: ...

    # ── self-hosted authorization server ────────────────────────────────────
    def as_enabled(self) -> bool: ...
    def as_username(self) -> str | None: ...
    def as_password_hash(self) -> str | None: ...
    def as_signing_key(self) -> str | None: ...
    def as_token_ttl(self) -> int: ...
    def as_client_id_allowlist(self) -> set[str]: ...

    # ── refresh tokens (optional; the auth server reads these via getattr with the
    # defaults below, so a host adapter that predates them keeps working) ─────────
    # def as_refresh_enabled(self) -> bool: ...    # default False (no refresh token issued)
    # def as_access_ttl(self) -> int: ...          # default 3600 when refresh on, else as_token_ttl()
    # def as_refresh_ttl(self) -> int: ...         # default 2_592_000 (30 d)
    # def as_refresh_rotation(self) -> bool: ...   # default False (static, non-rotating — spec §5a)


@dataclass(frozen=True)
class Branding:
    """The host-specific labels woven into user-visible output: `service_name` titles the
    login form, names the protected resource, and tags the CIMD fetch User-Agent;
    `session_cookie` is the first-party webapp session cookie name."""
    service_name: str = "mcp"
    session_cookie: str = "mcp_session"


_provider: ConfigProvider | None = None
_branding = Branding()


def configure(provider: ConfigProvider, *, service_name: str | None = None,
              session_cookie: str | None = None) -> None:
    """Bind the host config + branding. Call once at startup, before the auth routes /
    middleware handle a request. Idempotent; a later call replaces the binding."""
    global _provider, _branding
    _provider = provider
    _branding = Branding(
        service_name=service_name if service_name is not None else _branding.service_name,
        session_cookie=(session_cookie if session_cookie is not None
                        else _branding.session_cookie))


def provider() -> ConfigProvider:
    """The bound provider, or a loud failure if the host never called configure() — never
    a silent default that could leave the gate misconfigured (fail loud, not open)."""
    if _provider is None:
        raise RuntimeError(
            "mcp_oauth is not configured: the host must call mcp_oauth.configure(provider) "
            "before the auth surface handles a request")
    return _provider


def branding() -> Branding:
    return _branding
