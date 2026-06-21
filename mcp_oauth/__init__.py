"""Shared OAuth 2.1 auth for an MCP HTTP surface — host-agnostic, dependency-injected.

Two surfaces, both reused across services (genoscope-mcp, activities-mcp):
  - resource_server: the bearer-JWT gate (JwksTokenVerifier, RequireAuthMiddleware,
    protected_resource_routes) that protects the mounted /mcp app.
  - auth_server: a minimal self-hosted OAuth 2.1 authorization server that issues the
    RS256 JWTs the gate validates, plus the first-party webapp session gate.

The host wires its own config in once at startup:

    import mcp_oauth
    mcp_oauth.configure(my_config, service_name="my-mcp", session_cookie="my_session")

`my_config` is any object exposing the accessors in `mcp_oauth.config.ConfigProvider`
(resolved per call). See `config.py`.
"""

from __future__ import annotations

from .config import Branding, ConfigProvider, branding, configure, provider

__all__ = ["Branding", "ConfigProvider", "branding", "configure", "provider"]

__version__ = "0.1.0"
