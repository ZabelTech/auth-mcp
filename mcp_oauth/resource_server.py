"""OAuth 2.1 resource-server gate for an MCP HTTP surface.

A thin ASGI middleware rather than the SDK's `FastMCP(auth=...)` for two reasons: the SDK
enforces token auth on *every* request with no skip hook, whereas the gate here is
**conditional** on `provider().require_auth()` (default true; bypassed by the host for a
local single-user context); and the gate adds a **single-subject** check on top of token
validity, because DCR + open IdP signup mean "authenticated" != "you".

The decision reads no connection peer and no forwarded header — only the require-auth flag
and the bearer token — so there is no spoofable locality signal. Host settings arrive via
`mcp_oauth.config` (see configure()); nothing here is genoscope/activities specific.
"""

from __future__ import annotations

import asyncio
import json
import logging

import jwt
from pydantic import AnyHttpUrl

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.routes import (build_resource_metadata_url,
                                     create_protected_resource_routes)

from .config import branding, provider

log = logging.getLogger("mcp_oauth.resource_server")


class JwksTokenVerifier:
    """Verify a bearer JWT against the IdP JWKS (RS256): signature, issuer, audience,
    expiry, and the presence of a `sub`. Returns an `AccessToken` on success or None on
    any failure (the caller maps None to a 401 — never leaks the reason to the client)."""

    def __init__(self, jwks_url: str, issuer: str, audience: str):
        self.jwks_url, self.issuer, self.audience = jwks_url, issuer, audience
        self._client: jwt.PyJWKClient | None = None

    def _signing_key(self, token: str):
        # Network fetch on first use, then cached by PyJWKClient. Isolated so tests can
        # inject a key without a live JWKS endpoint.
        if self._client is None:
            self._client = jwt.PyJWKClient(self.jwks_url)
        return self._client.get_signing_key_from_jwt(token).key

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = await asyncio.to_thread(self._signing_key, token)
            claims = jwt.decode(
                token, key, algorithms=["RS256"], audience=self.audience,
                issuer=self.issuer, leeway=30,
                options={"require": ["exp", "iss", "aud", "sub"]})
        except Exception as e:  # noqa: BLE001 — any verification failure -> unauthenticated
            log.info("token rejected: %s", e)
            return None
        return AccessToken(
            token=token,
            client_id=claims.get("client_id") or claims.get("azp") or "",
            scopes=(claims.get("scope") or "").split(),
            expires_at=claims.get("exp"),
            resource=self.audience,
            subject=claims.get("sub"),
            claims=claims)


def build_verifier() -> JwksTokenVerifier | None:
    """A verifier from the configured OAuth settings, or None when the resource server
    isn't fully configured (jwks + issuer + resource) — the middleware treats None under
    require_auth as a fail-loud misconfiguration, never as "allow"."""
    cfg = provider()
    jwks, iss, aud = cfg.oauth_jwks_url(), cfg.oauth_issuer(), cfg.oauth_resource_url()
    if not (jwks and iss and aud):
        return None
    return JwksTokenVerifier(jwks, iss, aud)


def protected_resource_routes():
    """RFC 9728 protected-resource-metadata route(s) (`/.well-known/oauth-protected-
    resource`) pointing clients at the authorization server. Empty when issuer/resource
    are unset (nothing to advertise)."""
    cfg = provider()
    res, iss = cfg.oauth_resource_url(), cfg.oauth_issuer()
    if not (res and iss):
        return []
    return create_protected_resource_routes(
        resource_url=AnyHttpUrl(res), authorization_servers=[AnyHttpUrl(iss)],
        resource_name=branding().service_name)


def _bearer_token(scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name == b"authorization":
            v = value.decode("latin-1")
            if v[:7].lower() == "bearer ":
                return v[7:].strip()
    return None


async def _send_json(send, status: int, payload: dict, extra_headers=()):
    body = json.dumps(payload).encode()
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode()), *extra_headers]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _prm_url() -> str | None:
    res = provider().oauth_resource_url()
    return str(build_resource_metadata_url(AnyHttpUrl(res))) if res else None


async def _challenge(send, error: str | None = None):
    """401 with a `WWW-Authenticate: Bearer` header naming the protected-resource
    metadata, which is what makes the host start the OAuth flow (RFC 9728)."""
    parts = ["Bearer"]
    if (prm := _prm_url()):
        parts.append(f'resource_metadata="{prm}"')
    if error:
        parts.append(f'error="{error}"')
    payload = {"error": True, "error_type": "unauthorized",
               "message": "authentication required",
               "suggestion": "obtain an access token via the OAuth flow advertised at "
                             "/.well-known/oauth-protected-resource"}
    await _send_json(send, 401, payload,
                     extra_headers=[(b"www-authenticate", " ".join(parts).encode())])


class RequireAuthMiddleware:
    """ASGI gate around the MCP app. Bypasses entirely when `provider().require_auth()` is
    false; otherwise requires a valid bearer JWT whose `sub` is in the allowlist, else
    401/403. Non-HTTP scopes (lifespan, websocket) pass through untouched so the
    session-manager lifespan still runs."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        cfg = provider()
        if scope["type"] != "http" or not cfg.require_auth():
            await self.app(scope, receive, send)
            return
        verifier = build_verifier()
        if verifier is None:
            # require_auth but no IdP configured: fail loud + closed, never open.
            log.error("auth is required but the OAuth resource server is not configured "
                      "(need issuer + jwks_url + resource)")
            await _send_json(send, 500, {
                "error": True, "error_type": "server_misconfigured",
                "message": "authentication is required but not configured on this server"})
            return
        token = _bearer_token(scope)
        if not token:
            await _challenge(send)
            return
        access = await verifier.verify_token(token)
        if access is None:
            await _challenge(send, error="invalid_token")
            return
        allowed = cfg.allowed_subjects()
        if not allowed or access.subject not in allowed:
            log.warning("authenticated but not authorized: sub=%r", access.subject)
            await _send_json(send, 403, {
                "error": True, "error_type": "forbidden",
                "message": "this token's subject is not authorized for this server"})
            return
        await self.app(scope, receive, send)
