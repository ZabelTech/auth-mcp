"""Tests for the shared MCP OAuth resource-server gate (mcp_oauth.resource_server).

Hermetic: a local RSA keypair mints/verifies RS256 JWTs in-process (no IdP, no network —
the JWKS signing-key lookup is monkeypatched). Covers JWT validation, the conditional
middleware (bypass / 401 / 403 / 200 / 500-misconfigured), and the protected-resource-
metadata route. Config is injected via mcp_oauth.configure() with a mutable test provider
(the genoscope-side env mapping is covered separately in test_auth_wiring.py).

    python -m unittest tests.test_auth
"""

from __future__ import annotations

import asyncio
import json
import time
import unittest
from contextlib import contextmanager
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import mcp_oauth
import mcp_oauth.resource_server as auth
from mcp_oauth.resource_server import (JwksTokenVerifier, RequireAuthMiddleware,
                                       protected_resource_routes)

ISS = "https://idp.example"
AUD = "https://rs.example/mcp"

_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIV_PEM = _priv.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
PUB_KEY = _priv.public_key()
_other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_PEM = _other.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())


def run(coro):
    return asyncio.run(coro)


def mint(sub="user-1", aud=AUD, iss=ISS, exp_delta=3600, key=PRIV_PEM, **extra):
    now = int(time.time())
    claims = {"aud": aud, "iss": iss, "iat": now, "exp": now + exp_delta, **extra}
    if sub is not None:
        claims["sub"] = sub
    return jwt.encode(claims, key, algorithm="RS256")


class _Cfg:
    """A mutable in-memory ConfigProvider for tests: every accessor reads its live value
    from `d`, so a test can flip require_auth/allowed_subjects mid-flight the way the old
    env-context tests flipped GENOSCOPE_* vars."""

    def __init__(self, **over):
        self.d = {"require_auth": True, "oauth_issuer": ISS,
                  "oauth_jwks_url": "http://jwks.invalid", "oauth_resource_url": AUD,
                  "allowed_subjects": {"abc", "def"}, "as_enabled": False,
                  "as_username": None, "as_password_hash": None, "as_signing_key": None,
                  "as_token_ttl": 28800, "as_client_id_allowlist": set()}
        self.d.update(over)

    def __getattr__(self, name):
        if name in self.__dict__.get("d", {}):
            return lambda: self.d[name]
        raise AttributeError(name)


@contextmanager
def configured(**over):
    cfg = _Cfg(**over)
    mcp_oauth.configure(cfg, service_name="test-mcp", session_cookie="test_session")
    yield cfg


def _verifier():
    v = JwksTokenVerifier("http://jwks.invalid", ISS, AUD)
    v._signing_key = lambda token: PUB_KEY        # inject the public key, no network
    return v


async def _asgi(app, method="POST", path="/", headers=()):
    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(),
             "query_string": b"", "scheme": "https", "server": ("rs.example", 443),
             "client": ("203.0.113.9", 4444),
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers]}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), body


class _Inner:
    """A stand-in MCP app that records whether the gate let the request through."""
    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


# ── JWT verification (signature / iss / aud / exp / sub) ──
class TokenVerifierTests(unittest.TestCase):
    def test_valid_token(self):
        a = run(_verifier().verify_token(mint(sub="abc")))
        self.assertIsNotNone(a)
        self.assertEqual(a.subject, "abc")

    def test_wrong_audience_rejected(self):
        self.assertIsNone(run(_verifier().verify_token(mint(aud="https://evil/mcp"))))

    def test_wrong_issuer_rejected(self):
        self.assertIsNone(run(_verifier().verify_token(mint(iss="https://evil"))))

    def test_expired_rejected(self):
        self.assertIsNone(run(_verifier().verify_token(mint(exp_delta=-3600))))

    def test_bad_signature_rejected(self):
        # signed by a different key than the verifier trusts
        self.assertIsNone(run(_verifier().verify_token(mint(key=OTHER_PEM))))

    def test_missing_sub_rejected(self):
        self.assertIsNone(run(_verifier().verify_token(mint(sub=None))))

    def test_garbage_rejected(self):
        self.assertIsNone(run(_verifier().verify_token("not-a-jwt")))


# ── conditional middleware ──
class MiddlewareTests(unittest.TestCase):
    def setUp(self):
        self._cm = configured(allowed_subjects={"abc", "def"})
        self.cfg = self._cm.__enter__()
        self._real_build = auth.build_verifier
        auth.build_verifier = _verifier         # avoid the live JWKS path

    def tearDown(self):
        auth.build_verifier = self._real_build
        self._cm.__exit__(None, None, None)

    def test_bypass_when_not_required(self):
        inner = _Inner()
        self.cfg.d["require_auth"] = False                 # no token
        status, _, _ = run(_asgi(RequireAuthMiddleware(inner)))
        self.assertTrue(inner.called)
        self.assertEqual(status, 200)

    def test_401_without_token(self):
        inner = _Inner()
        status, headers, _ = run(_asgi(RequireAuthMiddleware(inner)))
        self.assertFalse(inner.called)
        self.assertEqual(status, 401)
        self.assertIn(b"resource_metadata", headers[b"www-authenticate"])

    def test_401_invalid_token(self):
        inner = _Inner()
        status, headers, _ = run(_asgi(RequireAuthMiddleware(inner),
                                       headers=[("authorization", "Bearer nonsense")]))
        self.assertFalse(inner.called)
        self.assertEqual(status, 401)
        self.assertIn(b'error="invalid_token"', headers[b"www-authenticate"])

    def test_200_valid_token_allowed_subject(self):
        inner = _Inner()
        tok = mint(sub="abc")
        status, _, _ = run(_asgi(RequireAuthMiddleware(inner),
                                 headers=[("authorization", f"Bearer {tok}")]))
        self.assertTrue(inner.called)
        self.assertEqual(status, 200)

    def test_403_authenticated_but_not_allowed(self):
        inner = _Inner()
        tok = mint(sub="intruder")               # valid token, not in allowlist
        status, _, body = run(_asgi(RequireAuthMiddleware(inner),
                                    headers=[("authorization", f"Bearer {tok}")]))
        self.assertFalse(inner.called)
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error_type"], "forbidden")

    def test_403_when_allowlist_empty(self):
        # a valid token is still not authorization when nobody is allowlisted
        inner = _Inner()
        self.cfg.d["allowed_subjects"] = set()
        tok = mint(sub="abc")
        status, _, _ = run(_asgi(RequireAuthMiddleware(inner),
                                 headers=[("authorization", f"Bearer {tok}")]))
        self.assertFalse(inner.called)
        self.assertEqual(status, 403)

    def test_500_when_required_but_unconfigured(self):
        # require_auth on but no verifier buildable -> fail loud + closed, never open
        inner = _Inner()
        auth.build_verifier = lambda: None
        try:
            status, _, body = run(_asgi(RequireAuthMiddleware(inner),
                                        headers=[("authorization", "Bearer x")]))
        finally:
            auth.build_verifier = _verifier
        self.assertFalse(inner.called)
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body)["error_type"], "server_misconfigured")

    def test_lifespan_scope_passes_through(self):
        # non-HTTP scopes must not be gated (the session-manager lifespan still runs)
        seen = []

        async def inner(scope, receive, send):
            seen.append(scope["type"])

        run(RequireAuthMiddleware(inner)({"type": "lifespan"},
                                         lambda: None, lambda m: None))
        self.assertEqual(seen, ["lifespan"])


# ── protected-resource metadata route (RFC 9728) ──
class ProtectedResourceMetadataTests(unittest.TestCase):
    def test_metadata_served_and_points_at_as(self):
        from starlette.applications import Starlette
        with configured(oauth_issuer=ISS, oauth_resource_url=AUD):
            routes = protected_resource_routes()
            app = Starlette(routes=routes)
            from mcp.server.auth.routes import build_resource_metadata_url
            from pydantic import AnyHttpUrl
            path = urlparse(str(build_resource_metadata_url(AnyHttpUrl(AUD)))).path
            status, _, body = run(_asgi(app, method="GET", path=path))
        self.assertTrue(routes)
        self.assertEqual(status, 200)
        self.assertIn(ISS, json.dumps(json.loads(body)))

    def test_no_routes_when_unconfigured(self):
        with configured(oauth_issuer=None, oauth_resource_url=None):
            self.assertEqual(protected_resource_routes(), [])


if __name__ == "__main__":
    unittest.main()
