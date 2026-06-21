"""Tests for the shared first-party webapp session gate (mcp_oauth.auth_server).

Covers session cookie round-trip, the /login + /logout flow, and WebappSessionMiddleware:
local bypass, public-path passthrough, browser redirect-to-login vs API 401, and access
via either a session cookie or a bearer token. Hermetic — local RSA key, stubbed bearer
verifier, no network. Config is injected via mcp_oauth.configure() with a test provider.

    python -m unittest tests.test_webapp_auth
"""

from __future__ import annotations

import asyncio
import json
import time
import unittest
from contextlib import contextmanager
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

import mcp_oauth
import mcp_oauth.auth_server as a
import mcp_oauth.resource_server as rs

USERNAME = "owner"
PASSWORD = "s3cret-pw"
COOKIE = "test_session"
_KEY_PEM = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()).decode()


def run(coro):
    return asyncio.run(coro)


class _Cfg:
    """Mutable in-memory ConfigProvider for tests (every accessor reads its live value)."""

    def __init__(self, **over):
        self.d = {"require_auth": True, "oauth_issuer": "https://genome.example",
                  "oauth_jwks_url": "http://jwks.invalid",
                  "oauth_resource_url": "https://genome.example/mcp",
                  "allowed_subjects": {USERNAME}, "as_enabled": True,
                  "as_username": USERNAME, "as_password_hash": None,
                  "as_signing_key": _KEY_PEM, "as_token_ttl": 3600,
                  "as_client_id_allowlist": {"claude.ai"}}
        self.d.update(over)

    def __getattr__(self, name):
        if name in self.__dict__.get("d", {}):
            return lambda: self.d[name]
        raise AttributeError(name)


@contextmanager
def env(**kw):
    """Toggle settings mid-flight on the active test provider (maps old env names)."""
    _MAP = {"GENOSCOPE_REQUIRE_AUTH": ("require_auth", lambda v: v == "1")}
    cfg = mcp_oauth.config.provider()
    saved = {}
    for k, v in kw.items():
        key, conv = _MAP[k]
        saved[key] = cfg.d[key]
        cfg.d[key] = conv(v)
    try:
        yield
    finally:
        for key, old in saved.items():
            cfg.d[key] = old


async def _req(app, method, path, query="", headers=(), form=None):
    body, hdrs = b"", [(k.lower().encode(), v.encode()) for k, v in headers]
    if form is not None:
        body = urlencode(form).encode()
        hdrs += [(b"content-type", b"application/x-www-form-urlencoded"),
                 (b"content-length", str(len(body)).encode())]
    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(),
             "query_string": query.encode(), "headers": hdrs, "scheme": "https",
             "server": ("genome.example", 443), "client": ("203.0.113.5", 1)}
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        sent.append(m)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    rbody = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], start["headers"], rbody


def _hdr(headers, name):
    return next((v.decode() for k, v in headers if k == name.encode()), None)


HTML = ("accept", "text/html,application/xhtml+xml")
API = ("accept", "*/*")


async def _home(request):
    return PlainTextResponse("home")


def _gated_app():
    routes = [Route("/", _home), Route("/health", _home), Route("/mcp/x", _home),
              Route("/upload", _home, methods=["POST"]), *a.webapp_login_routes()]
    return a.WebappSessionMiddleware(Starlette(routes=routes))


class SessionHelperTests(unittest.TestCase):
    def setUp(self):
        mcp_oauth.configure(_Cfg(), service_name="test-mcp", session_cookie=COOKIE)

    def test_session_round_trip(self):
        self.assertEqual(a.verify_session(a.make_session("owner")), "owner")

    def test_tampered_session_rejected(self):
        self.assertIsNone(a.verify_session(a.make_session("owner") + "x"))

    def test_expired_session_rejected(self):
        now = int(time.time())
        tok = jwt.encode({"sub": "owner", "iat": now - 99, "exp": now - 9},
                         a._session_secret(), algorithm="HS256")
        self.assertIsNone(a.verify_session(tok))

    def test_safe_next(self):
        self.assertEqual(a._safe_next("/upload"), "/upload")
        self.assertEqual(a._safe_next("//evil.com"), "/")
        self.assertEqual(a._safe_next("https://evil.com"), "/")
        self.assertEqual(a._safe_next(None), "/")


class GateTests(unittest.TestCase):
    def setUp(self):
        self.cfg = _Cfg(as_password_hash=a.hash_password(PASSWORD))
        mcp_oauth.configure(self.cfg, service_name="test-mcp", session_cookie=COOKIE)
        self.app = _gated_app()

    def test_bypass_when_not_required(self):
        with env(GENOSCOPE_REQUIRE_AUTH="0"):
            s, _, b = run(_req(self.app, "GET", "/"))
        self.assertEqual((s, b), (200, b"home"))

    def test_unauth_browser_redirects_to_login(self):
        s, h, _ = run(_req(self.app, "GET", "/", headers=[HTML]))
        self.assertEqual(s, 302)
        self.assertEqual(_hdr(h, "location"), "/login?next=/")

    def test_unauth_api_gets_401(self):
        s, _, b = run(_req(self.app, "GET", "/", headers=[API]))
        self.assertEqual(s, 401)
        self.assertEqual(json.loads(b)["error_type"], "unauthorized")

    def test_session_cookie_opens_the_gate(self):
        cookie = a.make_session(USERNAME)
        s, _, b = run(_req(self.app, "GET", "/",
                           headers=[HTML, ("cookie", f"{COOKIE}={cookie}")]))
        self.assertEqual((s, b), (200, b"home"))

    def test_bearer_token_opens_the_gate(self):
        real, rs.build_verifier = rs.build_verifier, lambda: _StubVerifier()
        try:
            s, _, _ = run(_req(self.app, "POST", "/upload",
                               headers=[("authorization", "Bearer goodtoken")], form={}))
        finally:
            rs.build_verifier = real
        self.assertEqual(s, 200)

    def test_public_paths_pass_through(self):
        for path in ("/health", "/login", "/.well-known/jwks.json", "/mcp/x"):
            s, _, _ = run(_req(self.app, "GET", path, headers=[API]))
            self.assertNotIn(s, (302, 401), path)   # not challenged by this gate

    def test_login_flow_issues_cookie_that_opens_gate(self):
        bad = run(_req(self.app, "POST", "/login",
                       form={"username": USERNAME, "password": "wrong", "next": "/"}))
        self.assertEqual(bad[0], 401)
        ok = run(_req(self.app, "POST", "/login",
                      form={"username": USERNAME, "password": PASSWORD, "next": "/upload"}))
        self.assertEqual(ok[0], 302)
        self.assertEqual(_hdr(ok[1], "location"), "/upload")
        setc = _hdr(ok[1], "set-cookie")
        self.assertIn(COOKIE, setc)
        self.assertIn("HttpOnly", setc)
        cookie = setc.split(";")[0].split("=", 1)[1]
        # the issued cookie now opens the gate
        s, _, b = run(_req(self.app, "GET", "/",
                           headers=[HTML, ("cookie", f"{COOKIE}={cookie}")]))
        self.assertEqual((s, b), (200, b"home"))

    def test_logout_clears_cookie(self):
        s, h, _ = run(_req(self.app, "GET", "/logout"))
        self.assertEqual(s, 302)
        self.assertEqual(_hdr(h, "location"), "/login")
        self.assertIn(COOKIE, _hdr(h, "set-cookie"))


class _StubVerifier:
    async def verify_token(self, token):
        return (AccessToken(token=token, client_id="", scopes=[], subject=USERNAME)
                if token == "goodtoken" else None)


if __name__ == "__main__":
    unittest.main()
