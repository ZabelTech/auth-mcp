"""Tests for the shared minimal self-hosted OAuth AS (mcp_oauth.auth_server).

Hermetic: a local RSA key signs/verifies in-process; the CIMD `client_id` fetch is
monkeypatched (no network); RFC 7636's PKCE test vectors drive the code exchange. One
test per acceptance criterion (1-12). Config is injected via mcp_oauth.configure() with a
mutable test provider instead of GENOSCOPE_AS_* env.

    python -m unittest tests.test_auth_server
"""

from __future__ import annotations

import asyncio
import json
import time
import unittest
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette

import mcp_oauth
import mcp_oauth.auth_server as a
import mcp_oauth.resource_server as rs

ISS = "https://genome.example"
RESOURCE = "https://genome.example/mcp"
CLIENT_ID = "https://claude.ai/cimd.json"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
CIMD_DOC = {"client_id": CLIENT_ID, "redirect_uris": [REDIRECT]}
USERNAME = "owner"
PASSWORD = "s3cret-pw"
# RFC 7636 Appendix B test vectors.
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KEY_PEM = _KEY.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def run(coro):
    return asyncio.run(coro)


class _Cfg:
    """Mutable in-memory ConfigProvider for tests (every accessor reads its live value)."""

    def __init__(self, **over):
        self.d = {"require_auth": True, "oauth_issuer": ISS,
                  "oauth_jwks_url": "http://jwks.invalid", "oauth_resource_url": RESOURCE,
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
    """Compatibility shim retained for tests that toggle settings mid-flight: maps the old
    env names onto the active test provider's dict."""
    _MAP = {"GENOSCOPE_AS_ENABLED": ("as_enabled", lambda v: v == "1"),
            "GENOSCOPE_REQUIRE_AUTH": ("require_auth", lambda v: v == "1")}
    cfg = mcp_oauth.config.provider()
    saved = {}
    for k, v in kw.items():
        key, conv = _MAP[k]
        saved[key] = cfg.d[key]
        cfg.d[key] = conv(v) if v is not None else (False if key == "as_enabled" else True)
    try:
        yield
    finally:
        for key, old in saved.items():
            cfg.d[key] = old


async def _request(app, method, path, query="", form=None, headers=()):
    body = b""
    headers = [(k.lower().encode(), v.encode()) for k, v in headers]
    if form is not None:
        body = urlencode(form).encode()
        headers += [(b"content-type", b"application/x-www-form-urlencoded"),
                    (b"content-length", str(len(body)).encode())]
    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(),
             "query_string": query.encode(), "headers": headers, "scheme": "https",
             "server": ("genome.example", 443), "client": ("203.0.113.5", 4444)}
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        sent.append(m)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    rbody = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), rbody


class AuthServerTests(unittest.TestCase):
    def setUp(self):
        self.cfg = _Cfg(as_password_hash=a.hash_password(PASSWORD))
        mcp_oauth.configure(self.cfg, service_name="test-mcp", session_cookie="test_session")
        self.app = Starlette(routes=a.auth_server_routes())
        self._real_fetch = a._fetch_json
        a._fetch_json = lambda url: dict(CIMD_DOC)   # no network
        a._seen_jti.clear()

    def tearDown(self):
        a._fetch_json = self._real_fetch

    # helpers ----------------------------------------------------------------
    def _authorize(self, **over):
        form = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
                "code_challenge": CHALLENGE, "code_challenge_method": "S256",
                "state": "xyz", "resource": RESOURCE,
                "username": USERNAME, "password": PASSWORD}
        form.update(over)
        return run(_request(self.app, "POST", "/authorize", form=form))

    def _code_from(self, headers):
        loc = headers[b"location"].decode()
        return parse_qs(urlparse(loc).query)["code"][0]

    def _exchange(self, code, **over):
        form = {"grant_type": "authorization_code", "code": code, "code_verifier": VERIFIER,
                "redirect_uri": REDIRECT, "resource": RESOURCE}
        form.update(over)
        return run(_request(self.app, "POST", "/token", form=form))

    def _pubkey(self):
        jwk, _ = a._public_jwk_and_kid()
        return RSAAlgorithm.from_jwk(json.dumps(jwk))

    # criterion 1 ------------------------------------------------------------
    def test_metadata(self):
        s, _, b = run(_request(self.app, "GET", "/.well-known/oauth-authorization-server"))
        self.assertEqual(s, 200)
        m = json.loads(b)
        self.assertEqual(m["issuer"], ISS)
        self.assertEqual(m["authorization_endpoint"], ISS + "/authorize")
        self.assertEqual(m["token_endpoint"], ISS + "/token")
        self.assertEqual(m["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(m["token_endpoint_auth_methods_supported"], ["none"])
        self.assertTrue(m["client_id_metadata_document_supported"])
        self.assertTrue(m["authorization_response_iss_parameter_supported"])

    # criterion 2 ------------------------------------------------------------
    def test_jwks_round_trips(self):
        s, _, b = run(_request(self.app, "GET", "/.well-known/jwks.json"))
        self.assertEqual(s, 200)
        self.assertEqual(json.loads(b)["keys"][0]["kty"], "RSA")
        tok = a._mint_access_token(USERNAME, RESOURCE)
        claims = jwt.decode(tok, self._pubkey(), algorithms=["RS256"],
                            audience=RESOURCE, issuer=ISS)   # verifies against the JWKS key
        self.assertEqual(claims["sub"], USERNAME)

    # criterion 3 ------------------------------------------------------------
    def test_login_required_and_constant_time(self):
        # correct credential -> 302 with code + state + iss
        s, h, _ = self._authorize()
        self.assertEqual(s, 302)
        q = parse_qs(urlparse(h[b"location"].decode()).query)
        self.assertEqual(q["state"], ["xyz"])
        self.assertEqual(q["iss"], [ISS])
        self.assertIn("code", q)
        # wrong password and wrong username are both 401 with no redirect, same response
        bad_pw = self._authorize(password="nope")
        bad_user = self._authorize(username="someone")
        self.assertEqual(bad_pw[0], 401)
        self.assertEqual(bad_user[0], 401)
        self.assertNotIn(b"location", bad_pw[1])
        self.assertEqual(bad_pw[2], bad_user[2])     # indistinguishable

    # criterion 4 ------------------------------------------------------------
    def test_pkce_enforced(self):
        # authorize without a challenge -> 400
        s, _, _ = run(_request(self.app, "GET", "/authorize", query=urlencode({
            "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
            "resource": RESOURCE})))
        self.assertEqual(s, 400)
        # token with a wrong verifier -> invalid_grant
        code = self._code_from(self._authorize()[1])
        s2, _, b2 = self._exchange(code, code_verifier="wrong-verifier")
        self.assertEqual(s2, 400)
        self.assertEqual(json.loads(b2)["error"], "invalid_grant")

    # criterion 5 ------------------------------------------------------------
    def test_redirect_strictness(self):
        s, _, b = self._authorize(redirect_uri="https://claude.ai/evil")
        self.assertEqual(s, 400)
        self.assertEqual(json.loads(b)["error"], "invalid_request")

    # criterion 6 ------------------------------------------------------------
    def test_cimd_ssrf_guard(self):
        # a client_id on a non-allowlisted host is rejected WITHOUT fetching
        def boom(url):
            raise AssertionError("must not fetch a non-allowlisted client_id")
        a._fetch_json = boom
        try:
            s, _, _ = self._authorize(client_id="https://evil.example/cimd.json")
        finally:
            a._fetch_json = lambda url: dict(CIMD_DOC)
        self.assertEqual(s, 400)

    def test_cimd_fetch_failure_is_400_not_500(self):
        # a fetch/parse error on an allowlisted client_id must be a clean 400, not a 500
        def boom(url):
            raise ValueError("boom")   # stand in for HTTPError / JSONDecodeError
        a._fetch_json = boom
        try:
            s, _, b = self._authorize()
        finally:
            a._fetch_json = lambda url: dict(CIMD_DOC)
        self.assertEqual(s, 400)
        self.assertEqual(json.loads(b)["error"], "invalid_request")

    # criterion 7 ------------------------------------------------------------
    def test_token_and_audience(self):
        code = self._code_from(self._authorize()[1])
        s, _, b = self._exchange(code)
        self.assertEqual(s, 200)
        d = json.loads(b)
        self.assertEqual(d["token_type"], "Bearer")
        self.assertEqual(d["expires_in"], 3600)
        claims = jwt.decode(d["access_token"], self._pubkey(), algorithms=["RS256"],
                            audience=RESOURCE, issuer=ISS)
        self.assertEqual((claims["iss"], claims["sub"], claims["aud"]), (ISS, USERNAME, RESOURCE))
        self.assertEqual(claims["exp"] - claims["iat"], 3600)

    # criterion 8 ------------------------------------------------------------
    def test_single_use_code(self):
        code = self._code_from(self._authorize()[1])
        self.assertEqual(self._exchange(code)[0], 200)
        s2, _, b2 = self._exchange(code)                 # replay
        self.assertEqual(s2, 400)
        self.assertEqual(json.loads(b2)["error"], "invalid_grant")

    # criterion 9 ------------------------------------------------------------
    def test_code_expiry(self):
        now = int(time.time())
        expired = jwt.encode(
            {"typ": "code", "cc": CHALLENGE, "ru": REDIRECT, "res": RESOURCE,
             "sub": USERNAME, "jti": "x1", "iat": now - 600, "exp": now - 540},
            a._code_secret(), algorithm="HS256")
        s, _, b = self._exchange(expired)
        self.assertEqual(s, 400)
        self.assertEqual(json.loads(b)["error"], "invalid_grant")

    # criterion 10 -----------------------------------------------------------
    def test_end_to_end_with_existing_gate(self):
        access = a._mint_access_token(USERNAME, RESOURCE)
        verifier = rs.JwksTokenVerifier("http://x", ISS, RESOURCE)
        verifier._signing_key = lambda t: self._pubkey()      # avoid the JWKS HTTP fetch
        acc = run(verifier.verify_token(access))
        self.assertIsNotNone(acc)
        self.assertEqual(acc.subject, USERNAME)
        # a token for a different subject is rejected by the gate's single-subject check
        real_build, rs.build_verifier = rs.build_verifier, lambda: verifier
        try:
            wrong = a._mint_access_token("intruder", RESOURCE)
            status = self._gate(wrong)
            ok = self._gate(access)
        finally:
            rs.build_verifier = real_build
        self.assertEqual(status, 403)
        self.assertEqual(ok, 200)

    def _gate(self, token):
        """Run a Bearer token through the existing RequireAuthMiddleware; return the
        HTTP status (200 = let through, 403 = subject not allowlisted)."""
        async def inner(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        s, _, _ = run(_request(rs.RequireAuthMiddleware(inner), "POST", "/mcp",
                               headers=[("authorization", f"Bearer {token}")]))
        return s

    # criterion 11 -----------------------------------------------------------
    def test_survives_restart(self):
        # the key + kid come from the injected secret, so they're stable (a "restart" =
        # re-reading config), and a token issued "before" verifies "after".
        jwk1, kid1 = a._public_jwk_and_kid()
        tok = a._mint_access_token(USERNAME, RESOURCE)
        jwk2, kid2 = a._public_jwk_and_kid()
        self.assertEqual(kid1, kid2)
        self.assertEqual(jwt.get_unverified_header(tok)["kid"], kid1)
        jwt.decode(tok, self._pubkey(), algorithms=["RS256"], audience=RESOURCE, issuer=ISS)

    # criterion 12 -----------------------------------------------------------
    def test_disabled_by_default(self):
        with env(GENOSCOPE_AS_ENABLED="0"):
            self.assertEqual(a.auth_server_routes(), [])
        with env(GENOSCOPE_AS_ENABLED=None):
            self.assertEqual(a.auth_server_routes(), [])


if __name__ == "__main__":
    unittest.main()
