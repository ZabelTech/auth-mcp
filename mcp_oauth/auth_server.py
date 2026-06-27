"""Minimal self-hosted OAuth 2.1 authorization server.

Four stateless endpoints, no database, single fixed owner credential, CIMD-only (no
/register). It issues RS256 JWTs the resource-server verifier in `resource_server.py`
already validates — so it drops in behind the existing gate as the issuer.

  GET  /.well-known/oauth-authorization-server  RFC 8414 metadata
  GET  /.well-known/jwks.json                   the RS256 public key
  GET  /authorize                               login form
  POST /authorize                               verify credential -> auth code -> 302
  POST /token                                   authorization_code (code+PKCE) or
                                                refresh_token grant -> access token

Auth codes are short-lived HS256 blobs (secret derived from the signing key), single-use
via an in-memory jti set (the deploy is single-machine). The only outbound call is the
CIMD `client_id` fetch, bounded to an allowlist of hosts (SSRF guard).

All host settings (credential, signing key, TTL, issuer, allowlist) arrive through
`mcp_oauth.config`; nothing here is host specific beyond the injected branding.

Setup helpers (stdlib only), via the host's re-export module:
  python -m <host_auth_server_module> genkey   # print a fresh RSA private key (PEM)
  python -m <host_auth_server_module> hash PW   # print a pbkdf2 hash for the password
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import sys
import time
import urllib.request
from html import escape
from http.cookies import SimpleCookie
from urllib.parse import quote, urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from . import resource_server as rs
from .config import branding, provider

log = logging.getLogger("mcp_oauth.auth_server")

_PBKDF2_ROUNDS = 600_000
_CODE_TTL = 60  # seconds; the auth code is exchanged immediately

# ── refresh-token settings, read through the provider with back-compat defaults so a host
# whose adapter predates these accessors still works (refresh-tokens.spec §6). Only the
# static, non-rotating refresh path is implemented (spec §5a); rotation (§5) is parked. ──
_ACCESS_TTL_DEFAULT = 3600          # used when refresh is on but the host sets no access TTL
_REFRESH_TTL_DEFAULT = 2_592_000    # 30 days


def _refresh_enabled() -> bool:
    return bool(getattr(provider(), "as_refresh_enabled", lambda: False)())


def _access_ttl() -> int:
    """Access-token lifetime. A host `as_access_ttl()` wins; else 3600 when refresh is
    enabled (don't inherit a long `as_token_ttl` such as the 7-day quick fix), else
    `as_token_ttl()` for byte-for-byte back-compat (spec §3)."""
    fn = getattr(provider(), "as_access_ttl", None)
    if fn is not None:
        return fn()
    return _ACCESS_TTL_DEFAULT if _refresh_enabled() else provider().as_token_ttl()


def _refresh_ttl() -> int:
    fn = getattr(provider(), "as_refresh_ttl", None)
    return fn() if fn is not None else _REFRESH_TTL_DEFAULT


def _refresh_rotation() -> bool:
    """Rotation posture. Defaults False: only the static refresh path is implemented, so a
    host must opt into rotation (spec §5) explicitly once that path exists."""
    return bool(getattr(provider(), "as_refresh_rotation", lambda: False)())


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ─── credential (pbkdf2, stdlib — no new dependency) ────────────────────────
def hash_password(password: str, *, salt: bytes | None = None,
                  rounds: int = _PBKDF2_ROUNDS) -> str:
    """Produce a `pbkdf2_sha256$rounds$salt$dk` string for the AS password-hash secret."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a `hash_password` string."""
    try:
        algo, rounds, salt_b64, dk_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), _unb64(salt_b64), int(rounds))
    except Exception:  # noqa: BLE001 — any malformed hash -> auth fails, never crashes
        return False
    return hmac.compare_digest(dk, _unb64(dk_b64))


def _check_credentials(username: str, password: str) -> bool:
    """True iff (username, password) match the single fixed account. Always evaluates
    both factors (no short-circuit) so it can't time-leak which one was wrong."""
    cfg = provider()
    u, h = cfg.as_username(), cfg.as_password_hash()
    if not u or not h:
        return False
    user_ok = hmac.compare_digest(username or "", u)
    pass_ok = verify_password(password or "", h)
    return user_ok and pass_ok


# ─── signing key + JWKS ─────────────────────────────────────────────────────
def _private_key_pem() -> str:
    pem = provider().as_signing_key()
    if not pem:
        raise RuntimeError("the AS signing key is not configured")
    return pem


def _public_jwk_and_kid() -> tuple[dict, str]:
    """The RS256 public key as a JWK + a stable `kid` (also set on signed tokens so the
    verifier's JWKS lookup matches)."""
    priv = serialization.load_pem_private_key(_private_key_pem().encode(), password=None)
    pub = priv.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(pub))
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = hashlib.sha256(der).hexdigest()[:16]
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk, kid


# ─── auth codes (HS256, single-use) ─────────────────────────────────────────
_seen_jti: set[str] = set()


def _code_secret() -> bytes:
    # Mixed with the (per-deployment) signing key, so the prefix can be a fixed constant
    # while the secret stays unique per host.
    return hashlib.sha256(("mcp-oauth-code:" + _private_key_pem()).encode()).digest()


def _refresh_secret() -> bytes:
    # Same derivation as the code secret with a distinct domain prefix: a refresh token can
    # never be cross-validated as a code (or session), and rotating the RSA signing key
    # invalidates every refresh token along with the codes and sessions.
    return hashlib.sha256(("mcp-oauth-refresh:" + _private_key_pem()).encode()).digest()


def _mint_code(*, code_challenge: str, redirect_uri: str, resource: str, sub: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"typ": "code", "cc": code_challenge, "ru": redirect_uri, "res": resource,
         "sub": sub, "jti": secrets.token_urlsafe(12), "iat": now, "exp": now + _CODE_TTL},
        _code_secret(), algorithm="HS256")


def _consume_code(code: str) -> dict:
    """Verify a code (signature, expiry, type) and mark it used; raises on any problem."""
    claims = jwt.decode(code, _code_secret(), algorithms=["HS256"],
                        options={"require": ["exp", "jti", "typ"]})
    if claims.get("typ") != "code":
        raise jwt.InvalidTokenError("not an authorization code")
    jti = claims["jti"]
    if jti in _seen_jti:
        raise jwt.InvalidTokenError("authorization code already used")
    _seen_jti.add(jti)
    return claims


def _mint_access_token(sub: str, resource: str) -> str:
    now = int(time.time())
    _, kid = _public_jwk_and_kid()
    return jwt.encode(
        {"iss": provider().oauth_issuer(), "sub": sub, "aud": resource,
         "iat": now, "exp": now + _access_ttl(), "scope": ""},
        _private_key_pem(), algorithm="RS256", headers={"kid": kid})


def _mint_refresh_token(sub: str, resource: str) -> str:
    """A static (non-rotating) refresh token: an HS256 JWT bound to the subject and resource
    (spec §3). `sid`/`gen` are carried for forward-compatibility with the rotation path but
    are unused while rotation is off."""
    now = int(time.time())
    return jwt.encode(
        {"typ": "refresh", "sub": sub, "res": resource,
         "sid": secrets.token_urlsafe(16), "gen": 0, "jti": secrets.token_urlsafe(12),
         "iat": now, "exp": now + _refresh_ttl()},
        _refresh_secret(), algorithm="HS256")


def _pkce_ok(verifier: str, challenge: str) -> bool:
    return hmac.compare_digest(_b64(hashlib.sha256(verifier.encode()).digest()), challenge)


# ─── CIMD client resolution (the only outbound call; SSRF-guarded) ──────────
def _fetch_json(url: str) -> dict:
    # A real User-Agent is required: some IdP edges (e.g. Anthropic's) 403 the default
    # `Python-urllib/*` agent, which broke the CIMD fetch for Claude's client_id doc.
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": f"{branding().service_name}/1.0 (CIMD fetch)"})
    with urllib.request.urlopen(req, timeout=5) as r:  # host allowlisted by caller
        return json.loads(r.read(256 * 1024))


# Vetted CIMD fallback for known connectors. Some metadata docs sit behind bot
# protection that 403s a server-side fetch from datacenter egress — claude.ai is
# Cloudflare-challenged from a Fly host, though it serves fine from a browser/
# residential IP. When the live fetch fails we fall back to these values (verified
# from an unblocked network) so the connector still works. Still allowlist-gated
# and still exact-matched against the request's redirect_uri downstream.
_KNOWN_CLIENT_REDIRECT_URIS = {
    "https://claude.ai/oauth/mcp-oauth-client-metadata":
        ["https://claude.ai/api/mcp/auth_callback"],
}


def _client_redirect_uris(client_id: str) -> list[str]:
    """CIMD: the `client_id` is an HTTPS URL whose host must be allowlisted; fetch it and
    return its `redirect_uris`. On fetch failure, fall back to a vetted built-in registry
    for known connectors (bot-protected docs). Raises ValueError on any unresolved
    problem (no DCR fallback)."""
    u = urlparse(client_id)
    if u.scheme != "https" or not u.netloc:
        raise ValueError("client_id must be an https URL (CIMD)")
    if u.netloc not in provider().as_client_id_allowlist():
        raise ValueError("client_id host is not allowlisted")
    try:
        doc = _fetch_json(client_id)
    except Exception as e:  # noqa: BLE001 — HTTP error / non-JSON / timeout
        known = _KNOWN_CLIENT_REDIRECT_URIS.get(client_id)
        if known:
            return list(known)
        raise ValueError(f"could not fetch client metadata: {e}")
    uris = doc.get("redirect_uris") if isinstance(doc, dict) else None
    if not isinstance(uris, list) or not uris:
        raise ValueError("client metadata has no redirect_uris")
    return [str(x) for x in uris]


# ─── endpoint handlers ──────────────────────────────────────────────────────
def _issuer() -> str:
    return (provider().oauth_issuer() or "").rstrip("/")


async def authorization_server_metadata(request) -> Response:
    iss = _issuer()
    return JSONResponse({
        "issuer": iss,
        "authorization_endpoint": f"{iss}/authorize",
        "token_endpoint": f"{iss}/token",
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": (["authorization_code", "refresh_token"]
                                  if _refresh_enabled() else ["authorization_code"]),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
        "scopes_supported": [],
    })


async def jwks(request) -> Response:
    jwk, _ = _public_jwk_and_kid()
    return JSONResponse({"keys": [jwk]})


_OAUTH_PARAMS = ("response_type", "client_id", "redirect_uri", "code_challenge",
                 "code_challenge_method", "state", "resource", "scope")


def _validate_authorize(p: dict) -> tuple[list[str] | None, str | None]:
    """Validate an authorize request. Returns (allowed_redirect_uris, None) on success or
    (None, error) on a protocol problem (the caller 400s — never redirects to an
    unvalidated URI)."""
    if p.get("response_type") != "code":
        return None, "response_type must be 'code'"
    if not p.get("code_challenge") or p.get("code_challenge_method") != "S256":
        return None, "a PKCE code_challenge with method S256 is required"
    if not p.get("resource"):
        return None, "the resource parameter is required (RFC 8707)"
    try:
        allowed = _client_redirect_uris(p.get("client_id", ""))
    except ValueError as e:
        return None, f"invalid client_id: {e}"
    if p.get("redirect_uri") not in allowed:  # exact match only — no open redirect
        return None, "redirect_uri is not registered for this client"
    return allowed, None


def _login_form(p: dict, error: str | None = None) -> str:
    name = escape(branding().service_name)
    hidden = "".join(
        f'<input type="hidden" name="{escape(k)}" value="{escape(p.get(k, ""))}">'
        for k in _OAUTH_PARAMS if p.get(k))
    msg = f'<p style="color:#b00">{escape(error)}</p>' if error else ""
    return (
        f"<!doctype html><meta charset=utf-8><title>{name} sign in</title>"
        '<form method="post" style="max-width:20rem;margin:4rem auto;font-family:sans-serif">'
        f"<h2>{name}</h2>" + msg +
        '<p><input name="username" placeholder="username" autofocus></p>'
        '<p><input name="password" type="password" placeholder="password"></p>'
        + hidden +
        '<p><button type="submit">Authorize</button></p></form>')


async def authorize(request) -> Response:
    if request.method == "GET":
        p = dict(request.query_params)
        _, err = _validate_authorize(p)
        if err:
            return JSONResponse({"error": "invalid_request", "error_description": err}, 400)
        return HTMLResponse(_login_form(p))
    # POST — credential submission
    form = await request.form()
    p = {k: form.get(k, "") for k in (*_OAUTH_PARAMS, "username", "password")}
    _, err = _validate_authorize(p)
    if err:
        return JSONResponse({"error": "invalid_request", "error_description": err}, 400)
    if not _check_credentials(p["username"], p["password"]):
        return HTMLResponse(_login_form(p, error="Invalid credentials"), status_code=401)
    code = _mint_code(code_challenge=p["code_challenge"], redirect_uri=p["redirect_uri"],
                      resource=p["resource"], sub=provider().as_username())
    q = urlencode({"code": code, "state": p.get("state", ""), "iss": _issuer()})
    sep = "&" if urlparse(p["redirect_uri"]).query else "?"
    return RedirectResponse(f"{p['redirect_uri']}{sep}{q}", status_code=302)


def _token_error(code: str, status: int = 400) -> Response:
    return JSONResponse({"error": code}, status)


async def token(request) -> Response:
    form = await request.form()
    grant = form.get("grant_type")
    if grant == "refresh_token":
        return _token_refresh(form)
    if grant != "authorization_code":
        return _token_error("unsupported_grant_type")
    code, verifier = form.get("code", ""), form.get("code_verifier", "")
    redirect_uri, resource = form.get("redirect_uri", ""), form.get("resource", "")
    try:
        claims = _consume_code(code)
    except Exception:  # noqa: BLE001 — bad/expired/replayed code
        return _token_error("invalid_grant")
    if not verifier or not _pkce_ok(verifier, claims["cc"]):
        return _token_error("invalid_grant")
    if redirect_uri != claims["ru"] or (resource and resource != claims["res"]):
        return _token_error("invalid_grant")
    body = {"access_token": _mint_access_token(claims["sub"], claims["res"]),
            "token_type": "Bearer", "expires_in": _access_ttl(), "scope": ""}
    if _refresh_enabled():
        body["refresh_token"] = _mint_refresh_token(claims["sub"], claims["res"])
    return JSONResponse(body)


def _token_refresh(form) -> Response:
    """The `refresh_token` grant — static (non-rotating) mode, spec §5a: verify the refresh
    token, mint a fresh access token, and return the *same* refresh token. The whole
    rotation machinery (§5) is parked; a host that sets `as_refresh_rotation` True still gets
    static behaviour (logged once) until that path is built — never a silent failure."""
    if not _refresh_enabled():
        return _token_error("unsupported_grant_type")
    try:
        claims = jwt.decode(form.get("refresh_token", ""), _refresh_secret(),
                            algorithms=["HS256"], leeway=30,
                            options={"require": ["exp", "jti", "typ", "sub", "sid", "gen"]})
    except Exception:  # noqa: BLE001 — bad/expired/forged refresh token
        return _token_error("invalid_grant")
    if claims.get("typ") != "refresh":
        return _token_error("invalid_grant")
    resource = form.get("resource", "")
    if resource and resource != claims.get("res"):   # RFC 8707 audience binding
        return _token_error("invalid_grant")
    if _refresh_rotation():
        log.warning("as_refresh_rotation is set but rotation is not implemented; serving "
                    "static (non-rotating) refresh — see refresh-tokens.spec §5/§5a")
    return JSONResponse({
        "access_token": _mint_access_token(claims["sub"], claims.get("res", "")),
        "token_type": "Bearer", "expires_in": _access_ttl(), "scope": "",
        "refresh_token": form.get("refresh_token", "")})   # static: hand the same one back


# ─── first-party browser session + webapp gate ──────────────────────────────
# The OAuth flow above secures MCP clients (bearer tokens). A human-facing webapp UI is a
# browser that can't send a bearer header, so it gets a signed **session cookie** after a
# first-party login against the same single credential. The gate accepts either a session
# cookie or a bearer token.
def _cookie_name() -> str:
    return branding().session_cookie


def _session_secret() -> bytes:
    # Derived from the signing key so sessions need no extra secret and rotate with it.
    return hashlib.sha256(b"mcp-oauth-session:" + _private_key_pem().encode()).digest()


def make_session(sub: str) -> str:
    now = int(time.time())
    return jwt.encode({"sub": sub, "iat": now, "exp": now + provider().as_token_ttl()},
                      _session_secret(), algorithm="HS256")


def verify_session(cookie: str) -> str | None:
    """The session's subject if the cookie is a valid, unexpired session, else None."""
    try:
        c = jwt.decode(cookie, _session_secret(), algorithms=["HS256"],
                       options={"require": ["exp", "sub"]})
        return c["sub"]
    except Exception:  # noqa: BLE001 — bad/expired/forged cookie -> not logged in
        return None


def _safe_next(nxt: str | None) -> str:
    # Only same-origin absolute paths; never an open redirect target.
    return nxt if (nxt and nxt.startswith("/") and not nxt.startswith("//")) else "/"


def _session_login_form(nxt: str, error: str | None = None) -> str:
    name = escape(branding().service_name)
    msg = f'<p style="color:#b00">{escape(error)}</p>' if error else ""
    return (
        f"<!doctype html><meta charset=utf-8><title>{name} sign in</title>"
        '<form method="post" action="/login" '
        'style="max-width:20rem;margin:4rem auto;font-family:sans-serif">'
        f"<h2>{name}</h2>" + msg +
        '<p><input name="username" placeholder="username" autofocus></p>'
        '<p><input name="password" type="password" placeholder="password"></p>'
        f'<input type="hidden" name="next" value="{escape(nxt)}">'
        '<p><button type="submit">Sign in</button></p></form>')


async def login(request) -> Response:
    if request.method == "GET":
        return HTMLResponse(_session_login_form(_safe_next(request.query_params.get("next"))))
    form = await request.form()
    nxt = _safe_next(form.get("next"))
    if not _check_credentials(form.get("username", ""), form.get("password", "")):
        return HTMLResponse(_session_login_form(nxt, error="Invalid credentials"),
                            status_code=401)
    resp = RedirectResponse(nxt, status_code=302)
    # Secure on https (the real deploy); off over http://localhost so local testing
    # works (browsers won't send a Secure cookie over plain http).
    resp.set_cookie(_cookie_name(), make_session(provider().as_username()), httponly=True,
                    secure=(request.url.scheme == "https"), samesite="lax",
                    max_age=provider().as_token_ttl(), path="/")
    return resp


async def logout(request) -> Response:
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(_cookie_name(), path="/")
    return resp


def webapp_login_routes() -> list[Route]:
    return [Route("/login", login, methods=["GET", "POST"]),
            Route("/logout", logout, methods=["GET"])]


# Paths the webapp gate never challenges: health, the login pages themselves, and the
# OAuth bootstrap (its own gate handles /mcp; /.well-known + /authorize + /token must be
# reachable unauthenticated for the flow to start).
_GATE_PUBLIC_EXACT = {"/health", "/login", "/logout", "/authorize", "/token", "/favicon.ico"}
_GATE_PUBLIC_PREFIX = ("/mcp", "/.well-known/")


def _cookies(scope) -> dict:
    for k, v in scope.get("headers", []):
        if k == b"cookie":
            jar = SimpleCookie()
            jar.load(v.decode("latin-1"))
            return {name: m.value for name, m in jar.items()}
    return {}


async def _bearer_ok(scope) -> bool:
    token = rs._bearer_token(scope)
    if not token:
        return False
    verifier = rs.build_verifier()
    if not verifier:
        return False
    acc = await verifier.verify_token(token)
    return bool(acc and acc.subject in provider().allowed_subjects())


def _wants_html(scope) -> bool:
    for k, v in scope.get("headers", []):
        if k == b"accept":
            return b"text/html" in v
    return False


async def _send(send, status, headers, body=b""):
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class WebappSessionMiddleware:
    """Gate the first-party webapp UI. When auth is required, every non-public path needs
    a valid session cookie OR a valid bearer token; an unauthenticated browser GET is
    redirected to /login, anything else gets 401. Bypassed entirely when
    provider().require_auth() is false (local single-user); non-HTTP scopes and the
    public/bootstrap paths pass straight through."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not provider().require_auth():
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path in _GATE_PUBLIC_EXACT or path.startswith(_GATE_PUBLIC_PREFIX):
            return await self.app(scope, receive, send)
        cookie = _cookies(scope).get(_cookie_name())
        if (cookie and verify_session(cookie)) or await _bearer_ok(scope):
            return await self.app(scope, receive, send)
        if scope.get("method") == "GET" and _wants_html(scope):
            await _send(send, 302, [(b"location", f"/login?next={quote(path)}".encode())])
        else:
            body = (b'{"error":true,"error_type":"unauthorized",'
                    b'"message":"authentication required"}')
            await _send(send, 401, [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())], body)


def auth_server_routes() -> list[Route]:
    """The four AS routes — only when the host enables the AS (else this server is not its
    own issuer). Mounted at the app root alongside the protected-resource metadata."""
    if not provider().as_enabled():
        return []
    return [
        Route("/.well-known/oauth-authorization-server",
              authorization_server_metadata, methods=["GET"]),
        Route("/.well-known/jwks.json", jwks, methods=["GET"]),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/token", token, methods=["POST"]),
    ]


def _main(argv: list[str]) -> int:
    """Setup helpers — see module docstring."""
    if len(argv) >= 1 and argv[0] == "genkey":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sys.stdout.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode())
        return 0
    if len(argv) >= 2 and argv[0] == "hash":
        print(hash_password(argv[1]))
        return 0
    sys.stderr.write("usage: python -m mcp_oauth.auth_server (genkey | hash PASSWORD)\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
