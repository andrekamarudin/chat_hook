"""Single-owner OAuth 2.1 authorization server for the protected /mcp resource.

Fail-closed by design: without CHAT_HOOK_PUBLIC_URL and a 32+ character
CHAT_HOOK_OWNER_PASSWORD every authorization and MCP request is refused.
Codes and tokens are random, stored only as SHA-256 hashes, PKCE S256 is
mandatory, and clients may only redirect to ChatGPT connector callbacks.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from chat_hook.app import connect

SCOPES = ("hooks.events", "hooks.read", "hooks.outcomes")
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
CODE_TTL = 300
MAX_CLIENTS = 50
LOGIN_FAILURE_LIMIT = 5
LOGIN_GLOBAL_FAILURE_LIMIT = 100
LOGIN_WINDOW_SECONDS = 900
REDIRECT_HOSTS = frozenset({"chatgpt.com", "chat.openai.com"})
PAGE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "form-action 'self'; frame-ancestors 'none'",
}
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

router = APIRouter(include_in_schema=False)


class OAuthError(Exception):
    def __init__(self, error, description, status=400):
        super().__init__(description)
        self.error, self.description, self.status = error, description, status


@dataclass(frozen=True)
class Principal:
    owner: str
    client_id: str
    scopes: frozenset
    categories: frozenset

    def require(self, scope):
        if scope not in self.scopes:
            raise HTTPException(403, "Insufficient scope", headers={
                "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'})


def public_url():
    value = os.getenv("CHAT_HOOK_PUBLIC_URL", "").rstrip("/")
    parts = urlsplit(value)
    local = parts.hostname in ("localhost", "127.0.0.1", "testserver")
    if not value or parts.scheme not in ("https",) + (("http",) if local else ()) or parts.path:
        return None
    return value


def owner():
    return os.getenv("CHAT_HOOK_OWNER", "owner")


def configured():
    return public_url() is not None and len(os.getenv("CHAT_HOOK_OWNER_PASSWORD", "")) >= 32


def require_configured():
    if not configured():
        raise HTTPException(503, "OAuth is not configured")


def resource_url():
    return public_url() + "/mcp"


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
        created_at REAL NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS oauth_codes (
        code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
        challenge TEXT NOT NULL, scope TEXT NOT NULL, categories TEXT NOT NULL,
        resource TEXT NOT NULL, family TEXT NOT NULL, expires_at REAL NOT NULL,
        used INTEGER NOT NULL DEFAULT 0)""")
    db.execute("""CREATE TABLE IF NOT EXISTS oauth_tokens (
        token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('access','refresh')),
        client_id TEXT NOT NULL, owner TEXT NOT NULL, scope TEXT NOT NULL,
        categories TEXT NOT NULL, resource TEXT NOT NULL, family TEXT NOT NULL,
        expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_oauth_family ON oauth_tokens(family)")
    db.execute("""CREATE TABLE IF NOT EXISTS oauth_login_failures (
        at REAL NOT NULL, key TEXT NOT NULL)""")


def allowed_redirect(uri):
    if not isinstance(uri, str) or len(uri) > 2048:
        return False
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    return (parts.scheme == "https" and parts.hostname in REDIRECT_HOSTS and parts.port is None
            and not parts.username and not parts.fragment
            and (parts.path == "/connector/oauth" or parts.path.startswith("/connector/oauth/")))


def _categories():
    from chat_hook.control import CATEGORIES

    return CATEGORIES


def _parse_scope(raw):
    requested = (raw or " ".join(SCOPES)).split()
    if not requested or set(requested) - set(SCOPES):
        raise OAuthError("invalid_scope", "Unsupported scope")
    return " ".join(s for s in SCOPES if s in requested)


def _client(client_id):
    with connect() as db:
        row = db.execute("SELECT redirect_uris FROM oauth_clients WHERE client_id=?",
                         (client_id or "",)).fetchone()
    return json.loads(row[0]) if row else None


def _metadata_headers():
    return {"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"}


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource_metadata():
    require_configured()
    return JSONResponse({
        "resource": resource_url(), "authorization_servers": [public_url()],
        "scopes_supported": list(SCOPES), "bearer_methods_supported": ["header"],
        "resource_name": "Chat Hook",
    }, headers=_metadata_headers())


@router.get("/.well-known/oauth-authorization-server")
@router.get("/.well-known/openid-configuration")
def authorization_server_metadata():
    require_configured()
    base = public_url()
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": base + "/oauth/authorize",
        "token_endpoint": base + "/oauth/token",
        "registration_endpoint": base + "/oauth/register",
        "revocation_endpoint": base + "/oauth/revoke",
        "scopes_supported": list(SCOPES),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True,
    }, headers=_metadata_headers())


@router.post("/oauth/register", status_code=201)
async def register(request: Request):
    require_configured()
    try:
        body = await request.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_client_metadata"}, 400)
    uris = body.get("redirect_uris")
    if (not isinstance(uris, list) or not 1 <= len(uris) <= 5
            or not all(allowed_redirect(u) for u in uris)):
        return JSONResponse({"error": "invalid_redirect_uri",
                             "error_description": "Only ChatGPT connector callbacks are allowed"}, 400)
    if body.get("token_endpoint_auth_method", "none") != "none":
        return JSONResponse({"error": "invalid_client_metadata",
                             "error_description": "Only public PKCE clients are supported"}, 400)
    name = body.get("client_name") if isinstance(body.get("client_name"), str) else "ChatGPT"
    client_id = "client_" + secrets.token_urlsafe(18)
    now = time.time()
    with connect() as db:
        db.execute("INSERT INTO oauth_clients VALUES (?,?,?,?)",
                   (client_id, name[:80], json.dumps(uris), now))
        # Bound unauthenticated registration growth: drop the oldest clients without live tokens.
        db.execute("""DELETE FROM oauth_clients WHERE client_id IN (
            SELECT client_id FROM oauth_clients c WHERE NOT EXISTS (
                SELECT 1 FROM oauth_tokens t WHERE t.client_id=c.client_id
                AND t.revoked=0 AND t.expires_at>?)
            ORDER BY created_at DESC LIMIT -1 OFFSET ?)""", (now, MAX_CLIENTS))
    return JSONResponse({
        "client_id": client_id, "client_id_issued_at": int(now), "client_name": name[:80],
        "redirect_uris": uris, "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "scope": " ".join(SCOPES),
    }, 201, headers=NO_STORE)


def _validate_authorization(params):
    """Validate a request before any redirect. Bad clients get a local error page."""
    uris = _client(params.get("client_id"))
    redirect_uri = params.get("redirect_uri")
    if uris is None or redirect_uri not in uris:
        raise OAuthError("invalid_request", "Unknown client or unregistered redirect_uri")
    if params.get("response_type") != "code":
        raise OAuthError("unsupported_response_type", "Only response_type=code is supported")
    challenge = params.get("code_challenge") or ""
    if params.get("code_challenge_method") != "S256" or not 43 <= len(challenge) <= 128:
        raise OAuthError("invalid_request", "PKCE S256 code_challenge is required")
    resource = params.get("resource") or resource_url()
    if resource.rstrip("/") != resource_url():
        raise OAuthError("invalid_target", "Unknown resource")
    return {"client_id": params["client_id"], "redirect_uri": redirect_uri,
            "challenge": challenge, "scope": _parse_scope(params.get("scope")),
            "resource": resource_url(), "state": params.get("state") or ""}


def _error_page(message, status=400):
    return HTMLResponse(f"<!doctype html><title>Chat Hook</title><p>{html.escape(message)}</p>",
                        status, headers=PAGE_HEADERS)


def _consent_page(request, error=""):
    categories = _categories()
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in request.items())
    boxes = "".join(
        f'<label><input type="checkbox" name="category" value="{html.escape(slug)}" checked> '
        f'{html.escape(name)}</label>' for slug, name in categories.items())
    alert = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Chat Hook</title>
<style>body{{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}}
label{{display:block;margin:.4rem 0}}input[type=password]{{width:100%;padding:.5rem}}
button{{margin-top:1rem;padding:.6rem 1.2rem}}.err{{color:#b00020}}</style></head><body>
<h1>Authorize ChatGPT</h1>
<p>Grant ChatGPT access to Chat Hook events, read-only event lookup and outcome recording
for the selected categories. Scopes: <code>{html.escape(request["scope"])}</code>.</p>{alert}
<form method="post" action="/oauth/authorize">{hidden}
<fieldset><legend>Categories</legend>{boxes}</fieldset>
<label>Owner password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Authorize</button></form></body></html>"""


@router.get("/oauth/authorize")
def authorize_form(request: Request):
    if not configured():
        return _error_page("OAuth is not configured on this server.", 503)
    try:
        params = _validate_authorization(dict(request.query_params))
    except OAuthError as exc:
        return _error_page(exc.description)
    return HTMLResponse(_consent_page(params), headers=PAGE_HEADERS)


def _client_ip(request):
    # Only Caddy can reach the app; it appends the real peer to X-Forwarded-For.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded.strip():
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _rate_limited(key):
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with connect() as db:
        db.execute("DELETE FROM oauth_login_failures WHERE at<?", (cutoff,))
        mine = db.execute("SELECT COUNT(*) FROM oauth_login_failures WHERE key=?",
                          (key,)).fetchone()[0]
        total = db.execute("SELECT COUNT(*) FROM oauth_login_failures").fetchone()[0]
    return mine >= LOGIN_FAILURE_LIMIT or total >= LOGIN_GLOBAL_FAILURE_LIMIT


@router.post("/oauth/authorize")
async def authorize_submit(request: Request):
    if not configured():
        return _error_page("OAuth is not configured on this server.", 503)
    form = await request.form()
    fields = {k: form.get(k) for k in (
        "client_id", "redirect_uri", "challenge", "scope", "resource", "state")}
    if not all(isinstance(v, str) for v in fields.values()):
        return _error_page("Invalid authorization form.")
    try:
        params = _validate_authorization({
            "client_id": fields["client_id"], "redirect_uri": fields["redirect_uri"],
            "response_type": "code", "code_challenge": fields["challenge"],
            "code_challenge_method": "S256", "scope": fields["scope"],
            "resource": fields["resource"], "state": fields["state"]})
    except OAuthError as exc:
        return _error_page(exc.description)
    # Per-IP lockout so anonymous clients cannot lock the owner out; a high global
    # ceiling still bounds distributed guessing.
    ip_key = "ip:" + _client_ip(request)
    if _rate_limited(ip_key):
        return _error_page("Too many failed attempts. Try again later.", 429)
    password = form.get("password")
    expected = os.getenv("CHAT_HOOK_OWNER_PASSWORD", "")
    if not isinstance(password, str) or not hmac.compare_digest(password.encode(), expected.encode()):
        with connect() as db:
            db.execute("INSERT INTO oauth_login_failures VALUES (?,?)", (time.time(), ip_key))
        return HTMLResponse(_consent_page(params, "Invalid password."), 401, headers=PAGE_HEADERS)
    allowed = _categories()
    chosen = sorted({c for c in form.getlist("category") if isinstance(c, str) and c in allowed})
    if not chosen:
        return HTMLResponse(_consent_page(params, "Select at least one category."), 400,
                            headers=PAGE_HEADERS)
    code = secrets.token_urlsafe(32)
    with connect() as db:
        db.execute("""INSERT INTO oauth_codes
            (code_hash,client_id,redirect_uri,challenge,scope,categories,resource,family,expires_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (digest(code), params["client_id"], params["redirect_uri"], params["challenge"],
             params["scope"], json.dumps(chosen), params["resource"],
             "fam_" + secrets.token_hex(12), time.time() + CODE_TTL))
    query = {"code": code, "iss": public_url()}
    if params["state"]:
        query["state"] = params["state"]
    separator = "&" if "?" in params["redirect_uri"] else "?"
    return RedirectResponse(params["redirect_uri"] + separator + urlencode(query), 302,
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


def _issue(db, client_id, scope, categories, resource, family):
    now = time.time()
    access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    for value, kind, ttl in ((access, "access", ACCESS_TTL), (refresh, "refresh", REFRESH_TTL)):
        db.execute("""INSERT INTO oauth_tokens
            (token_hash,kind,client_id,owner,scope,categories,resource,family,expires_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (digest(value), kind, client_id, owner(), scope, categories, resource, family, now + ttl))
    return {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL,
            "refresh_token": refresh, "scope": scope}


def _pkce_matches(verifier, challenge):
    if not isinstance(verifier, str) or not 43 <= len(verifier) <= 128:
        return False
    computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return hmac.compare_digest(computed.decode(), challenge)


def _token_response(form):
    grant = form.get("grant_type")
    client_id = form.get("client_id")
    if not isinstance(client_id, str) or _client(client_id) is None:
        raise OAuthError("invalid_client", "Unknown client", 401)
    resource = form.get("resource")
    if resource and resource.rstrip("/") != resource_url():
        raise OAuthError("invalid_target", "Unknown resource")
    if grant == "authorization_code":
        code = form.get("code")
        if not isinstance(code, str):
            raise OAuthError("invalid_request", "Missing code")
        with connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM oauth_codes WHERE code_hash=?", (digest(code),)).fetchone()
            if row is None or row["client_id"] != client_id:
                raise OAuthError("invalid_grant", "Invalid authorization code")
            if row["used"]:
                # Replay of a redeemed code: revoke everything issued from it (RFC 9700 4.2.1).
                db.execute("UPDATE oauth_tokens SET revoked=1 WHERE family=?", (row["family"],))
                db.commit()
                raise OAuthError("invalid_grant", "Authorization code already used")
            if row["expires_at"] < time.time() or form.get("redirect_uri") != row["redirect_uri"]:
                raise OAuthError("invalid_grant", "Invalid authorization code")
            if not _pkce_matches(form.get("code_verifier"), row["challenge"]):
                raise OAuthError("invalid_grant", "PKCE verification failed")
            if not db.execute("UPDATE oauth_codes SET used=1 WHERE code_hash=? AND used=0",
                              (row["code_hash"],)).rowcount:
                raise OAuthError("invalid_grant", "Authorization code already used")
            return _issue(db, client_id, row["scope"], row["categories"], row["resource"], row["family"])
    if grant == "refresh_token":
        token = form.get("refresh_token")
        if not isinstance(token, str):
            raise OAuthError("invalid_request", "Missing refresh_token")
        with connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM oauth_tokens WHERE token_hash=? AND kind='refresh'",
                             (digest(token),)).fetchone()
            if row is None or row["client_id"] != client_id:
                raise OAuthError("invalid_grant", "Invalid refresh token")
            if row["revoked"]:
                # A rotated refresh token was replayed: treat the family as compromised.
                db.execute("UPDATE oauth_tokens SET revoked=1 WHERE family=?", (row["family"],))
                db.commit()
                raise OAuthError("invalid_grant", "Refresh token revoked")
            if row["expires_at"] < time.time():
                raise OAuthError("invalid_grant", "Refresh token expired")
            scope = row["scope"]
            if form.get("scope"):
                narrowed = _parse_scope(form.get("scope"))
                if set(narrowed.split()) - set(scope.split()):
                    raise OAuthError("invalid_scope", "Scope exceeds original grant")
                scope = narrowed
            if not db.execute("UPDATE oauth_tokens SET revoked=1 WHERE token_hash=? AND revoked=0",
                              (row["token_hash"],)).rowcount:
                # Lost a concurrent rotation race: treat as replay.
                db.execute("UPDATE oauth_tokens SET revoked=1 WHERE family=?", (row["family"],))
                db.commit()
                raise OAuthError("invalid_grant", "Refresh token revoked")
            return _issue(db, client_id, scope, row["categories"], row["resource"], row["family"])
    raise OAuthError("unsupported_grant_type", "Unsupported grant_type")


@router.post("/oauth/token")
async def token(request: Request):
    require_configured()
    form = await request.form()
    try:
        return JSONResponse(_token_response({k: v for k, v in form.items() if isinstance(v, str)}),
                            headers=NO_STORE)
    except OAuthError as exc:
        return JSONResponse({"error": exc.error, "error_description": exc.description},
                            exc.status, headers=NO_STORE)


@router.post("/oauth/revoke")
async def revoke(request: Request):
    require_configured()
    form = await request.form()
    value = form.get("token")
    if isinstance(value, str):
        with connect() as db:
            row = db.execute("SELECT family,kind FROM oauth_tokens WHERE token_hash=?",
                             (digest(value),)).fetchone()
            if row and row[1] == "refresh":
                db.execute("UPDATE oauth_tokens SET revoked=1 WHERE family=?", (row[0],))
            elif row:
                db.execute("UPDATE oauth_tokens SET revoked=1 WHERE token_hash=?", (digest(value),))
    return JSONResponse({}, headers=NO_STORE)


def challenge_header(error=None):
    value = f'Bearer resource_metadata="{public_url()}/.well-known/oauth-protected-resource"'
    if error:
        value += f', error="{error}"'
    return {"WWW-Authenticate": value}


def authenticate(request: Request) -> Principal:
    require_configured()
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer ") or len(header) > 512:
        raise HTTPException(401, "Authentication required", headers=challenge_header())
    with connect() as db:
        row = db.execute("""SELECT owner,client_id,scope,categories,resource,expires_at,revoked
            FROM oauth_tokens WHERE token_hash=? AND kind='access'""",
            (digest(header[7:].strip()),)).fetchone()
    if (row is None or row[6] or row[5] < time.time() or row[4] != resource_url()
            or row[0] != owner()):
        raise HTTPException(401, "Invalid or expired token",
                            headers=challenge_header("invalid_token"))
    return Principal(owner=row[0], client_id=row[1], scopes=frozenset(row[2].split()),
                     categories=frozenset(json.loads(row[3])))
