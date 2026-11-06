"""Signed MCP webhook delivery with SSRF-safe DNS pinning and durable state.

Callback signing secrets are encrypted at rest with CHAT_HOOK_DATA_KEY. An HTTP
2xx from the callback is a delivery receipt only; it never proves that a
ChatGPT Work run executed. That proof comes from the authenticated
acknowledge tool on /mcp.
"""

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import ssl
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from chat_hook.app import connect, utc_now

NAME = "hook.event"
MAX_BYTES = 262144
MAX_ATTEMPTS = 6
DEFAULT_TTL_SECONDS = 86400
MIN_TTL_SECONDS = 300
VERIFICATION_CACHE_SECONDS = 3600
ROTATION_OVERLAP_SECONDS = 600
PENDING_MAX_AGE = timedelta(hours=24)


class CallbackError(Exception):
    """Callback verification, security or delivery failure.

    ``reason`` is a stable category returned to MCP clients; ``callback`` marks
    failures of the callback endpoint itself (JSON-RPC -32015) rather than
    invalid subscription parameters.
    """

    def __init__(self, message, reason="invalid_params", callback=False):
        super().__init__(message)
        self.reason, self.callback = reason, callback


def initialize():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL,
            arguments TEXT NOT NULL, url TEXT NOT NULL, secret TEXT NOT NULL,
            expires_at TEXT NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
            event_id TEXT NOT NULL, subscription_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt TEXT NOT NULL, last_http INTEGER,
            PRIMARY KEY(event_id,subscription_id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS callback_verifications (
            owner TEXT NOT NULL, url TEXT NOT NULL, secret_hash TEXT NOT NULL,
            verified_at REAL NOT NULL, PRIMARY KEY(owner,url,secret_hash))""")
        add_columns(db, "subscriptions", {
            "category": "TEXT", "previous_secret": "TEXT", "previous_until": "TEXT",
            "refreshed_at": "TEXT"})
        add_columns(db, "deliveries", {
            "queued_at": "TEXT", "last_attempt_at": "TEXT", "delivered_at": "TEXT",
            "owner": "TEXT"})
        add_columns(db, "events", {"queued_at": "TEXT"})
        db.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status,next_attempt)")


def add_columns(db, table, columns):
    existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    for name, kind in columns.items():
        if name not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")


def _fernet():
    from cryptography.fernet import Fernet

    key = os.getenv("CHAT_HOOK_DATA_KEY", "")
    if len(key) < 32:
        raise CallbackError("Subscription storage key is not configured", "server_not_configured")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(
        b"chat-hook/callback-secret/v1/" + key.encode()).digest()))


def seal(secret):
    return "enc:v1:" + _fernet().encrypt(secret.encode()).decode()


def unseal(stored):
    from cryptography.fernet import InvalidToken

    if not stored:
        return None
    if not stored.startswith("enc:v1:"):
        return stored  # Pre-encryption rows; resealed on next refresh.
    try:
        return _fernet().decrypt(stored[7:].encode()).decode()
    except InvalidToken as exc:
        raise CallbackError("Stored callback secret cannot be decrypted", "server_error") from exc


def public_destination(url):
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise CallbackError("Invalid URL", "invalid_url") from exc
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.fragment or port not in (None, 443) or len(url) > 2048):
        raise CallbackError("Only public HTTPS callbacks on port 443 are supported", "invalid_url")
    host = parts.hostname.lower().rstrip(".")
    suffixes = [x.strip().lower() for x in os.getenv(
        "CHAT_HOOK_CALLBACK_HOST_SUFFIXES", "chatgpt.com,openai.com"
    ).split(",") if x.strip()]
    if not any(host == suffix or host.endswith("." + suffix) for suffix in suffixes):
        raise CallbackError("Callback host not on allowlist", "invalid_url")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = [entry[4][0] for entry in addresses]
    except OSError as exc:
        raise CallbackError("Callback DNS failed", "dns_failure", callback=True) from exc
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise CallbackError("Callback DNS contains a non-public IP", "blocked_destination")
    return parts, ips[0]


def post_pinned(url, data, headers):
    parts, ip = public_destination(url)

    class PinnedConnection(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, 443), timeout=8)
            self.sock = self._context.wrap_socket(sock, server_hostname=parts.hostname)

    connection = PinnedConnection(parts.hostname, context=ssl.create_default_context(), timeout=8)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    try:
        # http.client never follows redirects; a 3xx is treated as a failed delivery.
        connection.request("POST", path, body=data, headers={
            "Host": parts.hostname, "Content-Type": "application/json",
            "Accept": "application/json", **headers,
        })
        reply = connection.getresponse()
        return reply.status, reply.read(8192)
    except TimeoutError as exc:
        raise CallbackError("Callback timed out", "timeout", callback=True) from exc
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise CallbackError("Callback transport failure", "connection_failed", callback=True) from exc
    finally:
        connection.close()


def _signing_key(secret):
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise CallbackError("Invalid signing secret prefix", "invalid_secret")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CallbackError("Invalid signing secret encoding", "invalid_secret") from exc
    if not 24 <= len(key) <= 64:
        raise CallbackError("Invalid signing secret length", "invalid_secret")
    return key


def signature_headers(payload, event_id, subscription_id, secret, extra_secrets=()):
    keys = [_signing_key(secret)] + [_signing_key(s) for s in extra_secrets if s]
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX_BYTES:
        raise CallbackError("Delivery too large", "payload_too_large")
    stamp = str(int(time.time()))
    signed = event_id.encode() + b"." + stamp.encode() + b"." + raw
    signature = " ".join(
        "v1," + base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
        for key in keys)
    return raw, {"webhook-id": event_id, "webhook-timestamp": stamp,
                 "webhook-signature": signature, "X-MCP-Subscription-Id": subscription_id}


def signed_post(url, secret, sid, payload, eid, extra_secrets=()):
    raw, headers = signature_headers(payload, eid, sid, secret, extra_secrets)
    return post_pinned(url, raw, headers)


def identity(owner, url, name, arguments):
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    raw = json.dumps([owner, url, name, canonical]).encode()
    return "sub_" + hashlib.sha256(raw).hexdigest()[:40]


def event_category(source):
    """Category used for subscription routing. Internal reports use a configured category."""
    from chat_hook.control import get_source

    if source == "chat_hook":
        return os.getenv("CHAT_HOOK_REPORT_CATEGORY", "personal")
    cfg = get_source(source)
    return cfg["category"] if cfg else None


def validate_arguments(arguments, categories):
    from chat_hook.control import CATEGORIES, get_source

    if not isinstance(arguments, dict) or set(arguments) - {"source", "event_type", "category"}:
        raise CallbackError("Unsupported event filter")
    if any(not isinstance(v, str) or not 0 < len(v) <= 100 for v in arguments.values()):
        raise CallbackError("Invalid event filter")
    category = arguments.get("category")
    if category not in CATEGORIES:
        raise CallbackError("A valid category filter is required")
    if category not in categories:
        raise CallbackError("Category not granted to this connection", "forbidden")
    source = arguments.get("source")
    if source and event_category(source) != category:
        raise CallbackError("Source does not belong to the category")
    if source and source != "chat_hook" and get_source(source) is None:
        raise CallbackError("Unknown source")
    return category


def _verify_callback(owner, url, secret, sid):
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    with connect() as db:
        db.execute("DELETE FROM callback_verifications WHERE verified_at<?",
                   (time.time() - VERIFICATION_CACHE_SECONDS,))
        if db.execute("""SELECT 1 FROM callback_verifications
            WHERE owner=? AND url=? AND secret_hash=?""", (owner, url, secret_hash)).fetchone():
            return
    challenge = secrets.token_urlsafe(32)
    status, body = signed_post(
        url, secret, sid, {"type": "verification", "challenge": challenge},
        "msg_verification_" + secrets.token_hex(16),
    )
    try:
        echoed = json.loads(body).get("challenge", "")
    except (ValueError, TypeError, AttributeError) as exc:
        raise CallbackError("Invalid callback verification body", "challenge_failed", True) from exc
    if not 200 <= status < 300 or not isinstance(echoed, str) or not hmac.compare_digest(challenge, echoed):
        raise CallbackError("Callback verification challenge failed", "challenge_failed", True)
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO callback_verifications VALUES (?,?,?,?)",
                   (owner, url, secret_hash, time.time()))


def subscribe(owner, name, arguments, delivery, ttl_ms=None, categories=frozenset()):
    """Create or refresh one owner-scoped subscription.

    Only one live subscription is kept per (owner, category): subscribing from a
    different Work chat replaces the previous one, so each category maps to one
    continuing conversation rather than fanning out to many.
    """
    if name != NAME:
        raise CallbackError("Unsupported event")
    category = validate_arguments(arguments, categories)
    if not isinstance(delivery, dict) or delivery.get("mode") != "webhook":
        raise CallbackError("Only webhook delivery is supported")
    url, secret = delivery.get("url"), delivery.get("secret")
    if not isinstance(url, str):
        raise CallbackError("Missing callback URL", "invalid_url")
    _signing_key(secret)
    sid = identity(owner, url, name, arguments)
    _verify_callback(owner, url, secret, sid)
    seconds = ttl_ms // 1000 if isinstance(ttl_ms, int) and not isinstance(ttl_ms, bool) else DEFAULT_TTL_SECONDS
    seconds = min(max(seconds, MIN_TTL_SECONDS), DEFAULT_TTL_SECONDS)
    expiry = (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()
    args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    sealed = seal(secret)
    with connect() as db:
        current = db.execute("SELECT secret FROM subscriptions WHERE id=? AND owner=?",
                             (sid, owner)).fetchone()
        previous, until = None, None
        if current and unseal(current[0]) != secret:
            # Keep signing with the old key briefly so in-flight receivers can roll over.
            previous = current[0]
            until = (datetime.now(UTC) + timedelta(seconds=ROTATION_OVERLAP_SECONDS)).isoformat()
        db.execute("""INSERT INTO subscriptions
            (id,owner,name,arguments,url,secret,expires_at,created_at,category,
             previous_secret,previous_until,refreshed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
            secret=excluded.secret,expires_at=excluded.expires_at,
            previous_secret=COALESCE(excluded.previous_secret,subscriptions.previous_secret),
            previous_until=COALESCE(excluded.previous_until,subscriptions.previous_until),
            refreshed_at=excluded.refreshed_at""",
            (sid, owner, name, args, url, sealed, expiry, utc_now(), category,
             previous, until, utc_now()))
        replaced = [r[0] for r in db.execute(
            "SELECT id FROM subscriptions WHERE owner=? AND category=? AND id!=?",
            (owner, category, sid))]
        for old in replaced:
            db.execute("DELETE FROM deliveries WHERE subscription_id=? AND status='pending'", (old,))
            db.execute("DELETE FROM subscriptions WHERE id=?", (old,))
        if replaced:
            from chat_hook.control import audit

            audit(db, "subscription.replaced", category, {"replaced": len(replaced)})
    return {"id": sid, "refreshBefore": expiry, "cursor": None, "truncated": False}


def unsubscribe(owner, name, arguments, delivery):
    if not isinstance(delivery, dict) or not isinstance(delivery.get("url"), str):
        raise CallbackError("Invalid unsubscribe arguments")
    sid = identity(owner, delivery["url"], name, arguments)
    with connect() as db:
        if db.execute("DELETE FROM subscriptions WHERE id=? AND owner=?", (sid, owner)).rowcount:
            db.execute("DELETE FROM deliveries WHERE subscription_id=? AND status='pending'", (sid,))
    return {}


def queue_event(event):
    if event.get("triage_route") not in ("wake", "review"):
        return 0
    # Enforce runtime switches even for events triaged before a switch changed.
    from chat_hook.control import get_source

    cfg = get_source(event["source"])
    if cfg and (not cfg["enabled"] or not cfg["category_enabled"] or cfg["mode"] == "digest"):
        return 0
    category = event_category(event["source"])
    with connect() as db:
        subscriptions = db.execute(
            "SELECT id,arguments,category,owner FROM subscriptions WHERE expires_at>?", (utc_now(),)
        ).fetchall()
        count = 0
        for sid, raw_args, sub_category, sub_owner in subscriptions:
            filters = json.loads(raw_args)
            if sub_category is None or sub_category != category:
                continue
            if filters.get("source") not in (None, event["source"]):
                continue
            if filters.get("event_type") not in (None, event["name"]):
                continue
            count += db.execute("""INSERT OR IGNORE INTO deliveries
                (event_id,subscription_id,next_attempt,queued_at,owner) VALUES (?,?,?,?,?)""",
                (event["id"], sid, utc_now(), utc_now(), sub_owner)).rowcount
    return count


def _suppress_blocked():
    """Stop already-queued sends for disabled, digest-only or expired targets."""
    now = utc_now()
    with connect() as db:
        db.execute("""UPDATE deliveries SET status='suppressed' WHERE status='pending'
            AND event_id IN (SELECT e.id FROM events e
                JOIN hook_sources h ON h.slug=e.source JOIN hook_categories c ON c.slug=h.category
                WHERE h.enabled=0 OR c.enabled=0 OR h.mode='digest')""")
        db.execute("""UPDATE deliveries SET status='expired' WHERE status='pending'
            AND subscription_id NOT IN (SELECT id FROM subscriptions WHERE expires_at>?)""", (now,))
        stale = (datetime.now(UTC) - PENDING_MAX_AGE).isoformat()
        db.execute("""UPDATE deliveries SET status='failed' WHERE status='pending'
            AND COALESCE(queued_at,next_attempt)<?""", (stale,))


def dispatch(limit=25):
    """2xx is webhook receipt, never proof that ChatGPT actually executed."""
    _suppress_blocked()
    now = utc_now()
    with connect() as db:
        db.row_factory = sqlite3.Row
        rows = [dict(r) for r in db.execute("""
            SELECT d.event_id,d.subscription_id,d.attempts,s.url,s.secret,s.previous_secret,
                   s.previous_until,e.source,e.name,e.summary,e.occurred_at,e.triage_route
            FROM deliveries d JOIN subscriptions s ON s.id=d.subscription_id
            JOIN events e ON e.id=d.event_id
            WHERE d.status='pending' AND d.next_attempt<=? AND s.expires_at>?
            ORDER BY d.next_attempt LIMIT ?""", (now, now, limit))]
    for row in rows:
        payload = {"eventId": row["event_id"], "name": NAME,
                   "timestamp": row["occurred_at"], "cursor": None,
                   "data": {"event_id": row["event_id"], "source": row["source"],
                            "event_type": row["name"], "summary": row["summary"],
                            "route": row["triage_route"]}}
        status = None
        try:
            extra = ()
            if row["previous_secret"] and (row["previous_until"] or "") > now:
                extra = (unseal(row["previous_secret"]),)
            status, _ = signed_post(row["url"], unseal(row["secret"]), row["subscription_id"],
                                    payload, row["event_id"], extra)
        except CallbackError:
            pass
        success = status is not None and 200 <= status < 300
        attempts = row["attempts"] + 1
        terminal = success or attempts >= MAX_ATTEMPTS or status in (410, 413)
        due = (datetime.now(UTC) + timedelta(seconds=min(3600, 2 ** attempts * 10))).isoformat()
        with connect() as db:
            db.execute("""UPDATE deliveries SET status=?,attempts=?,next_attempt=?,last_http=?,
                last_attempt_at=?,delivered_at=? WHERE event_id=? AND subscription_id=?""",
                ("delivered" if success else ("failed" if terminal else "pending"),
                 attempts, due, status, utc_now(), utc_now() if success else None,
                 row["event_id"], row["subscription_id"]))
            if status == 410:
                # Receiver says the subscription is gone; stop all further deliveries to it.
                db.execute("UPDATE subscriptions SET expires_at=? WHERE id=?",
                           (utc_now(), row["subscription_id"]))
    return len(rows)
