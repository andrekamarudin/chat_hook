"""Signed MCP webhook delivery with SSRF-safe DNS pinning and durable state."""

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from chat_hook.app import connect, utc_now

NAME = "hook.event"
MAX_BYTES = 262144


class CallbackError(Exception):
    """Callback verification, security or delivery failure."""


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


def public_destination(url):
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise CallbackError("Invalid URL") from exc
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.fragment or port not in (None, 443) or len(url) > 2048):
        raise CallbackError("Only public HTTPS callbacks on port 443 are supported")
    host = parts.hostname.lower().rstrip(".")
    suffixes = [x.strip().lower() for x in os.getenv(
        "CHAT_HOOK_CALLBACK_HOST_SUFFIXES", "chatgpt.com,openai.com"
    ).split(",") if x.strip()]
    if not any(host == suffix or host.endswith("." + suffix) for suffix in suffixes):
        raise CallbackError("Callback host not on allowlist")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ips = [entry[4][0] for entry in addresses]
    except OSError as exc:
        raise CallbackError("Callback DNS failed") from exc
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise CallbackError("Callback DNS contains a non-public IP")
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
        connection.request("POST", path, body=data, headers={
            "Host": parts.hostname, "Content-Type": "application/json",
            "Accept": "application/json", **headers,
        })
        reply = connection.getresponse()
        return reply.status, reply.read(8192)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise CallbackError("Callback transport failure") from exc
    finally:
        connection.close()


def signature_headers(payload, event_id, subscription_id, secret):
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise CallbackError("Invalid signing secret prefix")
    try:
        key = base64.b64decode(secret[6:], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CallbackError("Invalid signing secret encoding") from exc
    if not 24 <= len(key) <= 64:
        raise CallbackError("Invalid signing secret length")
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX_BYTES:
        raise CallbackError("Delivery too large")
    stamp = str(int(time.time()))
    signed = event_id.encode() + b"." + stamp.encode() + b"." + raw
    digest = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return raw, {"webhook-id": event_id, "webhook-timestamp": stamp,
                 "webhook-signature": "v1," + digest, "X-MCP-Subscription-Id": subscription_id}


def signed_post(url, secret, sid, payload, eid):
    raw, headers = signature_headers(payload, eid, sid, secret)
    return post_pinned(url, raw, headers)


def identity(owner, url, name, arguments):
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    raw = json.dumps([owner, url, name, canonical]).encode()
    return "sub_" + hashlib.sha256(raw).hexdigest()[:40]


def subscribe(owner, name, arguments, delivery, ttl_ms=None):
    if name != NAME or not isinstance(arguments, dict) or set(arguments) - {"source", "event_type", "category"}:
        raise CallbackError("Unsupported event or filter")
    if any(not isinstance(v, str) or not 0 < len(v) <= 100 for v in arguments.values()):
        raise CallbackError("Invalid event filter")
    if not isinstance(delivery, dict) or delivery.get("mode") != "webhook":
        raise CallbackError("Only webhook delivery is supported")
    url, secret = delivery.get("url"), delivery.get("secret")
    if not isinstance(url, str):
        raise CallbackError("Missing callback URL")
    sid = identity(owner, url, name, arguments)
    challenge = secrets.token_urlsafe(32)
    status, body = signed_post(
        url, secret, sid, {"type": "verification", "challenge": challenge},
        "msg_verification_" + secrets.token_hex(16),
    )
    try:
        echoed = json.loads(body).get("challenge", "")
    except (ValueError, TypeError, AttributeError) as exc:
        raise CallbackError("Invalid callback verification body") from exc
    if not 200 <= status < 300 or not isinstance(echoed, str) or not hmac.compare_digest(challenge, echoed):
        raise CallbackError("Callback verification challenge failed")
    seconds = min(max(int(ttl_ms / 1000) if isinstance(ttl_ms, int) else 86400, 300), 86400)
    expiry = (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()
    args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    with connect() as db:
        db.execute("""INSERT INTO subscriptions
            (id,owner,name,arguments,url,secret,expires_at,created_at)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
            secret=excluded.secret,expires_at=excluded.expires_at""",
            (sid, owner, name, args, url, secret, expiry, utc_now()))
    return {"id": sid, "refreshBefore": expiry, "cursor": None, "truncated": False}


def unsubscribe(owner, name, arguments, delivery):
    if not isinstance(delivery, dict) or not isinstance(delivery.get("url"), str):
        raise CallbackError("Invalid unsubscribe arguments")
    sid = identity(owner, delivery["url"], name, arguments)
    with connect() as db:
        db.execute("DELETE FROM subscriptions WHERE id=? AND owner=?", (sid, owner))
        db.execute("DELETE FROM deliveries WHERE subscription_id=?", (sid,))
    return {}


def queue_event(event):
    if event.get("triage_route") not in ("wake", "review"):
        return 0
    # Enforce runtime switches even for events triaged before a switch changed.
    from chat_hook.control import get_source

    cfg = get_source(event["source"])
    if cfg and (not cfg["enabled"] or not cfg["category_enabled"] or cfg["mode"] == "digest"):
        return 0
    with connect() as db:
        subscriptions = db.execute("SELECT id,arguments FROM subscriptions WHERE expires_at>?",
                                   (utc_now(),)).fetchall()
        count = 0
        for sid, raw_args in subscriptions:
            filters = json.loads(raw_args)
            if filters.get("source") not in (None, event["source"]):
                continue
            if filters.get("event_type") not in (None, event["name"]):
                continue
            if filters.get("category") not in (None, cfg["category"] if cfg else None):
                continue
            count += db.execute("""INSERT OR IGNORE INTO deliveries
                (event_id,subscription_id,next_attempt) VALUES (?,?,?)""",
                (event["id"], sid, utc_now())).rowcount
    return count


def dispatch(limit=25):
    """2xx is webhook receipt, never proof that ChatGPT actually executed."""
    with connect() as db:
        db.row_factory = __import__("sqlite3").Row
        rows = [dict(r) for r in db.execute("""
            SELECT d.event_id,d.subscription_id,d.attempts,s.url,s.secret,e.source,
                   e.name,e.summary,e.occurred_at,e.triage_route
            FROM deliveries d JOIN subscriptions s ON s.id=d.subscription_id
            JOIN events e ON e.id=d.event_id
            LEFT JOIN hook_sources h ON h.slug=e.source
            LEFT JOIN hook_categories c ON c.slug=h.category
            WHERE d.status='pending' AND d.next_attempt<=? AND s.expires_at>?
            AND COALESCE(h.enabled,1)=1 AND COALESCE(c.enabled,1)=1
            AND COALESCE(h.mode,'triage')!='digest'
            ORDER BY d.next_attempt LIMIT ?""", (utc_now(), utc_now(), limit))]
    for row in rows:
        payload = {"eventId": row["event_id"], "name": NAME,
                   "timestamp": row["occurred_at"], "cursor": None,
                   "data": {"event_id": row["event_id"], "source": row["source"],
                            "event_type": row["name"], "summary": row["summary"],
                            "route": row["triage_route"]}}
        status = None
        try:
            status, _ = signed_post(row["url"], row["secret"], row["subscription_id"],
                                    payload, row["event_id"])
        except CallbackError:
            pass
        success = status is not None and 200 <= status < 300
        attempts = row["attempts"] + 1
        terminal = success or attempts >= 6 or status in (410, 413)
        due = (datetime.now(UTC) + timedelta(seconds=min(3600, 2 ** attempts * 10))).isoformat()
        with connect() as db:
            db.execute("""UPDATE deliveries SET status=?,attempts=?,next_attempt=?,last_http=?
                WHERE event_id=? AND subscription_id=?""",
                ("delivered" if success else ("failed" if terminal else "pending"),
                 attempts, due, status, row["event_id"], row["subscription_id"]))
    return len(rows)
