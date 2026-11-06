"""Authenticated multi-source event inbox with an OAuth-protected MCP Events surface."""

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

MAX_BODY_BYTES = 64 * 1024
MAX_SKEW_SECONDS = 300


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def database_path() -> Path:
    return Path(os.environ.get("CHAT_HOOK_DB", "/data/chat_hook.sqlite3"))


@contextmanager
def connect():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=15)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=15000")
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                external_id TEXT NOT NULL,
                name TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                data_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'acknowledged')),
                UNIQUE(source, external_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status, received_at)")
        # Compatibility with the original ingestion-only database.
        existing = {r[1] for r in db.execute("PRAGMA table_info(events)")}
        if "triage_route" not in existing:
            db.execute("ALTER TABLE events ADD COLUMN triage_route TEXT")
        db.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                event_id TEXT PRIMARY KEY REFERENCES events(id),
                model TEXT,
                probability REAL,
                route TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ok','error','skipped')),
                latency_ms INTEGER,
                input_tokens INTEGER,
                evaluated_at TEXT NOT NULL
            )
        """)
        cols = {row[1] for row in db.execute("PRAGMA table_info(decisions)")}
        if "policy_version" not in cols:
            db.execute("ALTER TABLE decisions ADD COLUMN policy_version INTEGER")
        db.execute("""
            CREATE TABLE IF NOT EXISTS outcomes (
                event_id TEXT PRIMARY KEY REFERENCES events(id),
                woke_confirmed INTEGER CHECK(woke_confirmed IN (0,1)),
                actionable INTEGER CHECK(actionable IN (0,1)),
                reviewer TEXT NOT NULL,
                reviewed_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_samples (
                event_id TEXT PRIMARY KEY REFERENCES events(id),
                sampled_at TEXT NOT NULL
            )
        """)
        from chat_hook.control import setup_schema
        from chat_hook.oauth import initialize as setup_oauth

        setup_schema(db)
        setup_oauth(db)
    from chat_hook.delivery import initialize as setup_delivery

    setup_delivery()


def sources() -> dict[str, str]:
    try:
        value = json.loads(os.environ.get("CHAT_HOOK_SOURCES_JSON", "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid CHAT_HOOK_SOURCES_JSON") from exc
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and len(v) >= 32
        for k, v in value.items()
    ):
        raise RuntimeError("Source keys must be mapped to secrets of at least 32 characters")
    return value


def verify_ingress(source: str, raw: bytes, headers):
    from chat_hook.control import ingress_key

    secret = ingress_key(source)
    if not secret:
        raise HTTPException(404, "Unknown source")
    # WAHA uses HMAC-SHA512(raw body), with a millisecond timestamp header.
    # This differs from our generic signed ingress protocol.
    from chat_hook.control import get_source

    config = get_source(source)
    if source == "waha" or (config and config["kind"] == "waha"):
        timestamp = headers.get("x-webhook-timestamp")
        signature = headers.get("x-webhook-hmac")
        if headers.get("x-webhook-hmac-algorithm") != "sha512":
            raise HTTPException(401, "Unsupported WAHA HMAC algorithm")
        digest = hmac.new(secret.encode(), raw, hashlib.sha512).hexdigest()
        divisor = 1000
        expected = digest
    else:
        timestamp = headers.get("x-chat-hook-timestamp")
        signature = headers.get("x-chat-hook-signature")
        digest = None
        divisor = 1
    if not timestamp or not signature:
        raise HTTPException(401, "Missing webhook signature")
    try:
        epoch = int(timestamp) / divisor
    except ValueError as exc:
        raise HTTPException(401, "Invalid timestamp") from exc
    if abs(time.time() - epoch) > MAX_SKEW_SECONDS:
        raise HTTPException(401, "Expired webhook timestamp")
    if digest is None:
        digest = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        expected = "sha256=" + digest
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Invalid webhook signature")


def iso_timestamp(value) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC).isoformat()
    if isinstance(value, str):
        try:
            result = datetime.fromisoformat(value)
            if result.tzinfo is not None:
                return result.isoformat()
        except ValueError:
            pass
    return utc_now()


def normalize(source: str, body: dict) -> dict | None:
    """Translate a source payload to a bounded event record. Never treat content as instructions."""
    from chat_hook.control import get_source

    config = get_source(source)
    if source == "waha" or (config and config["kind"] == "waha"):
        name = body.get("event")
        if name not in ("message", "session.status"):
            return None
        payload = body.get("payload") or {}
        if not isinstance(payload, dict):
            raise HTTPException(422, "Invalid WAHA payload")
        if name == "message":
            if payload.get("fromMe") is True:
                return None
            message_id = payload.get("id")
            if isinstance(message_id, dict):
                message_id = message_id.get("_serialized") or message_id.get("id")
            chat_id = payload.get("from") or payload.get("chatId")
            if not message_id or not chat_id:
                raise HTTPException(422, "Missing WAHA message ID or chat ID")
            event_name = "message.received"
            external_id = f"{body.get('session', 'default')}:{message_id}"
            data = {
                "session": body.get("session", "default"),
                "chat_id": chat_id,
                "message_id": str(message_id),
            }
            summary = "Incoming WhatsApp message (read via authorized WhatsApp tool)"
        else:
            event_name = "connection.status_changed"
            data = {"session": body.get("session", "default"), "status": payload.get("status")}
            # A source must supply a stable ID to guarantee redelivery deduplication.
            external_id = body.get("id") or f"{data['session']}:{data['status']}:{body.get('timestamp')}"
            summary = "WhatsApp session status changed"
        return {
            "name": event_name,
            "external_id": str(external_id),
            "occurred_at": iso_timestamp(body.get("timestamp") or payload.get("timestamp")),
            "summary": summary,
            "data": data,
        }

    # Generic sources provide their own stable ID. Do not default to a hash of the body:
    # two legitimately distinct notifications can have identical contents.
    external_id = body.get("id")
    if not isinstance(external_id, str) or not external_id:
        raise HTTPException(422, "Generic events require a stable string id")
    name = body.get("type")
    if not isinstance(name, str) or not name or len(name) > 120:
        raise HTTPException(422, "Generic events require a type")
    summary = body.get("summary", name)
    if not isinstance(summary, str):
        raise HTTPException(422, "summary must be a string")
    return {
        "name": name,
        "external_id": external_id,
        "occurred_at": iso_timestamp(body.get("timestamp")),
        "summary": summary[:500],
        "data": body.get("data") if isinstance(body.get("data"), dict) else {},
    }


def require_admin(authorization: Annotated[str | None, Header()] = None):
    secret = os.environ.get("CHAT_HOOK_ADMIN_TOKEN", "")
    if len(secret) < 32:
        raise HTTPException(503, "Admin endpoint is not configured")
    if not authorization or not hmac.compare_digest(authorization, "Bearer " + secret):
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize()
    yield


app = FastAPI(
    title="Chat Hook", version="0.1.0", docs_url=None, redoc_url=None,
    lifespan=lifespan,
)


@app.get("/healthz")
def health():
    from chat_hook.oauth import configured

    with connect() as db:
        db.execute("SELECT 1").fetchone()
    # "enabled" means the authenticated MCP surface can accept subscriptions; it does not
    # mean any ChatGPT Work subscription exists or that a wake has been confirmed.
    ready = configured() and len(os.getenv("CHAT_HOOK_DATA_KEY", "")) >= 32
    return {"status": "ok", "delivery": "enabled" if ready else "disabled"}


@app.post("/v1/ingest/{source}", status_code=202)
async def ingest(source: str, request: Request):
    # Reject before JSON decoding or persistence. Body size includes all nested fields.
    if request.headers.get("content-length"):
        try:
            if int(request.headers["content-length"]) > MAX_BODY_BYTES:
                raise HTTPException(413, "Payload too large")
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length") from exc
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(413, "Payload too large")
    verify_ingress(source, raw, request.headers)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Invalid JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(422, "Expected JSON object")
    from chat_hook.control import mapped_payload

    record = normalize(source, mapped_payload(source, body))
    if record is None:
        return JSONResponse(status_code=202, content={"status": "ignored"})
    event_id = "evt_" + uuid.uuid4().hex
    with connect() as db:
        inserted = db.execute(
            """INSERT OR IGNORE INTO events
            (id, source, external_id, name, occurred_at, received_at, summary, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id, source, record["external_id"], record["name"],
                record["occurred_at"], utc_now(), record["summary"],
                json.dumps(record["data"], separators=(",", ":")),
            ),
        ).rowcount
        if not inserted:
            event_id = db.execute(
                "SELECT id FROM events WHERE source=? AND external_id=?",
                (source, record["external_id"]),
            ).fetchone()[0]
    return {"id": event_id, "status": "queued" if inserted else "duplicate"}


@app.get("/v1/events", dependencies=[Depends(require_admin)])
def list_events(status: str = "pending", limit: int = 50):
    if status not in ("pending", "acknowledged") or not 1 <= limit <= 100:
        raise HTTPException(422, "Invalid filter")
    with connect() as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """SELECT id, source, name, occurred_at, received_at, summary, status
            FROM events WHERE status=? ORDER BY received_at ASC LIMIT ?""",
            (status, limit),
        ).fetchall()
    return {"events": [dict(r) for r in rows]}


@app.get("/v1/events/{event_id}", dependencies=[Depends(require_admin)])
def get_event(event_id: str):
    with connect() as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Event not found")
    result = dict(row)
    result["data"] = json.loads(result.pop("data_json"))
    return result


@app.post("/v1/events/{event_id}/ack", dependencies=[Depends(require_admin)])
def ack_event(event_id: str):
    with connect() as db:
        updated = db.execute(
            "UPDATE events SET status='acknowledged' WHERE id=?", (event_id,)
        ).rowcount
    if not updated:
        raise HTTPException(404, "Event not found")
    return {"id": event_id, "status": "acknowledged"}


@app.post("/v1/triage/{event_id}", dependencies=[Depends(require_admin)])
def triage_event(event_id: str):
    """Manual, idempotent triage. Does NOT wake ChatGPT or send any messages."""
    from chat_hook.control import get_source, policy_for_source
    from chat_hook.decisions import DecisionError, choose_route, classify

    with connect() as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Event not found")
        event = dict(row)
        if event["triage_route"] is not None:
            return {"id": event_id, "route": event["triage_route"], "status": "already_triaged"}

    config = get_source(event["source"])
    if config and (not config["enabled"] or not config["category_enabled"]):
        result = {"route": "digest", "status": "skipped", "model": None,
                  "probability": None, "latency_ms": None, "input_tokens": None}
    elif config and config["mode"] in ("wake", "digest"):
        result = {"route": config["mode"], "status": "skipped", "model": None,
                  "probability": None, "latency_ms": None, "input_tokens": None}
    elif config and config["kind"] == "waha" and event["name"] == "message.received":
        # Without message content, a probabilistic decision has no meaningful evidence.
        # ChatGPT needs its authorized WhatsApp read tools to inspect the message.
        result = {"route": "review", "status": "skipped", "model": None, "probability": None,
                  "latency_ms": None, "input_tokens": None}
    else:
        try:
            prediction = classify(event)
            result = dict(route=choose_route(prediction["probability"], event["source"]), status="ok", **prediction)
        except DecisionError:
            # Fail open to review rather than silently dropping potentially important events.
            result = {"route": "review", "status": "error", "model": "gpt-6-luna",
                      "probability": None, "latency_ms": None, "input_tokens": None}
    # Resolve policy before taking the write lock for the decision record.
    policy = policy_for_source(event["source"])
    with connect() as db:
        # First successful stored triage wins. Concurrent calls cannot silently overwrite it.
        changed = db.execute("UPDATE events SET triage_route=? WHERE id=? AND triage_route IS NULL",
                             (result["route"], event_id)).rowcount
        if changed:
            db.execute("""INSERT INTO decisions
                (event_id,model,probability,route,status,latency_ms,input_tokens,evaluated_at,policy_version)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (event_id, result["model"], result["probability"], result["route"],
                 result["status"], result["latency_ms"], result["input_tokens"],
                 utc_now(), policy["policy_version"] if policy else None))
        else:
            result["route"] = db.execute("SELECT triage_route FROM events WHERE id=?", (event_id,)).fetchone()[0]
            result["status"] = "already_triaged"
    return {"id": event_id, "route": result["route"], "status": result["status"]}


@app.get("/v1/stats/daily", dependencies=[Depends(require_admin)])
def get_daily_stats(day: date | None = None):
    from datetime import timedelta

    from chat_hook.metrics import daily_report

    target = day or (datetime.now(ZoneInfo("Asia/Singapore")).date() - timedelta(days=1))
    return daily_report(target)


@app.post("/v1/audit-samples", dependencies=[Depends(require_admin)])
def create_audit_sample(day: date, size: int = 20):
    """Persist a uniform random sample of Luna-suppressed events for later ChatGPT review.

    No content is sent externally or assessed automatically. Results need a
    ChatGPT-labelled review before a false-negative rate can be calculated.
    """
    import secrets

    from chat_hook.metrics import utc_bounds

    if not 1 <= size <= 500:
        raise HTTPException(422, "Invalid audit sample size")
    start, end = utc_bounds(day)
    with connect() as db:
        ids = [r[0] for r in db.execute("""
            SELECT id FROM events WHERE triage_route='ignore'
            AND received_at>=? AND received_at<?
            ORDER BY id""", (start, end))]
        current = [r[0] for r in db.execute("""
            SELECT a.event_id FROM audit_samples a JOIN events e ON e.id=a.event_id
            WHERE e.received_at>=? AND e.received_at<? ORDER BY a.sampled_at, a.event_id""", (start, end))]
        remaining = [eid for eid in ids if eid not in set(current)]
        desired = max(0, min(size, len(ids)) - len(current))
        selected = secrets.SystemRandom().sample(remaining, desired)
        for event_id in selected:
            db.execute("INSERT OR IGNORE INTO audit_samples(event_id,sampled_at) VALUES (?,?)",
                       (event_id, utc_now()))
    return {"date_sgt": day.isoformat(), "population_ignored": len(ids),
            "sample_ids": current + selected, "reviewed": False,
            "note": "Random sample only. A ChatGPT review pipeline is not deployed."}


from chat_hook.control import router as admin_router
from chat_hook.mcp_server import router as mcp_router
from chat_hook.oauth import router as oauth_router

app.include_router(admin_router)
app.include_router(oauth_router)
app.include_router(mcp_router)


@app.get("/admin", include_in_schema=False)
def admin_page():
    """Public login shell. Admin data is fetched separately with bearer auth."""
    from fastapi.responses import HTMLResponse

    page = Path(__file__).with_name("admin.html").read_text(encoding="utf-8")
    return HTMLResponse(page, headers={
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                   "script-src 'unsafe-inline'; connect-src 'self'; "
                                   "form-action 'none'; frame-ancestors 'none'",
    })
