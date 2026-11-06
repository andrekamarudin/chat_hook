"""Pilot controls: bounded wake budget, short-window dedup, synthetic canaries, reports.

A "requested wake" is a signed callback queued for a ChatGPT Work subscription.
It is never evidence that Work executed; only acknowledge/outcome tools are.
Held events (budget overflow or duplicates) are retained, listed in reports and
remain readable through the MCP list/get tools. Nothing is deleted.
"""

import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException

from chat_hook.app import connect, require_admin, utc_now

CANARY_PREFIX = "canary-"
INTERNAL_SOURCE = "chat_hook"

router = APIRouter(prefix="/v1/admin", dependencies=[Depends(require_admin)])


def _env_int(name, default, low, high):
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(low, min(high, value))


def limits():
    return {
        "per_hour": _env_int("CHAT_HOOK_WAKE_LIMIT_HOUR", 3, 0, 1000),
        "per_day": _env_int("CHAT_HOOK_WAKE_LIMIT_DAY", 20, 0, 10000),
        "dedup_seconds": _env_int("CHAT_HOOK_DEDUP_SECONDS", 300, 0, 86400),
    }


def signature(event):
    """Stable signature: source, type and whitespace/case-normalized summary."""
    summary = re.sub(r"\s+", " ", (event.get("summary") or "").strip().lower())
    raw = "\x1f".join((event["source"], event["name"], summary))
    return hashlib.sha256(raw.encode()).hexdigest()


def exempt(event):
    """Owner-initiated canaries and internal digests never consume the wake budget."""
    return bool(event.get("canary")) or event["source"] == INTERNAL_SOURCE


def admit(event, db=None):
    """Return None to allow a wake, or the hold reason. Records signature/holds durably.

    Pass ``db`` to make the decision part of the caller's transaction, so the
    budget check and the resulting queue write commit together.
    """
    if exempt(event):
        return None
    if db is None:
        with connect() as own:
            return _admit(event, own)
    return _admit(event, db)


def _admit(event, db):
    cfg = limits()
    sig = signature(event)
    now = datetime.now(UTC)
    db.execute("UPDATE events SET signature=? WHERE id=?", (sig, event["id"]))
    if cfg["dedup_seconds"]:
        received = event.get("received_at") or now.isoformat()
        since = (datetime.fromisoformat(received) - timedelta(seconds=cfg["dedup_seconds"])).isoformat()
        original = db.execute("""SELECT id FROM events WHERE signature=? AND id!=?
            AND received_at>=? AND received_at<=? AND duplicate_of IS NULL
            AND triage_route IN ('wake','review') ORDER BY received_at LIMIT 1""",
            (sig, event["id"], since, received)).fetchone()
        if original:
            db.execute("""UPDATE events SET held_reason='duplicate',held_at=?,duplicate_of=?
                WHERE id=?""", (utc_now(), original[0], event["id"]))
            return "duplicate"
    hour = (now - timedelta(hours=1)).isoformat()
    day = (now - timedelta(days=1)).isoformat()
    counted = """SELECT COUNT(*) FROM events WHERE queued_at>=? AND source!=?
        AND COALESCE(canary,0)=0"""
    used_hour = db.execute(counted, (hour, INTERNAL_SOURCE)).fetchone()[0]
    used_day = db.execute(counted, (day, INTERNAL_SOURCE)).fetchone()[0]
    if used_hour >= cfg["per_hour"] or used_day >= cfg["per_day"]:
        db.execute("UPDATE events SET held_reason='budget',held_at=? WHERE id=?",
                   (utc_now(), event["id"]))
        return "budget"
    return None


def producer_status(db):
    """Real producers per category. Canary and disabled sources do not count."""
    from chat_hook.control import CATEGORIES

    rows = db.execute("""SELECT c.slug,c.enabled,s.slug,s.enabled,s.kind FROM hook_categories c
        LEFT JOIN hook_sources s ON s.category=c.slug""").fetchall()
    status = {slug: {"category_enabled": None, "producers": []} for slug in CATEGORIES}
    for cat, cat_enabled, src, src_enabled, kind in rows:
        if cat not in status:
            continue
        status[cat]["category_enabled"] = bool(cat_enabled)
        if src and src_enabled and not src.startswith(CANARY_PREFIX) and src != "canary":
            status[cat]["producers"].append(src)
    for item in status.values():
        item["producers"].sort()
        item["status"] = "producer wired" if item["producers"] else "no producer wired"
    return status


@router.get("/producers")
def producers():
    with connect() as db:
        return {"categories": producer_status(db),
                "note": "Category enabled does not mean events are flowing."}


@router.post("/canaries/{category}", status_code=201)
def create_canary(category: str):
    """Owner-only synthetic event. Internal only: no outbound action besides the Work wake."""
    from chat_hook.control import CATEGORIES, audit

    if category not in CATEGORIES:
        raise HTTPException(404, "Unknown category")
    slug = CANARY_PREFIX + category
    event_id = "evt_" + uuid.uuid4().hex
    with connect() as db:
        db.execute("""INSERT OR IGNORE INTO hook_sources
            (slug,name,kind,category,enabled,mode,credential_type,changed_at)
            VALUES (?,?,'internal',?,1,'triage','derived',?)""",
            (slug, "Synthetic canary (" + category + ")", category, utc_now()))
        enabled = db.execute("SELECT enabled FROM hook_categories WHERE slug=?", (category,)).fetchone()[0]
        if not enabled:
            raise HTTPException(409, "Category is disabled")
        summary = (f"Synthetic Chat Hook canary for the {category} category. Not a real incident. "
                   "Call acknowledge_hook_event with this event_id, then record_hook_outcome "
                   "with actionable=false. Take no other action.")
        db.execute("""INSERT INTO events (id,source,external_id,name,occurred_at,received_at,
            summary,data_json,canary) VALUES (?,?,?,?,?,?,?,?,1)""",
            (event_id, slug, "canary:" + uuid.uuid4().hex, "canary.synthetic", utc_now(),
             utc_now(), summary, json.dumps({"canary": True, "category": category})))
        audit(db, "canary.created", slug, {"event_id": event_id})
    return {"event_id": event_id, "category": category, "source": slug}


def _stage_rows(db, where, params):
    db.row_factory = sqlite3.Row
    events = [dict(r) for r in db.execute(f"""SELECT e.id,e.source,e.received_at,e.queued_at,
        e.triage_route,e.held_reason,e.duplicate_of,d.probability,d.route AS luna_route,
        d.status AS luna_status,d.evaluated_at,o.acknowledged_at,o.labelled_at,o.actionable
        FROM events e LEFT JOIN decisions d ON d.event_id=e.id
        LEFT JOIN outcomes o ON o.event_id=e.id WHERE {where}
        ORDER BY e.received_at DESC LIMIT 200""", params)]
    for event in events:
        rows = db.execute("""SELECT status,last_http,delivered_at,last_attempt_at FROM deliveries
            WHERE event_id=?""", (event["id"],)).fetchall()
        event["callbacks"] = [dict(r) for r in rows]
    return events


@router.get("/canaries")
def canary_status(hours: int = 48):
    """Per-stage evidence. Each stage is recorded separately; missing means not reached."""
    if not 1 <= hours <= 720:
        raise HTTPException(422, "Invalid window")
    since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    with connect() as db:
        events = _stage_rows(db, "e.canary=1 AND e.received_at>=?", (since,))
    from chat_hook.delivery import event_category

    return {"canaries": [{
        "event_id": e["id"], "category": event_category(e["source"]),
        "ingested_at": e["received_at"],
        "luna": {"evaluated_at": e["evaluated_at"], "status": e["luna_status"],
                 "probability": e["probability"], "verdict": e["luna_route"]},
        "callback_requested_at": e["queued_at"],
        "callback_receipts": e["callbacks"],
        "work_acknowledged_at": e["acknowledged_at"],
        "outcome_recorded_at": e["labelled_at"],
        "outcome_actionable": None if e["actionable"] is None else bool(e["actionable"]),
    } for e in events],
        "note": "A callback 2xx is a receipt only. Work execution is proven by acknowledgment."}


def pilot_report(hours=24):
    since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
    with connect() as db:
        db.row_factory = sqlite3.Row
        events = [dict(r) for r in db.execute("""SELECT e.id,e.source,e.triage_route,e.queued_at,
            e.held_reason,COALESCE(e.canary,0) AS canary,o.woke_confirmed,o.actionable,
            (SELECT COUNT(*) FROM deliveries x WHERE x.event_id=e.id AND x.status='delivered') AS receipts
            FROM events e LEFT JOIN outcomes o ON o.event_id=e.id WHERE e.received_at>=?""", (since,))]
        subs = db.execute("SELECT category,expires_at FROM subscriptions WHERE expires_at>?",
                          (utc_now(),)).fetchall()
        producers_now = producer_status(db)
    from chat_hook.delivery import event_category

    def counts(items):
        wakeish = [e for e in items if e["triage_route"] in ("wake", "review")]
        requested = [e for e in items if e["queued_at"]]
        acked = [e for e in items if e["woke_confirmed"] == 1]
        ignored = [e for e in items if e["triage_route"] == "ignore"]
        return {
            "received": len(items),
            "filtered": sum(e["triage_route"] in ("ignore", "digest") for e in items),
            "held_budget": sum(e["held_reason"] == "budget" for e in items),
            "held_duplicate": sum(e["held_reason"] == "duplicate" for e in items),
            "wake_requested": len(requested),
            "callback_delivered": sum(e["receipts"] > 0 for e in items),
            "work_acknowledged": len(acked),
            "routed_without_subscription": sum(not e["queued_at"] and not e["held_reason"]
                                               for e in wakeish),
            "false_positive": sum(e["actionable"] == 0 for e in acked),
            "fp_unlabelled": sum(e["actionable"] is None for e in acked),
            "false_negative": sum(e["actionable"] == 1 for e in ignored),
            "fn_unlabelled": sum(e["actionable"] is None for e in ignored),
        }

    real = [e for e in events if not e["canary"]]
    per_category = {}
    for event in real:
        per_category.setdefault(event_category(event["source"]) or "unknown", []).append(event)
    return {
        "window_hours": hours, "since": since, "limits": limits(),
        "totals": counts(real),
        "by_category": {k: counts(v) for k, v in sorted(per_category.items())},
        "canaries": counts([e for e in events if e["canary"]]),
        "active_subscriptions": sorted({row[0] for row in subs if row[0]}),
        "producers": producers_now,
        "note": ("Requested wakes are not confirmed Work runs. Unlabelled FP/FN are unknown, "
                 "not zero. ntfy P0 alerts are independent of Chat Hook and unchanged."),
    }


@router.get("/pilot-report")
def get_pilot_report(hours: int = 24):
    if not 1 <= hours <= 720:
        raise HTTPException(422, "Invalid window")
    return pilot_report(hours)
