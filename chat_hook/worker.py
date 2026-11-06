"""Single-process bounded worker for event triage, scheduled signals and reporting.

No WhatsApp replies or model-generated messages are sent by this worker.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from chat_hook.app import connect, utc_now
from chat_hook.delivery import dispatch, initialize as init_delivery, queue_event
from chat_hook.metrics import daily_report, render_text

SGT = ZoneInfo("Asia/Singapore")


def add_internal_event(external_id, kind, summary, payload):
    """Durable, idempotent event. No untrusted instruction text."""
    from chat_hook.app import initialize as init_app

    init_app()
    with connect() as db:
        event_id = "evt_" + uuid.uuid4().hex
        inserted = db.execute("""INSERT OR IGNORE INTO events
            (id,source,external_id,name,occurred_at,received_at,summary,data_json,triage_route)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (event_id, "chat_hook", external_id, kind, utc_now(), utc_now(),
             summary[:500], json.dumps(payload, separators=(",", ":")), "review")).rowcount
    return inserted


def review_due_events(limit=30):
    """Run Luna or choose review for each new event; failures must not drop work."""
    from chat_hook.app import triage_event

    with connect() as db:
        ids = [r[0] for r in db.execute(
            "SELECT id FROM events WHERE triage_route IS NULL ORDER BY received_at LIMIT ?", (limit,)
        )]
    for event_id in ids:
        triage_event(event_id)
    return len(ids)


def deliver_due_events(limit=50):
    with connect() as db:
        db.row_factory = __import__("sqlite3").Row
        events = [dict(r) for r in db.execute("""
            SELECT id,source,name,triage_route FROM events
            WHERE triage_route IN ('review','wake') ORDER BY received_at LIMIT ?""", (limit,))]
    for event in events:
        queue_event(event)
    return dispatch(limit)


def prepare_daily_report(now=None):
    """Create one report event for the previous SGT day after 07:05 SGT."""
    now = now or datetime.now(SGT)
    if now.hour < 7 or (now.hour == 7 and now.minute < 5):
        return False
    yesterday = now.date() - timedelta(days=1)
    report = daily_report(yesterday)
    return bool(add_internal_event(
        "daily:" + yesterday.isoformat(), "report.daily",
        render_text(report), {"date": yesterday.isoformat(), "report": report},
    ))


def prepare_audit(now=None, sample_size=20):
    """Select an unbiased sample of ignored events; actual judgment stays with ChatGPT."""
    import secrets

    from chat_hook.metrics import utc_bounds

    now = now or datetime.now(SGT)
    day = now.date() - timedelta(days=1)
    start, end = utc_bounds(day)
    with connect() as db:
        ignored = [row[0] for row in db.execute("""
            SELECT id FROM events WHERE triage_route='ignore'
            AND received_at>=? AND received_at<? ORDER BY id""", (start, end))]
        sampled = {row[0] for row in db.execute("""
            SELECT a.event_id FROM audit_samples a JOIN events e ON a.event_id=e.id
            WHERE e.received_at>=? AND e.received_at<?""", (start, end))}
        target = min(sample_size, len(ignored))
        if len(sampled) < target:
            candidates = [eid for eid in ignored if eid not in sampled]
            for eid in secrets.SystemRandom().sample(candidates, target - len(sampled)):
                db.execute("INSERT OR IGNORE INTO audit_samples VALUES (?,?)", (eid, utc_now()))
                sampled.add(eid)
    return bool(add_internal_event(
        "audit:" + day.isoformat(), "audit.review",
        f"Review {len(sampled)} sampled suppressed events from {day.isoformat()}.",
        {"date": day.isoformat(), "sampled_event_ids": sorted(sampled), "population_size": len(ignored)},
    ))


def run_once():
    """Bounded work. Can be invoked manually or from the main worker loop."""
    from chat_hook.app import initialize as init_app

    init_app()
    init_delivery()
    result = {"triaged": review_due_events(), "delivered": 0}
    result["daily_created"] = prepare_daily_report()
    # Audit review events are labelled separately and never count as natural wake successes.
    result["audit_created"] = prepare_audit()
    result["delivered"] = deliver_due_events()
    return result


def main():
    seconds = max(5, min(300, int(os.getenv("CHAT_HOOK_WORKER_INTERVAL", "15"))))
    while True:
        try:
            run_once()
        except Exception:
            # Docker logging captures exception without leaking request bodies.
            logging.getLogger(__name__).exception("Chat Hook worker cycle failed")
        time.sleep(seconds)


if __name__ == "__main__":
    main()
