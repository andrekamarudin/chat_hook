"""Daily Luna Decisions telemetry with explicit review denominators."""

from collections import Counter
from datetime import UTC, date, datetime, time, timedelta
from math import sqrt
from zoneinfo import ZoneInfo

from chat_hook.app import connect

SGT = ZoneInfo("Asia/Singapore")


def utc_bounds(day: date) -> tuple[str, str]:
    start = datetime.combine(day, time.min, SGT)
    return start.astimezone(UTC).isoformat(), (start + timedelta(days=1)).astimezone(UTC).isoformat()


def percentage(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 1) if denominator else None


def wilson_95(success: int, total: int) -> list[float] | None:
    if total <= 0:
        return None
    z = 1.96
    p = success / total
    denom = 1 + z * z / total
    mid = (p + z * z / (2 * total)) / denom
    margin = (z * sqrt((p * (1 - p) / total) + z * z / (4 * total * total))) / denom
    return [round(100 * (mid - margin), 1), round(100 * (mid + margin), 1)]


def daily_report(day: date) -> dict:
    start, end = utc_bounds(day)
    with connect() as db:
        db.row_factory = __import__("sqlite3").Row
        events = [dict(r) for r in db.execute(
            "SELECT id,source,triage_route FROM events WHERE received_at>=? AND received_at<?",
            (start, end),
        )]
        ids = [e["id"] for e in events]
        if ids:
            marks = ",".join("?" for _ in ids)
            decisions = [dict(r) for r in db.execute(
                f"SELECT event_id,route,status FROM decisions WHERE event_id IN ({marks})", ids,
            )]
            outcomes = [dict(r) for r in db.execute(
                f"SELECT event_id,woke_confirmed,actionable,reviewer FROM outcomes WHERE event_id IN ({marks})", ids,
            )]
            receipts = db.execute(
                f"SELECT COUNT(DISTINCT event_id) FROM deliveries WHERE status='delivered' AND event_id IN ({marks})",
                ids,
            ).fetchone()[0]
        else:
            decisions, outcomes, receipts = [], [], 0
    routes = Counter(e["triage_route"] or "untriaged" for e in events)
    decisions_success = [r for r in decisions if r["status"] == "ok"]
    assessed = [r for r in outcomes if r["reviewer"] == "chatgpt" and r["actionable"] is not None]
    confirmed = [r for r in outcomes if r["woke_confirmed"] == 1]
    assessed_wakes = [r for r in assessed if r["woke_confirmed"] == 1]
    false_positives = sum(r["actionable"] == 0 for r in assessed_wakes)
    id_routes = {e["id"]: e["triage_route"] for e in events}
    assessed_ignores = [r for r in assessed if id_routes.get(r["event_id"]) == "ignore"]
    false_negatives = sum(r["actionable"] == 1 for r in assessed_ignores)
    return {
        "date_sgt": day.isoformat(),
        "received": len(events),
        "sources": dict(Counter(e["source"] for e in events)),
        "routes": dict(routes),
        "luna_decisions": {
            "requested": sum(r["status"] in ("ok", "error") for r in decisions),
            "successful": len(decisions_success),
            "errors": sum(r["status"] == "error" for r in decisions),
            "skipped": sum(r["status"] == "skipped" for r in decisions),
            "routes": dict(Counter(r["route"] for r in decisions_success)),
        },
        "chatgpt": {
            "wake_requested": routes["wake"] + routes["review"],
            "callback_receipts": receipts,
            "wake_confirmed": len(confirmed),
            "reviewed_confirmed_wakes": len(assessed_wakes),
            "false_positives": false_positives,
            "false_positive_pct": percentage(false_positives, len(assessed_wakes)),
        },
        "false_negative_audit": {
            "reviewed_suppressed": len(assessed_ignores),
            "missed_actionable": false_negatives,
            "sample_false_negative_pct": percentage(false_negatives, len(assessed_ignores)),
            "sample_95pct_wilson_interval": wilson_95(false_negatives, len(assessed_ignores)),
            "note": "Only a sample rate; population estimate requires unbiased sampling and completed ChatGPT reviews.",
        },
        "note": "No confirmation or review means unknown, not zero. Requested wakes are not confirmed wakes.",
    }


def render_text(report: dict) -> str:
    c = report["chatgpt"]
    a = report["false_negative_audit"]
    fmt = lambda x: "N/A (not reviewed)" if x is None else f"{x:.1f}%"
    return (
        f"Chat Hook | {report['date_sgt']} SGT\n"
        f"Events: {report['received']} | routes {report['routes']}\n"
        f"Luna Decisions: {report['luna_decisions']}\n"
        f"ChatGPT wakes: {c['wake_confirmed']} confirmed / {c.get('callback_receipts', 0)} callback receipts"
        f" / {c['wake_requested']} requested\n"
        f"ChatGPT-rated false positives: {c['false_positives']}/{c['reviewed_confirmed_wakes']} "
        f"({fmt(c['false_positive_pct'])})\n"
        f"False-negative audit: {a['missed_actionable']}/{a['reviewed_suppressed']} "
        f"({fmt(a['sample_false_negative_pct'])}); unbiased population estimate unavailable until sampling.\n"
        "Unknown outcomes remain unknown, not zero."
    )
