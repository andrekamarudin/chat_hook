"""Pilot controls: wake budget, dedup, canaries, producer status and reports."""

import base64
import json

from conftest import add_event, add_source
from fastapi.testclient import TestClient

from chat_hook import delivery
from chat_hook.app import app, connect
from chat_hook.worker import deliver_due_events

ADMIN = "admin-token-0123456789abcdef0123456789abcdef"


def _subscribe(category):
    delivery.subscribe("owner", delivery.NAME, {"category": category},
                       {"mode": "webhook", "url": "https://chatgpt.com/hooks/" + category,
                        "secret": "whsec_" + base64.b64encode(b"W" * 32).decode()},
                       categories=frozenset({category}))


def _fake_sender(monkeypatch):
    sent = []

    def fake_post(url, sec, sid, payload, eid, extra=()):
        if payload.get("type") == "verification":
            return 200, json.dumps({"challenge": payload["challenge"]}).encode()
        sent.append(payload["eventId"])
        return 204, b""

    monkeypatch.setattr(delivery, "signed_post", fake_post)
    return sent


def _add_distinct(event_id, source, summary):
    add_event(event_id, source)
    with connect() as db:
        db.execute("UPDATE events SET summary=? WHERE id=?", (summary, event_id))


def test_hourly_budget_holds_overflow_without_dropping(monkeypatch):
    sent = _fake_sender(monkeypatch)
    with TestClient(app):
        add_source("ops", "infra")
        for i in range(5):
            _add_distinct(f"evt_{i}", "ops", f"distinct incident {i}")
        _subscribe("infra")
        deliver_due_events()
        assert len(sent) == 3
        with connect() as db:
            held = db.execute("SELECT COUNT(*) FROM events WHERE held_reason='budget'").fetchone()[0]
            total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert held == 2 and total == 5


def test_daily_budget_applies_across_categories(monkeypatch):
    monkeypatch.setenv("CHAT_HOOK_WAKE_LIMIT_HOUR", "100")
    monkeypatch.setenv("CHAT_HOOK_WAKE_LIMIT_DAY", "4")
    sent = _fake_sender(monkeypatch)
    with TestClient(app):
        add_source("ops", "infra")
        add_source("proj", "projects")
        for i in range(3):
            _add_distinct(f"evt_i{i}", "ops", f"infra {i}")
            _add_distinct(f"evt_p{i}", "proj", f"project {i}")
        _subscribe("infra")
        _subscribe("projects")
        deliver_due_events()
        assert len(sent) == 4


def test_duplicate_signature_within_window_is_retained_not_sent(monkeypatch):
    sent = _fake_sender(monkeypatch)
    with TestClient(app):
        add_source("ops", "infra")
        add_event("evt_a", "ops")
        add_event("evt_b", "ops")  # same source, type and summary
        _subscribe("infra")
        deliver_due_events()
        assert sent == ["evt_a"]
        with connect() as db:
            row = db.execute("SELECT held_reason,duplicate_of FROM events WHERE id='evt_b'").fetchone()
        assert row == ("duplicate", "evt_a")


def test_no_subscription_does_not_consume_budget_or_hold(monkeypatch):
    _fake_sender(monkeypatch)
    with TestClient(app):
        add_source("ops", "infra")
        add_source("proj", "projects")
        _subscribe("projects")
        for i in range(5):
            _add_distinct(f"evt_{i}", "ops", f"infra {i}")
        deliver_due_events()
        with connect() as db:
            assert db.execute("SELECT COUNT(*) FROM events WHERE held_reason IS NOT NULL").fetchone()[0] == 0


def test_unmatched_filter_or_disabled_source_is_not_budget_held(monkeypatch):
    monkeypatch.setenv("CHAT_HOOK_WAKE_LIMIT_HOUR", "0")
    sent = _fake_sender(monkeypatch)
    with TestClient(app):
        add_source("ops", "infra")
        delivery.subscribe("owner", delivery.NAME, {"category": "infra", "event_type": "other.type"},
                           {"mode": "webhook", "url": "https://chatgpt.com/hooks/infra",
                            "secret": "whsec_" + base64.b64encode(b"W" * 32).decode()},
                           categories=frozenset({"infra"}))
        for i in range(3):
            _add_distinct(f"evt_{i}", "ops", f"infra {i}")
        for _ in range(3):
            deliver_due_events()
        assert sent == []
        with connect() as db:
            held = db.execute("SELECT COUNT(*) FROM events WHERE held_reason IS NOT NULL").fetchone()[0]
            queued = db.execute("SELECT COUNT(*) FROM events WHERE queued_at IS NOT NULL").fetchone()[0]
        assert held == 0 and queued == 0


def test_canary_is_admin_only_forces_wake_and_records_luna(monkeypatch):
    monkeypatch.setenv("CHAT_HOOK_ADMIN_TOKEN", ADMIN)
    from chat_hook import decisions

    monkeypatch.setattr(decisions, "classify", lambda event: {
        "model": "gpt-6-luna", "probability": 0.02, "latency_ms": 5, "input_tokens": 10})
    sent = _fake_sender(monkeypatch)
    monkeypatch.setenv("CHAT_HOOK_WAKE_LIMIT_HOUR", "0")  # canaries are budget exempt
    with TestClient(app) as client:
        assert client.post("/v1/admin/canaries/infra").status_code == 401
        auth = {"Authorization": "Bearer " + ADMIN}
        assert client.post("/v1/admin/canaries/nope", headers=auth).status_code == 404
        created = client.post("/v1/admin/canaries/infra", headers=auth).json()
        from chat_hook.app import triage_event

        assert triage_event(created["event_id"])["route"] == "wake"
        _subscribe("infra")
        deliver_due_events()
        assert sent == [created["event_id"]]
        status = client.get("/v1/admin/canaries", headers=auth).json()["canaries"][0]
        assert status["luna"]["verdict"] == "ignore" and status["luna"]["probability"] == 0.02
        assert status["callback_requested_at"] and status["callback_receipts"][0]["status"] == "delivered"
        assert status["work_acknowledged_at"] is None
        producers = client.get("/v1/admin/producers", headers=auth).json()["categories"]
        assert producers["infra"]["status"] == "no producer wired"


def test_ack_and_outcome_timestamps_are_separate(monkeypatch):
    from chat_hook.mcp_server import _upsert_outcome

    with TestClient(app):
        add_source("ops", "infra")
        add_event("evt_x", "ops")
        _upsert_outcome("evt_x", woke=1)
        with connect() as db:
            ack, lab = db.execute("SELECT acknowledged_at,labelled_at FROM outcomes").fetchone()
        assert ack and lab is None
        _upsert_outcome("evt_x", woke=1, actionable=0)
        with connect() as db:
            ack2, lab2 = db.execute("SELECT acknowledged_at,labelled_at FROM outcomes").fetchone()
        assert ack2 == ack and lab2


def test_pilot_report_separates_requested_from_acknowledged(monkeypatch):
    monkeypatch.setenv("CHAT_HOOK_ADMIN_TOKEN", ADMIN)
    _fake_sender(monkeypatch)
    with TestClient(app) as client:
        add_source("ops", "infra")
        _add_distinct("evt_1", "ops", "one")
        add_event("evt_2", "ops", route="ignore")
        _subscribe("infra")
        deliver_due_events()
        report = client.get("/v1/admin/pilot-report",
                            headers={"Authorization": "Bearer " + ADMIN}).json()
        totals = report["totals"]
        assert totals["received"] == 2 and totals["filtered"] == 1
        assert totals["wake_requested"] == 1 and totals["callback_delivered"] == 1
        assert totals["work_acknowledged"] == 0 and totals["fn_unlabelled"] == 1
        assert report["limits"] == {"per_hour": 3, "per_day": 20, "dedup_seconds": 300}
        assert report["producers"]["infra"]["producers"] == ["ops"]
