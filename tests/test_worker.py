"""Worker behavior: events are durable and reporting remains idempotent."""

from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient

from chat_hook.app import app, connect
from chat_hook.delivery import initialize as init_delivery
from chat_hook.worker import add_internal_event, prepare_daily_report, run_once


def test_internal_event_dedup_and_no_external_dependency(monkeypatch, tmp_path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "test.db"))
    with TestClient(app):
        init_delivery()
        assert add_internal_event("test-event", "internal.test", "hello", {}) == 1
        assert add_internal_event("test-event", "internal.test", "hello", {}) == 0
        with connect() as db:
            assert db.execute("SELECT COUNT(*) FROM events WHERE source='chat_hook'").fetchone()[0] == 1


def test_daily_report_is_once_per_day(monkeypatch, tmp_path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "test.db"))
    when = datetime(2026, 11, 7, 7, 8, tzinfo=ZoneInfo("Asia/Singapore"))
    with TestClient(app):
        assert prepare_daily_report(when) is True
        assert prepare_daily_report(when) is False
        with connect() as db:
            row = db.execute("SELECT name,triage_route FROM events").fetchone()
            assert row == ("report.daily", "review")


def test_due_worker_safely_without_subscriptions(monkeypatch, tmp_path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "test.db"))
    with TestClient(app):
        result = run_once()
        assert result["delivered"] == 0

def test_worker_queues_beyond_first_batch(monkeypatch):
    import base64
    import json

    from conftest import add_event, add_source

    from chat_hook import delivery
    from chat_hook.worker import deliver_due_events

    sent = []

    def fake_post(url, sec, sid, payload, eid, extra=()):
        if payload.get("type") == "verification":
            return 200, json.dumps({"challenge": payload["challenge"]}).encode()
        sent.append(payload["eventId"])
        return 204, b""

    monkeypatch.setattr(delivery, "signed_post", fake_post)
    with TestClient(app):
        add_source("manual", "projects")
        for i in range(60):
            add_event(f"evt_{i:03d}", "manual")
        assert deliver_due_events() == 0  # no subscription yet: nothing marked queued
        delivery.subscribe("owner", delivery.NAME, {"category": "projects"},
                           {"mode": "webhook", "url": "https://chatgpt.com/hooks/w",
                            "secret": "whsec_" + base64.b64encode(b"W" * 32).decode()},
                           categories=frozenset({"projects"}))
        for _ in range(3):
            deliver_due_events()
        assert len(sent) == 60 and len(set(sent)) == 60
        with connect() as db:
            assert db.execute("SELECT COUNT(*) FROM events WHERE queued_at IS NULL").fetchone()[0] == 0


def test_event_waits_for_its_own_category_subscription(monkeypatch):
    import base64
    import json

    from conftest import add_event, add_source

    from chat_hook import delivery
    from chat_hook.worker import deliver_due_events

    sent = []

    def fake_post(url, sec, sid, payload, eid, extra=()):
        if payload.get("type") == "verification":
            return 200, json.dumps({"challenge": payload["challenge"]}).encode()
        sent.append(payload["eventId"])
        return 204, b""

    def subscribe(category):
        delivery.subscribe("owner", delivery.NAME, {"category": category},
                           {"mode": "webhook", "url": "https://chatgpt.com/hooks/" + category,
                            "secret": "whsec_" + base64.b64encode(b"W" * 32).decode()},
                           categories=frozenset({category}))

    monkeypatch.setattr(delivery, "signed_post", fake_post)
    with TestClient(app):
        add_source("manual", "projects")
        add_source("infra_logs", "infra")
        add_event("evt_proj", "manual")
        add_event("evt_infra", "infra_logs")
        subscribe("projects")
        deliver_due_events()
        assert sent == ["evt_proj"]
        subscribe("infra")
        deliver_due_events()
        assert sent == ["evt_proj", "evt_infra"]
