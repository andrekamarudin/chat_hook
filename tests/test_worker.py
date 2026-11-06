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
