"""Shared test environment. Values are throwaway test fixtures, not deploy secrets."""

import pytest

TEST_PASSWORD = "test-owner-password-0123456789abcdef"


@pytest.fixture(autouse=True)
def chat_hook_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "chat_hook.db"))
    monkeypatch.setenv("CHAT_HOOK_DATA_KEY", "test-data-key-0123456789abcdef0123456789")
    monkeypatch.setenv("CHAT_HOOK_PUBLIC_URL", "http://testserver")
    monkeypatch.setenv("CHAT_HOOK_OWNER", "owner")
    monkeypatch.setenv("CHAT_HOOK_OWNER_PASSWORD", TEST_PASSWORD)


def add_source(slug, category, mode="triage", enabled=1):
    from chat_hook.app import connect, utc_now

    with connect() as db:
        db.execute("""INSERT OR REPLACE INTO hook_sources
            (slug,name,kind,category,enabled,mode,changed_at) VALUES (?,?,?,?,?,?,?)""",
            (slug, slug, "webhook", category, enabled, mode, utc_now()))


def add_event(event_id, source, route="wake", name="test.raised", received_at=None):
    from chat_hook.app import connect, utc_now

    with connect() as db:
        db.execute("""INSERT INTO events (id,source,external_id,name,occurred_at,received_at,
            summary,data_json,triage_route) VALUES (?,?,?,?,?,?,?,?,?)""",
            (event_id, source, event_id, name, utc_now(), received_at or utc_now(),
             "test summary", '{"pointer":"x"}', route))
