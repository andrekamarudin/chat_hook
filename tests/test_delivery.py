"""Signed callback safety and persisted queue contract."""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import add_event, add_source
from fastapi.testclient import TestClient

from chat_hook import delivery
from chat_hook.app import app, connect

ALL = frozenset({"projects", "infra", "personal", "research", "whatsapp"})
URL = "https://chatgpt.com/hooks/test"


def secret(char):
    return "whsec_" + base64.b64encode(char.encode() * 32).decode()


@pytest.fixture
def ready():
    with TestClient(app) as c:
        add_source("manual", "projects")
        yield c


class Calls(list):
    pass


@pytest.fixture
def cb(monkeypatch):
    calls = Calls()
    calls.status = 204

    def fake_post(url, sec, sid, payload, eid, extra=()):
        calls.append({"url": url, "payload": payload, "secret": sec, "extra": extra})
        if payload.get("type") == "verification":
            return 200, json.dumps({"challenge": payload["challenge"]}).encode()
        return calls.status, b""

    monkeypatch.setattr(delivery, "signed_post", fake_post)
    return calls


def sub(category="projects", char="A", url=URL, categories=ALL, **filters):
    return delivery.subscribe("owner", delivery.NAME, {"category": category, **filters},
                              {"mode": "webhook", "url": url, "secret": secret(char)},
                              categories=categories)


def queue(event_id, source="manual"):
    return delivery.queue_event({"id": event_id, "source": source, "name": "test.raised",
                                 "triage_route": "wake"})


def test_signatures_are_standard_webhooks():
    raw, headers = delivery.signature_headers({"eventId": "e1", "data": {}}, "e1", "s1", secret("X"))
    signed = b"e1." + headers["webhook-timestamp"].encode() + b"." + raw
    expected = base64.b64encode(hmac.new(b"X" * 32, signed, hashlib.sha256).digest()).decode()
    assert headers["webhook-signature"] == "v1," + expected


def test_rotation_dual_signs():
    _, headers = delivery.signature_headers({}, "e1", "s1", secret("X"), (secret("Y"),))
    assert len(headers["webhook-signature"].split(" ")) == 2


def test_subscription_verifies_then_dispatches(ready, cb):
    result = sub()
    assert result["id"].startswith("sub_") and result["truncated"] is False
    add_event("evt_test", "manual")
    assert queue("evt_test") == 1
    assert delivery.dispatch() == 1
    assert cb[1]["payload"]["eventId"] == "evt_test"
    assert cb[0]["payload"]["type"] == "verification"
    with connect() as db:
        row = db.execute("SELECT status,owner,delivered_at FROM deliveries").fetchone()
        assert row[0] == "delivered" and row[1] == "owner" and row[2]


def test_secret_encrypted_at_rest(ready, cb):
    sub()
    with connect() as db:
        stored = db.execute("SELECT secret FROM subscriptions").fetchone()[0]
    assert stored.startswith("enc:v1:") and secret("A") not in stored


def test_missing_data_key_refuses_subscription(ready, cb, monkeypatch):
    monkeypatch.delenv("CHAT_HOOK_DATA_KEY")
    with pytest.raises(delivery.CallbackError) as exc:
        sub()
    assert exc.value.reason == "server_not_configured"


def test_category_required_and_must_be_granted(ready, cb):
    with pytest.raises(delivery.CallbackError):
        delivery.subscribe("owner", delivery.NAME, {}, {"mode": "webhook", "url": URL,
                                                        "secret": secret("A")}, categories=ALL)
    with pytest.raises(delivery.CallbackError) as exc:
        sub("infra", categories=frozenset({"projects"}))
    assert exc.value.reason == "forbidden"
    with pytest.raises(delivery.CallbackError):
        sub("infra", source="manual")  # manual belongs to projects


def test_verification_failure_does_not_persist(ready, monkeypatch):
    monkeypatch.setattr(delivery, "signed_post", lambda *args: (200, b'{"challenge":"wrong"}'))
    with pytest.raises(delivery.CallbackError) as exc:
        sub()
    assert exc.value.callback and exc.value.reason == "challenge_failed"
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] == 0


def test_verification_is_cached(ready, cb):
    sub()
    sub()
    assert sum(c["payload"].get("type") == "verification" for c in cb) == 1


def test_one_subscription_per_category(ready, cb):
    first = sub(url="https://chatgpt.com/hooks/one")
    second = sub(url="https://chatgpt.com/hooks/two")
    assert first["id"] != second["id"]
    with connect() as db:
        ids = [r[0] for r in db.execute("SELECT id FROM subscriptions")]
    assert ids == [second["id"]]


def test_events_route_only_to_matching_category(ready, cb):
    add_source("infra_logs", "infra")
    sub("infra")
    add_event("evt_projects", "manual")
    assert queue("evt_projects") == 0
    add_event("evt_infra", "infra_logs")
    assert queue("evt_infra", "infra_logs") == 1


def test_secret_rotation_keeps_previous_briefly(ready, cb):
    sub(char="A")
    sub(char="B")
    add_event("evt_rot", "manual")
    queue("evt_rot")
    delivery.dispatch()
    sent = cb[-1]
    assert sent["secret"] == secret("B") and sent["extra"] == (secret("A"),)


def test_disabled_source_suppresses_queued(ready, cb):
    sub()
    add_event("evt_off", "manual")
    queue("evt_off")
    add_source("manual", "projects", enabled=0)
    assert delivery.dispatch() == 0
    with connect() as db:
        assert db.execute("SELECT status FROM deliveries").fetchone()[0] == "suppressed"


def test_gone_expires_subscription(ready, cb):
    sub()
    add_event("evt_gone", "manual")
    queue("evt_gone")
    cb.status = 410
    delivery.dispatch()
    with connect() as db:
        status = db.execute("SELECT status FROM deliveries").fetchone()[0]
        expires = db.execute("SELECT expires_at FROM subscriptions").fetchone()[0]
    assert status == "failed" and expires <= datetime.now(UTC).isoformat()


def test_ttl_clamped(ready, cb):
    result = delivery.subscribe("owner", delivery.NAME, {"category": "projects"},
                                {"mode": "webhook", "url": URL, "secret": secret("A")},
                                ttl_ms=10, categories=ALL)
    expiry = datetime.fromisoformat(result["refreshBefore"])
    assert expiry > datetime.now(UTC) + timedelta(seconds=delivery.MIN_TTL_SECONDS - 5)


def test_unsubscribe_is_owner_scoped(ready, cb):
    sub()
    delivery.unsubscribe("someone_else", delivery.NAME, {"category": "projects"},
                         {"url": URL})
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] == 1
    assert delivery.unsubscribe("owner", delivery.NAME, {"category": "projects"}, {"url": URL}) == {}
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] == 0


def test_private_destinations_blocked(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *_args, **_kwargs: [(2, 1, 0, "", ("127.0.0.1", 443))])
    with pytest.raises(delivery.CallbackError):
        delivery.public_destination("https://chatgpt.com/internal")
    with pytest.raises(delivery.CallbackError):
        delivery.public_destination("https://evil.example.net/path")
