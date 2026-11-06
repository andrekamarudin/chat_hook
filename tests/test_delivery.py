"""Signed callback safety and persisted queue contract."""

import base64
import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from chat_hook import delivery
from chat_hook.app import app, connect


@pytest.fixture
def ready(monkeypatch, tmp_path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "data.db"))
    with TestClient(app) as c:
        delivery.initialize()
        yield c


def test_signatures_are_standard_webhooks():
    payload = {"eventId": "e1", "data": {}}
    raw, headers = delivery.signature_headers(
        payload, "e1", "s1", "whsec_" + base64.b64encode(b"X" * 32).decode(),
    )
    import hashlib
    import hmac

    signed = b"e1." + headers["webhook-timestamp"].encode() + b"." + raw
    expected = base64.b64encode(hmac.new(b"X" * 32, signed, hashlib.sha256).digest()).decode()
    assert headers["webhook-signature"] == "v1," + expected


def test_subscription_verifies_then_dispatches(ready, monkeypatch):
    callback_calls = []

    def fake_post(url, secret, sid, payload, eid):
        callback_calls.append(payload)
        if payload.get("type") == "verification":
            return 200, json.dumps({"challenge": payload["challenge"]}).encode()
        return 204, b""

    monkeypatch.setattr(delivery, "signed_post", fake_post)
    sub = delivery.subscribe(
        "owner", delivery.NAME, {"source": "manual"},
        {"mode": "webhook", "url": "https://chatgpt.com/hooks/test",
         "secret": "whsec_" + base64.b64encode(b"A" * 32).decode()},
    )
    assert sub["id"].startswith("sub_")
    with connect() as db:
        db.execute("""INSERT INTO events (id,source,external_id,name,occurred_at,received_at,
            summary,data_json,triage_route) VALUES (?,?,?,?,?,?,?,?,?)""",
                   ("evt_test", "manual", "external", "test.raised", datetime.now(UTC).isoformat(),
                    datetime.now(UTC).isoformat(), "manual test", "{}", "wake"))
    count = delivery.queue_event({"id": "evt_test", "source": "manual",
                                  "name": "test.raised", "triage_route": "wake"})
    assert count == 1
    assert delivery.dispatch() == 1
    assert callback_calls[1]["eventId"] == "evt_test"
    with connect() as db:
        assert db.execute("SELECT status FROM deliveries").fetchone()[0] == "delivered"


def test_verification_failure_does_not_persist(ready, monkeypatch):
    monkeypatch.setattr(delivery, "signed_post", lambda *args: (200, b'{"challenge":"wrong"}'))
    with pytest.raises(delivery.CallbackError):
        delivery.subscribe("owner", delivery.NAME, {},
                           {"mode": "webhook", "url": "https://chatgpt.com/test",
                            "secret": "whsec_" + base64.b64encode(b"B" * 32).decode()})
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
