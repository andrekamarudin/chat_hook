"""End-to-end HTTP tests for the first safe Chat Hook slice."""

import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chat_hook.app import app

SECRET = "test-source-secret-value-that-is-long-enough"
ADMIN = "test-admin-secret-value-that-is-long-enough"


@pytest.fixture
def client(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "events.sqlite3"))
    monkeypatch.setenv("CHAT_HOOK_SOURCES_JSON", json.dumps({"waha": SECRET, "github": SECRET}))
    monkeypatch.setenv("CHAT_HOOK_ADMIN_TOKEN", ADMIN)
    with TestClient(app) as c:
        yield c


def sign(body: dict, *, secret: str = SECRET, timestamp: int | None = None):
    raw = json.dumps(body, separators=(",", ":")).encode()
    moment = str(timestamp if timestamp is not None else int(time.time()))
    signature = hmac.new(secret.encode(), moment.encode() + b"." + raw, hashlib.sha256).hexdigest()
    return raw, {"X-Chat-Hook-Timestamp": moment, "X-Chat-Hook-Signature": "sha256=" + signature}


def sign_waha(body: dict):
    raw = json.dumps(body, separators=(",", ":")).encode()
    signature = hmac.new(SECRET.encode(), raw, hashlib.sha512).hexdigest()
    return raw, {
        "X-Webhook-Timestamp": str(int(time.time() * 1000)),
        "X-Webhook-Hmac": signature,
        "X-Webhook-Hmac-Algorithm": "sha512",
    }


def test_signed_generic_event_is_durable_and_idempotent(client):
    payload = {"id": "ci-123", "type": "build.failed", "summary": "CI failed", "data": {"repo": "chat_hook"}}
    raw, headers = sign(payload)
    first = client.post("/v1/ingest/github", content=raw, headers=headers)
    second = client.post("/v1/ingest/github", content=raw, headers=headers)
    assert first.status_code == 202
    assert first.json()["status"] == "queued"
    assert second.json() == {"id": first.json()["id"], "status": "duplicate"}
    authed = {"Authorization": "Bearer " + ADMIN}
    assert len(client.get("/v1/events", headers=authed).json()["events"]) == 1
    event_id = first.json()["id"]
    assert client.get(f"/v1/events/{event_id}", headers=authed).json()["data"] == {"repo": "chat_hook"}
    assert client.post(f"/v1/events/{event_id}/ack", headers=authed).json()["status"] == "acknowledged"
    assert client.get("/v1/events", headers=authed).json()["events"] == []
    assert len(client.get("/v1/events?status=acknowledged", headers=authed).json()["events"]) == 1


def test_invalid_and_expired_signatures_rejected(client):
    raw, headers = sign({"id": "evt1", "type": "test"}, secret="wrong-key-is-long-enough-to-sign-something")
    assert client.post("/v1/ingest/github", content=raw, headers=headers).status_code == 401
    raw, headers = sign({"id": "evt2", "type": "test"}, timestamp=int(time.time()) - 600)
    assert client.post("/v1/ingest/github", content=raw, headers=headers).status_code == 401
    assert client.post("/v1/ingest/github", json={"id": "x", "type": "y"}).status_code == 401
    assert client.get("/v1/events").status_code == 401


def test_waha_message_minimizes_personal_content_and_drops_echoes(client):
    message = {
        "event": "message", "session": "default", "timestamp": 1793990000,
        "payload": {"id": "msg-1", "from": "123@c.us", "body": "PRIVATE PERSONAL TEXT", "fromMe": False},
    }
    raw, headers = sign_waha(message)
    result = client.post("/v1/ingest/waha", content=raw, headers=headers)
    assert result.status_code == 202
    event = client.get(f"/v1/events/{result.json()['id']}", headers={"Authorization": "Bearer " + ADMIN}).json()
    assert event["name"] == "message.received"
    assert event["data"] == {"session": "default", "chat_id": "123@c.us", "message_id": "msg-1"}
    assert "PRIVATE PERSONAL TEXT" not in json.dumps(event)
    message["payload"]["fromMe"] = True
    raw, headers = sign_waha(message)
    assert client.post("/v1/ingest/waha", content=raw, headers=headers).json() == {"status": "ignored"}


def test_untrusted_generic_event_needs_explicit_identity(client):
    raw, headers = sign({"type": "build.failed", "data": {"x": 1}})
    assert client.post("/v1/ingest/github", content=raw, headers=headers).status_code == 422


def test_health_reports_delivery_disabled(client):
    assert client.get("/healthz").json() == {"status": "ok", "delivery": "disabled"}


def test_waha_requires_its_real_sha512_signature_headers(client):
    payload = {"event": "message", "session": "default", "payload": {"id": "unique", "from": "123@c.us"}}
    raw, headers = sign_waha(payload)
    assert client.post("/v1/ingest/waha", content=raw, headers=headers).status_code == 202
    bad = dict(headers, **{"X-Webhook-Hmac-Algorithm": "md5"})
    assert client.post("/v1/ingest/waha", content=raw, headers=bad).status_code == 401
    bad = dict(headers, **{"X-Webhook-Timestamp": str(int(time.time() * 1000) - 700_000)})
    assert client.post("/v1/ingest/waha", content=raw, headers=bad).status_code == 401
    bad = dict(headers, **{"X-Webhook-Hmac": "invalid"})
    assert client.post("/v1/ingest/waha", content=raw, headers=bad).status_code == 401


def test_luna_decisions_api_uses_openai_direct_and_metadata_only(monkeypatch):
    from chat_hook import decisions

    monkeypatch.setenv("OPENAI_API_KEY", "fake-unit-test-secret")
    received = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return json.dumps({
                "model": "gpt-6-luna",
                "answers": [{"type": "predicate", "name": "worth_waking", "probability": 0.92}],
                "usage": {"input_tokens": 72, "output_tokens": 0},
            }).encode()

    def fake_urlopen(request, timeout):
        received["url"] = request.full_url
        received["body"] = json.loads(request.data)
        assert timeout == 12
        return Response()

    monkeypatch.setattr(decisions, "urlopen", fake_urlopen)
    result = decisions.classify({"source": "github", "name": "ci.failed",
                                "summary": "CI failed", "data_json": "PRIVATE TEXT"})
    assert received["url"] == "https://api.openai.com/v1/decisions"
    assert received["body"]["model"] == "gpt-6-luna"
    assert received["body"]["questions"][0]["type"] == "predicate"
    assert received["body"]["questions"][0]["name"] == "worth_waking"
    assert "PRIVATE TEXT" not in str(received["body"])
    assert result["probability"] == 0.92
    assert result["input_tokens"] == 72


def test_signed_event_can_be_triaged_once_without_waking_chatgpt(client, monkeypatch):
    from chat_hook import decisions

    raw, headers = sign({"id": "ci-777", "type": "ci.failed", "summary": "build failed"})
    event_id = client.post("/v1/ingest/github", content=raw, headers=headers).json()["id"]
    call_count = {"n": 0}

    def stub(_event):
        call_count["n"] += 1
        return {"probability": 0.97, "model": "gpt-6-luna", "latency_ms": 15, "input_tokens": 35}

    monkeypatch.setattr(decisions, "classify", stub)
    auth = {"Authorization": "Bearer " + ADMIN}
    first = client.post(f"/v1/triage/{event_id}", headers=auth)
    again = client.post(f"/v1/triage/{event_id}", headers=auth)
    assert first.json() == {"id": event_id, "route": "wake", "status": "ok"}
    assert again.json()["status"] == "already_triaged"
    assert call_count["n"] == 1
    from datetime import datetime
    from zoneinfo import ZoneInfo

    day = datetime.now(ZoneInfo("Asia/Singapore")).date().isoformat()
    report = client.get(f"/v1/stats/daily?day={day}", headers=auth).json()
    assert report["received"] == 1
    assert report["luna_decisions"]["successful"] == 1
    assert report["chatgpt"]["wake_requested"] == 1
    assert report["chatgpt"]["wake_confirmed"] == 0
    assert report["chatgpt"]["false_positive_pct"] is None


def test_waha_pointer_bypasses_luna_and_model_error_fails_open(client, monkeypatch):
    from chat_hook import decisions

    def fail(_):
        raise decisions.DecisionError("do not call network")

    monkeypatch.setattr(decisions, "classify", fail)
    raw, headers = sign_waha({"event": "message", "session": "default",
                              "payload": {"id": "m4", "from": "123@c.us", "fromMe": False}})
    event_id = client.post("/v1/ingest/waha", content=raw, headers=headers).json()["id"]
    auth = {"Authorization": "Bearer " + ADMIN}
    result = client.post(f"/v1/triage/{event_id}", headers=auth).json()
    assert result["route"] == "review"
    assert result["status"] == "skipped"

    raw, headers = sign({"id": "ci-778", "type": "ci.failed", "summary": "build failed"})
    event_id = client.post("/v1/ingest/github", content=raw, headers=headers).json()["id"]
    result = client.post(f"/v1/triage/{event_id}", headers=auth).json()
    assert result["route"] == "review"
    assert result["status"] == "error"


def test_false_negative_sampling_reports_unknown_until_chatgpt_review(client, monkeypatch):
    from chat_hook import decisions
    from datetime import datetime
    from zoneinfo import ZoneInfo

    monkeypatch.setattr(decisions, "classify", lambda _: {
        "probability": 0.01, "model": "gpt-6-luna", "latency_ms": 12, "input_tokens": 24,
    })
    day = datetime.now(ZoneInfo("Asia/Singapore")).date().isoformat()
    auth = {"Authorization": "Bearer " + ADMIN}
    for number in range(5):
        raw, headers = sign({"id": f"unimportant-{number}", "type": "routine.notice"})
        eid = client.post("/v1/ingest/github", content=raw, headers=headers).json()["id"]
        assert client.post(f"/v1/triage/{eid}", headers=auth).json()["route"] == "ignore"
    sample = client.post(f"/v1/audit-samples?day={day}&size=3", headers=auth).json()
    repeated = client.post(f"/v1/audit-samples?day={day}&size=3", headers=auth).json()
    assert len(sample["sample_ids"]) == 3
    assert set(sample["sample_ids"]) == set(repeated["sample_ids"])
    assert sample["population_ignored"] == 5
    report = client.get(f"/v1/stats/daily?day={day}", headers=auth).json()
    assert report["routes"]["ignore"] == 5
    assert report["false_negative_audit"]["sample_false_negative_pct"] is None
    assert report["false_negative_audit"]["sample_95pct_wilson_interval"] is None
