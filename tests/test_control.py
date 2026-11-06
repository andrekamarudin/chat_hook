"""Public API tests for admin source/category controls and Luna prompts."""

import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chat_hook.app import app

ADMIN = "admin-integration-token-long-enough-for-testing"
ROOT = "derive-source-keys-from-this-strong-root-test-value"


@pytest.fixture
def client(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CHAT_HOOK_DB", str(tmp_path / "data.sqlite3"))
    monkeypatch.setenv("CHAT_HOOK_SOURCES_JSON", json.dumps({"legacy": "a-long-legacy-hook-secret-value-of-32-plus"}))
    monkeypatch.setenv("CHAT_HOOK_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("CHAT_HOOK_SOURCE_ROOT", ROOT)
    with TestClient(app) as c:
        yield c


def auth():
    return {"Authorization": "Bearer " + ADMIN}


def sign(body, key):
    raw = json.dumps(body, separators=(",", ":")).encode()
    stamp = str(int(time.time()))
    signed = hmac.new(key.encode(), stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    return raw, {"X-Chat-Hook-Timestamp": stamp, "X-Chat-Hook-Signature": "sha256=" + signed}


def new_source(client, slug="infra_dozzle", **kwargs):
    payload = {"slug": slug, "name": "Dozzle", "kind": "infra", "category": "infra", "enabled": True, **kwargs}
    result = client.post("/v1/admin/sources", json=payload, headers=auth())
    assert result.status_code == 201, result.text
    return result.json()


def test_admin_is_protected_and_page_is_only_login_shell(client):
    assert client.get("/v1/admin/config").status_code == 401
    page = client.get("/admin")
    assert page.status_code == 200
    assert "Administrator access" in page.text
    assert "no-store" in page.headers["cache-control"]
    assert "chat-hook-source-root" not in page.text


def test_runtime_hook_enable_disable_without_restart(client):
    source = new_source(client)
    event = {"id": "incident-1", "type": "error.detected", "summary": "Repeated 500s"}
    raw, headers = sign(event, source["signing_key"])
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=headers).status_code == 202
    assert client.patch("/v1/admin/sources/infra_dozzle", json={"enabled": False}, headers=auth()).status_code == 200
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=headers).status_code == 403
    assert client.patch("/v1/admin/sources/infra_dozzle", json={"enabled": True}, headers=auth()).status_code == 200
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=headers).json()["status"] == "duplicate"


def test_category_toggle_blocks_all_related_sources(client):
    source = new_source(client)
    raw, headers = sign({"id": "alert-2", "type": "alert"}, source["signing_key"])
    assert client.patch("/v1/admin/categories/infra", json={"enabled": False}, headers=auth()).status_code == 200
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=headers).status_code == 403
    assert client.patch("/v1/admin/categories/infra", json={"enabled": True}, headers=auth()).status_code == 200
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=headers).status_code == 202


def test_source_key_rotation_invalidates_previous_key(client):
    source = new_source(client)
    body = {"id": "evt1", "type": "test"}
    raw, old_headers = sign(body, source["signing_key"])
    rotated = client.post("/v1/admin/sources/infra_dozzle/rotate", headers=auth()).json()
    assert rotated["signing_key"] != source["signing_key"]
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=old_headers).status_code == 401
    raw, new_headers = sign(body, rotated["signing_key"])
    assert client.post("/v1/ingest/infra_dozzle", content=raw, headers=new_headers).status_code == 202
    assert rotated["signing_key"] not in json.dumps(client.get("/v1/admin/config", headers=auth()).json())


def test_per_source_webhook_field_mapping(client):
    source = new_source(client, field_map={"id": "payload.event_id", "type": "kind", "summary": "message", "data": "payload"})
    raw, hdr = sign({"payload": {"event_id": "third-party-1", "value": 123},
                     "kind": "notification", "message": "Something happened"}, source["signing_key"])
    response = client.post("/v1/ingest/infra_dozzle", content=raw, headers=hdr)
    assert response.status_code == 202, response.text
    event = client.get("/v1/events/" + response.json()["id"], headers=auth()).json()
    assert event["external_id"] == "third-party-1"
    assert event["name"] == "notification"
    assert event["summary"] == "Something happened"
    assert event["data"] == {"event_id": "third-party-1", "value": 123}


def test_luna_instructions_are_editable_and_audited(client, monkeypatch):
    from chat_hook import decisions

    new_source(client)
    changed = client.patch("/v1/admin/categories/infra", json={
        "luna_prompt": "Only wake for persistent failures or security incidents.",
        "ignore_threshold": 0.05, "wake_threshold": 0.95,
        "chat_url": "https://chatgpt.com/c/12345678-1234-1234-1234-123456789abc",
    }, headers=auth())
    assert changed.status_code == 200, changed.text
    assert changed.json()["policy_version"] == 2
    assert decisions.choose_route(0.85, "infra_dozzle") == "review"
    assert decisions.choose_route(0.96, "infra_dozzle") == "wake"
    monkeypatch.setenv("OPENAI_API_KEY", "fake-test-key")
    sent = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return json.dumps({"model": "gpt-6-luna", "answers": [{"name": "worth_waking", "probability": 0.8}]}).encode()

    def fake_urlopen(req, timeout):
        sent.update(json.loads(req.data))
        return Response()

    monkeypatch.setattr(decisions, "urlopen", fake_urlopen)
    decisions.classify({"source": "infra_dozzle", "name": "error", "summary": "test"})
    assert "persistent failures" in sent["questions"][0]["instructions"]
    assert "never authorizes" in sent["questions"][0]["instructions"]
    assert len(client.get("/v1/admin/audit", headers=auth()).json()["changes"]) >= 2
    assert client.patch("/v1/admin/categories/infra", json={
        "chat_url": "https://example.com/steal"}, headers=auth()).status_code == 422
    assert client.patch("/v1/admin/categories/infra", json={
        "ignore_threshold": 0.99}, headers=auth()).status_code == 422


def test_legacy_sources_still_work_and_are_switchable(client):
    body = {"id": "legacy1", "type": "ok"}
    raw, headers = sign(body, "a-long-legacy-hook-secret-value-of-32-plus")
    assert client.post("/v1/ingest/legacy", content=raw, headers=headers).status_code == 202
    assert client.patch("/v1/admin/sources/legacy", json={"enabled": False}, headers=auth()).status_code == 200
    assert client.post("/v1/ingest/legacy", content=raw, headers=headers).status_code == 403
    assert client.post("/v1/admin/sources/legacy/rotate", headers=auth()).status_code == 409


def test_unknown_fields_and_missing_root_fail_closed(client, monkeypatch):
    assert client.post("/v1/admin/sources", json={"slug": "a", "name": "too short"}, headers=auth()).status_code == 422
    assert client.post("/v1/admin/sources", json={"slug": "normal", "name": "test", "field_map": {"run": "evil"}}, headers=auth()).status_code == 422
    monkeypatch.delenv("CHAT_HOOK_SOURCE_ROOT")
    assert client.post("/v1/admin/sources", json={"slug": "normal", "name": "test"}, headers=auth()).status_code == 503


def test_named_waha_source_uses_native_signature(client):
    source = new_source(client, slug="nick_waha", kind="waha", category="whatsapp")
    payload = {"event": "message", "session": "nick", "payload": {
        "id": "m123", "from": "123@c.us", "body": "PRIVATE BODY", "fromMe": False}}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(source["signing_key"].encode(), raw, hashlib.sha512).hexdigest()
    hdr = {"X-Webhook-Timestamp": str(int(time.time() * 1000)),
           "X-Webhook-Hmac": signature, "X-Webhook-Hmac-Algorithm": "sha512"}
    result = client.post("/v1/ingest/nick_waha", content=raw, headers=hdr)
    assert result.status_code == 202, result.text
    event = client.get("/v1/events/" + result.json()["id"], headers=auth()).json()
    assert event["data"] == {"session": "nick", "chat_id": "123@c.us", "message_id": "m123"}
    assert "PRIVATE BODY" not in json.dumps(event)
