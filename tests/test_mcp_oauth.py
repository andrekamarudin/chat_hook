"""OAuth 2.1 authorization server and authenticated MCP endpoint."""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import TEST_PASSWORD, add_event, add_source
from fastapi.testclient import TestClient

from chat_hook import delivery
from chat_hook.app import app, connect

REDIRECT = "https://chatgpt.com/connector/oauth/abc123"
RESOURCE = "http://testserver/mcp"


@pytest.fixture
def client():
    with TestClient(app) as c:
        add_source("manual", "projects")
        add_source("infra_logs", "infra")
        yield c


def register(client):
    response = client.post("/oauth/register", json={"redirect_uris": [REDIRECT], "client_name": "t"})
    assert response.status_code == 201
    return response.json()["client_id"]


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


def authorize(client, client_id, challenge, categories=("projects",), password=TEST_PASSWORD,
              scope="hooks.events hooks.read hooks.outcomes"):
    form = {"client_id": client_id, "redirect_uri": REDIRECT, "challenge": challenge,
            "scope": scope, "resource": RESOURCE, "state": "st", "password": password,
            "category": list(categories)}
    return client.post("/oauth/authorize", data=form, follow_redirects=False)


def login(client, categories=("projects",), scope="hooks.events hooks.read hooks.outcomes"):
    client_id = register(client)
    verifier, challenge = pkce()
    response = authorize(client, client_id, challenge, categories, scope=scope)
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["state"] == ["st"] and query["iss"] == ["http://testserver"]
    tokens = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": query["code"][0], "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": RESOURCE}).json()
    tokens["client_id"] = client_id
    tokens["code"] = query["code"][0]
    tokens["verifier"] = verifier
    return tokens


def rpc(client, token, method, params=None, **headers):
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method,
                                     "params": params or {}},
                       headers={"Authorization": "Bearer " + token, **headers})


def tool(client, token, name, **arguments):
    body = rpc(client, token, "tools/call", {"name": name, "arguments": arguments}).json()
    return body["result"]


def test_metadata_documents(client):
    prm = client.get("/.well-known/oauth-protected-resource").json()
    assert prm["resource"] == RESOURCE and prm["authorization_servers"] == ["http://testserver"]
    asm = client.get("/.well-known/oauth-authorization-server").json()
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["registration_endpoint"].endswith("/oauth/register")


def test_unconfigured_fails_closed(client, monkeypatch):
    monkeypatch.delenv("CHAT_HOOK_OWNER_PASSWORD")
    assert client.post("/oauth/register", json={"redirect_uris": [REDIRECT]}).status_code == 503
    assert client.post("/mcp", json={}).status_code == 503


def test_register_rejects_foreign_redirects(client):
    for uri in ("https://evil.example/connector/oauth", "http://chatgpt.com/connector/oauth",
                "https://chatgpt.com/other"):
        assert client.post("/oauth/register", json={"redirect_uris": [uri]}).status_code == 400


def test_register_accepts_stable_chatgpt_redirect(client):
    for uri in ("https://chatgpt.com/connector_platform_oauth_redirect",
                "https://chatgpt.com/connector/oauth/cb_1"):
        resp = client.post("/oauth/register", json={
            "redirect_uris": [uri], "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"], "client_name": "ChatGPT"})
        assert resp.status_code == 201, resp.text
    for uri in ("https://chatgpt.com/connector_platform_oauth_redirect/x",
                "https://evil.example/connector_platform_oauth_redirect"):
        assert client.post("/oauth/register", json={"redirect_uris": [uri]}).status_code == 400


def test_full_flow_and_mcp_initialize(client):
    tokens = login(client)
    assert tokens["token_type"] == "Bearer"
    body = rpc(client, tokens["access_token"], "initialize",
               {"protocolVersion": "2025-06-18", "capabilities": {}}).json()
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert "events" in body["result"]["capabilities"]
    names = {t["name"] for t in rpc(client, tokens["access_token"], "tools/list").json()["result"]["tools"]}
    assert names == {"list_hook_events", "get_hook_event", "acknowledge_hook_event",
                     "record_hook_outcome"}
    events = rpc(client, tokens["access_token"], "events/list").json()["result"]["events"]
    assert events[0]["inputSchema"]["properties"]["category"]["enum"] == ["projects"]


def test_wrong_password_and_rate_limit(client):
    client_id = register(client)
    _, challenge = pkce()
    for _ in range(5):
        assert authorize(client, client_id, challenge, password="nope").status_code == 401
    assert authorize(client, client_id, challenge).status_code == 429


def test_lockout_is_per_client_ip(client):
    client_id = register(client)
    _, challenge = pkce()
    form = {"client_id": client_id, "redirect_uri": REDIRECT, "challenge": challenge,
            "scope": "hooks.read", "resource": RESOURCE, "state": "st",
            "password": "wrong", "category": ["projects"]}
    attacker = {"X-Forwarded-For": "203.0.113.9"}
    for _ in range(5):
        assert client.post("/oauth/authorize", data=form, headers=attacker).status_code == 401
    assert client.post("/oauth/authorize", data=form, headers=attacker).status_code == 429
    owner_form = dict(form, password=TEST_PASSWORD)
    response = client.post("/oauth/authorize", data=owner_form, follow_redirects=False,
                           headers={"X-Forwarded-For": "198.51.100.7"})
    assert response.status_code == 302


def test_pkce_mismatch_rejected(client):
    client_id = register(client)
    _, challenge = pkce()
    location = authorize(client, client_id, challenge).headers["location"]
    code = parse_qs(urlsplit(location).query)["code"][0]
    response = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": secrets.token_urlsafe(48)})
    assert response.json()["error"] == "invalid_grant"


def test_code_replay_revokes_family(client):
    tokens = login(client)
    replay = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": tokens["code"], "client_id": tokens["client_id"],
        "redirect_uri": REDIRECT, "code_verifier": tokens["verifier"]})
    assert replay.status_code == 400
    assert rpc(client, tokens["access_token"], "ping").status_code == 401


def test_refresh_rotation_and_reuse_detection(client):
    tokens = login(client)
    refreshed = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
        "client_id": tokens["client_id"]}).json()
    assert refreshed["access_token"] != tokens["access_token"]
    assert rpc(client, refreshed["access_token"], "ping").status_code == 200
    reuse = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
        "client_id": tokens["client_id"]})
    assert reuse.json()["error"] == "invalid_grant"
    assert rpc(client, refreshed["access_token"], "ping").status_code == 401


def test_refresh_cannot_widen_scope(client):
    tokens = login(client, scope="hooks.read")
    response = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
        "client_id": tokens["client_id"], "scope": "hooks.read hooks.outcomes"})
    assert response.json()["error"] == "invalid_scope"


def test_wrong_resource_rejected(client):
    client_id = register(client)
    _, challenge = pkce()
    response = client.get("/oauth/authorize", params={
        "client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code",
        "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": "https://elsewhere.example/mcp"})
    assert response.status_code == 400


def test_mcp_requires_bearer(client):
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]
    assert rpc(client, "not-a-token", "ping").status_code == 401


def test_mcp_rejects_foreign_origin(client):
    tokens = login(client)
    assert rpc(client, tokens["access_token"], "ping", Origin="https://evil.example").status_code == 403
    assert rpc(client, tokens["access_token"], "ping", Origin="https://chatgpt.com").status_code == 200


def test_insufficient_scope(client):
    tokens = login(client, scope="hooks.read")
    response = rpc(client, tokens["access_token"], "events/list")
    assert response.status_code == 403
    assert "insufficient_scope" in response.headers["www-authenticate"]


def test_subscribe_forbidden_category_and_callback_error(client, monkeypatch):
    tokens = login(client)
    delivery_spec = {"mode": "webhook", "url": "https://chatgpt.com/hooks/x",
                     "secret": "whsec_" + base64.b64encode(b"A" * 32).decode()}
    body = rpc(client, tokens["access_token"], "events/subscribe", {
        "name": "hook.event", "arguments": {"category": "infra"}, "delivery": delivery_spec}).json()
    assert body["error"]["code"] == -32602 and body["error"]["data"]["reason"] == "forbidden"
    monkeypatch.setattr(delivery, "signed_post", lambda *a: (500, b""))
    body = rpc(client, tokens["access_token"], "events/subscribe", {
        "name": "hook.event", "arguments": {"category": "projects"}, "delivery": delivery_spec}).json()
    assert body["error"]["code"] == -32015
    assert body["error"]["data"]["reason"] == "challenge_failed"


def deliver(event_id, source="manual", owner="owner"):
    with connect() as db:
        db.execute("""INSERT INTO deliveries (event_id,subscription_id,status,next_attempt,owner)
            VALUES (?,?,?,?,?)""", (event_id, "sub_x", "delivered", "2026-01-01", owner))


def test_tools_are_category_scoped(client):
    tokens = login(client)
    add_event("evt_p", "manual")
    add_event("evt_i", "infra_logs")
    listed = tool(client, tokens["access_token"], "list_hook_events")
    assert [e["event_id"] for e in listed["structuredContent"]["events"]] == ["evt_p"]
    hidden = tool(client, tokens["access_token"], "get_hook_event", event_id="evt_i")
    assert hidden["isError"] is True
    shown = tool(client, tokens["access_token"], "get_hook_event", event_id="evt_p")
    assert shown["structuredContent"]["data"] == {"pointer": "x"}


def test_acknowledge_requires_delivery_to_owner(client):
    tokens = login(client)
    add_event("evt_a", "manual")
    assert tool(client, tokens["access_token"], "acknowledge_hook_event", event_id="evt_a")["isError"]
    deliver("evt_a", owner="someone_else")
    assert tool(client, tokens["access_token"], "acknowledge_hook_event", event_id="evt_a")["isError"]
    deliver_row = ("evt_a",)
    with connect() as db:
        db.execute("UPDATE deliveries SET owner='owner' WHERE event_id=?", deliver_row)
    for _ in range(2):  # idempotent
        result = tool(client, tokens["access_token"], "acknowledge_hook_event", event_id="evt_a")
        assert result["structuredContent"]["woke_confirmed"] is True
    with connect() as db:
        assert db.execute("SELECT woke_confirmed,actionable,reviewer FROM outcomes").fetchall() == [
            (1, None, "chatgpt")]


def test_outcome_for_audit_sample_and_delivery(client):
    tokens = login(client)
    add_event("evt_ignored", "manual", route="ignore")
    result = tool(client, tokens["access_token"], "record_hook_outcome",
                  event_id="evt_ignored", actionable=True)
    assert result["isError"]  # not delivered, not sampled
    with connect() as db:
        db.execute("INSERT INTO audit_samples VALUES ('evt_ignored','2026-01-01')")
    result = tool(client, tokens["access_token"], "record_hook_outcome",
                  event_id="evt_ignored", actionable=True)
    assert result["isError"] is False
    with connect() as db:
        assert db.execute("SELECT woke_confirmed,actionable FROM outcomes").fetchone() == (None, 1)
    add_event("evt_d", "manual")
    deliver("evt_d")
    tool(client, tokens["access_token"], "record_hook_outcome", event_id="evt_d", actionable=False)
    with connect() as db:
        assert db.execute("SELECT woke_confirmed,actionable FROM outcomes WHERE event_id='evt_d'"
                          ).fetchone() == (1, 0)


def test_read_only_token_cannot_record(client):
    tokens = login(client, scope="hooks.read")
    add_event("evt_r", "manual")
    response = rpc(client, tokens["access_token"], "tools/call",
                   {"name": "acknowledge_hook_event", "arguments": {"event_id": "evt_r"}})
    assert response.status_code == 403


def test_notifications_and_batches(client):
    tokens = login(client)
    auth = {"Authorization": "Bearer " + tokens["access_token"]}
    note = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                       headers=auth)
    assert note.status_code == 202
    batch = client.post("/mcp", content=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]),
                        headers={**auth, "Content-Type": "application/json"})
    assert batch.status_code == 400
    assert client.get("/mcp", headers=auth).status_code == 405
