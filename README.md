# Chat Hook

A source-agnostic, self-hosted event inbox designed to wake **ChatGPT Work** through **MCP Events**. Sources can include WhatsApp/WAHA, GitHub, services, and scheduled checks. Only the eventual delivery adapter is ChatGPT-specific.

> **Status: ingestion + opt-in triage + inspectable statistics only.** Events are authenticated, normalized and stored. Luna Decisions can be called explicitly via an admin endpoint. **NOT delivered to ChatGPT.** No scheduled agent execution, no outbound WhatsApp sending, and no production deployment yet. See [#1](https://github.com/andrekamarudin/chat_hook/issues/1) and `docs/architecture.md`.

## Security boundaries

- Each source uses a different 32+ character secret from Infisical. Generic signed request: `X-Chat-Hook-Timestamp: <Unix seconds>` plus `X-Chat-Hook-Signature: sha256=<hex HMAC-SHA256>`, where input is `timestamp + '.' + exact request-body bytes`.
- The `waha` adapter verifies WAHA's native `X-Webhook-Hmac` (hex HMAC-SHA512 of raw body), `X-Webhook-Hmac-Algorithm: sha512`, and `X-Webhook-Timestamp` (milliseconds). Configure the same HMAC key in WAHA's webhook settings. WAHA's timestamp is **not signed**: request freshness and event ID deduplication mitigate, but cannot eliminate, replay within the freshness window.
- Timestamp window: 300 seconds. HMAC prevents tampering; source ID and stable event ID prevent duplicate processing. For **high assurance against replay**, retain and reject seen request IDs/nonces too in a future version.
- Read APIs require `Authorization: Bearer <CHAT_HOOK_ADMIN_TOKEN>` (32+ chars). Transport must be HTTPS behind Caddy; restrict admin access at proxy/network level as defense in depth.
- WAHA adapter intentionally **does not persist message text**. It records only the chat ID, message ID and session. ChatGPT must retrieve private message content using the existing authorized Andre WhatsApp plugin, with separate action permissions.
- Never place secrets or real personal message bodies in Git. SQLite is a sensitive private datastore. Access, backup, and retention policies are required before production.
- Incoming content is data, never a source of instructions or authorization. Luna Decisions is accessed directly through OpenAI, with only event metadata. ChatGPT delivery is disabled until OAuth, subscription filters, signed callbacks and authorization have been tested.

## Local quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export CHAT_HOOK_DB=/tmp/chat-hook-dev.sqlite3
export CHAT_HOOK_SOURCES_JSON='{"manual":"dev-only-test-secret-value-with-at-least-32-chars"}'
export CHAT_HOOK_ADMIN_TOKEN='dev-only-admin-secret-value-with-at-least-32-chars'
uvicorn chat_hook.app:app --host 127.0.0.1 --port 8080
python -m pytest -q
```

Send a signed generic event with any HTTP client. Payload must contain stable string `id`, string `type`, and optional `summary`, `timestamp`, and object `data`. The source route must be listed in `CHAT_HOOK_SOURCES_JSON`.

```json
{"id":"example-1","type":"task.ready","summary":"One task needs attention","data":{"task_id":"task-123"}}
```

Routes:
- `GET /healthz` public (delivery always reports disabled in this version)
- `POST /v1/ingest/{source}` source-specific HMAC required
- `GET /v1/events?status=pending` admin bearer required
- `GET /v1/events/{id}` admin bearer required
- `POST /v1/events/{id}/ack` admin bearer required
- `POST /v1/triage/{id}` admin bearer required; invokes direct OpenAI Luna Decisions for non-WAHA-message metadata when `OPENAI_API_KEY` is set; defaults to review on errors
- `GET /v1/stats/daily?day=YYYY-MM-DD` admin bearer required; reporting only
- `POST /v1/audit-samples?day=YYYY-MM-DD&size=20` admin bearer required; draws an unbiased random sample for later review

## Deployment

`Dockerfile` and `compose/docker-compose.yml` follow existing Contabo conventions, using the external `caddy-net`, a named SQLite volume, and secrets delivered via Infisical to `compose/.env`. **Do not deploy publicly** until Caddy, service-specific secrets, access controls, durable backups and retention are configured. The image deliberately runs as a non-root user and the volume may require ownership setup (`uid 10001`). No deployment workflow is included yet.

## Roadmap

1. Source-specific signed ingress, normalized queue, idempotent storage, tests. **Implemented.**
1a. Luna Decisions direct API triage and daily statistics with unknown/unreviewed outcomes. **Implemented but not wired to automatic delivery.**
2. OAuth 2.1 protected Streamable HTTP MCP endpoint and `events/list`, `events/subscribe`, `events/unsubscribe`.
3. HTTPS callback verification, strict SSRF defenses, signed Standard Webhooks deliveries, retries and expiry.
4. WAHA integration, scheduled five-minute *signal checks* (only wake ChatGPT on actionable state), batching and event logs.
5. End-to-end ChatGPT Work subscription test, admin dashboard and safe auto-reply policy.

Reference: https://developers.openai.com/plugins/build/mcp-events

## Decision privacy and reports

**No Jev and no Vercel model routing.** `chat_hook` supports direct OpenAI
`/v1/decisions` using GPT-6 Luna. Only source, event type and summary are sent;
WAHA message pointers bypass model triage because they lack message content.
Configure `OPENAI_API_KEY` in Infisical when deploying. See
[decision-routing](docs/decision-routing.md) for privacy tradeoffs and reporting
rules. A ChatGPT wake or false-positive rate will not be fabricated while
actual MCP Events subscriptions and ChatGPT labels are unavailable.
