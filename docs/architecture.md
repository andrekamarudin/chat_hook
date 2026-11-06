# Architecture and boundaries

## Inputs

- WAHA (WhatsApp) posts `message` / `session.status` through an authenticated source route using native HMAC-SHA512 verification. Only minimal pointers are persisted; message bodies are not copied into the event store.
- Generic JSON sources (GitHub, email bridge, CI, home automations) post `{id,type,timestamp,summary,data}`. Each has a unique signing key.
- A future scheduler can emit standardized events when checks find pending work. A five-minute empty check must not force a ChatGPT run.

## Processing

`source -> verify signature -> cap body -> normalize -> SQLite unique(source,external_id) -> pending queue -> ChatGPT delivery adapter`

The HTTP ingress ends at the queue; the worker fans routed (`wake`/`review`) events out to live subscriptions. Nothing sends to WhatsApp.

## MCP Events delivery

- `chat_hook/oauth.py`: single-owner OAuth 2.1 authorization server (PKCE S256 only, RFC 8707 resource binding to `<public>/mcp`, DCR limited to `https://chatgpt.com|chat.openai.com/connector/oauth...`, rotating refresh tokens with family revocation on reuse, rate-limited consent password). Tokens carry scopes and the categories chosen on the consent page.
- `chat_hook/mcp_server.py`: `POST /mcp` JSON-RPC (Streamable HTTP, JSON responses only, Origin allow-list). Advertises `events` in `initialize` and via `server/discover`.
- `chat_hook/delivery.py`: deterministic subscription IDs, constant-time callback challenge (cached 1h per owner/URL/secret), JSON-RPC `-32015` with `data.reason` for callback failures, TTL clamped to 5 min–24 h, one subscription per owner and category, Fernet-encrypted secrets, 10-minute dual signing on secret rotation, SSRF-pinned HTTPS posts without redirects, retries with backoff, no retry on `410`/`413` (410 also expires the subscription), and suppression of queued sends when a source/category is disabled or switched to digest.
- Event payloads are pointers plus summaries. Model instructions live in the authenticated ChatGPT Work subscription, never in event text. Source events cannot grant permission to reply.
- Confirmed wake = `acknowledge_hook_event` from the same owner for an event actually delivered to them. Outcome labels may be recorded only for delivered or audit-sampled events; missing labels stay unknown.

## Reliability and safety gates

- Avoid duplicate work with stable IDs and downstream idempotency keys. Persist event and delivery states independently.
- Do not log raw webhook bodies or authorization headers.
- Batch bursts, ignore WAHA self-sent messages, avoid echo loops.
- Restrict event source subscriptions by account, source and chat IDs. Default action is notify or draft, not automatic send.
- Design for an audited retention policy, database backups, dead-letter queue, delivery receipts, structured logs, and admin controls before enabling production.

## Scope separation

| Repo/component | Owns |
|---|---|
| `andrekamarudin/waha` | WhatsApp API deployment, sessions and direct WAHA integration |
| `andrekamarudin/chat_hook` | Incoming triggers, normalization, durable event queue and ChatGPT-specific event-delivery adapter |
| Andre WhatsApp ChatGPT plugin | WhatsApp read/send tools, their current authentication and permissions |

No code is moved from WAHA or the existing ChatGPT plugin into this repository.
