# Architecture and boundaries

## Inputs

- WAHA (WhatsApp) posts `message` / `session.status` through an authenticated source route using native HMAC-SHA512 verification. Only minimal pointers are persisted; message bodies are not copied into the event store.
- Generic JSON sources (GitHub, email bridge, CI, home automations) post `{id,type,timestamp,summary,data}`. Each has a unique signing key.
- A future scheduler can emit standardized events when checks find pending work. A five-minute empty check must not force a ChatGPT run.

## Processing

`source -> verify signature -> cap body -> normalize -> SQLite unique(source,external_id) -> pending queue -> ChatGPT delivery adapter`

The current HTTP surface ends at the pending queue. It deliberately cannot send to ChatGPT or WhatsApp yet.

## MCP Events delivery (planned)

- Standalone authenticated HTTPS `/mcp` endpoint, using MCP Streamable HTTP (or MCP 2.0 HTTP) and OAuth 2.1 with PKCE, authorization server metadata, protected-resource metadata and per-subject permissions.
- Advertise event capabilities via `initialize`/`server/discover`; implement `events/list`, `events/subscribe`, `events/unsubscribe`.
- Persist subscriptions including owner, filters, callback URL and secret. Accept only verified external HTTPS callbacks with DNS rebinding and SSRF defenses, no redirects, and Standard Webhooks HMAC signatures.
- Deliver one event per request with `eventId`, `name`, `timestamp`, `data`, `cursor` and signed headers. Verify callback challenge before activation, retry safely, and stop at expiry or revocation.
- Model instructions reside in the authenticated ChatGPT Work subscription, not in externally supplied event text. Source events cannot independently grant permission to reply.

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
