# Luna Decisions triage (OpenAI direct, not Jev or Vercel)

Architecture: deterministic signed-ingress checks -> durable event queue ->
**OpenAI GPT-6 Luna Decisions** -> possible MCP Events wake -> **ChatGPT Work**.
Only ChatGPT Work investigates content, drafts and acts using delegated permissions.

## Privacy

- Default triage endpoint: `https://api.openai.com/v1/decisions`, model `gpt-6-luna`.
  This avoids Jev/TypeSafe and Vercel being involved in the request path.
- The triage call sends only `source`, `type` and `summary`. It excludes the
  original body and WhatsApp identifiers. Treat generic summaries as sensitive
  and configure sources to redact them before sending to OpenAI.
- WAHA message events contain only pointers, not message content. We deliberately
  bypass Luna for them and request ChatGPT review when delivery is later enabled.
- The OpenAI API is a **separate** service from ChatGPT Work. Store
  `OPENAI_API_KEY` in Infisical. The API's standard retention/data controls
  apply; do not assume zero-data-retention is automatically enabled.
- Model probability is a triage hint, never authorization for a side effect.

## Current implementation

- `POST /v1/triage/{event_id}` (admin only) makes at most one bounded Luna
  decision per event and writes the outcome. On provider failure, route to review.
- Thresholds: `CHAT_HOOK_IGNORE_THRESHOLD=0.10` and
  `CHAT_HOOK_WAKE_THRESHOLD=0.80` are initial, **uncalibrated defaults**.
  Only strong negative assessments may be suppressed. Review other results.
- Triaged but undelivered events are not ChatGPT wakes.
- `GET /v1/stats/daily?day=YYYY-MM-DD` provides daily SGT metrics.
- `POST /v1/audit-samples?day=YYYY-MM-DD&size=20` draws and persists a
  uniform random sample of ignored events for **future ChatGPT review**.
- False-positive and false-negative percentages remain null until labelled
  by a genuinely authenticated ChatGPT reviewer. Missing outcomes are unknown,
  not zero. Do not equate Luna's prediction with ground truth.

## Planned

1. Protected MCP Events adapter and tested ChatGPT subscription.
2. Signed wake-confirmation receipts and trusted ChatGPT verdict recording.
3. Daily scheduled report delivery once a deployment and recipient exist.
4. One-time sampling and ChatGPT audit, with recorded population, sample size,
   labels, confidence interval and bias limitations.
5. Consent-gated short-lived content enrichment if metadata-only routing
   proves too weak, without storing raw WAHA messages in the gateway.

References:
- https://developers.openai.com/api/docs/guides/decisions
- https://developers.openai.com/api/reference/resources/decisions/methods/create
- https://developers.openai.com/plugins/build/mcp-events
