# Chat Hook control plane (first delivery slice)

This is a **runtime configuration** UI and API, not a parallel agent. ChatGPT
remains the only substantive reasoning/writing actor. Luna Decisions is a bounded
triage gate; no Jev, TypeSafe or Vercel model calls are made.

## Admin surface

- `GET /admin` shows a credential-free login shell.
- Authenticate in the browser with `CHAT_HOOK_ADMIN_TOKEN`. The token is held in
  tab memory only, not written to URLs, localStorage or cookies. Use HTTPS and
  protect the admin origin at Caddy/network level too.
- `GET /v1/admin/config` returns source/category configuration and recent edits.
- `POST /v1/admin/sources` creates a source. It starts **disabled** unless
  explicitly enabled, and returns the signing key only on creation.
- `PATCH /v1/admin/sources/{slug}` toggles a source, changes routing mode,
  category, name and optional JSON field mapping without restarting the app.
- `POST /v1/admin/sources/{slug}/rotate` invalidates the old signing key.
- `PATCH /v1/admin/categories/{slug}` toggles every source in a category,
  records a ChatGPT conversation **display link**, and changes the Luna
  predicate instructions and two confidence thresholds.
- `GET /v1/admin/audit` shows configuration mutations, excluding credentials.

Hook signatures are derived per source from `CHAT_HOOK_SOURCE_ROOT`, a high
entropy secret held in Infisical. A new source doesn't require a new environment
variable. Rotation increments a per-source version. Set the root before
creating dynamic sources, and keep it stable across redeploys. A root rotation
invalidates all derived keys and requires a coordinated migration. Existing
`CHAT_HOOK_SOURCES_JSON` sources remain usable and can be disabled from the UI.
They must be migrated to derived credentials separately before key rotation.

Field mapping supports safe dotted JSON paths for `id`, `type`, `timestamp`,
`summary`, and `data`. Stable IDs remain mandatory. No user-defined scripts,
arbitrary HTTP URL fetches, or templating are executed by the gateway. Full
payloads aren't shipped to Luna; it sees bounded summary metadata.

**Be explicit about what the mode means:**
- `triage`: apply Luna's configured app-level decision criteria.
- `wake`: request delivery to subscribed ChatGPT Work after the MCP pipeline is
  enabled; never bypasses action permissions.
- `digest`: retain the event for future batching, don't enqueue immediate wake.
- Disabling a source or its category blocks new webhook ingestion; the delivery
  worker must also recheck the toggle at time of send so already-queued events
  cannot escape. No live delivery is authorized just by changing a category.

The Luna editor changes the `worth_waking` question's additional instructions.
It does not modify the model's hidden system prompt. Each category has a
monotonic `policy_version`. Never change source-authentication, notification
permissions, or prompt-injection constraints through this field.

## Routing to existing ChatGPT chats

The single stable event type `hook.event` can carry `category`, `source`, and
`event_type` filters. **The callback URL is supplied by ChatGPT** during
`events/subscribe` in the destination Work chat. Pasting a chat UI URL into the
admin console cannot make events appear there; it's an index/link for the owner.
One Work chat can receive multiple events and use its chat instructions.

Categories:

| ID | Work conversation |
| --- | --- |
| `whatsapp` | WhatsApp Agent |
| `infra` | Infrastructure Operations |
| `research` | Research & Newsletters |
| `personal` | Personal Operations |
| `projects` | Business & Projects |

Review OpenAI's current Work/Projects support in the owner's actual interface.
Published help pages differ on whether Work is supported inside Projects, and
scheduled tasks created in projects can have limited project-file access.
Do not promise project files/instructions work on a particular event-triggered
run until verified end to end.

## Infrastructure monitoring target

Existing Dozzle error-level log alerts publish to ntfy `dozzle`. Do not simply
replace that transport with LLM decisions: P0 events need a direct fallback.

- **P0**: confirmed host/disk/database/security/backup-threatening condition.
  Immediate direct ntfy escalation plus a ChatGPT event (if available).
- **P1**: anomalous logs, repeat clusters, emerging errors. Redacted, deduped
  bounded summaries to Luna; request ChatGPT when warranted.
- **P2**: routine, transient or repeated noise. Retain for periodic digest and
  trend review without individual phone notification.
- **Periodic review**: every six hours, emit a single `infra.audit_due` check.
  ChatGPT Work then uses authorized BSPT Ops tools to inspect all four hosts,
  review trend evidence, and send a concise digest or actionable alert.

**Safe rollout:** shadow-classify against existing ntfy for at least a week;
measure sampled false negatives and incidents. Only after verification should
lower-priority direct ntfy alerts be reduced. Keep P0 direct fallbacks.

## Fishnet / Karakeep target

Fishnet receives and archives newsletter mail on Contabo. The current Telegram
LLM briefing is actually created in `karakeep/briefing.py`, not Fishnet. Wire
new entries or completed batches into `chat_hook` through a signed, authenticated
source. ChatGPT retrieves full items through authorized tools, writes summaries,
then chooses WhatsApp, ntfy, or no notification. Keep Karakeep's existing
Telegram briefing as a fallback until parity and delivery are proven.

## Still not production-complete

This admin slice does **not** install collectors on the VPSes, create Work chat
subscriptions, deploy the container, send WhatsApp/ntfy, or execute recurring
infrastructure checks. The MCP Events adapter, delivery worker, authenticated
ChatGPT outcome labeling, daily report delivery and one-time false-negative
review need an end-to-end test. Admin UI controls must not imply these are active.
