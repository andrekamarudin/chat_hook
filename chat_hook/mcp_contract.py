"""MCP Events catalog and dispatch surface.

Callers must pass an authenticated Principal (see chat_hook.oauth). Nothing
here performs HTTP authentication itself.
"""

from chat_hook.delivery import NAME, CallbackError, subscribe, unsubscribe

VERSION = "0.4.0"
MCP2_VERSION = "2026-07-28"
SERVER_INFO = {"name": "Chat Hook", "version": VERSION}


def discover():
    return {"resultType": "complete", "supportedVersions": [MCP2_VERSION],
            "capabilities": {"events": {}, "tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO}}


def catalog(categories=None):
    from chat_hook.control import CATEGORIES

    allowed = sorted(c for c in CATEGORIES if categories is None or c in categories)
    return {"events": [{
        "name": NAME,
        "description": ("A validated Chat Hook event in one category needs assistant attention. "
                        "Subscribe once per category from the Work chat that owns that category. "
                        "The payload is a pointer and summary; use get_hook_event for details."),
        "delivery": ["webhook"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": allowed,
                             "description": "Category routed to this conversation."},
                "source": {"type": "string", "description": "Optional source slug within the category."},
                "event_type": {"type": "string", "description": "Optional exact event type."},
            },
            "required": ["category"],
            "additionalProperties": False,
        },
        "payloadSchema": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"}, "source": {"type": "string"},
                "event_type": {"type": "string"}, "summary": {"type": "string"},
                "route": {"type": "string"},
            },
            "required": ["event_id", "source", "event_type", "summary", "route"],
            "additionalProperties": False,
        },
    }]}


def event_request(method, params, principal):
    if principal is None or not principal.owner:
        raise ValueError("Missing authenticated principal")
    if method == "server/discover":
        return discover()
    principal.require("hooks.events")
    if method == "events/list":
        return catalog(principal.categories)
    if method == "events/subscribe":
        return subscribe(principal.owner, params.get("name"), params.get("arguments") or {},
                         params.get("delivery"), params.get("ttlMs"), principal.categories)
    if method == "events/unsubscribe":
        return unsubscribe(principal.owner, params.get("name"), params.get("arguments") or {},
                           params.get("delivery"))
    raise ValueError("Unsupported method")


__all__ = ["CallbackError", "catalog", "discover", "event_request"]
