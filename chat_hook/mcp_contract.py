"""MCP Events catalog and dispatch surface.

HTTP authentication must be verified before calling these functions.
"""

from chat_hook.delivery import NAME, subscribe, unsubscribe


def discover():
    return {"resultType": "complete", "supportedVersions": ["2026-07-28"],
            "capabilities": {"events": {}, "tools": {}},
            "_meta": {"io.modelcontextprotocol/serverInfo":
                      {"name": "Chat Hook", "version": "0.3.0"}}}


def catalog():
    return {"events": [{
        "name": NAME,
        "description": "A validated event requires an assistant to investigate it.",
        "delivery": ["webhook"],
        "inputSchema": {
            "type": "object",
            "properties": {"source": {"type": "string"}, "event_type": {"type": "string"}},
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


def event_request(method, params, owner):
    if not owner:
        raise ValueError("Missing authenticated principal")
    if method == "server/discover":
        return discover()
    if method == "events/list":
        return catalog()
    if method == "events/subscribe":
        return subscribe(owner, params.get("name"), params.get("arguments") or {},
                         params.get("delivery"), params.get("ttlMs"))
    if method == "events/unsubscribe":
        return unsubscribe(owner, params.get("name"), params.get("arguments") or {},
                           params.get("delivery"))
    raise ValueError("Unsupported method")
