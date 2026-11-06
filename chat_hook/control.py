"""Runtime event-source and topic policy controls. No new code deploy for ordinary hooks.

Admin bearer checks are provided by the existing Chat Hook API. New hook secrets
are derived from an Infisical-backed root, never stored plaintext in SQLite.
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from chat_hook.app import connect, require_admin

SLUG = re.compile(r"^[a-z][a-z0-9_-]{1,39}$")
CATEGORIES = {
    "whatsapp": "WhatsApp Agent",
    "infra": "Infrastructure Operations",
    "research": "Research & Newsletters",
    "personal": "Personal Operations",
    "projects": "Business & Projects",
}
MODES = {"triage", "wake", "digest"}
KINDS = {"webhook", "waha", "fishnet", "internal", "schedule", "infra"}

router = APIRouter(prefix="/v1/admin", dependencies=[Depends(require_admin)])


def now():
    return datetime.now(UTC).isoformat()


def setup_schema(db: sqlite3.Connection):
    db.execute("""CREATE TABLE IF NOT EXISTS hook_categories (
        slug TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        chat_url TEXT NOT NULL DEFAULT '', luna_prompt TEXT NOT NULL DEFAULT '',
        ignore_threshold REAL NOT NULL DEFAULT 0.10,
        wake_threshold REAL NOT NULL DEFAULT 0.80,
        policy_version INTEGER NOT NULL DEFAULT 1,
        changed_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS hook_sources (
        slug TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
        category TEXT NOT NULL REFERENCES hook_categories(slug),
        enabled INTEGER NOT NULL DEFAULT 1, mode TEXT NOT NULL DEFAULT 'triage',
        key_version INTEGER NOT NULL DEFAULT 1, credential_type TEXT NOT NULL DEFAULT 'derived',
        field_map_json TEXT NOT NULL DEFAULT '{}', changed_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS config_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
        action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL)""")
    for slug, name in CATEGORIES.items():
        db.execute("""INSERT OR IGNORE INTO hook_categories
            (slug,name,changed_at) VALUES (?,?,?)""", (slug, name, now()))
    # Preserve working env-configured sources. Existing keys remain in Infisical.
    legacy = json.loads(os.getenv("CHAT_HOOK_SOURCES_JSON", "{}"))
    if isinstance(legacy, dict):
        for slug in legacy:
            if SLUG.fullmatch(slug):
                db.execute("""INSERT OR IGNORE INTO hook_sources
                    (slug,name,kind,category,credential_type,changed_at)
                    VALUES (?,?,?,?,?,?)""",
                    (slug, slug, "waha" if slug == "waha" else "webhook",
                     "whatsapp" if slug == "waha" else "projects", "legacy", now()))


def audit(db, action, target, detail=None):
    # No credentials or untrusted raw message content in audit records.
    db.execute("INSERT INTO config_audit(at,action,target,detail) VALUES (?,?,?,?)",
               (now(), action, target, json.dumps(detail or {}, sort_keys=True)))


def get_source(slug: str):
    try:
        with connect() as db:
            db.row_factory = sqlite3.Row
            row = db.execute("""SELECT s.*,c.enabled as category_enabled
                FROM hook_sources s JOIN hook_categories c ON s.category=c.slug
                WHERE s.slug=?""", (slug,)).fetchone()
    except sqlite3.OperationalError:
        # Pure model-client usage can occur before the ASGI lifespan starts.
        return None
    return dict(row) if row else None


def derived_key(slug, version):
    root = os.getenv("CHAT_HOOK_SOURCE_ROOT", "")
    if len(root) < 32:
        raise HTTPException(503, "Source signing root is not configured")
    return hmac.new(root.encode(), f"chat-hook/source/v1/{slug}/{version}".encode(),
                    hashlib.sha256).hexdigest()


def ingress_key(slug):
    config = get_source(slug)
    if config is None:
        # Read-only fallback for legacy deployments before schema initialization.
        return json.loads(os.getenv("CHAT_HOOK_SOURCES_JSON", "{}" )).get(slug)
    if not config["enabled"] or not config["category_enabled"]:
        raise HTTPException(403, "Source is disabled")
    if config["credential_type"] == "legacy":
        legacy = json.loads(os.getenv("CHAT_HOOK_SOURCES_JSON", "{}"))
        if slug not in legacy:
            raise HTTPException(503, "Legacy credential missing")
        return legacy[slug]
    return derived_key(slug, config["key_version"])


def policy_for_source(slug):
    cfg = get_source(slug)
    if cfg is None:
        return None
    with connect() as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM hook_categories WHERE slug=?",
                         (cfg["category"],)).fetchone()
    return dict(row) if row else None


def extract_field(payload, dotted):
    value = payload
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def mapped_payload(slug, body):
    cfg = get_source(slug)
    if not cfg or cfg["kind"] == "waha":
        return body
    mapping = json.loads(cfg["field_map_json"])
    if not mapping:
        return body
    values = {}
    for key in ("id", "type", "timestamp", "summary", "data"):
        if mapping.get(key):
            values[key] = extract_field(body, mapping[key])
        else:
            values[key] = body.get(key)
    # A missing stable ID is not replaced with a guessed hash.
    return values


class CreateSource(BaseModel):
    slug: str = Field(min_length=2, max_length=40)
    name: str = Field(min_length=1, max_length=80)
    kind: str = "webhook"
    category: str = "projects"
    mode: str = "triage"
    enabled: bool = False
    field_map: dict[str, str] = Field(default_factory=dict)


class PatchSource(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = None
    category: str | None = None
    mode: str | None = None
    field_map: dict[str, str] | None = None


class PatchCategory(BaseModel):
    enabled: bool | None = None
    chat_url: str | None = Field(default=None, max_length=1024)
    luna_prompt: str | None = Field(default=None, max_length=4000)
    ignore_threshold: float | None = Field(default=None, ge=0, le=1)
    wake_threshold: float | None = Field(default=None, ge=0, le=1)


def validate_mapping(mapping):
    if set(mapping) - {"id", "type", "timestamp", "summary", "data"}:
        raise HTTPException(422, "Invalid field map key")
    if any(not isinstance(v, str) or len(v) > 90 or not re.fullmatch(
            r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", v) for v in mapping.values()):
        raise HTTPException(422, "Invalid source field path")


@router.get("/config")
def config():
    with connect() as db:
        db.row_factory = sqlite3.Row
        categories = [dict(row) for row in db.execute("SELECT * FROM hook_categories ORDER BY slug")]
        sources = [dict(row) for row in db.execute("SELECT * FROM hook_sources ORDER BY slug")]
        audits = [dict(row) for row in db.execute("SELECT * FROM config_audit ORDER BY id DESC LIMIT 30")]
    for item in sources:
        item["field_map"] = json.loads(item.pop("field_map_json"))
    return {"categories": categories, "sources": sources, "recent_config_changes": audits,
            "delivery_configurable": False,
            "note": "Chat URLs are display links, not MCP delivery credentials. Subscribe inside each Work chat."}


@router.post("/sources", status_code=201)
def create_source(data: CreateSource):
    if not SLUG.fullmatch(data.slug) or data.kind not in KINDS or data.mode not in MODES:
        raise HTTPException(422, "Invalid source slug, kind or mode")
    if data.category not in CATEGORIES:
        raise HTTPException(422, "Invalid category")
    validate_mapping(data.field_map)
    key = derived_key(data.slug, 1)  # Fail closed if master key is absent.
    try:
        with connect() as db:
            db.execute("""INSERT INTO hook_sources
                (slug,name,kind,category,enabled,mode,field_map_json,changed_at)
                VALUES (?,?,?,?,?,?,?,?)""", (data.slug, data.name, data.kind, data.category,
                        int(data.enabled), data.mode, json.dumps(data.field_map), now()))
            audit(db, "source.created", data.slug, {"kind": data.kind, "category": data.category})
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "Source already exists") from exc
    return {"slug": data.slug, "url_path": "/v1/ingest/" + data.slug,
            "signing_key": key, "note": "Copy securely. Never put this value in a URL or log."}


@router.patch("/sources/{slug}")
def patch_source(slug: str, data: PatchSource):
    changes = data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, "No changes")
    if any(changes.get(k) is None for k in ("name", "enabled", "category", "mode")
           if k in changes):
        raise HTTPException(422, "Source fields cannot be null")
    if changes.get("category") not in (None, *CATEGORIES.keys()):
        raise HTTPException(422, "Invalid category")
    if changes.get("mode") not in (None, *MODES):
        raise HTTPException(422, "Invalid mode")
    if changes.get("field_map") is not None:
        validate_mapping(changes["field_map"])
        changes["field_map_json"] = json.dumps(changes.pop("field_map"))
    if "enabled" in changes:
        changes["enabled"] = int(changes["enabled"])
    cols = ",".join(f"{key}=?" for key in changes)
    with connect() as db:
        updated = db.execute(f"UPDATE hook_sources SET {cols},changed_at=? WHERE slug=?",
                             [*changes.values(), now(), slug]).rowcount
        if updated:
            audit(db, "source.updated", slug, {key: value for key, value in changes.items()
                                               if key != "field_map_json"})
    if not updated:
        raise HTTPException(404, "Source not found")
    return {"slug": slug, "updated": list(changes)}


@router.post("/sources/{slug}/rotate")
def rotate_source(slug: str):
    config = get_source(slug)
    if not config:
        raise HTTPException(404, "Unknown source")
    if config["credential_type"] != "derived":
        raise HTTPException(409, "Legacy source credentials must be migrated first")
    key = derived_key(slug, config["key_version"] + 1)
    with connect() as db:
        db.execute("UPDATE hook_sources SET key_version=key_version+1,changed_at=? WHERE slug=?",
                   (now(), slug))
        audit(db, "source.rotated", slug)
    return {"slug": slug, "signing_key": key, "note": "Old signing key is now invalid"}


@router.patch("/categories/{slug}")
def patch_category(slug: str, data: PatchCategory):
    if slug not in CATEGORIES:
        raise HTTPException(404, "Unknown category")
    changes = data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, "No changes")
    if changes.get("chat_url"):
        url = urlsplit(changes["chat_url"])
        if (url.scheme != "https" or url.netloc != "chatgpt.com"
                or "/c/" not in url.path or url.username or url.password):
            raise HTTPException(422, "Only ChatGPT conversation links are allowed")
    if "enabled" in changes:
        changes["enabled"] = int(changes["enabled"])
    with connect() as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM hook_categories WHERE slug=?", (slug,)).fetchone()
        candidate = dict(row)
        candidate.update(changes)
        if not 0 <= candidate["ignore_threshold"] < candidate["wake_threshold"] <= 1:
            raise HTTPException(422, "Ignore threshold must be below wake threshold")
        changes["policy_version"] = row["policy_version"] + 1
        cols = ",".join(f"{key}=?" for key in changes)
        db.execute(f"UPDATE hook_categories SET {cols},changed_at=? WHERE slug=?",
                   [*changes.values(), now(), slug])
        audit(db, "category.updated", slug, {"changed_fields": sorted(changes)})
    return {"slug": slug, "policy_version": changes["policy_version"]}


@router.get("/audit")
def audits(limit: int = 50):
    if not 1 <= limit <= 200:
        raise HTTPException(422, "Invalid limit")
    with connect() as db:
        db.row_factory = sqlite3.Row
        return {"changes": [dict(row) for row in db.execute(
            "SELECT * FROM config_audit ORDER BY id DESC LIMIT ?", (limit,))]}
