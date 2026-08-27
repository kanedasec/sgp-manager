from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models import AuditLog


SENSITIVE_KEYS = {"password", "password_hash", "api_key", "key_hash", "access_token", "authorization"}


def sanitize_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: sanitize_metadata(item) for key, item in value.items() if key.lower() not in SENSITIVE_KEYS}
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]
    return value


def record_audit(
    db: Session,
    event_type: str,
    actor_type: str,
    actor_id: UUID | str | None,
    entity_type: str | None = None,
    entity_id: UUID | str | None = None,
    metadata: dict | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        event_type=event_type,
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id else None,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id else None,
        event_metadata=sanitize_metadata(metadata or {}),
        source_ip=source_ip,
    )
    db.add(entry)
    return entry

