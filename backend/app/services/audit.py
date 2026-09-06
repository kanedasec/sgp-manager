from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.metrics import record_business_event
from app.models import AuditLog
from app.services.audit_sink import build_payload, submit_delivery


SENSITIVE_KEYS = {"password", "password_hash", "api_key", "key_hash", "access_token", "authorization"}

_PENDING_WEBHOOK_PAYLOADS_KEY = "sgp_pending_audit_webhook_payloads"


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
    entry_id = uuid4()
    timestamp = datetime.now(UTC)
    sanitized_metadata = sanitize_metadata(metadata or {})
    entry = AuditLog(
        id=entry_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id else None,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id else None,
        event_metadata=sanitized_metadata,
        source_ip=source_ip,
        timestamp=timestamp,
    )
    db.add(entry)
    # Both the external SIEM webhook and the sgp_business_events_total metric
    # are only dispatched from the after_commit hook below, so a rolled-back
    # transaction (e.g. a later IntegrityError in the same request) never
    # forwards or counts an event for state that was never actually
    # persisted.
    payload = build_payload(
        entry_id, event_type, actor_type, entry.actor_id, entity_type, entry.entity_id,
        timestamp.isoformat(), sanitized_metadata, source_ip,
    )
    db.info.setdefault(_PENDING_WEBHOOK_PAYLOADS_KEY, []).append((event_type, payload))
    return entry


@event.listens_for(Session, "after_commit")
def _dispatch_pending_audit_events(session: Session) -> None:
    pending = session.info.pop(_PENDING_WEBHOOK_PAYLOADS_KEY, None)
    if not pending:
        return
    for event_type, payload in pending:
        record_business_event(event_type)
        submit_delivery(payload)


@event.listens_for(Session, "after_rollback")
def _discard_pending_audit_events_on_rollback(session: Session) -> None:
    session.info.pop(_PENDING_WEBHOOK_PAYLOADS_KEY, None)

