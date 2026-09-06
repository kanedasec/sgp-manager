"""Asynchronous external audit sink (SIEM webhook forwarding).

`audit_logs` in PostgreSQL is the durable source of truth and is never
bypassed or delayed by this module: delivery to an external SIEM is a
best-effort copy, submitted to a background thread pool only after the
owning database transaction actually commits (see the SQLAlchemy Session
events registered in app.services.audit), so a SIEM outage can never
block, slow down, or roll back an administrative action, and a rolled
back transaction never delivers an event for state that was never
persisted.

Delivery is signed (HMAC-SHA256 over the raw JSON body) so the receiver
can verify authenticity, and retried with bounded exponential backoff
before being dropped and logged as a delivery failure — the event
remains fully available in the local `audit_logs` table regardless.

Configuring `AUDIT_WEBHOOK_URL` is optional. Without it, this module is
inert and audit events are recorded only in PostgreSQL as before.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import UUID

import httpx

from app.core.config import get_settings
from app.core.metrics import record_webhook_delivery

logger = logging.getLogger("audit_sink")

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-sink")


def _serialize(entry: dict[str, Any]) -> str:
    return json.dumps(entry, default=str, sort_keys=True, separators=(",", ":"))


def _sign(body: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()


def build_payload(
    event_id: UUID,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    entity_type: str | None,
    entity_id: str | None,
    timestamp: str,
    metadata: dict[str, Any],
    source_ip: str | None,
) -> dict[str, Any]:
    return {
        "id": str(event_id),
        "event_type": event_type,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "timestamp": timestamp,
        "metadata": metadata,
        "source_ip": source_ip,
    }


def deliver(payload: dict[str, Any]) -> bool:
    """Best-effort delivery with bounded retries and exponential backoff.
    Intended to run off the request thread (see `submit_delivery`).
    Returns True if the receiver acknowledged with a 2xx status, False
    otherwise; never raises so a failure can never surface to the caller
    that recorded the audit event."""
    settings = get_settings()
    if not settings.audit_webhook_url:
        return False
    body = _serialize(payload)
    headers = {"Content-Type": "application/json"}
    if settings.audit_webhook_secret:
        headers["X-SGP-Signature"] = _sign(body, settings.audit_webhook_secret.get_secret_value())
    attempts = max(1, settings.audit_webhook_max_retries)
    for attempt in range(1, attempts + 1):
        try:
            response = httpx.post(
                settings.audit_webhook_url,
                content=body,
                headers=headers,
                timeout=settings.audit_webhook_timeout_seconds,
            )
            if 200 <= response.status_code < 300:
                record_webhook_delivery(success=True)
                return True
            logger.warning(
                "audit webhook delivery rejected",
                extra={"status": response.status_code, "attempt": attempt, "event_id": payload.get("id")},
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "audit webhook delivery failed",
                extra={"error": str(exc), "attempt": attempt, "event_id": payload.get("id")},
            )
        if attempt < attempts:
            time.sleep(min(2 ** (attempt - 1), 8))
    logger.error(
        "audit webhook delivery exhausted retries, event kept only in the local audit log",
        extra={"event_id": payload.get("id")},
    )
    record_webhook_delivery(success=False)
    return False


def submit_delivery(payload: dict[str, Any]) -> None:
    """Hand a payload off for delivery without blocking the caller. No-op
    when no webhook is configured. Delivery normally runs on a background
    thread; deployments/tests may set `audit_webhook_deliver_synchronously`
    to force inline delivery (used by the test suite to assert behavior
    deterministically without waiting on a background thread)."""
    settings = get_settings()
    if not settings.audit_webhook_url:
        return
    if settings.audit_webhook_deliver_synchronously:
        deliver(payload)
        return
    _executor.submit(deliver, payload)
