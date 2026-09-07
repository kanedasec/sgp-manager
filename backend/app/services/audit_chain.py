"""Tamper-evident hash chaining for the audit log.

`audit_logs` had no protection against a database-level compromise
silently rewriting or deleting history: no API route allows editing or
deleting an entry (that part was already correct), but nothing stopped
someone with direct database access from doing so, and there was no way
to detect it after the fact.

Each row's `entry_hash` commits to its own fields plus the immediately
preceding row's `entry_hash` (classic hash chain / Merkle-list
construction), ordered by a database-assigned monotonic `sequence`
rather than the application-clock `timestamp`. Editing or deleting any
historical row breaks the hash of every row chained after it, which
`verify_chain` detects deterministically without needing any external
reference beyond the table itself.

This does not prevent a sufficiently privileged database attacker from
rewriting the *entire* chain from some point forward and recomputing
consistent hashes -- no purely in-database chain can prevent that on its
own. What it adds is: (1) partial/selective tampering (editing one row
without touching everything after it) becomes detectable, and (2) the
external audit webhook sink (PR #16) gives every event an independent
copy outside the database entirely, so a full in-database rewrite still
disagrees with what was actually delivered to the external SIEM at the
time.
"""

from __future__ import annotations

import hashlib
from datetime import UTC
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import AuditLog

GENESIS_HASH = "0" * 64


def _canonical_row_payload(
    sequence: int, prev_hash: str, event_type: str, actor_type: str, actor_id: str | None,
    entity_type: str | None, entity_id: str | None, timestamp: str, metadata: dict[str, Any],
    source_ip: str | None,
) -> str:
    import json

    return json.dumps(
        {
            "sequence": sequence, "prev_hash": prev_hash, "event_type": event_type, "actor_type": actor_type,
            "actor_id": actor_id, "entity_type": entity_type, "entity_id": entity_id, "timestamp": timestamp,
            "metadata": metadata, "source_ip": source_ip,
        },
        sort_keys=True, separators=(",", ":"), default=str,
    )


def compute_entry_hash(
    sequence: int, prev_hash: str, event_type: str, actor_type: str, actor_id: str | None,
    entity_type: str | None, entity_id: str | None, timestamp: str, metadata: dict[str, Any],
    source_ip: str | None,
) -> str:
    payload = _canonical_row_payload(
        sequence, prev_hash, event_type, actor_type, actor_id, entity_type, entity_id, timestamp, metadata,
        source_ip,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_SESSION_CHAIN_STATE_KEY = "sgp_audit_chain_tip"


def latest_chain_state(db: Session) -> tuple[int, str]:
    """Returns (last_sequence, last_hash) for the most recently chained
    row, or (0, GENESIS_HASH) if the chain is empty.

    Cached in `db.info` for the lifetime of the session/transaction: the
    session is created with autoflush=False (see app.core.database), so a
    second record_audit() call within the same not-yet-committed
    transaction would not see the first call's pending insert via a plain
    SELECT. Caching the running tip in Python avoids relying on
    flush/visibility semantics for chaining multiple audit entries written
    in the same request. The first read in a session still queries the
    database (with a row lock where the backend supports one) to serialize
    against other, already-committed sessions/replicas.
    """
    cached = db.info.get(_SESSION_CHAIN_STATE_KEY)
    if cached is not None:
        return cached
    row = db.execute(
        select(AuditLog.sequence, AuditLog.entry_hash)
        .where(AuditLog.entry_hash.is_not(None))
        .order_by(AuditLog.sequence.desc())
        .limit(1)
        .with_for_update()
    ).first()
    state = (0, GENESIS_HASH) if row is None or row.sequence is None or row.entry_hash is None else (row.sequence, row.entry_hash)
    db.info[_SESSION_CHAIN_STATE_KEY] = state
    return state


def advance_chain_state(db: Session, sequence: int, entry_hash: str) -> None:
    """Records the tip after a new row has been added (not yet committed)
    so the next record_audit() call in the same transaction chains onto
    it. Must be paired with clear_chain_state() on rollback -- otherwise a
    rolled-back write's hash would incorrectly seed the next attempt."""
    db.info[_SESSION_CHAIN_STATE_KEY] = (sequence, entry_hash)


def clear_chain_state(db: Session) -> None:
    db.info.pop(_SESSION_CHAIN_STATE_KEY, None)


class ChainVerificationError(Exception):
    def __init__(self, entry_id: str, sequence: int | None, reason: str):
        self.entry_id = entry_id
        self.sequence = sequence
        self.reason = reason
        super().__init__(f"audit chain broken at entry {entry_id} (sequence={sequence}): {reason}")


def verify_chain(db: Session) -> int:
    """Recomputes every hashed row's entry_hash from its stored fields and
    checks it against both the stored value and the next row's prev_hash.
    Returns the count of verified rows. Raises ChainVerificationError on
    the first mismatch found, which is the specific row (or a row
    immediately after it) that was altered or removed. Rows written
    before this feature shipped (entry_hash is NULL) are skipped, not
    treated as a break -- the chain guarantee only covers hashed rows."""
    rows = db.scalars(
        select(AuditLog).where(AuditLog.entry_hash.is_not(None)).order_by(AuditLog.sequence.asc())
    ).all()
    expected_prev = GENESIS_HASH
    verified = 0
    for row in rows:
        if row.prev_hash != expected_prev:
            raise ChainVerificationError(str(row.id), row.sequence, "prev_hash does not match the preceding entry")
        # Must normalize identically to app.services.audit.record_audit's
        # write-time hash input: SQLite drops tzinfo on a
        # DateTime(timezone=True) round-trip, so a raw row.timestamp read
        # back from the database may be naive even though it was aware
        # (and UTC) at write time. Treating a naive value as already-UTC
        # (rather than calling astimezone, which would misinterpret it as
        # local time) reproduces the exact bytes that were hashed.
        row_timestamp = row.timestamp if row.timestamp.tzinfo else row.timestamp.replace(tzinfo=UTC)
        timestamp_iso = row_timestamp.astimezone(UTC).replace(tzinfo=None).isoformat()
        recomputed = compute_entry_hash(
            row.sequence, row.prev_hash, row.event_type, row.actor_type, row.actor_id, row.entity_type,
            row.entity_id, timestamp_iso, row.event_metadata, row.source_ip,
        )
        if recomputed != row.entry_hash:
            raise ChainVerificationError(str(row.id), row.sequence, "stored entry_hash does not match its own fields")
        expected_prev = row.entry_hash
        verified += 1
    return verified
