from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models import BypassPolicy, BypassPolicyGate, Gate


def overlapping_policy(
    db: Session, application_id: UUID, gate_id: UUID, valid_from: datetime, expires_at: datetime,
    exclude_id: UUID | None = None,
) -> BypassPolicyGate | None:
    statement = select(BypassPolicyGate).where(
        BypassPolicyGate.application_id == application_id,
        BypassPolicyGate.gate_id == gate_id,
        BypassPolicyGate.revoked_at.is_(None),
        BypassPolicyGate.valid_from < expires_at,
        BypassPolicyGate.expires_at > valid_from,
    )
    if exclude_id:
        statement = statement.where(BypassPolicyGate.policy_id != exclude_id)
    return db.scalar(statement)


def policy_query():
    return select(BypassPolicy).options(
        joinedload(BypassPolicy.application),
        joinedload(BypassPolicy.owner),
        joinedload(BypassPolicy.gate_scopes).joinedload(BypassPolicyGate.gate),
    )


def effective_policy_scopes(db: Session, application_id: UUID, now: datetime, gate_slug: str | None = None):
    statement = (
        select(BypassPolicyGate)
        .join(BypassPolicyGate.policy)
        .join(BypassPolicyGate.gate)
        .options(joinedload(BypassPolicyGate.gate), joinedload(BypassPolicyGate.policy))
        .where(
            BypassPolicyGate.application_id == application_id,
            BypassPolicyGate.revoked_at.is_(None),
            BypassPolicyGate.valid_from <= now,
            BypassPolicyGate.expires_at > now,
            BypassPolicy.revoked_at.is_(None),
            Gate.active.is_(True),
            # Defense in depth for pentest finding F-01: a gate's owner_id
            # can change after a bypass was created for it (the update path
            # itself now blocks that while an active bypass exists -- see
            # app.api.admin.update_gate -- but this keeps enforcement
            # correct even against any other route or direct-write path
            # that might move a gate's owner without going through it).
            BypassPolicy.owner_id == Gate.owner_id,
        )
    )
    if gate_slug:
        statement = statement.where(Gate.slug == gate_slug)
    return list(db.scalars(statement.order_by(BypassPolicyGate.expires_at, Gate.slug)).unique())
