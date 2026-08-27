from datetime import UTC, datetime
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Application, BypassPolicy, BypassPolicyGate, Gate, OwnerLabel, User
from app.repositories.policies import overlapping_policy
from app.schemas.admin import PolicyCreate, PolicyGateInput, PolicyGateResponse, PolicyResponse
from app.services.audit import record_audit


def aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def serialize_policy(policy: BypassPolicy) -> PolicyResponse:
    scopes = sorted(policy.gate_scopes, key=lambda item: item.gate.name.lower())
    return PolicyResponse(
        id=policy.id,
        application_id=policy.application_id,
        application_name=policy.application.name,
        application_slug=policy.application.slug,
        owner_id=policy.owner_id,
        owner_name=policy.owner.name,
        owner_slug=policy.owner.slug,
        gates=[PolicyGateResponse(
            gate_id=scope.gate_id,
            gate_name=scope.gate.name,
            gate_slug=scope.gate.slug,
            severities=scope.severities,
        ) for scope in scopes],
        justification=policy.justification,
        valid_from=policy.valid_from,
        expires_at=policy.expires_at,
        created_by=policy.created_by,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        revoked_at=policy.revoked_at,
        revoked_by=policy.revoked_by,
        revoke_reason=policy.revoke_reason,
        status=policy.status,
    )


def validate_gates(
    db: Session, application_id, owner_id, gates: list[PolicyGateInput], valid_from: datetime, expires_at: datetime,
    exclude_policy_id=None,
) -> list[Gate]:
    resolved: list[Gate] = []
    for requested in gates:
        gate = db.get(Gate, requested.gate_id)
        if not gate or not gate.active:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Gate {requested.gate_id} does not exist or is inactive")
        if gate.owner_id != owner_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Gate '{gate.slug}' belongs to a different owner; all gates must match the policy owner",
            )
        conflict = overlapping_policy(db, application_id, gate.id, valid_from, expires_at, exclude_policy_id)
        if conflict:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Gate '{gate.slug}' overlaps existing policy {conflict.policy_id} for this application",
            )
        resolved.append(gate)
    return resolved


def replace_policy_scopes(
    policy: BypassPolicy, requested: list[PolicyGateInput], valid_from: datetime, expires_at: datetime,
) -> None:
    existing = {scope.gate_id: scope for scope in policy.gate_scopes}
    requested_ids = {item.gate_id for item in requested}
    for scope in list(policy.gate_scopes):
        if scope.gate_id not in requested_ids:
            policy.gate_scopes.remove(scope)
    for item in requested:
        scope = existing.get(item.gate_id)
        if scope is None:
            scope = BypassPolicyGate(id=uuid4(), application_id=policy.application_id, gate_id=item.gate_id)
            policy.gate_scopes.append(scope)
        scope.severities = [severity.value for severity in item.severities]
        scope.valid_from = valid_from
        scope.expires_at = expires_at
        scope.revoked_at = policy.revoked_at


def create_policy(db: Session, data: PolicyCreate, user: User, source_ip: str | None) -> BypassPolicy:
    application = db.get(Application, data.application_id)
    if not application or not application.active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Application does not exist or is inactive")
    now = datetime.now(UTC)
    valid_from = data.valid_from or now
    owner = db.get(OwnerLabel, data.owner_id)
    if not owner or not owner.active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Owner does not exist or is inactive")
    resolved_gates = validate_gates(
        db, data.application_id, data.owner_id, data.gates, valid_from, data.expires_at
    )
    policy = BypassPolicy(
        id=uuid4(), application_id=data.application_id, owner_id=data.owner_id, justification=data.justification.strip(),
        valid_from=valid_from, expires_at=data.expires_at, created_by=user.id,
    )
    replace_policy_scopes(policy, data.gates, valid_from, data.expires_at)
    db.add(policy)
    record_audit(
        db, "BYPASS_CREATED", "USER", user.id, "BYPASS_POLICY", policy.id,
        {
            "application": application.slug,
            "owner": owner.slug,
            "gates": [gate.slug for gate in resolved_gates],
            "gate_policies": [
                {"gate": gate.slug, "severities": [s.value for s in requested.severities]}
                for gate, requested in zip(resolved_gates, data.gates, strict=True)
            ],
            "expires_at": data.expires_at.isoformat(),
        },
        source_ip,
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "One or more gate policy windows conflict with an existing policy") from None
    db.refresh(policy)
    return policy
