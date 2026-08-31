from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import Application, Gate, GatePolicy, GatePolicyGate
from app.schemas.admin import GatePolicyGateInput, GatePolicyResponse


DEFAULT_GATE_POLICY_ID = UUID("00000000-0000-4000-8000-000000000007")
DEFAULT_GATE_POLICY_SLUG = "default-security-policy"
CANONICAL_SEVERITIES = ("low", "medium", "high", "critical")


def gate_policy_query():
    return select(GatePolicy).options(
        selectinload(GatePolicy.gates).selectinload(GatePolicyGate.gate)
    )


def get_gate_policy(db: Session, policy_id: UUID) -> GatePolicy | None:
    return db.scalar(gate_policy_query().where(GatePolicy.id == policy_id))


def get_default_gate_policy(db: Session) -> GatePolicy | None:
    return db.scalar(
        gate_policy_query().where(GatePolicy.id == DEFAULT_GATE_POLICY_ID)
    )


def ensure_default_gate_policy(db: Session) -> GatePolicy:
    policy = get_default_gate_policy(db)
    if policy:
        return policy
    policy = GatePolicy(
        id=DEFAULT_GATE_POLICY_ID,
        name="Default Security Policy",
        slug=DEFAULT_GATE_POLICY_SLUG,
        description="Compatibility policy for the original shared security pipeline.",
        active=True,
    )
    db.add(policy)
    db.flush()
    return policy


def validate_policy_gates(
    db: Session, requested: list[GatePolicyGateInput]
) -> list[Gate]:
    gate_ids = [item.gate_id for item in requested]
    gates = list(db.scalars(select(Gate).where(Gate.id.in_(gate_ids))))
    by_id = {gate.id: gate for gate in gates}
    if len(by_id) != len(gate_ids):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Every policy gate must exist")
    if any(not gate.active for gate in gates):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Inactive gates cannot be added to a gate policy",
        )
    return [by_id[gate_id] for gate_id in gate_ids]


def replace_policy_gates(
    db: Session, policy: GatePolicy, requested: list[GatePolicyGateInput]
) -> list[Gate]:
    gates = validate_policy_gates(db, requested)
    policy.gates.clear()
    db.flush()
    for position, item in enumerate(requested):
        policy.gates.append(
            GatePolicyGate(
                id=uuid4(),
                gate_id=item.gate_id,
                position=position,
                blocking_severities=[severity.value for severity in item.blocking_severities],
            )
        )
    return gates


def serialize_gate_policy(db: Session, policy: GatePolicy) -> GatePolicyResponse:
    application_count = db.scalar(
        select(func.count(Application.id)).where(Application.gate_policy_id == policy.id)
    ) or 0
    return GatePolicyResponse(
        id=policy.id,
        name=policy.name,
        slug=policy.slug,
        description=policy.description,
        active=policy.active,
        gates=[
            {
                "gate_id": item.gate_id,
                "gate_name": item.gate.name,
                "gate_slug": item.gate.slug,
                "position": item.position,
                "blocking_severities": normalize_stored_severities(
                    item.blocking_severities
                ),
            }
            for item in sorted(policy.gates, key=lambda scope: scope.position)
        ],
        application_count=application_count,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def normalize_stored_severities(value: object) -> list[str]:
    if not isinstance(value, list):
        return list(CANONICAL_SEVERITIES)
    selected = {item for item in value if item in CANONICAL_SEVERITIES}
    if not selected:
        return list(CANONICAL_SEVERITIES)
    return [severity for severity in CANONICAL_SEVERITIES if severity in selected]
