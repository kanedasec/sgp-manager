from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import api_credential
from app.core.config import get_settings
from app.core.database import get_db
from app.core.metrics import record_enforcement_decision
from app.core.rate_limit import hit_count
from app.models import ApiCredential, Application, Gate, GatePolicy, GatePolicyGate
from app.repositories.policies import effective_policy_scopes
from app.schemas.evaluation import (
    EnforcementEvaluationResponse, EvaluatedGateEnforcement, EvaluatedPolicy, EvaluationRequest, EvaluationResponse,
    PipelineResolutionRequest, PipelineResolutionResponse, ResolvedPipelineGate,
)
from app.services.gate_policies import normalize_stored_severities


router = APIRouter(prefix="/policies", tags=["pipeline policy evaluation"])


def enforce_rate_limit(request: Request) -> None:
    limit = get_settings().evaluate_rate_limit_per_minute
    client = request.client.host if request.client else "unknown"
    if hit_count(client, limit) > limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")


@router.post(
    "/evaluate",
    response_model=EvaluationResponse,
    summary="Evaluate effective bypass policies for a CI/CD pipeline",
    description="Fail-closed endpoint. Only currently effective, non-revoked policies for active applications and gates are returned.",
)
def evaluate(
    data: EvaluationRequest,
    request: Request,
    _: ApiCredential = Depends(api_credential),
    db: Session = Depends(get_db),
):
    enforce_rate_limit(request)
    now = datetime.now(UTC)
    application = db.scalar(select(Application).where(Application.slug == data.application, Application.active.is_(True)))
    if not application:
        return EvaluationResponse(application=data.application, generated_at=now, policies=[])
    scopes = effective_policy_scopes(db, application.id, now, data.gate)
    result = [
        EvaluatedPolicy(
            gate=scope.gate.slug, bypass_severities=scope.severities,
            finding_scope=scope.finding_scope or None, expires_at=scope.expires_at,
        )
        for scope in scopes
    ]
    return EvaluationResponse(application=application.slug, generated_at=now, policies=result)


@router.post(
    "/resolve-pipeline",
    response_model=PipelineResolutionResponse,
    summary="Resolve the ordered security pipeline for an application",
    description=(
        "Fail-closed pipeline discovery endpoint. Returns the active gates selected by the reusable gate policy "
        "assigned to the application. Unknown or inactive applications and invalid policies are rejected."
    ),
)
def resolve_pipeline(
    data: PipelineResolutionRequest,
    request: Request,
    _: ApiCredential = Depends(api_credential),
    db: Session = Depends(get_db),
):
    enforce_rate_limit(request)
    now = datetime.now(UTC)
    application = db.scalar(select(Application).options(
        selectinload(Application.gate_policy)
        .selectinload(GatePolicy.gates)
        .selectinload(GatePolicyGate.gate)
    ).where(Application.slug == data.application, Application.active.is_(True)))
    if not application:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Active application not found")
    policy = application.gate_policy
    if not policy or not policy.active:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Application gate policy is not active")
    scopes = sorted(policy.gates, key=lambda item: item.position)
    if not scopes or any(not scope.gate.active for scope in scopes):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Application gate policy is invalid")
    if [scope.position for scope in scopes] != list(range(len(scopes))):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Application gate policy order is invalid")

    return PipelineResolutionResponse(
        application=application.slug,
        gate_policy=policy.slug,
        gate_policy_name=policy.name,
        generated_at=now,
        gates=[
            ResolvedPipelineGate(gate=scope.gate.slug, position=scope.position)
            for scope in scopes
        ],
    )


@router.post(
    "/evaluate-enforcement",
    response_model=EnforcementEvaluationResponse,
    summary="Resolve blocking severities for CI/CD security gates",
    description=(
        "Fail-closed enforcement endpoint. Uses the assigned gate policy for a known application and removes only "
        "severities covered by a currently effective bypass. Unknown applications receive full gate defaults."
    ),
)
def evaluate_enforcement(
    data: EvaluationRequest,
    request: Request,
    _: ApiCredential = Depends(api_credential),
    db: Session = Depends(get_db),
):
    enforce_rate_limit(request)
    now = datetime.now(UTC)
    requested_gate = None
    if data.gate:
        requested_gate = db.scalar(select(Gate).where(Gate.slug == data.gate, Gate.active.is_(True)))
    if data.gate and not requested_gate:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Active gate not found")

    application = db.scalar(select(Application).options(
        selectinload(Application.gate_policy)
        .selectinload(GatePolicy.gates)
        .selectinload(GatePolicyGate.gate)
    ).where(Application.slug == data.application, Application.active.is_(True)))
    scopes = effective_policy_scopes(db, application.id, now, data.gate) if application else []
    # Unscoped bypasses (finding_scope empty/None) remove the whole severity, matching
    # the original coarse behavior. Finding-scoped bypasses never remove a severity:
    # the pipeline cannot prove every finding at that severity is covered, only that
    # the specific listed finding IDs are, so those IDs are surfaced separately in
    # bypassed_findings while blocking_severities keeps blocking everything else.
    unscoped_bypasses: dict[object, set[str]] = {}
    scoped_findings: dict[object, list[tuple[set[str], set[str]]]] = {}
    for scope in scopes:
        if scope.finding_scope:
            # A finding-scoped bypass still only applies within its own selected
            # severities; a finding listed under a "high" bypass does not silently
            # cover the same finding at "critical".
            scoped_findings.setdefault(scope.gate_id, []).append(
                (set(scope.severities), set(scope.finding_scope))
            )
        else:
            unscoped_bypasses.setdefault(scope.gate_id, set()).update(scope.severities)
    canonical = ["low", "medium", "high", "critical"]
    result: list[EvaluatedGateEnforcement] = []
    if application:
        policy = application.gate_policy
        if not policy or not policy.active or not policy.gates:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Application gate policy is invalid")
        policy_by_gate = {item.gate_id: item for item in policy.gates if item.gate.active}
        if len(policy_by_gate) != len(policy.gates):
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Application gate policy is invalid")
        if requested_gate and requested_gate.id not in policy_by_gate:
            return EnforcementEvaluationResponse(
                application=data.application,
                generated_at=now,
                gates=[EvaluatedGateEnforcement(gate=requested_gate.slug, blocking_severities=[])],
            )
        selected = (
            [policy_by_gate[requested_gate.id]] if requested_gate
            else sorted(policy.gates, key=lambda item: item.position)
        )
        configured_gates = [
            (item.gate, normalize_stored_severities(item.blocking_severities))
            for item in selected
        ]
    else:
        gate_query = select(Gate).where(Gate.active.is_(True))
        if requested_gate:
            gate_query = gate_query.where(Gate.id == requested_gate.id)
        configured_gates = [
            (gate, normalize_stored_severities(gate.default_blocking_severities))
            for gate in db.scalars(gate_query.order_by(Gate.slug))
        ]
    for gate, configured in configured_gates:
        defaults = set(configured)
        unscoped = unscoped_bypasses.get(gate.id, set())
        blocking = [severity for severity in canonical if severity in defaults and severity not in unscoped]
        bypassed_findings: set[str] = set()
        for scoped_severities, finding_ids in scoped_findings.get(gate.id, []):
            if scoped_severities & set(blocking):
                bypassed_findings.update(finding_ids)
        record_enforcement_decision(gate.slug, blocking)
        result.append(EvaluatedGateEnforcement(
            gate=gate.slug,
            blocking_severities=blocking,
            bypassed_findings=sorted(bypassed_findings),
        ))
    return EnforcementEvaluationResponse(application=data.application, generated_at=now, gates=result)
