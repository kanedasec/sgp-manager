from collections import defaultdict, deque
from datetime import UTC, datetime
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import api_credential
from app.core.config import get_settings
from app.core.database import get_db
from app.models import ApiCredential, Application, Gate
from app.repositories.policies import effective_policy_scopes
from app.schemas.evaluation import (
    EnforcementEvaluationResponse, EvaluatedGateEnforcement, EvaluatedPolicy, EvaluationRequest, EvaluationResponse,
)


router = APIRouter(prefix="/policies", tags=["pipeline policy evaluation"])
_hits: dict[str, deque[float]] = defaultdict(deque)
_hits_lock = Lock()


def enforce_rate_limit(request: Request) -> None:
    import time

    limit = get_settings().evaluate_rate_limit_per_minute
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _hits_lock:
        bucket = _hits[client]
        while bucket and bucket[0] < now - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
        bucket.append(now)


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
        EvaluatedPolicy(gate=scope.gate.slug, bypass_severities=scope.severities, expires_at=scope.expires_at)
        for scope in scopes
    ]
    return EvaluationResponse(application=application.slug, generated_at=now, policies=result)


@router.post(
    "/evaluate-enforcement",
    response_model=EnforcementEvaluationResponse,
    summary="Resolve blocking severities for CI/CD security gates",
    description=(
        "Fail-closed enforcement endpoint. Starts with each active gate's default blocking severities and removes "
        "only severities covered by a currently effective bypass for the requested active application."
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
    gate_query = select(Gate).where(Gate.active.is_(True))
    if data.gate:
        gate_query = gate_query.where(Gate.slug == data.gate)
    gates = list(db.scalars(gate_query.order_by(Gate.slug)))
    if data.gate and not gates:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Active gate not found")

    application = db.scalar(
        select(Application).where(Application.slug == data.application, Application.active.is_(True))
    )
    scopes = effective_policy_scopes(db, application.id, now, data.gate) if application else []
    bypasses = {scope.gate_id: set(scope.severities) for scope in scopes}
    canonical = ["low", "medium", "high", "critical"]
    result: list[EvaluatedGateEnforcement] = []
    for gate in gates:
        configured = gate.default_blocking_severities
        defaults = {item for item in configured if item in canonical} if isinstance(configured, list) else set()
        if not defaults:
            defaults = set(canonical)
        bypassed = bypasses.get(gate.id, set())
        result.append(EvaluatedGateEnforcement(
            gate=gate.slug,
            blocking_severities=[severity for severity in canonical if severity in defaults and severity not in bypassed],
        ))
    return EnforcementEvaluationResponse(application=data.application, generated_at=now, gates=result)
