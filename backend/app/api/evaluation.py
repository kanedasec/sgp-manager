from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import api_credential, api_credential_application_manage, source_ip
from app.core.config import get_settings
from app.core.database import get_db
from app.core.metrics import record_enforcement_decision
from app.core.rate_limit import hit_count
from app.models import ApiCredential, Application, Gate, GatePolicy, GatePolicyGate
from app.repositories.custom_policies import EffectiveCustomPolicy, effective_custom_policies
from app.repositories.policies import effective_policy_scopes
from app.schemas.evaluation import (
    CustomPolicyDocumentRequest, CustomPolicyResolutionRequest, CustomPolicyResolutionResponse, CustomPolicySource,
    EnforcementEvaluationResponse, EnsureApplicationRequest, EnsureApplicationResponse, EvaluatedGateEnforcement,
    EvaluatedPolicy, EvaluationRequest, EvaluationResponse, PipelineResolutionRequest, PipelineResolutionResponse,
    ResolvedCustomPolicy, ResolvedPipelineGate,
)
from app.services.audit import record_audit
from app.services.custom_policies import (
    MEDIA_TYPES, UnrenderableCustomPolicy, canonical_digest, policy_file_response, render_custom_policy,
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


def load_validated_pipeline(db: Session, application_slug: str) -> tuple[Application, GatePolicy, list[GatePolicyGate]]:
    """Fail-closed pipeline lookup shared by every pre-scan endpoint.

    Unknown/inactive applications raise 404; an inactive, empty, inactive-gate
    or non-contiguous assigned policy raises 503.
    """
    application = db.scalar(select(Application).options(
        selectinload(Application.gate_policy)
        .selectinload(GatePolicy.gates)
        .selectinload(GatePolicyGate.gate)
    ).where(Application.slug == application_slug, Application.active.is_(True)))
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
    return application, policy, scopes


def serialize_custom_policy(entry: EffectiveCustomPolicy, format: str | None) -> ResolvedCustomPolicy:
    policy = entry.policy
    content = None
    if format is not None:
        try:
            content = render_custom_policy(policy.format, policy.document, policy.parsed_document, format)
        except UnrenderableCustomPolicy:
            # Fail closed: a consumer that asked for this format must not
            # receive a partial set of the policies bound to its pipeline.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"Custom policy {entry.key} cannot be rendered as {format.upper()}",
            ) from None
    return ResolvedCustomPolicy(
        key=entry.key,
        owner=policy.owner.slug,
        slug=policy.slug,
        name=policy.name,
        source_format=policy.format,
        digest=canonical_digest(policy.parsed_document),
        updated_at=policy.updated_at,
        sources=[CustomPolicySource(type=kind, target=target) for kind, target in entry.sources],
        gates=entry.gates,
        format=format,
        content=content,
        document=policy.parsed_document if format is not None else None,
    )


@router.post(
    "/resolve-pipeline",
    response_model=PipelineResolutionResponse,
    summary="Resolve the ordered security pipeline for an application",
    description=(
        "Fail-closed pipeline discovery endpoint. Returns the active gates selected by the reusable gate policy "
        "assigned to the application, plus references to the active custom policies bound to the application, "
        "its gate policy, or its gates. Set `custom_policy_format` to embed rendered custom policy content. "
        "Unknown or inactive applications and invalid policies are rejected."
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
    application, policy, scopes = load_validated_pipeline(db, data.application)
    custom = effective_custom_policies(db, application, [scope.gate for scope in scopes])
    return PipelineResolutionResponse(
        application=application.slug,
        gate_policy=policy.slug,
        gate_policy_name=policy.name,
        generated_at=now,
        gates=[
            ResolvedPipelineGate(gate=scope.gate.slug, position=scope.position)
            for scope in scopes
        ],
        custom_policies=[serialize_custom_policy(entry, data.custom_policy_format) for entry in custom],
    )


@router.post(
    "/resolve-custom-policies",
    response_model=CustomPolicyResolutionResponse,
    summary="Retrieve the custom policies bound to an application's pipeline",
    description=(
        "Returns every active custom policy bound to the application, its assigned gate policy, or a gate in "
        "that policy, rendered in the requested format (json, yaml, or toml). With `gate`, returns the "
        "application- and gate-policy-wide policies plus those bound to that gate. Uses the same fail-closed "
        "application and gate-policy validation as resolve-pipeline."
    ),
)
def resolve_custom_policies(
    data: CustomPolicyResolutionRequest,
    request: Request,
    _: ApiCredential = Depends(api_credential),
    db: Session = Depends(get_db),
):
    enforce_rate_limit(request)
    now = datetime.now(UTC)
    application, policy, scopes = load_validated_pipeline(db, data.application)
    if data.gate and data.gate not in {scope.gate.slug for scope in scopes}:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gate is not part of this application's pipeline")
    custom = effective_custom_policies(db, application, [scope.gate for scope in scopes])
    if data.gate:
        custom = [entry for entry in custom if entry.pipeline_wide or data.gate in entry.gates]
    return CustomPolicyResolutionResponse(
        application=application.slug,
        gate_policy=policy.slug,
        gate=data.gate,
        format=data.format,
        generated_at=now,
        custom_policies=[serialize_custom_policy(entry, data.format) for entry in custom],
    )


@router.post(
    "/custom-policy-document",
    response_class=Response,
    summary="Download one bound custom policy as a JSON, YAML, or TOML file",
    description=(
        "Returns the raw policy file. The policy must be active and bound to the application, its gate policy, "
        "or one of its pipeline gates; otherwise 404. The `X-Policy-Digest` header carries the canonical digest."
    ),
    responses={200: {"content": {media: {} for media in MEDIA_TYPES.values()}}},
)
def custom_policy_document(
    data: CustomPolicyDocumentRequest,
    request: Request,
    _: ApiCredential = Depends(api_credential),
    db: Session = Depends(get_db),
):
    enforce_rate_limit(request)
    application, _policy, scopes = load_validated_pipeline(db, data.application)
    key = f"{data.owner}/{data.policy}"
    entry = next(
        (item for item in effective_custom_policies(db, application, [scope.gate for scope in scopes])
         if item.key == key),
        None,
    )
    if entry is None:
        # Unbound, inactive, and nonexistent policies are indistinguishable.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Custom policy is not bound to this application")
    return policy_file_response(entry.policy, data.format)


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


@router.post(
    "/applications/ensure",
    response_model=EnsureApplicationResponse,
    summary="Ensure an application exists under a given gate policy (CI/CD bootstrap)",
    description=(
        "Fail-closed, idempotent endpoint for CI/CD-driven onboarding: looks up an application by slug and "
        "creates it under the requested gate policy if it does not exist yet. Never modifies an existing "
        "application's gate policy assignment -- if the application already exists under a different policy "
        "than requested, this reports policy_matches=false rather than silently reassigning it, since an "
        "unattended pipeline call is not an appropriate place to change security policy on an existing "
        "application. Requires the 'application:manage' API credential scope in addition to the credential "
        "otherwise only needing 'policy:read' for evaluation calls."
    ),
)
def ensure_application(
    data: EnsureApplicationRequest,
    request: Request,
    credential: ApiCredential = Depends(api_credential_application_manage),
    db: Session = Depends(get_db),
):
    enforce_rate_limit(request)
    policy = db.scalar(select(GatePolicy).where(GatePolicy.slug == data.gate_policy))
    if not policy or not policy.active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Gate policy does not exist or is inactive")

    existing = db.scalar(select(Application).where(Application.slug == data.application))
    if existing:
        return EnsureApplicationResponse(
            application=existing.slug,
            created=False,
            gate_policy=existing.gate_policy.slug,
            policy_matches=existing.gate_policy_id == policy.id,
        )

    item = Application(
        id=uuid4(), name=(data.name or data.application).strip(), slug=data.application,
        gate_policy_id=policy.id,
    )
    db.add(item)
    record_audit(
        db, "APPLICATION_CREATED", "API_CREDENTIAL", credential.id, "APPLICATION", item.id,
        {"slug": item.slug, "gate_policy": policy.slug, "via": "policies/applications/ensure"},
        source_ip(request),
    )
    try:
        db.commit()
    except IntegrityError:
        # Two concurrent CI/CD calls racing to create the same application:
        # the unique slug constraint rejects the loser, which is not an
        # error from the caller's point of view -- re-read and return the
        # winner's state exactly as the "already existed" branch above
        # does, so this endpoint is safe to call from parallel pipeline
        # stages without any caller-side locking.
        db.rollback()
        existing = db.scalar(select(Application).where(Application.slug == data.application))
        if not existing:
            raise HTTPException(status.HTTP_409_CONFLICT, "Application identifier conflict") from None
        return EnsureApplicationResponse(
            application=existing.slug,
            created=False,
            gate_policy=existing.gate_policy.slug,
            policy_matches=existing.gate_policy_id == policy.id,
        )
    db.refresh(item)
    return EnsureApplicationResponse(
        application=item.slug, created=True, gate_policy=policy.slug, policy_matches=True,
    )
