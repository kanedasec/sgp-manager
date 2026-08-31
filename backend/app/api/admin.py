from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import admin_user, current_user, source_ip
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import generate_api_key, hash_api_key, hash_password
from app.models import AccessGroup, ApiCredential, Application, AuditLog, BypassPolicy, BypassPolicyGate, Gate, OwnerLabel, User
from app.models.entities import UserRole
from app.repositories.policies import policy_query
from app.schemas.admin import (
    ApiCredentialCreate, ApiCredentialCreated, ApiCredentialResponse, ApplicationCreate, ApplicationResponse,
    ApplicationUpdate, AuditResponse, DashboardResponse, GateCreate, GateResponse, GateUpdate, PolicyCreate,
    OwnerResponse, PolicyResponse, PolicyUpdate, RevokeRequest, SecurityPipelineResponse, SecurityPipelineUpdate,
    UserAdminCreate, UserAdminResponse, UserAdminUpdate,
)
from app.services.audit import record_audit
from app.services.access import permitted_owner_ids, require_permission
from app.services.policies import aware, create_policy, replace_policy_scopes, serialize_policy, validate_gates


router = APIRouter(prefix="/admin", tags=["administration"], dependencies=[Depends(current_user)])


def commit_unique(db: Session, message: str) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, message) from None


@router.get("/owner-labels", response_model=list[OwnerResponse])
def list_owner_labels(db: Session = Depends(get_db)):
    return list(db.scalars(select(OwnerLabel).where(OwnerLabel.active.is_(True)).order_by(OwnerLabel.name)))


@router.get("/applications", response_model=list[ApplicationResponse])
def list_applications(
    search: str | None = Query(default=None, max_length=100), include_inactive: bool = True,
    db: Session = Depends(get_db),
):
    query = select(Application)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(Application.name.ilike(term), Application.slug.ilike(term)))
    if not include_inactive:
        query = query.where(Application.active.is_(True))
    return list(db.scalars(query.order_by(Application.name)))


@router.post("/applications", response_model=ApplicationResponse, status_code=201)
def create_application(data: ApplicationCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    item = Application(id=uuid4(), name=data.name.strip(), slug=data.slug, description=data.description)
    db.add(item)
    record_audit(db, "APPLICATION_CREATED", "USER", user.id, "APPLICATION", item.id, {"slug": item.slug}, source_ip(request))
    commit_unique(db, "Application identifier already exists")
    db.refresh(item)
    return item


@router.get("/applications/{item_id}", response_model=ApplicationResponse)
def get_application(item_id: UUID, db: Session = Depends(get_db)):
    item = db.get(Application, item_id)
    if not item:
        raise HTTPException(404, "Application not found")
    return item


@router.patch("/applications/{item_id}", response_model=ApplicationResponse)
def update_application(item_id: UUID, data: ApplicationUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    item = db.get(Application, item_id)
    if not item:
        raise HTTPException(404, "Application not found")
    changes = data.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(item, key, value.strip() if isinstance(value, str) else value)
    record_audit(db, "APPLICATION_UPDATED", "USER", user.id, "APPLICATION", item.id, {"fields": list(changes)}, source_ip(request))
    commit_unique(db, "Application identifier already exists")
    db.refresh(item)
    return item


@router.get("/gates", response_model=list[GateResponse])
def list_gates(
    include_inactive: bool = True, db: Session = Depends(get_db), user: User = Depends(current_user),
):
    query = select(Gate)
    allowed = permitted_owner_ids(user, "gates", "view")
    if allowed is not None:
        query = query.where(Gate.owner_id.in_(allowed))
    if not include_inactive:
        query = query.where(Gate.active.is_(True))
    return list(db.scalars(query.order_by(Gate.name)))


@router.post("/gates", response_model=GateResponse, status_code=201)
def create_gate(data: GateCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    owner = db.get(OwnerLabel, data.owner_id)
    if not owner or not owner.active:
        raise HTTPException(400, "Owner does not exist or is inactive")
    require_permission(user, "gates", "create", owner.id)
    item = Gate(
        id=uuid4(), owner_id=owner.id, name=data.name.strip(), slug=data.slug, description=data.description,
        default_blocking_severities=[severity.value for severity in data.default_blocking_severities],
    )
    db.add(item)
    record_audit(
        db, "GATE_CREATED", "USER", user.id, "GATE", item.id,
        {"slug": item.slug, "owner": owner.slug}, source_ip(request),
    )
    commit_unique(db, "Gate identifier already exists")
    db.refresh(item)
    return item


@router.get("/gates/{item_id}", response_model=GateResponse)
def get_gate(item_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)):
    item = db.get(Gate, item_id)
    if not item:
        raise HTTPException(404, "Gate not found")
    require_permission(user, "gates", "view", item.owner_id)
    return item


@router.patch("/gates/{item_id}", response_model=GateResponse)
def update_gate(item_id: UUID, data: GateUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    item = db.get(Gate, item_id)
    if not item:
        raise HTTPException(404, "Gate not found")
    require_permission(user, "gates", "edit", item.owner_id)
    changes = data.model_dump(exclude_unset=True)
    if "slug" in changes and changes["slug"] != item.slug and item.pipeline_position is not None:
        raise HTTPException(409, "Remove the gate from the security pipeline before changing its identifier")
    if changes.get("active") is False and item.pipeline_position is not None and user.role != UserRole.ADMIN:
        raise HTTPException(403, "Only an administrator can deactivate a gate in the global security pipeline")
    if "owner_id" in changes:
        new_owner = db.get(OwnerLabel, changes["owner_id"])
        if not new_owner or not new_owner.active:
            raise HTTPException(400, "Owner does not exist or is inactive")
        require_permission(user, "gates", "edit", new_owner.id)
    for key, value in changes.items():
        if key == "default_blocking_severities":
            value = [severity.value for severity in value]
        setattr(item, key, value.strip() if isinstance(value, str) else value)
    if changes.get("active") is False and item.pipeline_position is not None:
        item.pipeline_position = None
        db.flush()
        remaining_pipeline = list(db.scalars(
            select(Gate)
            .where(Gate.active.is_(True), Gate.pipeline_position.is_not(None))
            .order_by(Gate.pipeline_position)
        ))
        for position, gate in enumerate(remaining_pipeline):
            gate.pipeline_position = position
        record_audit(
            db, "SECURITY_PIPELINE_UPDATED", "USER", user.id, "SECURITY_PIPELINE", None,
            {
                "reason": "gate_deactivated",
                "removed_gate": item.slug,
                "gates": [gate.slug for gate in remaining_pipeline],
            },
            source_ip(request),
        )
    record_audit(db, "GATE_UPDATED", "USER", user.id, "GATE", item.id, {"fields": list(changes)}, source_ip(request))
    commit_unique(db, "Gate identifier already exists")
    db.refresh(item)
    return item


def serialize_security_pipeline(gates: list[Gate]) -> SecurityPipelineResponse:
    return SecurityPipelineResponse(gates=[
        {"id": gate.id, "name": gate.name, "slug": gate.slug, "position": gate.pipeline_position}
        for gate in gates
        if gate.pipeline_position is not None
    ])


@router.get("/security-pipeline", response_model=SecurityPipelineResponse)
def get_security_pipeline(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    gates = list(db.scalars(
        select(Gate)
        .where(Gate.active.is_(True), Gate.pipeline_position.is_not(None))
        .order_by(Gate.pipeline_position)
    ))
    return serialize_security_pipeline(gates)


@router.patch("/security-pipeline", response_model=SecurityPipelineResponse)
def update_security_pipeline(
    data: SecurityPipelineUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
):
    selected = list(db.scalars(select(Gate).where(Gate.id.in_(data.gate_ids))))
    selected_by_id = {gate.id: gate for gate in selected}
    if len(selected_by_id) != len(data.gate_ids):
        raise HTTPException(400, "Every pipeline gate must exist")
    if any(not gate.active for gate in selected):
        raise HTTPException(400, "Inactive gates cannot be added to the security pipeline")

    ordered = [selected_by_id[gate_id] for gate_id in data.gate_ids]
    previous = list(db.scalars(
        select(Gate)
        .where(Gate.pipeline_position.is_not(None))
        .order_by(Gate.pipeline_position)
    ))
    for gate in previous:
        gate.pipeline_position = None
    db.flush()
    for position, gate in enumerate(ordered):
        gate.pipeline_position = position

    record_audit(
        db, "SECURITY_PIPELINE_UPDATED", "USER", user.id, "SECURITY_PIPELINE", None,
        {
            "previous_gates": [gate.slug for gate in previous],
            "gates": [gate.slug for gate in ordered],
        },
        source_ip(request),
    )
    commit_unique(db, "Security pipeline positions conflict")
    return serialize_security_pipeline(ordered)


@router.get("/bypass-policies", response_model=list[PolicyResponse])
def list_policies(
    application_id: UUID | None = None, gate_id: UUID | None = None, policy_status: str | None = Query(default=None, alias="status"),
    valid_from: datetime | None = None, valid_until: datetime | None = None, db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = policy_query()
    allowed = permitted_owner_ids(user, "policies", "view")
    if allowed is not None:
        query = query.where(BypassPolicy.owner_id.in_(allowed))
    if application_id:
        query = query.where(BypassPolicy.application_id == application_id)
    if gate_id:
        query = query.where(BypassPolicy.gate_scopes.any(BypassPolicyGate.gate_id == gate_id))
    if valid_from:
        query = query.where(BypassPolicy.expires_at > valid_from)
    if valid_until:
        query = query.where(BypassPolicy.valid_from < valid_until)
    items = list(db.scalars(query.order_by(BypassPolicy.created_at.desc())).unique())
    result = [serialize_policy(item) for item in items]
    if policy_status:
        normalized = policy_status.upper()
        if normalized not in {"ACTIVE", "EXPIRED", "REVOKED", "SCHEDULED"}:
            raise HTTPException(400, "Invalid policy status")
        result = [item for item in result if item.status == normalized]
    return result


@router.post("/bypass-policies", response_model=PolicyResponse, status_code=201)
def create_bypass(data: PolicyCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    owner = db.get(OwnerLabel, data.owner_id)
    if not owner or not owner.active:
        raise HTTPException(400, "Owner does not exist or is inactive")
    require_permission(user, "policies", "create", owner.id)
    policy = create_policy(db, data, user, source_ip(request))
    policy = db.scalar(policy_query().where(BypassPolicy.id == policy.id))
    return serialize_policy(policy)


@router.get("/bypass-policies/{policy_id}", response_model=PolicyResponse)
def get_policy(policy_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)):
    policy = db.scalar(policy_query().where(BypassPolicy.id == policy_id))
    if not policy:
        raise HTTPException(404, "Bypass policy not found")
    require_permission(user, "policies", "view", policy.owner_id)
    return serialize_policy(policy)


@router.patch("/bypass-policies/{policy_id}", response_model=PolicyResponse)
def update_policy(policy_id: UUID, data: PolicyUpdate, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    policy = db.scalar(policy_query().where(BypassPolicy.id == policy_id))
    if not policy:
        raise HTTPException(404, "Bypass policy not found")
    require_permission(user, "policies", "edit", policy.owner_id)
    if policy.revoked_at:
        raise HTTPException(409, "Revoked policies cannot be edited")
    previous_scopes = [
        {"gate_id": str(scope.gate_id), "severities": list(scope.severities)} for scope in policy.gate_scopes
    ]
    previous_window = {"valid_from": policy.valid_from.isoformat(), "expires_at": policy.expires_at.isoformat()}
    changes = data.model_dump(exclude_unset=True)
    target_owner_id = changes.get("owner_id", policy.owner_id)
    if "owner_id" in changes:
        target_owner = db.get(OwnerLabel, target_owner_id)
        if not target_owner or not target_owner.active:
            raise HTTPException(400, "Owner does not exist or is inactive")
        require_permission(user, "policies", "edit", target_owner_id)
    new_start = changes.get("valid_from", policy.valid_from)
    new_expiry = changes.get("expires_at", policy.expires_at)
    if aware(new_expiry) <= datetime.now(UTC) or aware(new_expiry) <= aware(new_start):
        raise HTTPException(400, "Invalid policy validity window")
    requested_gates = data.gates if "gates" in changes else None
    if requested_gates is None:
        from app.schemas.admin import PolicyGateInput
        requested_gates = [PolicyGateInput(gate_id=scope.gate_id, severities=scope.severities) for scope in policy.gate_scopes]
    validate_gates(
        db, policy.application_id, target_owner_id, requested_gates, new_start, new_expiry, policy.id
    )
    for key, value in changes.items():
        if key == "gates":
            continue
        setattr(policy, key, value.strip() if isinstance(value, str) else value)
    replace_policy_scopes(policy, requested_gates, new_start, new_expiry)
    record_audit(db, "BYPASS_UPDATED", "USER", user.id, "BYPASS_POLICY", policy.id, {
        "fields": list(changes),
        "previous_gate_policies": previous_scopes,
        "gate_policies": [
            {"gate_id": str(item.gate_id), "severities": [severity.value for severity in item.severities]}
            for item in requested_gates
        ],
        "previous_window": previous_window,
        "window": {"valid_from": aware(new_start).isoformat(), "expires_at": aware(new_expiry).isoformat()},
    }, source_ip(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Updated validity window overlaps another policy") from None
    db.refresh(policy)
    return serialize_policy(policy)


@router.post("/bypass-policies/{policy_id}/revoke", response_model=PolicyResponse)
def revoke_policy(policy_id: UUID, data: RevokeRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    policy = db.scalar(policy_query().where(BypassPolicy.id == policy_id))
    if not policy:
        raise HTTPException(404, "Bypass policy not found")
    require_permission(user, "policies", "edit", policy.owner_id)
    if policy.revoked_at:
        raise HTTPException(409, "Policy is already revoked")
    policy.revoked_at = datetime.now(UTC)
    policy.revoked_by = user.id
    policy.revoke_reason = data.reason.strip()
    for scope in policy.gate_scopes:
        scope.revoked_at = policy.revoked_at
    record_audit(db, "BYPASS_REVOKED", "USER", user.id, "BYPASS_POLICY", policy.id, {"reason": data.reason}, source_ip(request))
    db.commit()
    db.refresh(policy)
    return serialize_policy(policy)


@router.get("/api-credentials", response_model=list[ApiCredentialResponse])
def list_credentials(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    return list(db.scalars(select(ApiCredential).order_by(ApiCredential.created_at.desc())))


@router.post("/api-credentials", response_model=ApiCredentialCreated, status_code=201)
def create_credential(data: ApiCredentialCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    plain_key, prefix = generate_api_key()
    item = ApiCredential(id=uuid4(), name=data.name.strip(), key_hash=hash_api_key(plain_key), prefix=prefix, expires_at=data.expires_at, created_by=user.id)
    db.add(item)
    record_audit(db, "API_CREDENTIAL_CREATED", "USER", user.id, "API_CREDENTIAL", item.id, {"name": item.name, "prefix": prefix}, source_ip(request))
    db.commit()
    db.refresh(item)
    return ApiCredentialCreated(**ApiCredentialResponse.model_validate(item).model_dump(), api_key=plain_key)


@router.post("/api-credentials/{credential_id}/revoke", response_model=ApiCredentialResponse)
def revoke_credential(credential_id: UUID, data: RevokeRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    item = db.get(ApiCredential, credential_id)
    if not item:
        raise HTTPException(404, "API credential not found")
    if not item.active:
        raise HTTPException(409, "API credential is already inactive")
    item.active = False
    record_audit(db, "API_CREDENTIAL_REVOKED", "USER", user.id, "API_CREDENTIAL", item.id, {"reason": data.reason, "prefix": item.prefix}, source_ip(request))
    db.commit()
    db.refresh(item)
    return item


@router.get("/users", response_model=list[UserAdminResponse])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    return list(db.scalars(select(User).order_by(User.display_name, User.username)))


@router.post("/users", response_model=UserAdminResponse, status_code=201)
def create_user(data: UserAdminCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(admin_user)):
    groups = list(db.scalars(select(AccessGroup).where(AccessGroup.id.in_(data.group_ids), AccessGroup.active.is_(True))))
    if len(groups) != len(set(data.group_ids)):
        raise HTTPException(400, "One or more groups do not exist or are inactive")
    item = User(
        id=uuid4(), username=data.username.strip(), password_hash=hash_password(data.password),
        display_name=data.display_name.strip(), email=str(data.email).lower(), role=UserRole(data.role), active=True,
        groups=groups,
    )
    db.add(item)
    record_audit(
        db, "USER_CREATED", "USER", user.id, "USER", item.id,
        {"username": item.username, "email": item.email, "role": item.role.value, "groups": [g.slug for g in groups]},
        source_ip(request),
    )
    commit_unique(db, "Username or email already exists")
    db.refresh(item)
    return item


@router.get("/users/{user_id}", response_model=UserAdminResponse)
def get_user(user_id: UUID, db: Session = Depends(get_db), _: User = Depends(admin_user)):
    item = db.get(User, user_id)
    if not item:
        raise HTTPException(404, "User not found")
    return item


@router.patch("/users/{user_id}", response_model=UserAdminResponse)
def update_user(
    user_id: UUID, data: UserAdminUpdate, request: Request, db: Session = Depends(get_db),
    actor: User = Depends(admin_user),
):
    item = db.get(User, user_id)
    if not item:
        raise HTTPException(404, "User not found")
    changes = data.model_dump(exclude_unset=True)
    if item.id == actor.id and (changes.get("active") is False or changes.get("role") == "USER"):
        raise HTTPException(409, "You cannot deactivate or remove your own administrator role")
    removes_admin = item.role == UserRole.ADMIN and (
        changes.get("active") is False or changes.get("role") == "USER"
    )
    if removes_admin and item.active:
        active_admins = db.scalar(
            select(func.count()).select_from(User).where(User.active.is_(True), User.role == UserRole.ADMIN)
        ) or 0
        if active_admins <= 1:
            raise HTTPException(409, "The last active administrator cannot be deactivated or downgraded")
    password = changes.pop("password", None)
    group_ids = changes.pop("group_ids", None)
    if group_ids is not None:
        groups = list(db.scalars(select(AccessGroup).where(AccessGroup.id.in_(group_ids), AccessGroup.active.is_(True))))
        if len(groups) != len(set(group_ids)):
            raise HTTPException(400, "One or more groups do not exist or are inactive")
        item.groups = groups
    if password:
        item.password_hash = hash_password(password)
    if "role" in changes:
        changes["role"] = UserRole(changes["role"])
    for key, value in changes.items():
        if key == "email":
            value = str(value).lower()
        elif isinstance(value, str):
            value = value.strip()
        setattr(item, key, value)
    audit_fields = list(changes)
    if password:
        audit_fields.append("password_changed")
    if group_ids is not None:
        audit_fields.append("groups")
    event = "USER_DEACTIVATED" if changes.get("active") is False else "USER_UPDATED"
    record_audit(db, event, "USER", actor.id, "USER", item.id, {"fields": audit_fields}, source_ip(request))
    commit_unique(db, "Email already exists")
    db.refresh(item)
    return item


@router.get("/audit-logs", response_model=list[AuditResponse])
def list_audit_logs(
    event_type: str | None = Query(default=None, max_length=80), entity_type: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0), db: Session = Depends(get_db),
    _: User = Depends(admin_user),
):
    query = select(AuditLog)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type)
    entries = db.scalars(query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset))
    return [AuditResponse(id=e.id, event_type=e.event_type, actor_type=e.actor_type, actor_id=e.actor_id, entity_type=e.entity_type, entity_id=e.entity_id, timestamp=e.timestamp, metadata=e.event_metadata, source_ip=e.source_ip) for e in entries]


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    now = datetime.now(UTC)
    soon = now + timedelta(days=get_settings().expiring_soon_days)
    recent = now - timedelta(days=7)
    base_active = (
        BypassPolicy.revoked_at.is_(None), BypassPolicy.valid_from <= now, BypassPolicy.expires_at > now,
        Application.active.is_(True), Gate.active.is_(True), BypassPolicyGate.revoked_at.is_(None),
    )
    expiring_query = (
        policy_query().join(BypassPolicy.application).join(BypassPolicy.gate_scopes).join(BypassPolicyGate.gate)
        .where(*base_active, BypassPolicy.expires_at <= soon).order_by(BypassPolicy.expires_at)
    )
    expiring_items = list(db.scalars(expiring_query).unique())
    return DashboardResponse(
        applications=db.scalar(select(func.count()).select_from(Application).where(Application.active.is_(True))) or 0,
        gates=db.scalar(select(func.count()).select_from(Gate).where(Gate.active.is_(True))) or 0,
        active_bypasses=db.scalar(
            select(func.count(func.distinct(BypassPolicy.id))).select_from(BypassPolicy)
            .join(BypassPolicy.application).join(BypassPolicy.gate_scopes).join(BypassPolicyGate.gate).where(*base_active)
        ) or 0,
        expiring_soon=len(expiring_items),
        recently_expired=db.scalar(select(func.count()).select_from(BypassPolicy).where(BypassPolicy.revoked_at.is_(None), BypassPolicy.expires_at <= now, BypassPolicy.expires_at >= recent)) or 0,
        expiring_policies=[serialize_policy(item) for item in expiring_items],
    )
