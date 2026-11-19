from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import admin_user, current_user, source_ip
from app.core.database import get_db
from app.models import (
    Application, CustomPolicy, CustomPolicyBinding, Gate, GatePolicy, GatePolicyGate, OwnerLabel, User,
)
from app.schemas.custom_policies import (
    CustomPolicyBindingCreate, CustomPolicyBindingResponse, CustomPolicyCreate, CustomPolicyResponse,
    CustomPolicyUpdate, PolicyFormat,
)
from app.services.access import permitted_owner_ids, require_permission
from app.services.audit import record_audit
from app.services.custom_policies import InvalidCustomPolicy, parse_custom_policy, policy_file_response


router = APIRouter(
    prefix="/admin/custom-policies",
    tags=["custom policies"],
    dependencies=[Depends(current_user)],
)


def commit_unique(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Custom policy slug already exists for this owner",
        ) from None


def parse_document(format: str, document: str) -> dict:
    try:
        return parse_custom_policy(format, document)
    except InvalidCustomPolicy as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None


def visible_policy(db: Session, policy_id: UUID, user: User, action: str) -> CustomPolicy:
    allowed = permitted_owner_ids(user, "custom-policies", action)
    query = select(CustomPolicy).where(CustomPolicy.id == policy_id)
    if allowed is not None:
        query = query.where(CustomPolicy.owner_id.in_(allowed))
    item = db.scalar(query)
    if not item:
        # Keep unauthorized and nonexistent object identifiers
        # indistinguishable on direct-object endpoints.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Custom policy not found")
    return item


@router.get("", response_model=list[CustomPolicyResponse])
def list_custom_policies(
    owner_id: UUID | None = None,
    include_inactive: bool = True,
    format: str | None = Query(default=None, pattern="^(json|yaml|toml)$"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    allowed = permitted_owner_ids(user, "custom-policies", "view")
    if allowed is not None and not allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No assigned custom policy permissions")
    query = select(CustomPolicy)
    if allowed is not None:
        query = query.where(CustomPolicy.owner_id.in_(allowed))
    if owner_id:
        query = query.where(CustomPolicy.owner_id == owner_id)
    if not include_inactive:
        query = query.where(CustomPolicy.active.is_(True))
    if format:
        query = query.where(CustomPolicy.format == format)
    return list(db.scalars(query.order_by(CustomPolicy.name)))


@router.post("", response_model=CustomPolicyResponse, status_code=status.HTTP_201_CREATED)
def create_custom_policy(
    data: CustomPolicyCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    owner = db.get(OwnerLabel, data.owner_id)
    if not owner or not owner.active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Owner does not exist or is inactive")
    require_permission(user, "custom-policies", "create", owner.id)
    item = CustomPolicy(
        id=uuid4(),
        owner_id=owner.id,
        owner=owner,
        name=data.name.strip(),
        slug=data.slug,
        description=data.description,
        format=data.format,
        document=data.document,
        parsed_document=parse_document(data.format, data.document),
        created_by=user.id,
    )
    db.add(item)
    record_audit(
        db,
        "CUSTOM_POLICY_CREATED",
        "USER",
        user.id,
        "CUSTOM_POLICY",
        item.id,
        {"slug": item.slug, "owner": owner.slug, "format": item.format},
        source_ip(request),
    )
    commit_unique(db)
    db.refresh(item)
    return item


@router.get("/{policy_id}", response_model=CustomPolicyResponse)
def get_custom_policy(
    policy_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    return visible_policy(db, policy_id, user, "view")


@router.patch("/{policy_id}", response_model=CustomPolicyResponse)
def update_custom_policy(
    policy_id: UUID,
    data: CustomPolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    item = visible_policy(db, policy_id, user, "edit")
    changes = data.model_dump(exclude_unset=True)
    if changes.get("active") is False:
        referenced_as_fallback = db.scalar(
            select(Gate.id).where(Gate.default_custom_policy_id == item.id).limit(1)
        )
        referenced_by_policy_gate = db.scalar(
            select(GatePolicyGate.id).where(GatePolicyGate.custom_policy_id == item.id).limit(1)
        )
        if referenced_as_fallback or referenced_by_policy_gate:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Remove this custom policy from every gate configuration before deactivating it",
            )
    if changes.get("active") is True and not item.owner.active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Custom policy owner is inactive")
    if "format" in changes or "document" in changes:
        next_format = changes.get("format", item.format)
        next_document = changes.get("document", item.document)
        item.parsed_document = parse_document(next_format, next_document)
    for key, value in changes.items():
        setattr(item, key, value.strip() if key in {"name", "description"} and isinstance(value, str) else value)
    record_audit(
        db,
        "CUSTOM_POLICY_UPDATED",
        "USER",
        user.id,
        "CUSTOM_POLICY",
        item.id,
        {"slug": item.slug, "owner": item.owner.slug, "fields": sorted(changes)},
        source_ip(request),
    )
    commit_unique(db)
    db.refresh(item)
    return item


@router.get(
    "/{policy_id}/export",
    response_class=Response,
    summary="Download a custom policy as a JSON, YAML, or TOML file",
)
def export_custom_policy(
    policy_id: UUID,
    format: PolicyFormat = Query(default="json"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    return policy_file_response(visible_policy(db, policy_id, user, "view"), format)


# Legacy bindings are retained for administrative API compatibility and audit
# history, but deterministic pipeline resolution no longer reads them. New
# scanner configuration belongs on GatePolicyGate.custom_policy_id or the
# gate's single default_custom_policy_id fallback.
BINDING_TARGETS = {
    "application": (Application, "application_id", "Application"),
    "gate_policy": (GatePolicy, "gate_policy_id", "Gate policy"),
    "gate": (Gate, "gate_id", "Gate"),
}


@router.get("/{policy_id}/bindings", response_model=list[CustomPolicyBindingResponse], deprecated=True)
def list_custom_policy_bindings(
    policy_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
):
    item = visible_policy(db, policy_id, user, "view")
    return list(item.bindings)


@router.post(
    "/{policy_id}/bindings",
    response_model=CustomPolicyBindingResponse,
    status_code=status.HTTP_201_CREATED,
    deprecated=True,
)
def create_custom_policy_binding(
    policy_id: UUID,
    data: CustomPolicyBindingCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
):
    item = visible_policy(db, policy_id, user, "edit")
    model, column, label = BINDING_TARGETS[data.target_type]
    target = db.get(model, data.target_id)
    if not target or not target.active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{label} does not exist or is inactive")
    binding = CustomPolicyBinding(
        id=uuid4(),
        custom_policy_id=item.id,
        target_type=data.target_type,
        created_by=user.id,
        **{column: target.id},
    )
    db.add(binding)
    record_audit(
        db,
        "CUSTOM_POLICY_BOUND",
        "USER",
        user.id,
        "CUSTOM_POLICY",
        item.id,
        {"slug": item.slug, "owner": item.owner.slug, "target_type": data.target_type, "target": target.slug},
        source_ip(request),
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Custom policy is already bound to this {label.lower()}",
        ) from None
    db.refresh(binding)
    return binding


@router.delete(
    "/{policy_id}/bindings/{binding_id}", status_code=status.HTTP_204_NO_CONTENT, deprecated=True,
)
def delete_custom_policy_binding(
    policy_id: UUID,
    binding_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
):
    item = visible_policy(db, policy_id, user, "edit")
    binding = db.scalar(select(CustomPolicyBinding).where(
        CustomPolicyBinding.id == binding_id, CustomPolicyBinding.custom_policy_id == item.id,
    ))
    if not binding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Custom policy binding not found")
    record_audit(
        db,
        "CUSTOM_POLICY_UNBOUND",
        "USER",
        user.id,
        "CUSTOM_POLICY",
        item.id,
        {
            "slug": item.slug, "owner": item.owner.slug,
            "target_type": binding.target_type, "target": binding.target_slug,
        },
        source_ip(request),
    )
    db.delete(binding)
    db.commit()
