from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import current_user, source_ip
from app.core.database import get_db
from app.models import CustomPolicy, OwnerLabel, User
from app.schemas.custom_policies import CustomPolicyCreate, CustomPolicyResponse, CustomPolicyUpdate
from app.services.access import permitted_owner_ids, require_permission
from app.services.audit import record_audit
from app.services.custom_policies import InvalidCustomPolicy, parse_custom_policy


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
    format: str | None = Query(default=None, pattern="^(json|yaml)$"),
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
