from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import admin_user, source_ip
from app.core.database import get_db
from app.models import AccessGroup, OwnerLabel, User
from app.schemas.admin import (
    AccessGroupCreate, AccessGroupResponse, AccessGroupUpdate, AvailableRolesResponse, OwnerCreate, OwnerResponse,
    OwnerUpdate,
)
from app.services.access import available_roles, permission_name, replace_group_permissions
from app.services.audit import record_audit


router = APIRouter(prefix="/admin", tags=["access management"], dependencies=[Depends(admin_user)])


def commit_unique(db: Session, message: str) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, message) from None


def group_query():
    return select(AccessGroup).options(
        selectinload(AccessGroup.permissions), selectinload(AccessGroup.users),
    )


def serialize_group(group: AccessGroup) -> AccessGroupResponse:
    return AccessGroupResponse(
        id=group.id, name=group.name, slug=group.slug, description=group.description, active=group.active,
        permissions=sorted(permission_name(item) for item in group.permissions), user_count=len(group.users),
        created_at=group.created_at, updated_at=group.updated_at,
    )


@router.get("/owners", response_model=list[OwnerResponse])
def list_owners(db: Session = Depends(get_db)):
    return list(db.scalars(select(OwnerLabel).order_by(OwnerLabel.name)))


@router.post("/owners", response_model=OwnerResponse, status_code=201)
def create_owner(
    data: OwnerCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(admin_user),
):
    if data.slug == "all":
        raise HTTPException(422, "Owner slug 'all' is reserved for global permission scopes")
    item = OwnerLabel(
        id=uuid4(), name=data.name.strip(), slug=data.slug, description=data.description, active=True,
    )
    db.add(item)
    record_audit(db, "OWNER_CREATED", "USER", actor.id, "OWNER", item.id, {"slug": item.slug}, source_ip(request))
    commit_unique(db, "Owner slug already exists")
    db.refresh(item)
    return item


@router.patch("/owners/{owner_id}", response_model=OwnerResponse)
def update_owner(
    owner_id: UUID, data: OwnerUpdate, request: Request, db: Session = Depends(get_db),
    actor: User = Depends(admin_user),
):
    item = db.get(OwnerLabel, owner_id)
    if not item:
        raise HTTPException(404, "Owner not found")
    changes = data.model_dump(exclude_unset=True)
    if changes.get("slug") == "all":
        raise HTTPException(422, "Owner slug 'all' is reserved for global permission scopes")
    for key, value in changes.items():
        setattr(item, key, value.strip() if isinstance(value, str) else value)
    record_audit(db, "OWNER_UPDATED", "USER", actor.id, "OWNER", item.id, {"fields": list(changes)}, source_ip(request))
    commit_unique(db, "Owner slug already exists")
    db.refresh(item)
    return item


@router.get("/roles", response_model=AvailableRolesResponse)
def list_available_roles(db: Session = Depends(get_db)):
    return AvailableRolesResponse(roles=available_roles(db))


@router.get("/groups", response_model=list[AccessGroupResponse])
def list_groups(db: Session = Depends(get_db)):
    groups = list(db.scalars(group_query().order_by(AccessGroup.name)).unique())
    return [serialize_group(group) for group in groups]


@router.post("/groups", response_model=AccessGroupResponse, status_code=201)
def create_group(
    data: AccessGroupCreate, request: Request, db: Session = Depends(get_db), actor: User = Depends(admin_user),
):
    group = AccessGroup(
        id=uuid4(), name=data.name.strip(), slug=data.slug, description=data.description, active=True,
    )
    replace_group_permissions(db, group, data.permissions)
    db.add(group)
    record_audit(
        db, "ACCESS_GROUP_CREATED", "USER", actor.id, "ACCESS_GROUP", group.id,
        {"slug": group.slug, "permissions": data.permissions}, source_ip(request),
    )
    commit_unique(db, "Group slug or permission already exists")
    group = db.scalar(group_query().where(AccessGroup.id == group.id))
    return serialize_group(group)


@router.patch("/groups/{group_id}", response_model=AccessGroupResponse)
def update_group(
    group_id: UUID, data: AccessGroupUpdate, request: Request, db: Session = Depends(get_db),
    actor: User = Depends(admin_user),
):
    group = db.scalar(group_query().where(AccessGroup.id == group_id))
    if not group:
        raise HTTPException(404, "Access group not found")
    changes = data.model_dump(exclude_unset=True)
    permissions = changes.pop("permissions", None)
    if permissions is not None:
        replace_group_permissions(db, group, permissions)
    for key, value in changes.items():
        setattr(group, key, value.strip() if isinstance(value, str) else value)
    audit_fields = list(changes)
    if permissions is not None:
        audit_fields.append("permissions")
    record_audit(
        db, "ACCESS_GROUP_UPDATED", "USER", actor.id, "ACCESS_GROUP", group.id,
        {"fields": audit_fields, "permissions": permissions if permissions is not None else None}, source_ip(request),
    )
    commit_unique(db, "Group slug or permission already exists")
    group = db.scalar(group_query().where(AccessGroup.id == group.id))
    return serialize_group(group)
