import re
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AccessGroup, GroupPermission, OwnerLabel, User
from app.models.entities import UserRole


ACTIONS = ("view", "create", "edit")
RESOURCES = ("gates", "policies")
ROLE_PATTERN = re.compile(r"^(view|create|edit)-(gates|policies):([a-z0-9]+(?:-[a-z0-9]+)*|all)$")


def is_admin(user: User) -> bool:
    return user.role == UserRole.ADMIN


def require_admin(user: User) -> None:
    if not is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required")


def permission_name(permission: GroupPermission) -> str:
    owner = permission.owner.slug if permission.owner else "all"
    return f"{permission.action}-{permission.resource}:{owner}"


def effective_permissions(user: User) -> list[str]:
    if is_admin(user):
        return ["*"]
    return sorted({
        permission_name(permission)
        for group in user.groups if group.active
        for permission in group.permissions
    })


def permitted_owner_ids(user: User, resource: str, action: str) -> set[UUID] | None:
    if is_admin(user):
        return None
    result: set[UUID] = set()
    for group in user.groups:
        if not group.active:
            continue
        for permission in group.permissions:
            if permission.resource != resource or permission.action != action:
                continue
            if permission.owner_id is None:
                return None
            result.add(permission.owner_id)
    return result


def has_permission(user: User, resource: str, action: str, owner_id: UUID) -> bool:
    allowed = permitted_owner_ids(user, resource, action)
    return allowed is None or owner_id in allowed


def require_permission(user: User, resource: str, action: str, owner_id: UUID) -> None:
    if not has_permission(user, resource, action, owner_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Missing permission {action}-{resource} for this owner",
        )


def parse_permissions(db: Session, values: list[str]) -> list[tuple[str, str, OwnerLabel | None]]:
    parsed: list[tuple[str, str, OwnerLabel | None]] = []
    for value in values:
        match = ROLE_PATTERN.fullmatch(value)
        if not match:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid permission role '{value}'")
        action, resource, owner_slug = match.groups()
        owner = None
        if owner_slug != "all":
            owner = db.scalar(select(OwnerLabel).where(OwnerLabel.slug == owner_slug))
            if not owner:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown owner '{owner_slug}'")
        parsed.append((action, resource, owner))
    return parsed


def replace_group_permissions(db: Session, group: AccessGroup, values: list[str]) -> None:
    parsed = parse_permissions(db, values)
    group.permissions.clear()
    for action, resource, owner in parsed:
        group.permissions.append(GroupPermission(
            id=uuid4(), resource=resource, action=action, owner_id=owner.id if owner else None,
            scope_key=str(owner.id) if owner else "all",
        ))


def available_roles(db: Session) -> list[str]:
    owners = list(db.scalars(select(OwnerLabel).where(OwnerLabel.active.is_(True)).order_by(OwnerLabel.slug)))
    scopes = ["all", *(owner.slug for owner in owners)]
    return [f"{action}-{resource}:{scope}" for resource in RESOURCES for action in ACTIONS for scope in scopes]
