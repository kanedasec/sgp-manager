"""Just-in-time provisioning of local User rows for federated OIDC identity.

An OIDC-authenticated identity is matched to a local `User` by
`oidc_subject` (the IdP's stable, non-reassignable `sub` claim — never by
email, which can be reused/changed at the IdP). A first-time login
creates the local row so admin/access-group management, audit logs, and
group-permission RBAC all continue to reference the same UUID-keyed User
model regardless of authentication method: OIDC is purely an
authentication front door, not a parallel authorization system.

Role/group entitlements are those already present in the OIDC identity's
resolved role; direct group_ids management for OIDC users still goes
through the existing admin `/users` API exactly like local accounts.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.oidc import OidcIdentity, resolve_role_for_groups
from app.models import User
from app.models.entities import AuthProvider, UserRole


def find_or_provision_user(db: Session, identity: OidcIdentity) -> User:
    user = db.scalar(select(User).where(User.oidc_subject == identity.subject))
    resolved_role = UserRole(resolve_role_for_groups(identity.groups))
    if user:
        if not user.active:
            return user
        user.role = resolved_role
        if identity.email:
            user.email = identity.email.lower()
        if identity.display_name:
            user.display_name = identity.display_name
        return user

    base_username = (identity.email or identity.subject).split("@")[0][:56] or "oidc-user"
    username = base_username
    suffix = 1
    while db.scalar(select(User.id).where(User.username == username)):
        suffix += 1
        username = f"{base_username}-{suffix}"[:64]

    user = User(
        id=uuid4(),
        username=username,
        password_hash=None,
        display_name=identity.display_name or username,
        email=(identity.email or f"{identity.subject}@oidc.invalid").lower(),
        role=resolved_role,
        active=True,
        must_change_password=False,
        auth_provider=AuthProvider.OIDC,
        oidc_subject=identity.subject,
    )
    db.add(user)
    db.flush()
    return user
