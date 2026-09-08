from datetime import UTC, datetime
from uuid import UUID

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import get_settings
from app.core.security import decode_access_token, hash_api_key
from app.core.token_revocation import is_token_revoked, user_tokens_revoked_before
from app.models import ApiCredential, User
from app.models.entities import UserRole
from app.services.access import require_admin


bearer = HTTPBearer(auto_error=False)


def source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def resolve_admin_user(token: str, db: Session) -> User:
    try:
        payload = decode_access_token(token)
        if payload.get("type") != "admin":
            raise ValueError("wrong token type")
        user_id = UUID(payload["sub"])
        jti = payload.get("jti")
        issued_at = payload["iat"]
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired access token") from None
    if jti and is_token_revoked(jti):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This session has been revoked")
    revoked_before = user_tokens_revoked_before(user_id)
    # <=, not <: JWT "iat" only has whole-second precision (PyJWT truncates
    # on encode), so a token minted in the very same wall-clock second as a
    # force-logout call cannot be reliably ordered against the cutoff. For
    # a security control that must err in one direction, treat that
    # ambiguous same-second case as revoked rather than valid.
    if revoked_before is not None and issued_at <= revoked_before:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This session has been revoked")
    user = db.get(User, user_id)
    if not user or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or inactive user")
    return user


def authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)
) -> User:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return resolve_admin_user(credentials.credentials, db)


def mfa_setup_required(user: User) -> bool:
    settings = get_settings()
    return bool(settings.mfa_required_for_admins and user.role == UserRole.ADMIN and not user.mfa_enabled)


def current_user(user: User = Depends(authenticated_user)) -> User:
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required before accessing the portal")
    if mfa_setup_required(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Multi-factor authentication enrollment is required for administrators before accessing the portal",
        )
    return user


def mfa_pending_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)
) -> User:
    """Resolves the user tied to a short-lived mfa_pending token issued after
    a correct username/password but before the TOTP code is verified. Used
    only by /auth/mfa/verify; every other authenticated dependency requires
    a full "admin" token and rejects this one, so a pending login cannot
    reach any other endpoint."""
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        payload = decode_access_token(credentials.credentials)
        if payload.get("type") != "mfa_pending":
            raise ValueError("wrong token type")
        user_id = UUID(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired MFA challenge") from None
    user = db.get(User, user_id)
    if not user or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or inactive user")
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    require_admin(user)
    return user


def docs_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(get_settings().admin_session_cookie_name)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Portal login required to access API documentation")
    user = resolve_admin_user(token, db)
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required before accessing API documentation")
    if mfa_setup_required(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Multi-factor authentication setup is required for administrators before accessing API documentation",
        )
    return user


def resolve_api_credential(x_api_key: str | None, db: Session) -> ApiCredential:
    """Authenticates an X-API-Key header (existence, active, not expired)
    without checking any scope. Scope enforcement is the caller's
    responsibility via require_credential_scope, so a single credential
    can carry multiple independent scopes (e.g. policy:read for pipeline
    evaluation calls, application:manage for CI/CD-driven application
    bootstrap) and each endpoint only requires the scope it actually
    needs."""
    if not x_api_key or len(x_api_key) > 256:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API credential")
    credential = db.scalar(select(ApiCredential).where(ApiCredential.key_hash == hash_api_key(x_api_key)))
    now = datetime.now(UTC)
    if not credential or not credential.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API credential")
    expiry = credential.expires_at
    if expiry and (expiry if expiry.tzinfo else expiry.replace(tzinfo=UTC)) <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API credential")
    credential.last_used_at = now
    db.commit()
    return credential


def require_credential_scope(credential: ApiCredential, scope: str, label: str) -> None:
    if scope not in credential.scopes:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Credential does not have {label} scope")


def api_credential(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"), db: Session = Depends(get_db)
) -> ApiCredential:
    credential = resolve_api_credential(x_api_key, db)
    require_credential_scope(credential, "policy:read", "policy read")
    return credential


def api_credential_application_manage(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"), db: Session = Depends(get_db)
) -> ApiCredential:
    credential = resolve_api_credential(x_api_key, db)
    require_credential_scope(credential, "application:manage", "application management")
    return credential
