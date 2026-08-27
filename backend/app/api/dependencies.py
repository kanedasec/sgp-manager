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
from app.models import ApiCredential, User
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
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired access token") from None
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


def current_user(user: User = Depends(authenticated_user)) -> User:
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required before accessing the portal")
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
    return user


def api_credential(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"), db: Session = Depends(get_db)
) -> ApiCredential:
    if not x_api_key or len(x_api_key) > 256:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API credential")
    credential = db.scalar(select(ApiCredential).where(ApiCredential.key_hash == hash_api_key(x_api_key)))
    now = datetime.now(UTC)
    if not credential or not credential.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API credential")
    expiry = credential.expires_at
    if expiry and (expiry if expiry.tzinfo else expiry.replace(tzinfo=UTC)) <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API credential")
    if "policy:read" not in credential.scopes:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Credential does not have policy read scope")
    credential.last_used_at = now
    db.commit()
    return credential
