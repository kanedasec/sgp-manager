from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import authenticated_user, source_ip
from app.core.database import get_db
from app.core.config import get_settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.schemas.auth import ChangePasswordRequest, LoginRequest, LoginResponse, UserResponse
from app.services.audit import record_audit
from app.services.access import effective_permissions


router = APIRouter(prefix="/auth", tags=["authentication"])


def user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id, username=user.username, display_name=user.display_name, email=user.email, role=user.role.value,
        groups=sorted(group.slug for group in user.groups if group.active), permissions=effective_permissions(user),
        must_change_password=user.must_change_password,
    )


def set_documentation_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.admin_session_cookie_name,
        value=token,
        max_age=settings.jwt_expire_minutes * 60,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        path="/",
    )


@router.post("/login", response_model=LoginResponse)
def login(data: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username.strip()))
    if not user or not user.active or not verify_password(data.password, user.password_hash):
        record_audit(db, "LOGIN_FAILED", "UNKNOWN", None, metadata={"username": data.username[:64]}, source_ip=source_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    token, expires = create_access_token(user.id, user.role.value)
    if user.must_change_password:
        settings = get_settings()
        response.delete_cookie(
            key=settings.admin_session_cookie_name, httponly=True, secure=settings.session_cookie_secure,
            samesite="strict", path="/",
        )
        event = "LOGIN_PASSWORD_CHANGE_REQUIRED"
    else:
        set_documentation_cookie(response, token)
        event = "LOGIN_SUCCEEDED"
    record_audit(db, event, "USER", user.id, "USER", user.id, source_ip=source_ip(request))
    db.commit()
    return LoginResponse(access_token=token, expires_at=expires, user=user_response(user))


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(authenticated_user)):
    return user_response(user)


@router.post("/change-password", response_model=LoginResponse)
def change_password(
    data: ChangePasswordRequest, request: Request, response: Response, db: Session = Depends(get_db),
    user: User = Depends(authenticated_user),
):
    if not verify_password(data.current_password, user.password_hash):
        record_audit(
            db, "PASSWORD_CHANGE_FAILED", "USER", user.id, "USER", user.id,
            metadata={"reason": "current_password_mismatch"}, source_ip=source_ip(request),
        )
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if data.current_password == data.new_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password must be different from the current password")
    mandatory_change = user.must_change_password
    user.password_hash = hash_password(data.new_password)
    user.must_change_password = False
    token, expires = create_access_token(user.id, user.role.value)
    set_documentation_cookie(response, token)
    record_audit(
        db, "PASSWORD_CHANGED", "USER", user.id, "USER", user.id,
        metadata={"mandatory_change_completed": mandatory_change}, source_ip=source_ip(request),
    )
    db.commit()
    return LoginResponse(access_token=token, expires_at=expires, user=user_response(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response):
    settings = get_settings()
    response.delete_cookie(
        key=settings.admin_session_cookie_name,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        path="/",
    )
