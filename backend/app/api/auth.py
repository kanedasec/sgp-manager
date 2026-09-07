import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import authenticated_user, current_user, mfa_pending_user, source_ip
from app.core.database import get_db
from app.core.config import get_settings
from app.core.mfa import (
    MfaNotConfiguredError, decrypt_totp_secret, encrypt_totp_secret, generate_totp_secret, provisioning_uri,
    verify_totp_code,
)
from app.core.oidc import OidcConfigurationError, OidcExchangeError, authorization_url, exchange_code_for_identity
from app.core.security import create_access_token, create_mfa_pending_token, hash_password, verify_password
from app.models import User
from app.models.entities import AuthProvider, UserRole
from app.schemas.auth import (
    ChangePasswordRequest, LoginRequest, LoginResponse, MfaChallengeResponse, MfaDisableRequest, MfaEnableRequest,
    MfaEnrollResponse, MfaVerifyRequest, UserResponse,
)
from app.services.audit import record_audit
from app.services.access import effective_permissions
from app.services.oidc_users import find_or_provision_user


router = APIRouter(prefix="/auth", tags=["authentication"])

# In-memory state/nonce store for the OIDC authorization code flow: short-lived
# (5 minutes), single-use, and only ever holds a random state value, never
# user data, so process-local storage (no shared cache needed) is sufficient
# even with multiple backend replicas — a callback landing on a different
# replica than the one that issued the state is treated the same as an
# expired one and simply must restart the login, which is an acceptable and
# rare edge case for an interactive human login flow.
_oidc_pending: dict[str, str] = {}


def user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id, username=user.username, display_name=user.display_name, email=user.email, role=user.role.value,
        groups=sorted(group.slug for group in user.groups if group.active), permissions=effective_permissions(user),
        must_change_password=user.must_change_password, auth_provider=user.auth_provider.value,
        mfa_enabled=user.mfa_enabled,
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


def issue_session(db: Session, user: User, response: Response, request: Request, event: str) -> LoginResponse:
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
    record_audit(db, event, "USER", user.id, "USER", user.id, source_ip=source_ip(request))
    db.commit()
    return LoginResponse(access_token=token, expires_at=expires, user=user_response(user))


@router.post("/login", response_model=LoginResponse | MfaChallengeResponse)
def login(data: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username.strip()))
    if (
        not user or not user.active or user.auth_provider != AuthProvider.LOCAL
        or not user.password_hash or not verify_password(data.password, user.password_hash)
    ):
        record_audit(db, "LOGIN_FAILED", "UNKNOWN", None, metadata={"username": data.username[:64]}, source_ip=source_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if user.mfa_enabled:
        mfa_token, expires = create_mfa_pending_token(user.id)
        record_audit(db, "LOGIN_MFA_CHALLENGE_ISSUED", "USER", user.id, "USER", user.id, source_ip=source_ip(request))
        db.commit()
        return MfaChallengeResponse(mfa_token=mfa_token, expires_at=expires)
    return issue_session(db, user, response, request, "LOGIN_SUCCEEDED")


@router.post("/mfa/verify", response_model=LoginResponse)
def verify_mfa(
    data: MfaVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db),
    user: User = Depends(mfa_pending_user),
):
    try:
        code_is_valid = (
            user.mfa_enabled and user.mfa_secret_encrypted
            and verify_totp_code(user.mfa_secret_encrypted, data.code)
        )
    except MfaNotConfiguredError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Multi-factor authentication is not available") from None
    if not code_is_valid:
        record_audit(db, "LOGIN_MFA_FAILED", "USER", user.id, "USER", user.id, source_ip=source_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired MFA code")
    return issue_session(db, user, response, request, "LOGIN_SUCCEEDED")


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(authenticated_user)):
    return user_response(user)


@router.post("/change-password", response_model=LoginResponse)
def change_password(
    data: ChangePasswordRequest, request: Request, response: Response, db: Session = Depends(get_db),
    user: User = Depends(authenticated_user),
):
    if user.auth_provider != AuthProvider.LOCAL or not user.password_hash:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Federated accounts do not manage a local password")
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


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def enroll_mfa(request: Request, db: Session = Depends(get_db), user: User = Depends(authenticated_user)):
    # Uses authenticated_user (token validity only), not current_user, because
    # an administrator with mfa_required_for_admins=true and no enrollment yet
    # is blocked by current_user everywhere else; this endpoint (and
    # /mfa/enable below) must remain reachable to let them complete
    # enrollment, exactly like /auth/change-password stays reachable while
    # must_change_password is set.
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Multi-factor authentication is already enabled")
    secret = generate_totp_secret()
    try:
        encrypted_secret = encrypt_totp_secret(secret)
    except MfaNotConfiguredError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Multi-factor authentication is not available") from None
    user.mfa_secret_encrypted = encrypted_secret
    record_audit(db, "MFA_ENROLLMENT_STARTED", "USER", user.id, "USER", user.id, source_ip=source_ip(request))
    db.commit()
    return MfaEnrollResponse(provisioning_uri=provisioning_uri(secret, user.username), secret=secret)


@router.post("/mfa/enable", response_model=UserResponse)
def enable_mfa(
    data: MfaEnableRequest, request: Request, db: Session = Depends(get_db),
    user: User = Depends(authenticated_user),
):
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Multi-factor authentication is already enabled")
    if not user.mfa_secret_encrypted:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Call /auth/mfa/enroll before enabling MFA")
    try:
        code_is_valid = verify_totp_code(user.mfa_secret_encrypted, data.code)
    except MfaNotConfiguredError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Multi-factor authentication is not available") from None
    if not code_is_valid:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid verification code")
    user.mfa_enabled = True
    record_audit(db, "MFA_ENABLED", "USER", user.id, "USER", user.id, source_ip=source_ip(request))
    db.commit()
    return user_response(user)


@router.post("/mfa/disable", response_model=UserResponse)
def disable_mfa(
    data: MfaDisableRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user),
):
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Multi-factor authentication is not enabled")
    if user.auth_provider != AuthProvider.LOCAL or not user.password_hash or not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    settings = get_settings()
    if settings.mfa_required_for_admins and user.role == UserRole.ADMIN:
        raise HTTPException(status.HTTP_409_CONFLICT, "Administrators cannot disable MFA while it is required by policy")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    record_audit(db, "MFA_DISABLED", "USER", user.id, "USER", user.id, source_ip=source_ip(request))
    db.commit()
    return user_response(user)


@router.get("/oidc/login")
def oidc_login():
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC login is not enabled")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    _oidc_pending[state] = nonce
    try:
        return {"authorization_url": authorization_url(state, nonce)}
    except OidcConfigurationError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None


@router.post("/oidc/callback", response_model=LoginResponse)
def oidc_callback(
    code: str, state: str, request: Request, response: Response, db: Session = Depends(get_db),
):
    settings = get_settings()
    if not settings.oidc_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC login is not enabled")
    nonce = _oidc_pending.pop(state, None)
    if nonce is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown or expired OIDC login state")
    try:
        identity = exchange_code_for_identity(code, nonce)
    except OidcExchangeError as exc:
        record_audit(db, "OIDC_LOGIN_FAILED", "UNKNOWN", None, metadata={"reason": str(exc)[:200]}, source_ip=source_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "OIDC authentication failed") from None
    try:
        user = find_or_provision_user(db, identity)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists locally") from None
    if not user.active:
        record_audit(db, "OIDC_LOGIN_REJECTED_INACTIVE", "USER", user.id, "USER", user.id, source_ip=source_ip(request))
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account has been deactivated")
    return issue_session(db, user, response, request, "OIDC_LOGIN_SUCCEEDED")
