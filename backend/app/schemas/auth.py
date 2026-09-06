from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class UserResponse(BaseModel):
    id: UUID
    username: str
    display_name: str
    email: str
    role: str
    groups: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    must_change_password: bool = False
    auth_provider: str = "LOCAL"
    mfa_enabled: bool = False

    model_config = ConfigDict(from_attributes=True)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserResponse


class MfaChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    expires_at: datetime


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8, pattern=r"^[0-9]+$")


class MfaEnrollResponse(BaseModel):
    provisioning_uri: str
    secret: str = Field(description="Displayed only during enrollment; never returned again after enable.")


class MfaEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8, pattern=r"^[0-9]+$")


class MfaDisableRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
