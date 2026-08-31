from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.schemas.common import Slug, ensure_utc


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class GatePolicySummary(BaseModel):
    id: UUID
    name: str
    slug: str
    active: bool
    model_config = ConfigDict(from_attributes=True)


class ApplicationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Slug = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    gate_policy_id: UUID


class ApplicationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: Slug | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None
    gate_policy_id: UUID | None = None


class ApplicationResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: str | None
    gate_policy_id: UUID
    gate_policy: GatePolicySummary
    active: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class OwnerCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Slug = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)


class OwnerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: Slug | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None


class OwnerResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: str | None
    active: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class GateCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Slug = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    owner_id: UUID
    default_blocking_severities: list[Severity] = Field(
        default_factory=lambda: list(Severity), min_length=1, max_length=4
    )

    @field_validator("default_blocking_severities")
    @classmethod
    def unique_default_severities(cls, value: list[Severity]) -> list[Severity]:
        return normalize_severities(value)


class GateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: Slug | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None
    owner_id: UUID | None = None
    default_blocking_severities: list[Severity] | None = Field(default=None, min_length=1, max_length=4)

    @field_validator("default_blocking_severities")
    @classmethod
    def unique_default_severities(cls, value: list[Severity] | None) -> list[Severity] | None:
        return normalize_severities(value) if value is not None else None


class GateResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: str | None
    active: bool
    created_at: datetime
    updated_at: datetime
    owner_id: UUID
    owner: OwnerResponse
    default_blocking_severities: list[str]
    model_config = ConfigDict(from_attributes=True)


class SecurityPipelineUpdate(BaseModel):
    gate_ids: list[UUID] = Field(min_length=1, max_length=32)

    @field_validator("gate_ids")
    @classmethod
    def unique_gate_ids(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate gates are not allowed")
        return value


class SecurityPipelineGateResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    position: int


class SecurityPipelineResponse(BaseModel):
    gates: list[SecurityPipelineGateResponse]


def normalize_severities(value: list[Severity]) -> list[Severity]:
    if len(set(value)) != len(value):
        raise ValueError("duplicate severities are not allowed")
    order = list(Severity)
    return sorted(value, key=order.index)


class GatePolicyGateInput(BaseModel):
    gate_id: UUID
    blocking_severities: list[Severity] = Field(min_length=1, max_length=4)

    @field_validator("blocking_severities")
    @classmethod
    def unique_blocking_severities(cls, value: list[Severity]) -> list[Severity]:
        return normalize_severities(value)


class GatePolicyGateResponse(BaseModel):
    gate_id: UUID
    gate_name: str
    gate_slug: str
    position: int
    blocking_severities: list[str]


class GatePolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Slug = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    gates: list[GatePolicyGateInput] = Field(min_length=1, max_length=32)

    @field_validator("gates")
    @classmethod
    def unique_gates(cls, value: list[GatePolicyGateInput]) -> list[GatePolicyGateInput]:
        if len({item.gate_id for item in value}) != len(value):
            raise ValueError("duplicate gates are not allowed")
        return value


class GatePolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: Slug | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None
    gates: list[GatePolicyGateInput] | None = Field(default=None, min_length=1, max_length=32)

    @field_validator("gates")
    @classmethod
    def unique_gates(cls, value: list[GatePolicyGateInput] | None) -> list[GatePolicyGateInput] | None:
        if value is not None and len({item.gate_id for item in value}) != len(value):
            raise ValueError("duplicate gates are not allowed")
        return value


class GatePolicyResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: str | None
    active: bool
    gates: list[GatePolicyGateResponse]
    application_count: int
    created_at: datetime
    updated_at: datetime


class PolicyGateInput(BaseModel):
    gate_id: UUID
    severities: list[Severity] = Field(min_length=1, max_length=4)

    @field_validator("severities")
    @classmethod
    def unique_severities(cls, value: list[Severity]) -> list[Severity]:
        return normalize_severities(value)


class PolicyGateResponse(BaseModel):
    gate_id: UUID
    gate_name: str
    gate_slug: str
    severities: list[str]


class PolicyCreate(BaseModel):
    application_id: UUID
    owner_id: UUID
    gates: list[PolicyGateInput] = Field(min_length=1)
    justification: str = Field(min_length=10, max_length=4000)
    valid_from: datetime | None = None
    expires_at: datetime

    @field_validator("valid_from", "expires_at")
    @classmethod
    def dates_must_have_timezone(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else value

    @field_validator("gates")
    @classmethod
    def unique_gates(cls, value: list[PolicyGateInput]) -> list[PolicyGateInput]:
        if len({item.gate_id for item in value}) != len(value):
            raise ValueError("duplicate gates are not allowed")
        return value

    @model_validator(mode="after")
    def validate_window(self):
        now = datetime.now(UTC)
        start = self.valid_from or now
        if self.expires_at <= now:
            raise ValueError("expires_at must be in the future")
        if self.expires_at <= start:
            raise ValueError("expires_at must be after valid_from")
        return self


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


class PolicyUpdate(BaseModel):
    owner_id: UUID | None = None
    gates: list[PolicyGateInput] | None = Field(default=None, min_length=1)
    justification: str | None = Field(default=None, min_length=10, max_length=4000)
    valid_from: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("valid_from", "expires_at")
    @classmethod
    def dates_must_have_timezone(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else value

    @field_validator("gates")
    @classmethod
    def unique_gates(cls, value: list[PolicyGateInput] | None) -> list[PolicyGateInput] | None:
        if value is not None and len({item.gate_id for item in value}) != len(value):
            raise ValueError("duplicate gates are not allowed")
        return value


class PolicyResponse(BaseModel):
    id: UUID
    application_id: UUID
    application_name: str
    application_slug: str
    owner_id: UUID
    owner_name: str
    owner_slug: str
    gates: list[PolicyGateResponse]
    justification: str
    valid_from: datetime
    expires_at: datetime
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None
    revoked_by: UUID | None
    revoke_reason: str | None
    status: str


class ApiCredentialCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def expiry_in_future(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            value = ensure_utc(value)
            if value <= datetime.now(UTC):
                raise ValueError("expires_at must be in the future")
        return value


class ApiCredentialResponse(BaseModel):
    id: UUID
    name: str
    prefix: str
    scopes: list[str]
    active: bool
    created_at: datetime
    created_by: UUID
    last_used_at: datetime | None
    expires_at: datetime | None
    model_config = ConfigDict(from_attributes=True)


class ApiCredentialCreated(ApiCredentialResponse):
    api_key: str = Field(description="Displayed only once; it is never stored in plaintext.")


class AuditResponse(BaseModel):
    id: UUID
    event_type: str
    actor_type: str
    actor_id: str | None
    entity_type: str | None
    entity_id: str | None
    timestamp: datetime
    metadata: dict
    source_ip: str | None


class DashboardResponse(BaseModel):
    applications: int
    gates: int
    active_bypasses: int
    expiring_soon: int
    recently_expired: int
    expiring_policies: list[PolicyResponse]


class AdminBootstrapInfo(BaseModel):
    username: str
    email: EmailStr


class UserAdminCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=256)
    display_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    role: str = Field(default="USER", pattern="^(ADMIN|USER)$")
    group_ids: list[UUID] = Field(default_factory=list)


class UserAdminUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=2, max_length=120)
    email: EmailStr | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)
    role: str | None = Field(default=None, pattern="^(ADMIN|USER)$")
    group_ids: list[UUID] | None = None


class GroupSummary(BaseModel):
    id: UUID
    name: str
    slug: str
    active: bool
    model_config = ConfigDict(from_attributes=True)


class UserAdminResponse(BaseModel):
    id: UUID
    username: str
    display_name: str
    email: str
    role: str
    active: bool
    created_at: datetime
    updated_at: datetime
    groups: list[GroupSummary]
    model_config = ConfigDict(from_attributes=True)


class AccessGroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Slug = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    permissions: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("permissions")
    @classmethod
    def unique_permissions(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().lower() for item in value]
        if len(set(normalized)) != len(normalized):
            raise ValueError("duplicate permissions are not allowed")
        return normalized


class AccessGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: Slug | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None
    permissions: list[str] | None = Field(default=None, max_length=500)

    @field_validator("permissions")
    @classmethod
    def unique_permissions(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized = [item.strip().lower() for item in value]
        if len(set(normalized)) != len(normalized):
            raise ValueError("duplicate permissions are not allowed")
        return normalized


class AccessGroupResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: str | None
    active: bool
    permissions: list[str]
    user_count: int
    created_at: datetime
    updated_at: datetime


class AvailableRolesResponse(BaseModel):
    roles: list[str]
