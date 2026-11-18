from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.schemas.common import Slug
from app.services.custom_policies import renderable_formats


PolicyFormat = Literal["json", "yaml", "toml"]
BindingTargetType = Literal["application", "gate_policy", "gate"]


class CustomPolicyOwner(BaseModel):
    id: UUID
    name: str
    slug: str
    active: bool
    model_config = ConfigDict(from_attributes=True)


class CustomPolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Slug = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    owner_id: UUID
    format: PolicyFormat
    document: str = Field(min_length=2, max_length=65536)


class CustomPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    slug: Slug | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    format: PolicyFormat | None = None
    document: str | None = Field(default=None, min_length=2, max_length=65536)
    active: bool | None = None


class CustomPolicyResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    description: str | None
    owner_id: UUID
    owner: CustomPolicyOwner
    format: PolicyFormat
    document: str
    parsed_document: dict[str, Any]
    active: bool
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

    @computed_field
    @property
    def renderable_formats(self) -> list[PolicyFormat]:
        """Formats this document can be exported or delivered in. JSON and
        YAML always work; TOML is excluded for documents containing nulls or
        integers outside the signed 64-bit range."""
        return renderable_formats(self.format, self.document, self.parsed_document)


class CustomPolicyBindingCreate(BaseModel):
    target_type: BindingTargetType
    target_id: UUID


class CustomPolicyBindingResponse(BaseModel):
    id: UUID
    custom_policy_id: UUID
    target_type: BindingTargetType
    target_id: UUID
    target_slug: str
    target_name: str
    created_by: UUID
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
