from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import Slug


class EvaluationRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Unique application identifier")
    gate: Slug | None = Field(default=None, min_length=2, max_length=100, description="Optional gate filter")


class PipelineResolutionRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Unique application identifier")


class ResolvedPipelineGate(BaseModel):
    gate: str
    position: int


class PipelineResolutionResponse(BaseModel):
    application: str
    generated_at: datetime
    gates: list[ResolvedPipelineGate]


class EvaluatedPolicy(BaseModel):
    gate: str
    bypass_severities: list[str]
    expires_at: datetime


class EvaluationResponse(BaseModel):
    application: str
    generated_at: datetime
    policies: list[EvaluatedPolicy]


class EvaluatedGateEnforcement(BaseModel):
    gate: str
    blocking_severities: list[str]


class EnforcementEvaluationResponse(BaseModel):
    application: str
    generated_at: datetime
    gates: list[EvaluatedGateEnforcement]
