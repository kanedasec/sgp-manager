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
    gate_policy: str
    gate_policy_name: str
    generated_at: datetime
    gates: list[ResolvedPipelineGate]


class EvaluatedPolicy(BaseModel):
    gate: str
    bypass_severities: list[str]
    finding_scope: list[str] | None = None
    expires_at: datetime


class EvaluationResponse(BaseModel):
    application: str
    generated_at: datetime
    policies: list[EvaluatedPolicy]


class EvaluatedGateEnforcement(BaseModel):
    gate: str
    blocking_severities: list[str]
    bypassed_findings: list[str] = Field(
        default_factory=list,
        description=(
            "Specific finding identifiers (CVE IDs or scanner fingerprints) that are "
            "excluded from blocking even though their severity remains in "
            "blocking_severities. A finding-scoped bypass narrows the exception to "
            "exactly these findings instead of bulk-clearing the whole severity: the "
            "consumer must still block every other finding at a blocking severity that "
            "is not listed here."
        ),
    )


class EnforcementEvaluationResponse(BaseModel):
    application: str
    generated_at: datetime
    gates: list[EvaluatedGateEnforcement]


class EnsureApplicationRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Application identifier to look up or create")
    gate_policy: Slug = Field(
        min_length=2, max_length=100,
        description="Gate policy to assign if the application does not exist yet",
    )
    name: str | None = Field(
        default=None, min_length=2, max_length=120,
        description="Display name for a newly created application; defaults to the application slug when omitted",
    )


class EnsureApplicationResponse(BaseModel):
    application: str
    created: bool = Field(description="True if this call created the application; false if it already existed")
    gate_policy: str = Field(description="The application's current gate policy slug")
    policy_matches: bool = Field(
        description=(
            "False when the application already existed under a DIFFERENT gate policy than requested. "
            "This endpoint never changes the policy of an existing application -- it only reports the "
            "mismatch so the caller (a CI/CD pipeline) can decide how to handle it, since silently "
            "reassigning security policy from an unattended pipeline call would be a governance risk."
        ),
    )
