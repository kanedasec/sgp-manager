from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import Slug


CustomPolicyFormat = Literal["json", "yaml", "toml"]


class EvaluationRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Unique application identifier")
    gate: Slug | None = Field(default=None, min_length=2, max_length=100, description="Optional gate filter")


class PipelineResolutionRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Unique application identifier")
    custom_policy_format: CustomPolicyFormat | None = Field(
        default=None,
        description=(
            "Optional. When set, every effective custom policy in the response also carries its rendered "
            "`content` in this format and its canonical `document`. When omitted (the default for existing "
            "consumers), only lightweight references are returned so the response stays small."
        ),
    )


class CustomPolicySource(BaseModel):
    type: Literal["application", "gate_policy", "gate"]
    target: str


class ResolvedCustomPolicy(BaseModel):
    key: str = Field(description="Stable `<owner>/<slug>` identifier, unique across owners")
    owner: str
    slug: str
    name: str
    source_format: CustomPolicyFormat
    digest: str = Field(description="Format-independent sha256 of the canonical JSON document")
    updated_at: datetime
    resolution_source: Literal["gate_policy_gate", "gate_fallback"] = Field(
        description="Deterministic assignment that selected this policy for the gate"
    )
    sources: list[CustomPolicySource] = Field(
        description="The gate fallback or composite Gate Policy + Gate selection"
    )
    gates: list[str] = Field(description="Pipeline gates this policy is bound to directly, in pipeline order")
    format: CustomPolicyFormat | None = Field(default=None, description="Format of `content`, when requested")
    content: str | None = Field(default=None, description="Rendered policy document, when requested")
    document: dict[str, Any] | None = Field(default=None, description="Canonical parsed document, when requested")


class ResolvedPipelineGate(BaseModel):
    # Deliberately unchanged: pinned platform-workflows consumers validate
    # these entries. Gate associations of custom policies are reported on
    # the top-level `custom_policies[].gates` instead.
    gate: str
    position: int


class PipelineResolutionResponse(BaseModel):
    application: str
    gate_policy: str
    gate_policy_name: str
    generated_at: datetime
    gates: list[ResolvedPipelineGate]
    custom_policies: list[ResolvedCustomPolicy] = Field(
        default_factory=list,
        description="At most one effective active custom policy per pipeline gate",
    )


class CustomPolicyResolutionRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Unique application identifier")
    gate: Slug | None = Field(
        default=None, min_length=2, max_length=100,
        description="Optional pipeline gate; returns only that gate's effective custom policy",
    )
    format: CustomPolicyFormat = Field(default="json", description="Format of each policy's rendered `content`")


class CustomPolicyResolutionResponse(BaseModel):
    application: str
    gate_policy: str
    gate: str | None
    format: CustomPolicyFormat
    generated_at: datetime
    custom_policies: list[ResolvedCustomPolicy]


class CustomPolicyDocumentRequest(BaseModel):
    application: Slug = Field(min_length=2, max_length=100, description="Unique application identifier")
    owner: Slug = Field(min_length=2, max_length=100, description="Owner slug of the custom policy")
    policy: Slug = Field(min_length=2, max_length=100, description="Custom policy slug within the owner")
    format: CustomPolicyFormat = Field(default="json", description="Output file format")


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
