from dataclasses import dataclass

from fastapi import HTTPException, status

from app.models import CustomPolicy, GatePolicy, GatePolicyGate


@dataclass(frozen=True)
class EffectiveCustomPolicy:
    """The single custom policy selected for one gate in one gate policy."""

    policy: CustomPolicy
    gate_policy_slug: str
    gate_slug: str
    resolution_source: str

    @property
    def key(self) -> str:
        return f"{self.policy.owner.slug}/{self.policy.slug}"

    @property
    def sources(self) -> list[tuple[str, str]]:
        # Preserve the existing source vocabulary for compatible consumers.
        # Two entries mean Gate Policy AND Gate; one gate entry is fallback.
        if self.resolution_source == "gate_policy_gate":
            return [
                ("gate_policy", self.gate_policy_slug),
                ("gate", self.gate_slug),
            ]
        return [("gate", self.gate_slug)]

    @property
    def gates(self) -> list[str]:
        return [self.gate_slug]


def effective_custom_policies(
    policy: GatePolicy,
    scopes: list[GatePolicyGate],
    requested_gate: str | None = None,
) -> list[EffectiveCustomPolicy]:
    """Resolve at most one active custom policy for every selected gate.

    Precedence is deliberately singular: the GatePolicyGate-specific policy,
    then the gate's global fallback. Legacy bindings are not considered and
    documents are never merged. A required gate without a valid effective
    policy makes preflight fail closed.
    """
    resolved: list[EffectiveCustomPolicy] = []
    for scope in sorted(scopes, key=lambda item: item.position):
        gate = scope.gate
        if requested_gate is not None and gate.slug != requested_gate:
            continue

        selected = scope.custom_policy
        source = "gate_policy_gate"
        if selected is None:
            selected = gate.default_custom_policy
            source = "gate_fallback"

        if selected is None:
            if gate.custom_policy_required:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    f"Gate {gate.slug} requires a custom policy, but none is configured",
                )
            continue
        if not selected.active or selected.owner_id != gate.owner_id:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                f"Custom policy configuration for gate {gate.slug} is invalid",
            )
        resolved.append(
            EffectiveCustomPolicy(
                policy=selected,
                gate_policy_slug=policy.slug,
                gate_slug=gate.slug,
                resolution_source=source,
            )
        )
    return resolved
