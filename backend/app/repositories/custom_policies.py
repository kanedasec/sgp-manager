from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from app.models import Application, CustomPolicy, CustomPolicyBinding, Gate


@dataclass
class EffectiveCustomPolicy:
    """One active custom policy delivered to an application's pipeline.

    ``sources`` lists every binding that made the policy effective, as
    ``(target_type, target_slug)`` pairs; ``gates`` lists the pipeline gate
    slugs it was bound to directly. A policy bound in several ways appears
    once with every source recorded.
    """

    policy: CustomPolicy
    sources: list[tuple[str, str]] = field(default_factory=list)
    gates: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.policy.owner.slug}/{self.policy.slug}"

    @property
    def pipeline_wide(self) -> bool:
        return any(target_type != "gate" for target_type, _ in self.sources)


SOURCE_ORDER = {"application": 0, "gate_policy": 1, "gate": 2}


def effective_custom_policies(
    db: Session, application: Application, pipeline_gates: list[Gate],
) -> list[EffectiveCustomPolicy]:
    """Resolve active custom policies bound to an application, its assigned
    gate policy, or an active gate selected by that gate policy.

    ``pipeline_gates`` must be the already-validated, ordered gate list of the
    application's assigned policy. Gate bindings for gates outside that list
    never apply, so a gate-bound policy cannot reach an application whose
    standard does not run that gate. Inactive custom policies are excluded.
    """
    gate_order = {gate.id: index for index, gate in enumerate(pipeline_gates) if gate.active}
    conditions = [
        CustomPolicyBinding.application_id == application.id,
        CustomPolicyBinding.gate_policy_id == application.gate_policy_id,
    ]
    if gate_order:
        conditions.append(CustomPolicyBinding.gate_id.in_(list(gate_order)))
    statement = (
        select(CustomPolicyBinding)
        .join(CustomPolicyBinding.custom_policy)
        .options(joinedload(CustomPolicyBinding.custom_policy).joinedload(CustomPolicy.owner))
        .where(CustomPolicy.active.is_(True), or_(*conditions))
    )
    resolved: dict[UUID, EffectiveCustomPolicy] = {}
    for binding in db.scalars(statement).unique():
        target_slug = binding.target_slug
        if target_slug is None:
            continue
        entry = resolved.setdefault(binding.custom_policy_id, EffectiveCustomPolicy(binding.custom_policy))
        entry.sources.append((binding.target_type, target_slug))
        if binding.target_type == "gate":
            entry.gates.append(target_slug)
    gate_position = {gate.slug: index for index, gate in enumerate(pipeline_gates)}
    for entry in resolved.values():
        entry.sources.sort(key=lambda item: (SOURCE_ORDER[item[0]], gate_position.get(item[1], 0), item[1]))
        entry.gates.sort(key=lambda slug: gate_position.get(slug, 0))
    return sorted(resolved.values(), key=lambda item: (item.policy.owner.slug, item.policy.slug))
