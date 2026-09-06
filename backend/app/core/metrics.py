"""Business-domain Prometheus metrics.

app.main already exposes HTTP-transport metrics (request counts/latency).
Those tell you the API is up; they do not tell you whether the product is
doing its job — how many bypasses exist, whether enforcement is actually
blocking anything, or whether the audit sink is keeping up. This module
adds that layer so `/metrics` can answer the questions a security team or
management actually asks:

- how many bypass policies get created/revoked, and how fast;
- how many enforcement calls result in a block vs. a pass, per gate;
- how many active bypasses exist right now, per owner;
- whether the external audit sink is delivering or failing.

Gauges that reflect current database state (`sgp_active_bypass_policies`,
`sgp_applications_total`, `sgp_gates_total`) are implemented as a custom
Prometheus collector queried once per `/metrics` scrape rather than
updated on every write, so they can never drift from the database and
never need to be kept in sync across multiple backend replicas.
"""

from __future__ import annotations

from datetime import UTC, datetime

from prometheus_client import Counter
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector
from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.models import Application, BypassPolicy, BypassPolicyGate, Gate, OwnerLabel

BUSINESS_EVENTS = Counter(
    "sgp_business_events_total",
    "Audited domain events, one increment per recorded audit log entry",
    ["event_type"],
)

ENFORCEMENT_DECISIONS = Counter(
    "sgp_enforcement_decisions_total",
    "Pipeline enforcement outcomes per gate: whether any severity remained blocking",
    ["gate", "outcome"],  # outcome: blocked | passed
)

AUDIT_WEBHOOK_DELIVERIES = Counter(
    "sgp_audit_webhook_deliveries_total",
    "External audit webhook delivery attempts by final result",
    ["result"],  # result: success | failed
)


class BusinessStateCollector(Collector):
    """Queries current domain state once per scrape. A dedicated short-lived
    session is used so a slow or failed scrape can never hold a connection
    open across requests or leak one on an exception."""

    def collect(self):
        active_bypasses = GaugeMetricFamily(
            "sgp_active_bypass_policies",
            "Currently active (non-revoked, in validity window) bypass policies, per owner",
            labels=["owner_slug"],
        )
        applications_total = GaugeMetricFamily(
            "sgp_applications_total", "Applications by active flag", labels=["active"],
        )
        gates_total = GaugeMetricFamily(
            "sgp_gates_total", "Security gates by owner and active flag", labels=["owner_slug", "active"],
        )

        try:
            with SessionLocal() as db:
                now = datetime.now(UTC)
                bypass_rows = db.execute(
                    select(OwnerLabel.slug, func.count(func.distinct(BypassPolicy.id)))
                    .select_from(BypassPolicy)
                    .join(BypassPolicy.owner)
                    .join(BypassPolicy.gate_scopes)
                    .where(
                        BypassPolicy.revoked_at.is_(None),
                        BypassPolicyGate.revoked_at.is_(None),
                        BypassPolicy.valid_from <= now,
                        BypassPolicy.expires_at > now,
                    )
                    .group_by(OwnerLabel.slug)
                ).all()
                for owner_slug, count in bypass_rows:
                    active_bypasses.add_metric([owner_slug], count)

                for active, count in db.execute(
                    select(Application.active, func.count()).select_from(Application).group_by(Application.active)
                ).all():
                    applications_total.add_metric([str(bool(active)).lower()], count)

                for owner_slug, active, count in db.execute(
                    select(OwnerLabel.slug, Gate.active, func.count())
                    .select_from(Gate).join(Gate.owner).group_by(OwnerLabel.slug, Gate.active)
                ).all():
                    gates_total.add_metric([owner_slug, str(bool(active)).lower()], count)
        except Exception:
            # A scrape must never 500 the /metrics endpoint because the
            # database is briefly unavailable; return whatever was gathered
            # (possibly nothing) and let the next scrape try again.
            pass

        yield active_bypasses
        yield applications_total
        yield gates_total


def record_enforcement_decision(gate_slug: str, blocking_severities: list[str]) -> None:
    outcome = "blocked" if blocking_severities else "passed"
    ENFORCEMENT_DECISIONS.labels(gate=gate_slug, outcome=outcome).inc()


def record_business_event(event_type: str) -> None:
    BUSINESS_EVENTS.labels(event_type=event_type).inc()


def record_webhook_delivery(success: bool) -> None:
    AUDIT_WEBHOOK_DELIVERIES.labels(result="success" if success else "failed").inc()
