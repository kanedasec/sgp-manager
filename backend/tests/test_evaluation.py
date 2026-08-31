from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.database import SessionLocal
from app.models import BypassPolicy, BypassPolicyGate, User

from .test_policies import payload


def evaluate(client, key, application="payment-api", gate=None):
    body = {"application": application}
    if gate:
        body["gate"] = gate
    return client.post("/api/v1/policies/evaluate", headers={"X-API-Key": key}, json=body)


def test_unknown_application_is_fail_closed(client, api_key):
    key, _ = api_key
    response = evaluate(client, key, "does-not-exist")
    assert response.status_code == 200
    assert response.json()["policies"] == []


def test_application_without_bypass(client, domain, api_key):
    key, _ = api_key
    assert evaluate(client, key).json()["policies"] == []


def test_active_bypass_is_returned(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, gate = domain
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{"gate_id": gate["id"], "severities": ["low", "medium", "high"]}],
    ))
    result = evaluate(client, key).json()["policies"]
    assert result[0]["gate"] == "secrets"
    assert result[0]["bypass_severities"] == ["low", "medium", "high"]


def test_gate_filter(client, admin_headers, domain, api_key):
    key, _ = api_key
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain))
    assert len(evaluate(client, key, gate="secrets").json()["policies"]) == 1
    assert evaluate(client, key, gate="sast").json()["policies"] == []


def test_multigate_policy_is_flattened_for_pipeline(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, secrets = domain
    sast = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "SAST", "slug": "sast", "owner_id": secrets["owner_id"]},
    ).json()
    created = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain, gates=[
        {"gate_id": secrets["id"], "severities": ["low"]},
        {"gate_id": sast["id"], "severities": ["high", "critical"]},
    ]))
    assert created.status_code == 201
    result = evaluate(client, key).json()["policies"]
    assert {item["gate"]: item["bypass_severities"] for item in result} == {
        "secrets": ["low"], "sast": ["high", "critical"],
    }


def test_expired_bypass_is_not_returned(client, domain, api_key):
    key, _ = api_key
    application, gate = domain
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="admin").one()
        start = datetime.now(UTC) - timedelta(days=2)
        expiry = datetime.now(UTC) - timedelta(days=1)
        policy = BypassPolicy(
            application_id=UUID(application["id"]), owner_id=UUID(gate["owner_id"]),
            justification="An old exception that has expired.",
            valid_from=start, expires_at=expiry, created_by=user.id,
        )
        policy.gate_scopes.append(BypassPolicyGate(
            application_id=UUID(application["id"]), gate_id=UUID(gate["id"]), severities=["low"],
            valid_from=start, expires_at=expiry,
        ))
        db.add(policy)
        db.commit()
    assert evaluate(client, key).json()["policies"] == []


def test_revoked_bypass_is_not_returned(client, admin_headers, domain, api_key):
    key, _ = api_key
    policy = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain)).json()
    client.post(f"/api/v1/admin/bypass-policies/{policy['id']}/revoke", headers=admin_headers, json={"reason": "No longer needed after remediation."})
    assert evaluate(client, key).json()["policies"] == []


def test_inactive_gate_is_not_returned(client, admin_headers, domain, api_key):
    key, _ = api_key
    application, gate = domain
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain))
    replacement = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "SAST", "slug": "sast", "owner_id": gate["owner_id"]},
    ).json()
    assert client.patch(
        f"/api/v1/admin/gate-policies/{application['gate_policy_id']}", headers=admin_headers,
        json={"gates": [{
            "gate_id": replacement["id"],
            "blocking_severities": ["low", "medium", "high", "critical"],
        }]},
    ).status_code == 200
    assert client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers, json={"active": False},
    ).status_code == 200
    assert evaluate(client, key).json()["policies"] == []


def test_invalid_api_key(client):
    assert evaluate(client, "sec_invalid").status_code == 401


def test_revoked_api_key(client, admin_headers, api_key):
    key, credential_id = api_key
    response = client.post(f"/api/v1/admin/api-credentials/{credential_id}/revoke", headers=admin_headers, json={"reason": "Credential rotation completed."})
    assert response.status_code == 200
    assert evaluate(client, key).status_code == 401
