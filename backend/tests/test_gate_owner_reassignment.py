"""Regression tests for pentest finding F-01: changing a gate's owner used
to silently preserve any active bypass created under the gate's previous
owner, letting gate-edit rights for two owners substitute for
policy-create rights on the destination owner."""
from datetime import UTC, datetime, timedelta


def create_owner(client, headers, name, slug):
    response = client.post("/api/v1/admin/owners", headers=headers, json={"name": name, "slug": slug})
    assert response.status_code == 201
    return response.json()


def create_gate(client, headers, owner, name, slug):
    response = client.post(
        "/api/v1/admin/gates", headers=headers, json={"name": name, "slug": slug, "owner_id": owner["id"]},
    )
    assert response.status_code == 201
    return response.json()


def test_gate_owner_change_blocked_while_active_bypass_references_it(client, admin_headers, domain):
    application, gate = domain
    owner_b = create_owner(client, admin_headers, "Quality", "quality")

    bypass = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json={
            "application_id": application["id"], "owner_id": gate["owner_id"],
            "gates": [{"gate_id": gate["id"], "severities": ["high"]}],
            "justification": "Approved temporary exception for an in-flight migration.",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
    )
    assert bypass.status_code == 201

    moved = client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers, json={"owner_id": owner_b["id"]},
    )
    assert moved.status_code == 409

    revoked = client.post(f"/api/v1/admin/bypass-policies/{bypass.json()['id']}/revoke", headers=admin_headers, json={
        "reason": "Cleared before the planned owner transfer.",
    })
    assert revoked.status_code == 200

    moved_after_revoke = client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers, json={"owner_id": owner_b["id"]},
    )
    assert moved_after_revoke.status_code == 200
    assert moved_after_revoke.json()["owner_id"] == owner_b["id"]


def test_gate_owner_change_allowed_without_any_bypass(client, admin_headers, domain):
    _application, gate = domain
    owner_b = create_owner(client, admin_headers, "Quality", "quality")
    moved = client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers, json={"owner_id": owner_b["id"]},
    )
    assert moved.status_code == 200
    assert moved.json()["owner_id"] == owner_b["id"]
