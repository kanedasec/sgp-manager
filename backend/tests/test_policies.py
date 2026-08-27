from datetime import UTC, datetime, timedelta


def payload(domain, **changes):
    application, gate = domain
    value = {
        "application_id": application["id"], "owner_id": gate["owner_id"],
        "gates": [{"gate_id": gate["id"], "severities": ["low", "medium"]}],
        "justification": "Temporary exception for a controlled migration.",
        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }
    value.update(changes)
    return value


def test_create_valid_policy(client, admin_headers, domain):
    response = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain))
    assert response.status_code == 201
    assert response.json()["status"] == "ACTIVE"
    assert response.json()["gates"][0]["severities"] == ["low", "medium"]


def test_reject_policy_without_severity(client, admin_headers, domain):
    application, gate = domain
    response = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{"gate_id": gate["id"], "severities": []}], application_id=application["id"],
    ))
    assert response.status_code == 422


def test_reject_expiration_in_past(client, admin_headers, domain):
    response = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain, expires_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat()))
    assert response.status_code == 422


def test_reject_overlapping_policy(client, admin_headers, domain):
    first = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain))
    assert first.status_code == 201
    _, gate = domain
    second = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{"gate_id": gate["id"], "severities": ["high"]}],
    ))
    assert second.status_code == 409


def test_revoked_policy_status(client, admin_headers, domain):
    created = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain)).json()
    response = client.post(f"/api/v1/admin/bypass-policies/{created['id']}/revoke", headers=admin_headers, json={"reason": "Migration completed successfully."})
    assert response.status_code == 200
    assert response.json()["status"] == "REVOKED"


def test_create_one_policy_with_multiple_gates(client, admin_headers, domain):
    application, first_gate = domain
    second_gate = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "SAST", "slug": "sast", "owner_id": first_gate["owner_id"], "default_blocking_severities": ["high", "critical"]},
    ).json()
    response = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain, gates=[
        {"gate_id": first_gate["id"], "severities": ["low", "medium"]},
        {"gate_id": second_gate["id"], "severities": ["high"]},
    ]))
    assert response.status_code == 201
    assert response.json()["application_id"] == application["id"]
    assert {scope["gate_slug"] for scope in response.json()["gates"]} == {"secrets", "sast"}


def test_gate_default_blocking_severities_are_persisted(client, admin_headers, owner):
    created = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "SCA", "slug": "sca", "owner_id": owner["id"], "default_blocking_severities": ["medium", "high"]},
    )
    assert created.status_code == 201
    assert created.json()["default_blocking_severities"] == ["medium", "high"]
    updated = client.patch(
        f"/api/v1/admin/gates/{created.json()['id']}", headers=admin_headers,
        json={"default_blocking_severities": ["critical"]},
    )
    assert updated.json()["default_blocking_severities"] == ["critical"]


def test_gate_requires_at_least_one_default_blocking_severity(client, admin_headers, owner):
    response = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "Container", "slug": "container", "owner_id": owner["id"], "default_blocking_severities": []},
    )
    assert response.status_code == 422


def test_update_policy_keeps_grouped_gate_scopes_consistent(client, admin_headers, domain):
    _, first_gate = domain
    second_gate = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "DAST", "slug": "dast", "owner_id": first_gate["owner_id"]},
    ).json()
    created = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain)).json()
    updated = client.patch(
        f"/api/v1/admin/bypass-policies/{created['id']}", headers=admin_headers,
        json={"gates": [
            {"gate_id": first_gate["id"], "severities": ["critical"]},
            {"gate_id": second_gate["id"], "severities": ["medium", "high"]},
        ]},
    )
    assert updated.status_code == 200
    scopes = {item["gate_slug"]: item["severities"] for item in updated.json()["gates"]}
    assert scopes == {"secrets": ["critical"], "dast": ["medium", "high"]}
