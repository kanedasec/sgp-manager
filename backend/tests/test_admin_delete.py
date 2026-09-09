from datetime import UTC, datetime, timedelta


def policy_payload(application, owner, gate, severity="high"):
    return {
        "application_id": application["id"], "owner_id": owner["id"],
        "gates": [{"gate_id": gate["id"], "severities": [severity]}],
        "justification": "Owner-scoped temporary exception for an approved migration.",
        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }


def test_admin_can_delete_an_unreferenced_application(client, admin_headers, domain):
    application, _gate = domain
    response = client.delete(f"/api/v1/admin/applications/{application['id']}", headers=admin_headers)
    assert response.status_code == 204
    assert client.get(f"/api/v1/admin/applications/{application['id']}", headers=admin_headers).status_code == 404


def test_deleting_application_blocked_by_bypass_policy_history(client, admin_headers, domain):
    application, gate = domain
    owners = client.get("/api/v1/admin/owner-labels", headers=admin_headers).json()
    owner = owners[0]
    bypass = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json=policy_payload(application, owner, gate),
    )
    assert bypass.status_code == 201, bypass.text

    response = client.delete(f"/api/v1/admin/applications/{application['id']}", headers=admin_headers)
    assert response.status_code == 409

    # Deleting the bypass first (even though it is still ACTIVE, not just
    # revoked/expired) then allows the application delete to proceed.
    assert client.delete(f"/api/v1/admin/bypass-policies/{bypass.json()['id']}", headers=admin_headers).status_code == 204
    assert client.delete(f"/api/v1/admin/applications/{application['id']}", headers=admin_headers).status_code == 204


def test_admin_can_delete_an_unreferenced_gate(client, admin_headers, owner):
    gate = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "Unused Scanner", "slug": "unused-scanner", "owner_id": owner["id"]},
    ).json()
    response = client.delete(f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers)
    assert response.status_code == 204
    assert client.get(f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers).status_code == 404


def test_deleting_gate_blocked_while_in_a_gate_policy(client, admin_headers, domain):
    _application, gate = domain
    response = client.delete(f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers)
    assert response.status_code == 409


def test_admin_can_delete_an_unreferenced_gate_policy(client, admin_headers, owner):
    gate = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "Lint", "slug": "lint", "owner_id": owner["id"]},
    ).json()
    policy = client.post(
        "/api/v1/admin/gate-policies", headers=admin_headers,
        json={
            "name": "Lightweight Policy", "slug": "lightweight-policy",
            "gates": [{"gate_id": gate["id"], "blocking_severities": ["critical"]}],
        },
    ).json()
    response = client.delete(f"/api/v1/admin/gate-policies/{policy['id']}", headers=admin_headers)
    assert response.status_code == 204
    assert client.get("/api/v1/admin/gate-policies", headers=admin_headers).status_code == 200
    assert all(item["id"] != policy["id"] for item in client.get("/api/v1/admin/gate-policies", headers=admin_headers).json())


def test_deleting_gate_policy_blocked_while_an_application_uses_it(client, admin_headers, domain):
    application, gate = domain
    gate_policy_id = application["gate_policy_id"]
    response = client.delete(f"/api/v1/admin/gate-policies/{gate_policy_id}", headers=admin_headers)
    assert response.status_code == 409


def test_admin_can_delete_a_bypass_policy(client, admin_headers, domain):
    application, gate = domain
    owners = client.get("/api/v1/admin/owner-labels", headers=admin_headers).json()
    owner = owners[0]
    bypass = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json=policy_payload(application, owner, gate),
    ).json()
    response = client.delete(f"/api/v1/admin/bypass-policies/{bypass['id']}", headers=admin_headers)
    assert response.status_code == 204
    assert all(item["id"] != bypass["id"] for item in client.get("/api/v1/admin/bypass-policies", headers=admin_headers).json())


def test_admin_can_delete_a_revoked_bypass_policy(client, admin_headers, domain):
    application, gate = domain
    owners = client.get("/api/v1/admin/owner-labels", headers=admin_headers).json()
    owner = owners[0]
    bypass = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json=policy_payload(application, owner, gate),
    ).json()
    revoked = client.post(
        f"/api/v1/admin/bypass-policies/{bypass['id']}/revoke", headers=admin_headers,
        json={"reason": "No longer needed after remediation."},
    )
    assert revoked.status_code == 200
    response = client.delete(f"/api/v1/admin/bypass-policies/{bypass['id']}", headers=admin_headers)
    assert response.status_code == 204


def test_delete_endpoints_return_404_for_unknown_ids(client, admin_headers):
    fake_id = "00000000-0000-0000-0000-000000000000"
    assert client.delete(f"/api/v1/admin/applications/{fake_id}", headers=admin_headers).status_code == 404
    assert client.delete(f"/api/v1/admin/gates/{fake_id}", headers=admin_headers).status_code == 404
    assert client.delete(f"/api/v1/admin/gate-policies/{fake_id}", headers=admin_headers).status_code == 404
    assert client.delete(f"/api/v1/admin/bypass-policies/{fake_id}", headers=admin_headers).status_code == 404


def test_delete_endpoints_require_admin_role(client, admin_headers, domain):
    application, gate = domain
    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Read Only Group", "slug": "read-only-group",
        "permissions": [f"view-gates:{application['id']}" if False else "view-gates:all"],
    })
    assert group.status_code == 201, group.text
    user = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "nonadmin.deleter", "password": "StrongTestPass!123",
        "display_name": "Nonadmin Deleter", "email": "nonadmin.deleter@example.com",
        "role": "USER", "group_ids": [group.json()["id"]],
    })
    assert user.status_code == 201, user.text
    login = client.post("/api/v1/auth/login", json={"username": "nonadmin.deleter", "password": "StrongTestPass!123"})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.delete(f"/api/v1/admin/applications/{application['id']}", headers=headers).status_code == 403
    assert client.delete(f"/api/v1/admin/gates/{gate['id']}", headers=headers).status_code == 403
    gate_policy_id = application["gate_policy_id"]
    assert client.delete(f"/api/v1/admin/gate-policies/{gate_policy_id}", headers=headers).status_code == 403


def test_audit_log_records_deletions(client, admin_headers, domain):
    application, _gate = domain
    application_id = application["id"]
    response = client.delete(f"/api/v1/admin/applications/{application_id}", headers=admin_headers)
    assert response.status_code == 204
    audit = client.get("/api/v1/admin/audit-logs?event_type=APPLICATION_DELETED", headers=admin_headers)
    assert audit.status_code == 200
    assert audit.json(), "expected an APPLICATION_DELETED audit entry"
