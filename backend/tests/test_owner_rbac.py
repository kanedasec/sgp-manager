from datetime import UTC, datetime, timedelta


def create_owner(client, headers, name, slug):
    response = client.post(
        "/api/v1/admin/owners", headers=headers, json={"name": name, "slug": slug},
    )
    assert response.status_code == 201
    return response.json()


def create_gate(client, headers, owner, name, slug):
    response = client.post(
        "/api/v1/admin/gates", headers=headers,
        json={"name": name, "slug": slug, "owner_id": owner["id"]},
    )
    assert response.status_code == 201
    return response.json()


def login_headers(client, username, password):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}, response.json()["user"]


def policy_payload(application, owner, gate, severity="high"):
    return {
        "application_id": application["id"], "owner_id": owner["id"],
        "gates": [{"gate_id": gate["id"], "severities": [severity]}],
        "justification": "Owner-scoped temporary exception for an approved migration.",
        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }


def provision_scoped_user(client, admin_headers, appsec):
    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "AppSec Chapters", "slug": "appsec-chapters",
        "permissions": [
            "view-gates:all", "view-policies:all", "create-policies:appsec", "edit-policies:appsec",
        ],
    })
    assert group.status_code == 201
    user = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "chapter.user", "password": "ScopedUserPass!123", "display_name": "Chapter User",
        "email": "chapter.user@example.com", "role": "USER", "group_ids": [group.json()["id"]],
    })
    assert user.status_code == 201
    return login_headers(client, "chapter.user", "ScopedUserPass!123")


def test_group_roles_are_exposed_in_authenticated_session(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    headers, session_user = provision_scoped_user(client, admin_headers, appsec)
    assert session_user["role"] == "USER"
    assert session_user["groups"] == ["appsec-chapters"]
    assert "edit-policies:appsec" in session_user["permissions"]
    assert client.get("/api/v1/auth/me", headers=headers).json()["permissions"] == session_user["permissions"]


def test_owner_scoped_policy_permissions_are_enforced(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    quality = create_owner(client, admin_headers, "Quality", "quality")
    appsec_gate = create_gate(client, admin_headers, appsec, "Secrets", "secrets")
    quality_gate = create_gate(client, admin_headers, quality, "Quality Check", "quality-check")
    application = client.post(
        "/api/v1/admin/applications", headers=admin_headers,
        json={"name": "Payment API", "slug": "payment-api"},
    ).json()
    appsec_policy = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json=policy_payload(application, appsec, appsec_gate),
    ).json()
    quality_policy = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json=policy_payload(application, quality, quality_gate),
    ).json()
    headers, _ = provision_scoped_user(client, admin_headers, appsec)

    visible = client.get("/api/v1/admin/bypass-policies", headers=headers)
    assert visible.status_code == 200
    assert {item["id"] for item in visible.json()} == {appsec_policy["id"], quality_policy["id"]}
    assert client.patch(
        f"/api/v1/admin/bypass-policies/{appsec_policy['id']}", headers=headers,
        json={"justification": "Updated by the authorized AppSec owner group."},
    ).status_code == 200
    assert client.patch(
        f"/api/v1/admin/bypass-policies/{quality_policy['id']}", headers=headers,
        json={"justification": "This update must not be authorized for AppSec."},
    ).status_code == 403
    assert client.post(
        "/api/v1/admin/bypass-policies", headers=headers,
        json=policy_payload(application, quality, quality_gate, "medium"),
    ).status_code == 403


def test_policy_cannot_include_gate_from_different_owner(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    quality = create_owner(client, admin_headers, "Quality", "quality")
    quality_gate = create_gate(client, admin_headers, quality, "Quality", "quality")
    application = client.post(
        "/api/v1/admin/applications", headers=admin_headers,
        json={"name": "Payment API", "slug": "payment-api"},
    ).json()
    response = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers,
        json=policy_payload(application, appsec, quality_gate),
    )
    assert response.status_code == 400
    assert "different owner" in response.json()["detail"]


def test_gate_permissions_filter_visibility_and_enforce_owner_scope(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    quality = create_owner(client, admin_headers, "Quality", "quality")
    appsec_gate = create_gate(client, admin_headers, appsec, "Secrets", "secrets")
    quality_gate = create_gate(client, admin_headers, quality, "Quality", "quality")
    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "AppSec Gate Managers", "slug": "appsec-gate-managers",
        "permissions": ["view-gates:appsec", "create-gates:appsec", "edit-gates:appsec"],
    })
    assert group.status_code == 201
    user = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "gate.manager", "password": "ScopedGatePass!123", "display_name": "Gate Manager",
        "email": "gate.manager@example.com", "role": "USER", "group_ids": [group.json()["id"]],
    })
    assert user.status_code == 201
    headers, _ = login_headers(client, "gate.manager", "ScopedGatePass!123")

    visible = client.get("/api/v1/admin/gates", headers=headers)
    assert visible.status_code == 200
    assert {item["id"] for item in visible.json()} == {appsec_gate["id"]}
    assert client.get(f"/api/v1/admin/gates/{quality_gate['id']}", headers=headers).status_code == 403
    assert client.patch(
        f"/api/v1/admin/gates/{appsec_gate['id']}", headers=headers,
        json={"description": "Managed by the authorized owner group."},
    ).status_code == 200
    assert client.patch(
        f"/api/v1/admin/gates/{quality_gate['id']}", headers=headers,
        json={"description": "Cross-owner edit must be denied."},
    ).status_code == 403
    assert client.post("/api/v1/admin/gates", headers=headers, json={
        "name": "Architecture Review", "slug": "architecture-review", "owner_id": quality["id"],
    }).status_code == 403


def test_regular_user_cannot_manage_access_or_credentials(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    headers, _ = provision_scoped_user(client, admin_headers, appsec)
    assert client.get("/api/v1/admin/groups", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/api-credentials", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/audit-logs", headers=headers).status_code == 403


def test_invalid_or_unknown_owner_role_is_rejected(client, admin_headers):
    invalid = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Invalid", "slug": "invalid", "permissions": ["delete-policies:all"],
    })
    assert invalid.status_code == 422
    unknown = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Unknown", "slug": "unknown", "permissions": ["view-policies:not-created"],
    })
    assert unknown.status_code == 422
