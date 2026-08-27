def test_admin_can_create_and_update_user(client, admin_headers):
    created = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "appsec.two", "password": "AnotherStrongPass!123",
        "display_name": "AppSec Two", "email": "appsec.two@example.com",
    })
    assert created.status_code == 201
    assert created.json()["active"] is True
    assert "password" not in created.text

    updated = client.patch(
        f"/api/v1/admin/users/{created.json()['id']}", headers=admin_headers,
        json={"display_name": "AppSec Operator", "active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["active"] is False


def test_admin_cannot_deactivate_self(client, admin_headers):
    current = client.get("/api/v1/auth/me", headers=admin_headers).json()
    response = client.patch(
        f"/api/v1/admin/users/{current['id']}", headers=admin_headers, json={"active": False},
    )
    assert response.status_code == 409


def test_user_management_requires_authentication(client):
    assert client.get("/api/v1/admin/users").status_code == 401
