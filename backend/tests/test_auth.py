def test_valid_login(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


def test_invalid_password(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401


def test_admin_route_requires_authentication(client):
    assert client.get("/api/v1/admin/applications").status_code == 401


def test_validation_error_does_not_echo_password(client):
    password = "never-echo-this-" * 30
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": password})
    assert response.status_code == 422
    assert password not in response.text


def test_api_documentation_requires_portal_login(client):
    assert client.get("/docs").status_code == 401
    assert client.get("/redoc").status_code == 401
    assert client.get("/openapi.json").status_code == 401


def test_portal_login_grants_documentation_session(client):
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    assert login.status_code == 200
    cookie = login.headers["set-cookie"]
    assert "sgbm_admin_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie

    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "connect-src 'self'" in docs.headers["content-security-policy"]
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    assert "/api/v1/policies/evaluate" in schema.json()["paths"]
    assert "/api/v1/policies/evaluate-enforcement" in schema.json()["paths"]


def test_logout_removes_documentation_session(client):
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    assert client.get("/docs").status_code == 200
    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.get("/docs").status_code == 401


def test_mandatory_password_change_blocks_portal_until_completed(client):
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.must_change_password = True
        db.commit()

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    assert login.status_code == 200
    assert login.json()["user"]["must_change_password"] is True
    assert "sgbm_admin_session=" not in login.headers.get("set-cookie", "") or "Max-Age=0" in login.headers["set-cookie"]
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    blocked = client.get("/api/v1/admin/applications", headers=headers)
    assert blocked.status_code == 403
    assert "Password change required" in blocked.json()["detail"]
    assert client.get("/docs").status_code == 401
    assert client.post("/api/v1/auth/change-password", headers=headers, json={
        "current_password": "incorrect", "new_password": "ReplacementPass!2026",
    }).status_code == 400

    changed = client.post("/api/v1/auth/change-password", headers=headers, json={
        "current_password": "StrongTestPass!123", "new_password": "ReplacementPass!2026",
    })
    assert changed.status_code == 200
    assert changed.json()["user"]["must_change_password"] is False
    replacement_headers = {"Authorization": f"Bearer {changed.json()['access_token']}"}
    assert client.get("/api/v1/admin/applications", headers=replacement_headers).status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.post("/api/v1/auth/login", json={
        "username": "admin", "password": "StrongTestPass!123",
    }).status_code == 401
from sqlalchemy import select

from app.core.database import SessionLocal
from app.models import User

