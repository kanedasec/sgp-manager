import os
from datetime import UTC, datetime

os.environ["DATABASE_URL"] = "sqlite:///./test_sgbm.db"
os.environ["JWT_SECRET"] = "test-jwt-secret-that-is-long-enough-123456789"
os.environ["API_KEY_PEPPER"] = "test-api-pepper-that-is-long-enough-123456789"
os.environ["ENVIRONMENT"] = "test"
os.environ["INITIAL_ADMIN_PASSWORD"] = "StrongTestPass!123"

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password
from app.main import app
from app.models import User
from app.models.entities import UserRole


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add(User(username="admin", password_hash=hash_password("StrongTestPass!123"), display_name="Test Admin", email="admin@test.local", role=UserRole.ADMIN))
        db.commit()
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


@pytest.fixture
def admin_headers(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def owner(client, admin_headers):
    response = client.post(
        "/api/v1/admin/owners", headers=admin_headers,
        json={"name": "AppSec", "slug": "appsec", "description": "Application security ownership."},
    )
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def domain(client, admin_headers, owner):
    gate = client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "Secrets", "slug": "secrets", "owner_id": owner["id"]},
    ).json()
    configured = client.patch(
        "/api/v1/admin/security-pipeline", headers=admin_headers,
        json={"gate_ids": [gate["id"]]},
    )
    assert configured.status_code == 200
    gate_policy = next(
        item for item in client.get(
            "/api/v1/admin/gate-policies", headers=admin_headers,
        ).json() if item["slug"] == "default-security-policy"
    )
    application_response = client.post(
        "/api/v1/admin/applications", headers=admin_headers,
        json={
            "name": "Payment API", "slug": "payment-api",
            "gate_policy_id": gate_policy["id"],
        },
    )
    assert application_response.status_code == 201
    application = application_response.json()
    return application, gate


@pytest.fixture
def api_key(client, admin_headers):
    response = client.post("/api/v1/admin/api-credentials", headers=admin_headers, json={"name": "pytest-pipeline"})
    assert response.status_code == 201
    return response.json()["api_key"], response.json()["id"]
