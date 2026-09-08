def ensure(client, key, application, gate_policy, name=None):
    body = {"application": application, "gate_policy": gate_policy}
    if name is not None:
        body["name"] = name
    return client.post("/api/v1/policies/applications/ensure", headers={"X-API-Key": key}, json=body)


def test_creates_application_when_it_does_not_exist(client, admin_headers, domain, management_api_key):
    # `domain` fixture (conftest.py) is what actually persists
    # default-security-policy: PATCH /admin/security-pipeline is the only
    # path that commits (not just flushes) ensure_default_gate_policy()'s
    # row, and it needs at least one real gate. `domain` also creates
    # "payment-api", unused here but harmless.
    key, _ = management_api_key
    response = ensure(client, key, "new-service", "default-security-policy")
    assert response.status_code == 200
    body = response.json()
    assert body["application"] == "new-service"
    assert body["created"] is True
    assert body["gate_policy"] == "default-security-policy"
    assert body["policy_matches"] is True

    # The application is now visible through the normal admin API.
    listed = client.get("/api/v1/admin/applications", headers=admin_headers).json()
    assert any(item["slug"] == "new-service" for item in listed)


def test_is_idempotent_when_application_already_exists_under_same_policy(client, admin_headers, domain, management_api_key):
    key, _ = management_api_key
    first = ensure(client, key, "idempotent-service", "default-security-policy")
    assert first.json()["created"] is True

    second = ensure(client, key, "idempotent-service", "default-security-policy")
    assert second.status_code == 200
    body = second.json()
    assert body["created"] is False
    assert body["policy_matches"] is True
    assert body["gate_policy"] == "default-security-policy"


def test_reports_mismatch_without_changing_policy_of_existing_application(client, admin_headers, domain, management_api_key):
    # `domain` fixture creates "payment-api" under "default-security-policy".
    key, _ = management_api_key
    application, gate = domain

    other_policy = client.post(
        "/api/v1/admin/gate-policies", headers=admin_headers,
        json={
            "name": "Strict Policy", "slug": "strict-policy",
            "gates": [{"gate_id": gate["id"], "blocking_severities": ["low", "medium", "high", "critical"]}],
        },
    )
    assert other_policy.status_code == 201, other_policy.text

    response = ensure(client, key, "payment-api", "strict-policy")
    assert response.status_code == 200
    body = response.json()
    assert body["created"] is False
    assert body["policy_matches"] is False
    # Still reports the application's ACTUAL current policy, not the requested one.
    assert body["gate_policy"] == "default-security-policy"

    # And the application's real assignment was not changed by this call.
    check = ensure(client, key, "payment-api", "default-security-policy")
    assert check.json()["policy_matches"] is True


def test_rejects_unknown_gate_policy(client, admin_headers, domain, management_api_key):
    key, _ = management_api_key
    response = ensure(client, key, "some-service", "does-not-exist")
    assert response.status_code == 400


def test_optional_name_defaults_to_slug(client, admin_headers, domain, management_api_key):
    key, _ = management_api_key
    ensure(client, key, "no-name-service", "default-security-policy")
    listed = client.get("/api/v1/admin/applications", headers=admin_headers).json()
    item = next(entry for entry in listed if entry["slug"] == "no-name-service")
    assert item["name"] == "no-name-service"


def test_explicit_name_is_used_when_provided(client, admin_headers, domain, management_api_key):
    key, _ = management_api_key
    ensure(client, key, "named-service", "default-security-policy", name="My Nice Service")
    listed = client.get("/api/v1/admin/applications", headers=admin_headers).json()
    item = next(entry for entry in listed if entry["slug"] == "named-service")
    assert item["name"] == "My Nice Service"


def test_requires_application_manage_scope_not_just_policy_read(client, api_key):
    # `api_key` fixture only grants the default policy:read scope.
    key, _ = api_key
    response = ensure(client, key, "should-not-be-created", "default-security-policy")
    assert response.status_code == 403


def test_requires_api_key_authentication(client):
    response = client.post(
        "/api/v1/policies/applications/ensure",
        json={"application": "no-key-service", "gate_policy": "default-security-policy"},
    )
    assert response.status_code == 401


def test_rejects_invalid_slug_format(client, management_api_key):
    key, _ = management_api_key
    response = client.post(
        "/api/v1/policies/applications/ensure", headers={"X-API-Key": key},
        json={"application": "Not A Valid Slug!", "gate_policy": "default-security-policy"},
    )
    assert response.status_code == 422


def test_api_credential_defaults_to_policy_read_scope_only(client, admin_headers):
    response = client.post("/api/v1/admin/api-credentials", headers=admin_headers, json={"name": "default-scope-key"})
    assert response.status_code == 201
    assert response.json()["scopes"] == ["policy:read"]


def test_api_credential_rejects_unknown_scope(client, admin_headers):
    response = client.post(
        "/api/v1/admin/api-credentials", headers=admin_headers,
        json={"name": "bad-scope-key", "scopes": ["not-a-real-scope"]},
    )
    assert response.status_code == 422


def test_api_credential_rejects_empty_scopes(client, admin_headers):
    response = client.post(
        "/api/v1/admin/api-credentials", headers=admin_headers, json={"name": "no-scope-key", "scopes": []},
    )
    assert response.status_code == 422


def test_api_credential_can_be_granted_application_manage_scope(client, admin_headers):
    response = client.post(
        "/api/v1/admin/api-credentials", headers=admin_headers,
        json={"name": "manage-scope-key", "scopes": ["application:manage"]},
    )
    assert response.status_code == 201
    assert response.json()["scopes"] == ["application:manage"]


def test_revoked_credential_cannot_call_ensure(client, admin_headers, domain, management_api_key):
    key, credential_id = management_api_key
    revoke = client.post(
        f"/api/v1/admin/api-credentials/{credential_id}/revoke", headers=admin_headers, json={"reason": "no longer needed"},
    )
    assert revoke.status_code == 200
    response = ensure(client, key, "revoked-key-service", "default-security-policy")
    assert response.status_code == 401
