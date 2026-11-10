from uuid import uuid4


def create_credential(client, headers, scopes):
    response = client.post(
        "/api/v1/admin/api-credentials",
        headers=headers,
        json={"name": "scoped-pipeline", "scopes": scopes},
    )
    assert response.status_code == 201
    return response.json()


def replace_scopes(client, headers, credential_id, scopes):
    return client.put(
        f"/api/v1/admin/api-credentials/{credential_id}/scopes",
        headers=headers,
        json={"scopes": scopes},
    )


def test_admin_can_list_supported_machine_scopes(client, admin_headers):
    response = client.get("/api/v1/admin/api-credential-scopes", headers=admin_headers)
    assert response.status_code == 200
    definitions = {item["scope"]: item for item in response.json()}
    assert set(definitions) == {"policy:read", "application:manage"}
    assert definitions["application:manage"]["endpoints"] == [
        "POST /api/v1/policies/applications/ensure",
    ]
    assert client.get("/api/v1/admin/api-credential-scopes").status_code == 401


def test_scope_replacement_changes_endpoint_access_immediately(client, admin_headers, domain):
    credential = create_credential(client, admin_headers, ["policy:read"])
    key_headers = {"X-API-Key": credential["api_key"]}

    policy_read = client.post(
        "/api/v1/policies/evaluate",
        headers=key_headers,
        json={"application": "payment-api"},
    )
    assert policy_read.status_code == 200
    denied_create = client.post(
        "/api/v1/policies/applications/ensure",
        headers=key_headers,
        json={"application": "new-machine-app", "gate_policy": "default-security-policy"},
    )
    assert denied_create.status_code == 403

    updated = replace_scopes(
        client, admin_headers, credential["id"], ["application:manage"],
    )
    assert updated.status_code == 200
    assert updated.json()["scopes"] == ["application:manage"]

    policy_read_after_replacement = client.post(
        "/api/v1/policies/evaluate",
        headers=key_headers,
        json={"application": "payment-api"},
    )
    assert policy_read_after_replacement.status_code == 403
    created = client.post(
        "/api/v1/policies/applications/ensure",
        headers=key_headers,
        json={"application": "new-machine-app", "gate_policy": "default-security-policy"},
    )
    assert created.status_code == 200
    assert created.json() == {
        "application": "new-machine-app",
        "created": True,
        "gate_policy": "default-security-policy",
        "policy_matches": True,
    }

    audit = client.get("/api/v1/admin/audit-logs", headers=admin_headers)
    event = next(
        item for item in audit.json()
        if item["event_type"] == "API_CREDENTIAL_SCOPES_UPDATED"
    )
    assert event["metadata"] == {
        "prefix": credential["prefix"],
        "previous_scopes": ["policy:read"],
        "scopes": ["application:manage"],
    }


def test_scope_replacement_rejects_invalid_or_empty_policy(client, admin_headers):
    credential = create_credential(client, admin_headers, ["policy:read"])
    assert replace_scopes(
        client, admin_headers, credential["id"], [],
    ).status_code == 422
    assert replace_scopes(
        client, admin_headers, credential["id"], ["admin:all"],
    ).status_code == 422
    assert replace_scopes(
        client, admin_headers, uuid4(), ["policy:read"],
    ).status_code == 404


def test_revoked_credential_scope_policy_is_immutable(client, admin_headers):
    credential = create_credential(client, admin_headers, ["policy:read"])
    revoked = client.post(
        f"/api/v1/admin/api-credentials/{credential['id']}/revoke",
        headers=admin_headers,
        json={"reason": "Credential is no longer assigned to a pipeline"},
    )
    assert revoked.status_code == 200
    response = replace_scopes(
        client, admin_headers, credential["id"], ["application:manage"],
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Revoked API credential access policies are immutable"
