def create_gate(client, admin_headers, owner, name, slug):
    response = client.post(
        "/api/v1/admin/gates",
        headers=admin_headers,
        json={"name": name, "slug": slug, "owner_id": owner["id"]},
    )
    assert response.status_code == 201
    return response.json()


def configure_pipeline(client, admin_headers, *gates):
    return client.patch(
        "/api/v1/admin/security-pipeline",
        headers=admin_headers,
        json={"gate_ids": [gate["id"] for gate in gates]},
    )


def resolve_pipeline(client, key, application="payment-api"):
    return client.post(
        "/api/v1/policies/resolve-pipeline",
        headers={"X-API-Key": key},
        json={"application": application},
    )


def test_admin_configures_and_reorders_security_pipeline(
    client, admin_headers, owner, domain, api_key
):
    application, secrets = domain
    sast = create_gate(client, admin_headers, owner, "SAST", "sast")
    sca = create_gate(client, admin_headers, owner, "SCA", "sca")

    configured = configure_pipeline(client, admin_headers, sast, secrets, sca)
    assert configured.status_code == 200
    assert configured.json()["gates"] == [
        {"id": sast["id"], "name": "SAST", "slug": "sast", "position": 0},
        {"id": secrets["id"], "name": "Secrets", "slug": "secrets", "position": 1},
        {"id": sca["id"], "name": "SCA", "slug": "sca", "position": 2},
    ]

    reordered = configure_pipeline(client, admin_headers, sca, sast)
    assert [gate["slug"] for gate in reordered.json()["gates"]] == ["sca", "sast"]
    assert [gate["position"] for gate in reordered.json()["gates"]] == [0, 1]

    key, _ = api_key
    resolved = resolve_pipeline(client, key, application["slug"])
    assert resolved.status_code == 200
    assert resolved.json()["application"] == "payment-api"
    assert resolved.json()["gates"] == [
        {"gate": "sca", "position": 0},
        {"gate": "sast", "position": 1},
    ]


def test_pipeline_update_rejects_empty_duplicate_unknown_and_inactive_gates(
    client, admin_headers, owner
):
    gate = create_gate(client, admin_headers, owner, "SAST", "sast")

    assert client.patch(
        "/api/v1/admin/security-pipeline", headers=admin_headers, json={"gate_ids": []}
    ).status_code == 422
    assert client.patch(
        "/api/v1/admin/security-pipeline",
        headers=admin_headers,
        json={"gate_ids": [gate["id"], gate["id"]]},
    ).status_code == 422
    assert client.patch(
        "/api/v1/admin/security-pipeline",
        headers=admin_headers,
        json={"gate_ids": ["11111111-1111-1111-1111-111111111111"]},
    ).status_code == 400

    disabled = client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers, json={"active": False}
    )
    assert disabled.status_code == 200
    assert configure_pipeline(client, admin_headers, gate).status_code == 400


def test_referenced_gate_must_be_removed_from_policy_before_mutation(
    client, admin_headers, owner
):
    sast = create_gate(client, admin_headers, owner, "SAST", "sast")
    secrets = create_gate(client, admin_headers, owner, "Secrets", "secrets")
    assert configure_pipeline(client, admin_headers, sast, secrets).status_code == 200

    rename = client.patch(
        f"/api/v1/admin/gates/{sast['id']}",
        headers=admin_headers,
        json={"slug": "renamed-sast"},
    )
    assert rename.status_code == 409

    disabled = client.patch(
        f"/api/v1/admin/gates/{sast['id']}", headers=admin_headers, json={"active": False}
    )
    assert disabled.status_code == 409
    default_policy = next(
        item for item in client.get(
            "/api/v1/admin/gate-policies", headers=admin_headers,
        ).json() if item["slug"] == "default-security-policy"
    )
    changed = client.patch(
        f"/api/v1/admin/gate-policies/{default_policy['id']}", headers=admin_headers,
        json={"gates": [{
            "gate_id": secrets["id"],
            "blocking_severities": ["low", "medium", "high", "critical"],
        }]},
    )
    assert changed.status_code == 200
    disabled = client.patch(
        f"/api/v1/admin/gates/{sast['id']}", headers=admin_headers, json={"active": False}
    )
    assert disabled.status_code == 200
    pipeline = client.get("/api/v1/admin/security-pipeline", headers=admin_headers)
    assert [gate["slug"] for gate in pipeline.json()["gates"]] == ["secrets"]
    assert pipeline.json()["gates"][0]["position"] == 0


def test_owner_scoped_gate_manager_cannot_mutate_referenced_gate_or_policy(
    client, admin_headers, owner
):
    gate = create_gate(client, admin_headers, owner, "SAST", "sast")
    assert configure_pipeline(client, admin_headers, gate).status_code == 200
    group = client.post(
        "/api/v1/admin/groups",
        headers=admin_headers,
        json={
            "name": "Gate managers",
            "slug": "gate-managers",
            "permissions": ["view-gates:appsec", "edit-gates:appsec"],
        },
    ).json()
    created_user = client.post(
        "/api/v1/admin/users",
        headers=admin_headers,
        json={
            "username": "gate.manager",
            "password": "ScopedGatePass!123",
            "display_name": "Gate Manager",
            "email": "gate.manager@example.com",
            "role": "USER",
            "group_ids": [group["id"]],
        },
    )
    assert created_user.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "gate.manager", "password": "ScopedGatePass!123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    denied = client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=headers, json={"active": False}
    )
    assert denied.status_code == 409
    assert client.get(
        "/api/v1/admin/security-pipeline", headers=headers
    ).status_code == 403


def test_pipeline_resolution_fails_closed(client, admin_headers, domain, api_key):
    key, _ = api_key
    assert resolve_pipeline(client, key).status_code == 200
    assert resolve_pipeline(client, key, "unknown-application").status_code == 404
    assert resolve_pipeline(client, "sec_invalid").status_code == 401
    assert client.get("/api/v1/admin/security-pipeline").status_code == 401
