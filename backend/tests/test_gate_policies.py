def create_gate(client, headers, owner, name, slug, defaults=None):
    response = client.post(
        "/api/v1/admin/gates", headers=headers,
        json={
            "name": name,
            "slug": slug,
            "owner_id": owner["id"],
            **({"default_blocking_severities": defaults} if defaults else {}),
        },
    )
    assert response.status_code == 201
    return response.json()


def create_policy(client, headers, gates, name="Crown Jewels", slug="crown-jewels"):
    return client.post(
        "/api/v1/admin/gate-policies", headers=headers,
        json={
            "name": name,
            "slug": slug,
            "description": "Strict policy for the most sensitive applications.",
            "gates": [{
                "gate_id": gate["id"],
                "blocking_severities": ["low", "medium", "high", "critical"],
            } for gate in gates],
        },
    )


def test_admin_creates_reusable_ordered_policy_and_assigns_multiple_applications(
    client, admin_headers, owner, api_key,
):
    sast = create_gate(client, admin_headers, owner, "SAST", "sast")
    secrets = create_gate(client, admin_headers, owner, "Secrets", "secrets")
    sca = create_gate(client, admin_headers, owner, "SCA", "sca")
    created = create_policy(client, admin_headers, [secrets, sast, sca])
    assert created.status_code == 201
    policy = created.json()
    assert [item["gate_slug"] for item in policy["gates"]] == ["secrets", "sast", "sca"]
    assert [item["position"] for item in policy["gates"]] == [0, 1, 2]
    assert all(item["blocking_severities"] == ["low", "medium", "high", "critical"] for item in policy["gates"])

    for name, slug in (("Payments", "payments"), ("Identity", "identity")):
        response = client.post(
            "/api/v1/admin/applications", headers=admin_headers,
            json={"name": name, "slug": slug, "gate_policy_id": policy["id"]},
        )
        assert response.status_code == 201
        assert response.json()["gate_policy"]["slug"] == "crown-jewels"

    listed = client.get("/api/v1/admin/gate-policies", headers=admin_headers)
    crown_jewels = next(item for item in listed.json() if item["id"] == policy["id"])
    assert crown_jewels["application_count"] == 2

    key, _ = api_key
    resolved = client.post(
        "/api/v1/policies/resolve-pipeline", headers={"X-API-Key": key},
        json={"application": "payments"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["gate_policy"] == "crown-jewels"
    assert resolved.json()["gate_policy_name"] == "Crown Jewels"
    assert resolved.json()["gates"] == [
        {"gate": "secrets", "position": 0},
        {"gate": "sast", "position": 1},
        {"gate": "sca", "position": 2},
    ]


def test_policy_severities_are_application_specific(client, admin_headers, owner, api_key):
    sast = create_gate(client, admin_headers, owner, "SAST", "sast")
    strict = create_policy(client, admin_headers, [sast]).json()
    relaxed = client.post(
        "/api/v1/admin/gate-policies", headers=admin_headers,
        json={
            "name": "Standard", "slug": "standard",
            "gates": [{"gate_id": sast["id"], "blocking_severities": ["high", "critical"]}],
        },
    ).json()
    for slug, policy in (("crown-app", strict), ("standard-app", relaxed)):
        assert client.post(
            "/api/v1/admin/applications", headers=admin_headers,
            json={"name": slug, "slug": slug, "gate_policy_id": policy["id"]},
        ).status_code == 201

    key, _ = api_key
    headers = {"X-API-Key": key}
    strict_result = client.post(
        "/api/v1/policies/evaluate-enforcement", headers=headers,
        json={"application": "crown-app", "gate": "sast"},
    )
    relaxed_result = client.post(
        "/api/v1/policies/evaluate-enforcement", headers=headers,
        json={"application": "standard-app", "gate": "sast"},
    )
    assert strict_result.json()["gates"][0]["blocking_severities"] == ["low", "medium", "high", "critical"]
    assert relaxed_result.json()["gates"][0]["blocking_severities"] == ["high", "critical"]


def test_policy_and_assignment_validation_fail_closed(client, admin_headers, owner, api_key):
    gate = create_gate(client, admin_headers, owner, "SAST", "sast")
    duplicate = client.post(
        "/api/v1/admin/gate-policies", headers=admin_headers,
        json={
            "name": "Duplicate", "slug": "duplicate",
            "gates": [
                {"gate_id": gate["id"], "blocking_severities": ["critical"]},
                {"gate_id": gate["id"], "blocking_severities": ["high"]},
            ],
        },
    )
    assert duplicate.status_code == 422
    assert client.post(
        "/api/v1/admin/applications", headers=admin_headers,
        json={"name": "Missing", "slug": "missing"},
    ).status_code == 422
    assert client.post(
        "/api/v1/admin/applications", headers=admin_headers,
        json={
            "name": "Unknown", "slug": "unknown",
            "gate_policy_id": "11111111-1111-1111-1111-111111111111",
        },
    ).status_code == 400

    policy = create_policy(client, admin_headers, [gate]).json()
    application = client.post(
        "/api/v1/admin/applications", headers=admin_headers,
        json={"name": "Protected", "slug": "protected", "gate_policy_id": policy["id"]},
    ).json()
    assert client.patch(
        f"/api/v1/admin/gate-policies/{policy['id']}", headers=admin_headers,
        json={"active": False},
    ).status_code == 409
    assert client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers,
        json={"active": False},
    ).status_code == 409
    assert client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers,
        json={"slug": "renamed"},
    ).status_code == 409

    key, _ = api_key
    assert client.post(
        "/api/v1/policies/resolve-pipeline", headers={"X-API-Key": key},
        json={"application": application["slug"]},
    ).status_code == 200


def test_gate_policy_management_is_admin_only(client, admin_headers, owner):
    gate = create_gate(client, admin_headers, owner, "SAST", "sast")
    group = client.post(
        "/api/v1/admin/groups", headers=admin_headers,
        json={
            "name": "Gate managers", "slug": "gate-managers",
            "permissions": ["view-gates:appsec", "edit-gates:appsec"],
        },
    ).json()
    client.post(
        "/api/v1/admin/users", headers=admin_headers,
        json={
            "username": "gate.policy.user", "password": "ScopedGatePass!123",
            "display_name": "Gate Policy User", "email": "gate.policy@example.com",
            "role": "USER", "group_ids": [group["id"]],
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "gate.policy.user", "password": "ScopedGatePass!123"},
    ).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    assert client.get("/api/v1/admin/gate-policies", headers=headers).status_code == 403
    assert create_policy(client, headers, [gate]).status_code == 403
