from .test_policies import payload


def enforce(client, key, application="payment-api", gate=None):
    body = {"application": application}
    if gate:
        body["gate"] = gate
    return client.post(
        "/api/v1/policies/evaluate-enforcement", headers={"X-API-Key": key}, json=body,
    )


def test_defaults_are_blocking_without_bypass(client, domain, api_key):
    key, _ = api_key
    response = enforce(client, key)
    assert response.status_code == 200
    assert response.json()["gates"] == [{
        "gate": "secrets", "blocking_severities": ["low", "medium", "high", "critical"],
    }]


def test_active_bypass_is_subtracted_from_blocking_defaults(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, gate = domain
    client.patch(
        f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers,
        json={"default_blocking_severities": ["medium", "high", "critical"]},
    )
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{"gate_id": gate["id"], "severities": ["medium", "high"]}],
    ))
    assert enforce(client, key).json()["gates"] == [{
        "gate": "secrets", "blocking_severities": ["critical"],
    }]


def test_revocation_restores_default_blocking_severities(client, admin_headers, domain, api_key):
    key, _ = api_key
    created = client.post(
        "/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain),
    ).json()
    client.post(
        f"/api/v1/admin/bypass-policies/{created['id']}/revoke", headers=admin_headers,
        json={"reason": "The remediation has been completed."},
    )
    assert enforce(client, key).json()["gates"][0]["blocking_severities"] == [
        "low", "medium", "high", "critical",
    ]


def test_unknown_application_gets_full_defaults_fail_closed(client, domain, api_key):
    key, _ = api_key
    result = enforce(client, key, application="unknown-application")
    assert result.status_code == 200
    assert result.json()["gates"][0]["blocking_severities"] == ["low", "medium", "high", "critical"]


def test_optional_gate_filter_and_unknown_gate(client, admin_headers, domain, api_key):
    key, _ = api_key
    client.post(
        "/api/v1/admin/gates", headers=admin_headers,
        json={"name": "SAST", "slug": "sast", "owner_id": domain[1]["owner_id"],
              "default_blocking_severities": ["high", "critical"]},
    )
    filtered = enforce(client, key, gate="sast")
    assert filtered.json()["gates"] == [{"gate": "sast", "blocking_severities": ["high", "critical"]}]
    assert enforce(client, key, gate="does-not-exist").status_code == 404


def test_enforcement_requires_valid_api_key(client):
    assert enforce(client, "sec_invalid").status_code == 401
