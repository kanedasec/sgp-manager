from .test_policies import payload


def enforce(client, key, application="payment-api", gate=None):
    body = {"application": application}
    if gate:
        body["gate"] = gate
    return client.post("/api/v1/policies/evaluate-enforcement", headers={"X-API-Key": key}, json=body)


def test_finding_scoped_bypass_never_clears_the_whole_severity(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, gate = domain
    created = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high", "critical"],
            "finding_scope": ["CVE-2026-98765"],
        }],
    ))
    assert created.status_code == 201
    assert created.json()["gates"][0]["finding_scope"] == ["CVE-2026-98765"]

    result = enforce(client, key).json()["gates"][0]
    # The severity remains blocking: a finding-scoped bypass cannot prove every
    # finding at that severity is covered, only the listed identifiers are.
    assert result["blocking_severities"] == ["low", "medium", "high", "critical"]
    assert result["bypassed_findings"] == ["CVE-2026-98765"]


def test_finding_scoped_bypass_only_applies_to_its_own_severities(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, gate = domain
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high"],
            "finding_scope": ["CVE-2026-11111"],
        }],
    ))
    result = enforce(client, key).json()["gates"][0]
    assert result["blocking_severities"] == ["low", "medium", "high", "critical"]
    assert result["bypassed_findings"] == ["CVE-2026-11111"]


def test_unscoped_bypass_still_clears_whole_severity(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, gate = domain
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{"gate_id": gate["id"], "severities": ["low", "medium"]}],
    ))
    result = enforce(client, key).json()["gates"][0]
    assert result["blocking_severities"] == ["high", "critical"]
    assert result["bypassed_findings"] == []


def test_finding_scope_surfaced_in_evaluate_endpoint(client, admin_headers, domain, api_key):
    key, _ = api_key
    _, gate = domain
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high"],
            "finding_scope": ["semgrep:hardcoded-secret:app/config.py:12"],
        }],
    ))
    response = client.post(
        "/api/v1/policies/evaluate", headers={"X-API-Key": key}, json={"application": "payment-api"},
    )
    assert response.status_code == 200
    policy = response.json()["policies"][0]
    assert policy["finding_scope"] == ["semgrep:hardcoded-secret:app/config.py:12"]


def test_default_severity_only_bypass_has_no_finding_scope(client, admin_headers, domain, api_key):
    key, _ = api_key
    client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(domain))
    response = client.post(
        "/api/v1/policies/evaluate", headers={"X-API-Key": key}, json={"application": "payment-api"},
    )
    assert response.json()["policies"][0]["finding_scope"] is None


def test_finding_scope_rejects_invalid_identifiers(client, admin_headers, domain):
    _, gate = domain
    response = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high"],
            "finding_scope": ["<script>alert(1)</script>"],
        }],
    ))
    assert response.status_code == 422


def test_finding_scope_rejects_duplicates(client, admin_headers, domain):
    _, gate = domain
    response = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high"],
            "finding_scope": ["CVE-2026-1", "CVE-2026-1"],
        }],
    ))
    assert response.status_code == 422


def test_update_policy_preserves_finding_scope_when_gates_untouched(client, admin_headers, domain):
    _, gate = domain
    created = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high"],
            "finding_scope": ["CVE-2026-2"],
        }],
    )).json()
    updated = client.patch(
        f"/api/v1/admin/bypass-policies/{created['id']}", headers=admin_headers,
        json={"justification": "Extending the window slightly for the same approved exception."},
    )
    assert updated.status_code == 200
    assert updated.json()["gates"][0]["finding_scope"] == ["CVE-2026-2"]


def test_update_policy_can_change_finding_scope(client, admin_headers, domain):
    _, gate = domain
    created = client.post("/api/v1/admin/bypass-policies", headers=admin_headers, json=payload(
        domain, gates=[{
            "gate_id": gate["id"], "severities": ["high"],
            "finding_scope": ["CVE-2026-3"],
        }],
    )).json()
    updated = client.patch(
        f"/api/v1/admin/bypass-policies/{created['id']}", headers=admin_headers,
        json={"gates": [{"gate_id": gate["id"], "severities": ["high", "critical"]}]},
    )
    assert updated.status_code == 200
    assert updated.json()["gates"][0]["finding_scope"] is None
    assert updated.json()["gates"][0]["severities"] == ["high", "critical"]
