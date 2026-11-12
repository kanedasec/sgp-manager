from uuid import uuid4


def application_payload(domain, owner, **overrides):
    existing_application, _ = domain
    payload = {
        "name": "Customer Portal",
        "slug": "customer-portal",
        "description": "Public customer account experience.",
        "owner_id": owner["id"],
        "company": "Acme Corporation",
        "criticality": "high",
        "gate_policy_id": existing_application["gate_policy_id"],
    }
    payload.update(overrides)
    return payload


def test_admin_can_create_search_and_update_application_metadata(client, admin_headers, domain, owner):
    created = client.post(
        "/api/v1/admin/applications",
        headers=admin_headers,
        json=application_payload(domain, owner),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["owner_id"] == owner["id"]
    assert body["owner"]["slug"] == "appsec"
    assert body["company"] == "Acme Corporation"
    assert body["criticality"] == "high"

    searched = client.get(
        "/api/v1/admin/applications?search=Acme",
        headers=admin_headers,
    )
    assert [item["id"] for item in searched.json()] == [body["id"]]

    updated = client.patch(
        f"/api/v1/admin/applications/{body['id']}",
        headers=admin_headers,
        json={"company": "Example Holdings", "criticality": "critical"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["company"] == "Example Holdings"
    assert updated.json()["criticality"] == "critical"
    assert updated.json()["owner"]["id"] == owner["id"]


def test_application_metadata_rejects_invalid_criticality_and_owner(client, admin_headers, domain, owner):
    malformed = client.post(
        "/api/v1/admin/applications",
        headers=admin_headers,
        json=application_payload(domain, owner, criticality="extreme"),
    )
    assert malformed.status_code == 422

    blank_company = client.post(
        "/api/v1/admin/applications",
        headers=admin_headers,
        json=application_payload(domain, owner, company="   "),
    )
    assert blank_company.status_code == 422

    unknown_owner = client.post(
        "/api/v1/admin/applications",
        headers=admin_headers,
        json=application_payload(domain, owner, owner_id=str(uuid4())),
    )
    assert unknown_owner.status_code == 400
    assert unknown_owner.json()["detail"] == "Owner does not exist or is inactive"


def test_application_metadata_create_remains_admin_only(client, domain, owner):
    denied = client.post(
        "/api/v1/admin/applications",
        json=application_payload(domain, owner),
    )
    assert denied.status_code == 401


def test_legacy_and_pipeline_created_applications_keep_nullable_metadata(
    client, admin_headers, domain, management_api_key,
):
    existing_application, _ = domain
    assert existing_application["owner_id"] is None
    assert existing_application["company"] is None
    assert existing_application["criticality"] is None

    key, _ = management_api_key
    ensured = client.post(
        "/api/v1/policies/applications/ensure",
        headers={"X-API-Key": key},
        json={"application": "pipeline-created", "gate_policy": "default-security-policy"},
    )
    assert ensured.status_code == 200

    listed = client.get("/api/v1/admin/applications", headers=admin_headers).json()
    pipeline_created = next(item for item in listed if item["slug"] == "pipeline-created")
    assert pipeline_created["owner_id"] is None
    assert pipeline_created["company"] is None
    assert pipeline_created["criticality"] is None
