import tomllib

import pytest
import yaml


TOML_DOCUMENT = '# Semgrep tuning for the payment team\n[rules]\nrequire_review = true\napprovals = 2\n\n[[exclusions]]\npath = "tests/"\n'


def create_owner(client, headers, name, slug):
    response = client.post("/api/v1/admin/owners", headers=headers, json={"name": name, "slug": slug})
    assert response.status_code == 201
    return response.json()


def create_policy(client, headers, owner, slug, format="json", document=None):
    if document is None:
        document = '{"rules":{"require_review":true,"approvals":2},"labels":["security"]}'
    response = client.post("/api/v1/admin/custom-policies", headers=headers, json={
        "name": slug.replace("-", " ").title(), "slug": slug, "owner_id": owner["id"],
        "format": format, "document": document,
    })
    return response


def bind(client, headers, policy_id, target_type, target_id):
    return client.post(
        f"/api/v1/admin/custom-policies/{policy_id}/bindings", headers=headers,
        json={"target_type": target_type, "target_id": target_id},
    )


def default_gate_policy(client, headers):
    return next(
        item for item in client.get("/api/v1/admin/gate-policies", headers=headers).json()
        if item["slug"] == "default-security-policy"
    )


def login(client, username, password):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def pipeline(client, api_key, body, path="resolve-pipeline"):
    return client.post(f"/api/v1/policies/{path}", headers={"X-API-Key": api_key}, json=body)


def test_toml_documents_are_parsed_validated_and_canonicalized(client, admin_headers, owner):
    created = create_policy(client, admin_headers, owner, "toml-policy", "toml", TOML_DOCUMENT)
    assert created.status_code == 201
    body = created.json()
    assert body["format"] == "toml"
    assert body["document"] == TOML_DOCUMENT
    assert body["parsed_document"] == {
        "rules": {"require_review": True, "approvals": 2}, "exclusions": [{"path": "tests/"}],
    }
    assert body["renderable_formats"] == ["json", "yaml", "toml"]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("rules = [unterminated", "Invalid TOML"),
        ("created = 2026-11-18T10:00:00Z\n", "JSON-compatible"),
        ('a = 1\na = 2\n', "Invalid TOML"),
    ],
)
def test_malformed_toml_is_rejected(client, admin_headers, owner, document, message):
    response = create_policy(client, admin_headers, owner, "bad-toml", "toml", document)
    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_admin_export_renders_every_format(client, admin_headers, owner):
    policy = create_policy(client, admin_headers, owner, "export-policy").json()
    base = f"/api/v1/admin/custom-policies/{policy['id']}/export"

    as_json = client.get(base, headers=admin_headers)
    assert as_json.status_code == 200
    assert as_json.headers["content-type"].startswith("application/json")
    # Same format as authored: the validated source is returned unchanged.
    assert as_json.text == policy["document"]

    as_toml = client.get(f"{base}?format=toml", headers=admin_headers)
    assert as_toml.status_code == 200
    assert as_toml.headers["content-type"].startswith("application/toml")
    assert as_toml.headers["content-disposition"] == 'attachment; filename="export-policy.toml"'
    assert as_toml.headers["cache-control"] == "no-store"
    assert tomllib.loads(as_toml.text) == policy["parsed_document"]

    as_yaml = client.get(f"{base}?format=yaml", headers=admin_headers)
    assert yaml.safe_load(as_yaml.text) == policy["parsed_document"]
    # The digest identifies the logical document independently of format.
    assert as_json.headers["x-policy-digest"] == as_toml.headers["x-policy-digest"] == as_yaml.headers["x-policy-digest"]

    assert client.get(f"{base}?format=xml", headers=admin_headers).status_code == 422


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ('{"rules":{"reviewer":null}}', "null value at $.rules.reviewer"),
        ('{"limit":' + str(2**63) + "}", "64-bit"),
    ],
)
def test_documents_that_toml_cannot_represent_are_refused(client, admin_headers, owner, document, message):
    policy = create_policy(client, admin_headers, owner, "no-toml", document=document).json()
    assert policy["renderable_formats"] == ["json", "yaml"]
    response = client.get(
        f"/api/v1/admin/custom-policies/{policy['id']}/export?format=toml", headers=admin_headers,
    )
    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_export_respects_owner_scoped_view_permission(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    quality = create_owner(client, admin_headers, "Quality", "quality")
    allowed = create_policy(client, admin_headers, appsec, "appsec-standard").json()
    denied = create_policy(client, admin_headers, quality, "quality-standard").json()
    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Readers", "slug": "readers", "permissions": ["view-custom-policies:appsec"],
    }).json()
    client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "reader", "password": "PolicyReaderPass!123", "display_name": "Reader",
        "email": "reader@example.com", "role": "USER", "group_ids": [group["id"]],
    })
    headers = login(client, "reader", "PolicyReaderPass!123")
    assert client.get(
        f"/api/v1/admin/custom-policies/{allowed['id']}/export?format=toml", headers=headers,
    ).status_code == 200
    assert client.get(
        f"/api/v1/admin/custom-policies/{denied['id']}/export?format=toml", headers=headers,
    ).status_code == 404


def test_binding_management_is_administrator_only_and_audited(client, admin_headers, owner, domain):
    application, gate = domain
    policy = create_policy(client, admin_headers, owner, "bound-policy").json()
    gate_policy = default_gate_policy(client, admin_headers)

    for target_type, target_id in (
        ("application", application["id"]), ("gate_policy", gate_policy["id"]), ("gate", gate["id"]),
    ):
        response = bind(client, admin_headers, policy["id"], target_type, target_id)
        assert response.status_code == 201, response.text
        assert response.json()["target_type"] == target_type
        assert response.json()["target_id"] == target_id

    duplicate = bind(client, admin_headers, policy["id"], "gate", gate["id"])
    assert duplicate.status_code == 409

    # Target type and identifier must agree: an application UUID is not a gate.
    assert bind(client, admin_headers, policy["id"], "gate", application["id"]).status_code == 400
    assert bind(client, admin_headers, policy["id"], "dashboard", gate["id"]).status_code == 422

    listed = client.get(f"/api/v1/admin/custom-policies/{policy['id']}/bindings", headers=admin_headers)
    assert listed.status_code == 200
    assert [(item["target_type"], item["target_slug"]) for item in listed.json()] == [
        ("application", "payment-api"), ("gate_policy", "default-security-policy"), ("gate", "secrets"),
    ]

    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Authors", "slug": "authors",
        "permissions": ["view-custom-policies:appsec", "edit-custom-policies:appsec", "edit-gates:appsec"],
    }).json()
    client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "author", "password": "PolicyAuthorPass!123", "display_name": "Author",
        "email": "author@example.com", "role": "USER", "group_ids": [group["id"]],
    })
    author = login(client, "author", "PolicyAuthorPass!123")
    assert bind(client, author, policy["id"], "gate", gate["id"]).status_code == 403
    assert client.get(f"/api/v1/admin/custom-policies/{policy['id']}/bindings", headers=author).status_code == 403
    binding_id = listed.json()[0]["id"]
    assert client.delete(
        f"/api/v1/admin/custom-policies/{policy['id']}/bindings/{binding_id}", headers=author,
    ).status_code == 403

    removed = client.delete(
        f"/api/v1/admin/custom-policies/{policy['id']}/bindings/{binding_id}", headers=admin_headers,
    )
    assert removed.status_code == 204
    assert client.delete(
        f"/api/v1/admin/custom-policies/{policy['id']}/bindings/{binding_id}", headers=admin_headers,
    ).status_code == 404

    audit = client.get("/api/v1/admin/audit-logs", headers=admin_headers).json()
    bound_events = [item for item in audit if item["event_type"] == "CUSTOM_POLICY_BOUND"]
    assert len(bound_events) == 3
    unbound = next(item for item in audit if item["event_type"] == "CUSTOM_POLICY_UNBOUND")
    assert unbound["metadata"] == {
        "slug": "bound-policy", "owner": "appsec", "target_type": "application", "target": "payment-api",
    }
    assert all("rules" not in str(item["metadata"]) for item in audit)


def test_bound_targets_cannot_be_hard_deleted(client, admin_headers, owner):
    gate = client.post("/api/v1/admin/gates", headers=admin_headers, json={
        "name": "Unused", "slug": "unused-gate", "owner_id": owner["id"],
    }).json()
    policy = create_policy(client, admin_headers, owner, "pinning-policy").json()
    assert bind(client, admin_headers, policy["id"], "gate", gate["id"]).status_code == 201
    response = client.delete(f"/api/v1/admin/gates/{gate['id']}", headers=admin_headers)
    assert response.status_code == 409
    assert "custom policy binding" in response.json()["detail"]


def test_resolve_pipeline_adds_references_without_changing_gate_entries(
    client, admin_headers, owner, domain, api_key,
):
    application, gate = domain
    key, _ = api_key
    before = pipeline(client, key, {"application": "payment-api"})
    assert before.status_code == 200
    assert before.json()["custom_policies"] == []

    app_policy = create_policy(client, admin_headers, owner, "app-policy").json()
    gate_policy_doc = create_policy(client, admin_headers, owner, "gate-policy-doc", "toml", TOML_DOCUMENT).json()
    gate_doc = create_policy(client, admin_headers, owner, "gate-doc", "yaml", "scanner:\n  severity: high\n").json()
    unrelated_gate = client.post("/api/v1/admin/gates", headers=admin_headers, json={
        "name": "SAST", "slug": "sast", "owner_id": owner["id"],
    }).json()
    unrelated = create_policy(client, admin_headers, owner, "unrelated-doc").json()
    inactive = create_policy(client, admin_headers, owner, "inactive-doc").json()

    assert bind(client, admin_headers, app_policy["id"], "application", application["id"]).status_code == 201
    assert bind(client, admin_headers, app_policy["id"], "gate", gate["id"]).status_code == 201
    assert bind(
        client, admin_headers, gate_policy_doc["id"], "gate_policy", default_gate_policy(client, admin_headers)["id"],
    ).status_code == 201
    assert bind(client, admin_headers, gate_doc["id"], "gate", gate["id"]).status_code == 201
    # A gate binding only reaches applications whose gate policy runs that gate.
    assert bind(client, admin_headers, unrelated["id"], "gate", unrelated_gate["id"]).status_code == 201
    assert bind(client, admin_headers, inactive["id"], "application", application["id"]).status_code == 201
    assert client.patch(
        f"/api/v1/admin/custom-policies/{inactive['id']}", headers=admin_headers, json={"active": False},
    ).status_code == 200

    response = pipeline(client, key, {"application": "payment-api"})
    assert response.status_code == 200
    body = response.json()
    assert body["gates"] == before.json()["gates"] == [{"gate": "secrets", "position": 0}]
    assert [item["key"] for item in body["custom_policies"]] == [
        "appsec/app-policy", "appsec/gate-doc", "appsec/gate-policy-doc",
    ]
    by_key = {item["key"]: item for item in body["custom_policies"]}
    assert by_key["appsec/app-policy"]["sources"] == [
        {"type": "application", "target": "payment-api"}, {"type": "gate", "target": "secrets"},
    ]
    assert by_key["appsec/app-policy"]["gates"] == ["secrets"]
    assert by_key["appsec/gate-policy-doc"]["sources"] == [
        {"type": "gate_policy", "target": "default-security-policy"},
    ]
    assert by_key["appsec/gate-policy-doc"]["source_format"] == "toml"
    assert by_key["appsec/gate-policy-doc"]["digest"].startswith("sha256:")
    # Default responses stay small for existing consumers: no document bodies.
    assert all(item["content"] is None and item["document"] is None for item in body["custom_policies"])
    for item in body["custom_policies"]:
        assert set(item) == {
            "key", "owner", "slug", "name", "source_format", "digest", "updated_at",
            "sources", "gates", "format", "content", "document",
        }

    embedded = pipeline(client, key, {"application": "payment-api", "custom_policy_format": "toml"})
    assert embedded.status_code == 200
    for item in embedded.json()["custom_policies"]:
        assert item["format"] == "toml"
        assert tomllib.loads(item["content"]) == item["document"]
    toml_item = next(
        item for item in embedded.json()["custom_policies"] if item["key"] == "appsec/gate-policy-doc"
    )
    assert toml_item["content"] == TOML_DOCUMENT

    assert pipeline(
        client, key, {"application": "payment-api", "custom_policy_format": "xml"},
    ).status_code == 422


def test_resolve_pipeline_fails_closed_when_requested_format_cannot_render(
    client, admin_headers, owner, domain, api_key,
):
    application, _ = domain
    key, _ = api_key
    policy = create_policy(client, admin_headers, owner, "nullable", document='{"reviewer":null}').json()
    assert bind(client, admin_headers, policy["id"], "application", application["id"]).status_code == 201
    assert pipeline(client, key, {"application": "payment-api"}).status_code == 200
    assert pipeline(client, key, {"application": "payment-api", "custom_policy_format": "json"}).status_code == 200
    refused = pipeline(client, key, {"application": "payment-api", "custom_policy_format": "toml"})
    assert refused.status_code == 503
    assert "appsec/nullable" in refused.json()["detail"]


def test_resolve_custom_policies_by_application_and_gate(client, admin_headers, owner, domain, api_key):
    application, gate = domain
    key, _ = api_key
    wide = create_policy(client, admin_headers, owner, "wide-policy").json()
    scoped = create_policy(client, admin_headers, owner, "secrets-policy", "yaml", "entropy: 4.5\n").json()
    assert bind(client, admin_headers, wide["id"], "application", application["id"]).status_code == 201
    assert bind(client, admin_headers, scoped["id"], "gate", gate["id"]).status_code == 201

    response = pipeline(
        client, key, {"application": "payment-api", "format": "toml"}, "resolve-custom-policies",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["application"] == "payment-api"
    assert body["gate_policy"] == "default-security-policy"
    assert body["format"] == "toml"
    assert [item["key"] for item in body["custom_policies"]] == ["appsec/secrets-policy", "appsec/wide-policy"]
    assert tomllib.loads(body["custom_policies"][0]["content"]) == {"entropy": 4.5}

    filtered = pipeline(
        client, key, {"application": "payment-api", "gate": "secrets"}, "resolve-custom-policies",
    )
    assert [item["key"] for item in filtered.json()["custom_policies"]] == [
        "appsec/secrets-policy", "appsec/wide-policy",
    ]
    client.post("/api/v1/admin/gates", headers=admin_headers, json={
        "name": "SCA", "slug": "sca", "owner_id": owner["id"],
    })
    assert pipeline(
        client, key, {"application": "payment-api", "gate": "sca"}, "resolve-custom-policies",
    ).status_code == 404
    assert pipeline(
        client, key, {"application": "unknown-app"}, "resolve-custom-policies",
    ).status_code == 404


def test_custom_policy_document_download_requires_binding(client, admin_headers, owner, domain, api_key):
    application, _ = domain
    key, _ = api_key
    quality = create_owner(client, admin_headers, "Quality", "quality")
    bound = create_policy(client, admin_headers, owner, "release-policy").json()
    # Same slug under a different owner: unbound, must not be served.
    create_policy(client, admin_headers, quality, "release-policy")
    assert bind(client, admin_headers, bound["id"], "application", application["id"]).status_code == 201

    request = {"application": "payment-api", "owner": "appsec", "policy": "release-policy", "format": "toml"}
    response = pipeline(client, key, request, "custom-policy-document")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/toml")
    assert response.headers["content-disposition"] == 'attachment; filename="release-policy.toml"'
    assert tomllib.loads(response.text) == bound["parsed_document"]

    for change in ({"owner": "quality"}, {"policy": "missing-policy"}, {"application": "unknown-app"}):
        assert pipeline(client, key, {**request, **change}, "custom-policy-document").status_code == 404

    client.patch(f"/api/v1/admin/custom-policies/{bound['id']}", headers=admin_headers, json={"active": False})
    assert pipeline(client, key, request, "custom-policy-document").status_code == 404


def test_custom_policy_pipeline_endpoints_require_policy_read_credential(
    client, admin_headers, owner, domain,
):
    manage_only = client.post("/api/v1/admin/api-credentials", headers=admin_headers, json={
        "name": "manage-only", "scopes": ["application:manage"],
    }).json()["api_key"]
    requests = (
        ("resolve-custom-policies", {"application": "payment-api"}),
        ("custom-policy-document", {"application": "payment-api", "owner": "appsec", "policy": "any-policy"}),
    )
    for path, body in requests:
        assert client.post(f"/api/v1/policies/{path}", json=body).status_code == 401
        assert pipeline(client, "sec_invalid", body, path).status_code == 401
        assert pipeline(client, manage_only, body, path).status_code == 403
        # Admin JWTs are not pipeline credentials.
        assert client.post(f"/api/v1/policies/{path}", headers=admin_headers, json=body).status_code == 401
