import json
import time

import pytest

from app.services.custom_policies import MAX_POLICY_BYTES


def create_owner(client, headers, name, slug):
    response = client.post(
        "/api/v1/admin/owners", headers=headers, json={"name": name, "slug": slug},
    )
    assert response.status_code == 201
    return response.json()


def create_policy(client, headers, owner, slug, format="json", document=None):
    if document is None:
        document = '{"rules":{"require_review":true},"labels":["security"]}'
    return client.post(
        "/api/v1/admin/custom-policies",
        headers=headers,
        json={
            "name": slug.replace("-", " ").title(),
            "slug": slug,
            "description": "A custom policy document used by an authorized team.",
            "owner_id": owner["id"],
            "format": format,
            "document": document,
        },
    )


def login(client, username, password):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_admin_creates_and_updates_json_and_yaml_custom_policies(client, admin_headers, owner):
    json_response = create_policy(client, admin_headers, owner, "review-policy")
    assert json_response.status_code == 201
    json_policy = json_response.json()
    assert json_policy["format"] == "json"
    assert json_policy["parsed_document"] == {
        "rules": {"require_review": True}, "labels": ["security"],
    }

    yaml_response = create_policy(
        client,
        admin_headers,
        owner,
        "release-policy",
        "yaml",
        "rules:\n  approvals: 2\n  protected: true\nlabels:\n  - release\n",
    )
    assert yaml_response.status_code == 201
    yaml_policy = yaml_response.json()
    assert yaml_policy["parsed_document"] == {
        "rules": {"approvals": 2, "protected": True}, "labels": ["release"],
    }

    updated = client.patch(
        f"/api/v1/admin/custom-policies/{yaml_policy['id']}",
        headers=admin_headers,
        json={"document": "rules:\n  approvals: 3\n", "active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["parsed_document"] == {"rules": {"approvals": 3}}
    assert updated.json()["active"] is False

    listed = client.get("/api/v1/admin/custom-policies", headers=admin_headers)
    assert listed.status_code == 200
    assert {item["slug"] for item in listed.json()} == {"review-policy", "release-policy"}

    # Gate policies remain a distinct resource and response contract.
    gate_policies = client.get("/api/v1/admin/gate-policies", headers=admin_headers)
    assert gate_policies.status_code == 200
    assert all("parsed_document" not in item for item in gate_policies.json())


def test_custom_policy_accepts_256_kib_and_rejects_larger_utf8_documents(
    client, admin_headers, owner,
):
    prefix = '{"payload":"'
    suffix = '"}'
    exact_limit = prefix + "a" * (MAX_POLICY_BYTES - len(prefix) - len(suffix)) + suffix
    assert len(exact_limit.encode("utf-8")) == MAX_POLICY_BYTES

    accepted = create_policy(
        client, admin_headers, owner, "maximum-size-policy", document=exact_limit,
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["document"] == exact_limit

    # This remains below Pydantic's character limit but exceeds the
    # authoritative UTF-8 byte limit because each value character is two bytes.
    multibyte_oversize = prefix + "é" * (MAX_POLICY_BYTES // 2) + suffix
    assert len(multibyte_oversize) < MAX_POLICY_BYTES
    assert len(multibyte_oversize.encode("utf-8")) > MAX_POLICY_BYTES
    rejected = create_policy(
        client, admin_headers, owner, "oversize-policy", document=multibyte_oversize,
    )
    assert rejected.status_code == 422
    assert f"exceeds {MAX_POLICY_BYTES} UTF-8 bytes" in rejected.json()["detail"]


def test_custom_policy_has_no_value_count_limit(client, admin_headers, owner):
    values = list(range(6000))
    document = json.dumps({"values": values})
    assert len(document.encode("utf-8")) < MAX_POLICY_BYTES

    created = create_policy(
        client, admin_headers, owner, "many-values-policy", document=document,
    )
    assert created.status_code == 201, created.text
    assert created.json()["parsed_document"]["values"] == values


def test_densest_maximum_size_document_is_accepted(client, admin_headers, owner):
    # A flow list of one-digit values is the most values per source byte a
    # document without aliases can have; it must stay within the budget.
    count = (MAX_POLICY_BYTES - len('{"v":[]}')) // 2
    document = '{"v":[' + ",".join(["1"] * count) + "]}"
    assert len(document.encode("utf-8")) <= MAX_POLICY_BYTES
    created = create_policy(client, admin_headers, owner, "dense-policy", document=document)
    assert created.status_code == 201, created.text
    assert len(created.json()["parsed_document"]["v"]) == count


def test_yaml_anchor_reuse_within_budget_is_accepted(client, admin_headers, owner):
    document = (
        "defaults: &defaults\n  severity: high\n  paths: [src/, lib/]\n"
        + "".join(f"rule{i}:\n  <<: *defaults\n  id: rule-{i}\n" for i in range(50))
    )
    created = create_policy(client, admin_headers, owner, "anchored-policy", "yaml", document)
    assert created.status_code == 201, created.text
    assert created.json()["parsed_document"]["rule7"] == {
        "severity": "high", "paths": ["src/", "lib/"], "id": "rule-7",
    }


def test_yaml_alias_expansion_is_rejected_quickly(client, admin_headers, owner):
    # 332 bytes that expand to 10**9 values ("billion laughs").
    levels = ["a: &a [x,x,x,x,x,x,x,x,x,x]"] + [
        f"{chr(98 + i)}: &{chr(98 + i)} [" + ",".join([f"*{chr(97 + i)}"] * 10) + "]" for i in range(8)
    ]
    document = "\n".join(levels) + "\n"
    assert len(document.encode("utf-8")) < 400
    started = time.monotonic()
    response = create_policy(client, admin_headers, owner, "alias-bomb", "yaml", document)
    assert time.monotonic() - started < 5
    assert response.status_code == 422
    assert "excessive YAML alias reuse" in response.json()["detail"]


@pytest.mark.parametrize(
    ("format", "document", "message"),
    [
        ("json", "{not-json}", "Invalid JSON"),
        ("json", '["not", "an", "object"]', "object at its root"),
        ("yaml", "rules: [unterminated", "Invalid YAML"),
        ("yaml", "created: 2026-11-09\n", "JSON-compatible"),
        ("yaml", "recursive: &loop\n  child: *loop\n", "Recursive YAML aliases"),
        ("json", '{"a":' * 1100 + "null" + "}" * 1100, "maximum depth"),
        ("json", '{"value":' + "9" * 5000 + "}", "Invalid JSON"),
    ],
)
def test_malformed_or_unsafe_documents_are_rejected(
    client, admin_headers, owner, format, document, message,
):
    response = create_policy(
        client, admin_headers, owner, f"invalid-{format}", format, document,
    )
    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_custom_policy_permissions_are_owner_scoped(client, admin_headers):
    appsec = create_owner(client, admin_headers, "AppSec", "appsec")
    quality = create_owner(client, admin_headers, "Quality", "quality")
    appsec_policy = create_policy(client, admin_headers, appsec, "appsec-standard").json()
    quality_policy = create_policy(client, admin_headers, quality, "quality-standard").json()

    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Custom Policy Authors",
        "slug": "custom-policy-authors",
        "permissions": [
            "view-custom-policies:appsec",
            "create-custom-policies:appsec",
            "edit-custom-policies:appsec",
        ],
    })
    assert group.status_code == 201
    user = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "policy.author",
        "password": "PolicyAuthorPass!123",
        "display_name": "Policy Author",
        "email": "policy.author@example.com",
        "role": "USER",
        "group_ids": [group.json()["id"]],
    })
    assert user.status_code == 201
    headers = login(client, "policy.author", "PolicyAuthorPass!123")

    assert client.get("/api/v1/admin/owner-labels", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/applications", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/bypass-policies", headers=headers).status_code == 403

    visible = client.get("/api/v1/admin/custom-policies", headers=headers)
    assert visible.status_code == 200
    assert [item["id"] for item in visible.json()] == [appsec_policy["id"]]
    assert client.get(
        f"/api/v1/admin/custom-policies/{quality_policy['id']}", headers=headers,
    ).status_code == 404
    assert client.patch(
        f"/api/v1/admin/custom-policies/{quality_policy['id']}",
        headers=headers,
        json={"description": "Cross-owner update"},
    ).status_code == 404
    assert create_policy(client, headers, quality, "quality-denied").status_code == 403
    assert create_policy(client, headers, appsec, "appsec-allowed").status_code == 201
    assert client.patch(
        f"/api/v1/admin/custom-policies/{appsec_policy['id']}",
        headers=headers,
        json={"description": "Updated inside the authorized owner boundary."},
    ).status_code == 200


def test_user_without_custom_policy_permissions_is_denied(client, admin_headers, owner):
    group = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Gate Viewers", "slug": "gate-viewers", "permissions": ["view-gates:all"],
    })
    user = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": "gate.viewer",
        "password": "GateViewerPass!123",
        "display_name": "Gate Viewer",
        "email": "gate.viewer@example.com",
        "role": "USER",
        "group_ids": [group.json()["id"]],
    })
    assert user.status_code == 201
    headers = login(client, "gate.viewer", "GateViewerPass!123")
    assert client.get("/api/v1/admin/custom-policies", headers=headers).status_code == 403
    assert create_policy(client, headers, owner, "not-allowed").status_code == 403


def test_custom_policy_audit_metadata_excludes_document(client, admin_headers, owner):
    document = '{"private_context":"must not enter audit metadata"}'
    created = create_policy(client, admin_headers, owner, "audited-policy", document=document)
    assert created.status_code == 201
    audit = client.get("/api/v1/admin/audit-logs", headers=admin_headers)
    assert audit.status_code == 200
    event = next(item for item in audit.json() if item["event_type"] == "CUSTOM_POLICY_CREATED")
    assert event["metadata"] == {
        "slug": "audited-policy", "owner": "appsec", "format": "json",
    }
    assert "private_context" not in str(event)
