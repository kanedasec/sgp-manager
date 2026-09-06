from app.services.access import ACTIONS, RESOURCES, ROLE_PATTERN


def test_role_pattern_is_derived_from_the_single_vocabulary_source():
    for action in ACTIONS:
        for resource in RESOURCES:
            assert ROLE_PATTERN.fullmatch(f"{action}-{resource}:all")
            assert ROLE_PATTERN.fullmatch(f"{action}-{resource}:appsec-team")
    assert not ROLE_PATTERN.fullmatch("delete-gates:all")
    assert not ROLE_PATTERN.fullmatch("view-widgets:all")
    assert not ROLE_PATTERN.fullmatch("view-gates:Invalid_Slug")


def test_available_roles_endpoint_exposes_the_vocabulary(client, admin_headers):
    response = client.get("/api/v1/admin/roles", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["actions"] == list(ACTIONS)
    assert body["resources"] == list(RESOURCES)
    # Every advertised role must itself validate against the same pattern
    # the server enforces at write time, so the frontend can never render
    # (and a user submit) a role string the backend would then reject.
    for role in body["roles"]:
        assert ROLE_PATTERN.fullmatch(role), role


def test_available_roles_includes_all_scope_and_every_active_owner(client, admin_headers):
    client.post("/api/v1/admin/owners", headers=admin_headers, json={"name": "AppSec", "slug": "appsec"})
    response = client.get("/api/v1/admin/roles", headers=admin_headers)
    body = response.json()
    assert any(role.endswith(":all") for role in body["roles"])
    assert any(role.endswith(":appsec") for role in body["roles"])
