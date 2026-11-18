from datetime import UTC, datetime, timedelta
from itertools import count

import pytest


_users = count()


def iso(delta: timedelta) -> str:
    return (datetime.now(UTC) + delta).isoformat()


def create_owner(client, headers, slug):
    response = client.post("/api/v1/admin/owners", headers=headers, json={"name": slug.title(), "slug": slug})
    assert response.status_code == 201
    return response.json()


def create_gate(client, headers, owner, slug):
    response = client.post("/api/v1/admin/gates", headers=headers, json={
        "name": slug.title(), "slug": slug, "owner_id": owner["id"],
    })
    assert response.status_code == 201
    return response.json()


def create_group(client, headers, slug, permissions, max_bypass_days=None):
    body = {"name": slug.title(), "slug": slug, "permissions": permissions}
    if max_bypass_days is not None:
        body["max_bypass_days"] = max_bypass_days
    response = client.post("/api/v1/admin/groups", headers=headers, json=body)
    assert response.status_code == 201, response.text
    return response.json()


def user_in(client, admin_headers, *groups):
    username = f"limited.{next(_users)}"
    response = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "username": username, "password": "LimitedUserPass!123", "display_name": "Limited User",
        "email": f"{username}@example.com", "role": "USER", "group_ids": [group["id"] for group in groups],
    })
    assert response.status_code == 201, response.text
    login = client.post("/api/v1/auth/login", json={"username": username, "password": "LimitedUserPass!123"})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def create_bypass(client, headers, application, owner, gate, expires_in, starts_in=None):
    body = {
        "application_id": application["id"], "owner_id": owner["id"],
        "gates": [{"gate_id": gate["id"], "severities": ["high"]}],
        "justification": "Vendor fix is scheduled; tracked in the remediation backlog.",
        "expires_at": iso(expires_in),
    }
    if starts_in is not None:
        body["valid_from"] = iso(starts_in)
    return client.post("/api/v1/admin/bypass-policies", headers=headers, json=body)


CREATE_APPSEC = ["view-policies:appsec", "create-policies:appsec", "edit-policies:appsec", "view-gates:appsec"]


def test_group_limit_caps_bypass_creation(client, admin_headers, owner, domain):
    application, gate = domain
    headers = user_in(client, admin_headers, create_group(client, admin_headers, "week", CREATE_APPSEC, 7))

    denied = create_bypass(client, headers, application, owner, gate, timedelta(days=7, minutes=5))
    assert denied.status_code == 403
    assert "7-day maximum" in denied.json()["detail"]
    allowed = create_bypass(client, headers, application, owner, gate, timedelta(days=7) - timedelta(minutes=1))
    assert allowed.status_code == 201, allowed.text


def test_most_permissive_active_group_wins(client, admin_headers, owner, domain):
    application, _ = domain
    week = create_group(client, admin_headers, "week", CREATE_APPSEC, 7)
    month = create_group(client, admin_headers, "month", ["create-policies:appsec"], 30)
    dormant = create_group(client, admin_headers, "dormant", ["create-policies:all"])
    headers = user_in(client, admin_headers, week, month, dormant)
    assert client.patch(
        f"/api/v1/admin/groups/{dormant['id']}", headers=admin_headers, json={"active": False},
    ).status_code == 200

    month_gate = create_gate(client, admin_headers, owner, "month-gate")
    assert create_bypass(client, headers, application, owner, month_gate, timedelta(days=29)).status_code == 201
    # The inactive unlimited group neither grants permission nor lifts the limit.
    assert create_bypass(client, headers, application, owner, month_gate, timedelta(days=45)).status_code == 403

    unlimited = create_group(client, admin_headers, "unlimited", ["create-policies:appsec"])
    headers = user_in(client, admin_headers, week, unlimited)
    long_gate = create_gate(client, admin_headers, owner, "long-gate")
    assert create_bypass(client, headers, application, owner, long_gate, timedelta(days=400)).status_code == 201


def test_limits_are_owner_scoped_and_all_scope_applies(client, admin_headers, owner, domain):
    application, gate = domain
    quality = create_owner(client, admin_headers, "quality")
    # An unlimited grant for a different owner does not lift the appsec limit.
    headers = user_in(
        client, admin_headers,
        create_group(client, admin_headers, "appsec-week", CREATE_APPSEC, 7),
        create_group(client, admin_headers, "quality-any", ["create-policies:quality"]),
    )
    assert create_bypass(client, headers, application, owner, gate, timedelta(days=20)).status_code == 403

    quality_gate = create_gate(client, admin_headers, quality, "quality-gate")
    global_headers = user_in(
        client, admin_headers,
        create_group(client, admin_headers, "global-short", ["create-policies:all", "view-gates:all"], 3),
    )
    assert create_bypass(
        client, global_headers, application, quality, quality_gate, timedelta(days=4),
    ).status_code == 403
    assert create_bypass(
        client, global_headers, application, quality, quality_gate, timedelta(days=2),
    ).status_code == 201


def test_future_start_cannot_push_expiry_past_the_limit(client, admin_headers, owner, domain):
    application, gate = domain
    headers = user_in(client, admin_headers, create_group(client, admin_headers, "week", CREATE_APPSEC, 7))
    # A 5-day window starting in 20 days still ends 25 days from now.
    far = create_bypass(client, headers, application, owner, gate, timedelta(days=25), timedelta(days=20))
    assert far.status_code == 403
    near = create_bypass(client, headers, application, owner, gate, timedelta(days=6), timedelta(days=1))
    assert near.status_code == 201, near.text


def test_administrators_are_unlimited(client, admin_headers, owner, domain):
    application, gate = domain
    response = create_bypass(client, admin_headers, application, owner, gate, timedelta(days=3000))
    assert response.status_code == 201


def test_edits_cannot_extend_past_the_limit(client, admin_headers, owner, domain):
    application, gate = domain
    headers = user_in(client, admin_headers, create_group(client, admin_headers, "week", CREATE_APPSEC, 7))
    created = create_bypass(client, headers, application, owner, gate, timedelta(days=5))
    assert created.status_code == 201
    policy_id = created.json()["id"]

    extended = client.patch(
        f"/api/v1/admin/bypass-policies/{policy_id}", headers=headers, json={"expires_at": iso(timedelta(days=10))},
    )
    assert extended.status_code == 403
    within = client.patch(
        f"/api/v1/admin/bypass-policies/{policy_id}", headers=headers, json={"expires_at": iso(timedelta(days=6))},
    )
    assert within.status_code == 200, within.text


def test_limited_editor_may_change_text_but_not_window_of_longer_policy(client, admin_headers, owner, domain):
    application, gate = domain
    approved = create_bypass(client, admin_headers, application, owner, gate, timedelta(days=90))
    assert approved.status_code == 201
    policy_id = approved.json()["id"]
    headers = user_in(client, admin_headers, create_group(client, admin_headers, "week", CREATE_APPSEC, 7))

    text_only = client.patch(f"/api/v1/admin/bypass-policies/{policy_id}", headers=headers, json={
        "justification": "Updated remediation plan with the vendor ticket reference.",
    })
    assert text_only.status_code == 200, text_only.text
    shorter_but_still_long = client.patch(
        f"/api/v1/admin/bypass-policies/{policy_id}", headers=headers, json={"expires_at": iso(timedelta(days=60))},
    )
    assert shorter_but_still_long.status_code == 403


def test_edit_limit_comes_from_edit_grants(client, admin_headers, owner, domain):
    application, gate = domain
    creator = user_in(
        client, admin_headers, create_group(client, admin_headers, "creators", ["create-policies:appsec"], 30),
    )
    created = create_bypass(client, creator, application, owner, gate, timedelta(days=20))
    assert created.status_code == 201
    editor = user_in(
        client, admin_headers,
        create_group(client, admin_headers, "editors", ["view-policies:appsec", "edit-policies:appsec"], 3),
    )
    response = client.patch(
        f"/api/v1/admin/bypass-policies/{created.json()['id']}", headers=editor,
        json={"expires_at": iso(timedelta(days=10))},
    )
    assert response.status_code == 403
    assert "3-day maximum" in response.json()["detail"]


@pytest.mark.parametrize("value", [0, -1, 3651, "thirty"])
def test_group_limit_validation(client, admin_headers, owner, value):
    response = client.post("/api/v1/admin/groups", headers=admin_headers, json={
        "name": "Invalid", "slug": "invalid", "permissions": [], "max_bypass_days": value,
    })
    assert response.status_code == 422


def test_group_limit_is_returned_updated_cleared_and_audited(client, admin_headers, owner):
    group = create_group(client, admin_headers, "week", CREATE_APPSEC, 7)
    assert group["max_bypass_days"] == 7
    updated = client.patch(f"/api/v1/admin/groups/{group['id']}", headers=admin_headers, json={"max_bypass_days": 14})
    assert updated.json()["max_bypass_days"] == 14
    unchanged = client.patch(f"/api/v1/admin/groups/{group['id']}", headers=admin_headers, json={"name": "Two Weeks"})
    assert unchanged.json()["max_bypass_days"] == 14
    cleared = client.patch(f"/api/v1/admin/groups/{group['id']}", headers=admin_headers, json={"max_bypass_days": None})
    assert cleared.json()["max_bypass_days"] is None

    audit = client.get("/api/v1/admin/audit-logs", headers=admin_headers).json()
    created = next(item for item in audit if item["event_type"] == "ACCESS_GROUP_CREATED")
    assert created["metadata"]["max_bypass_days"] == 7
    limit_updates = [
        item["metadata"]["max_bypass_days"] for item in audit
        if item["event_type"] == "ACCESS_GROUP_UPDATED" and "max_bypass_days" in item["metadata"]
    ]
    assert sorted(limit_updates, key=lambda value: value or 0) == [None, 14]


def test_session_reports_bypass_limits(client, admin_headers, owner):
    me = client.get("/api/v1/auth/me", headers=admin_headers).json()
    assert me["bypass_max_days"] == {"all": None}
    headers = user_in(
        client, admin_headers,
        create_group(client, admin_headers, "week", CREATE_APPSEC, 7),
        create_group(client, admin_headers, "month", ["create-policies:appsec"], 30),
        create_group(client, admin_headers, "global", ["create-policies:all"], 2),
        create_group(client, admin_headers, "viewers", ["view-policies:all"]),
    )
    assert client.get("/api/v1/auth/me", headers=headers).json()["bypass_max_days"] == {"appsec": 30, "all": 2}
