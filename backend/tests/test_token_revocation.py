def test_logout_revokes_the_current_token(client, admin_headers):
    assert client.get("/api/v1/admin/applications", headers=admin_headers).status_code == 200

    logout = client.post("/api/v1/auth/logout", headers=admin_headers)
    assert logout.status_code == 204

    denied = client.get("/api/v1/admin/applications", headers=admin_headers)
    assert denied.status_code == 401
    assert "revoked" in denied.json()["detail"].lower()


def test_logout_without_a_token_still_clears_the_cookie(client):
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 204


def test_other_tokens_for_the_same_user_remain_valid_after_one_logout(client):
    first_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    second_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    first_headers = {"Authorization": f"Bearer {first_login.json()['access_token']}"}
    second_headers = {"Authorization": f"Bearer {second_login.json()['access_token']}"}

    client.post("/api/v1/auth/logout", headers=first_headers)

    assert client.get("/api/v1/admin/applications", headers=first_headers).status_code == 401
    assert client.get("/api/v1/admin/applications", headers=second_headers).status_code == 200


def test_admin_can_force_logout_another_user(client, admin_headers):
    create = client.post(
        "/api/v1/admin/users", headers=admin_headers,
        json={
            "username": "target-user", "password": "AnotherStrongPass!456", "display_name": "Target User",
            "email": "target@example.com", "role": "USER", "group_ids": [],
        },
    )
    assert create.status_code == 201
    user_id = create.json()["id"]

    login = client.post("/api/v1/auth/login", json={"username": "target-user", "password": "AnotherStrongPass!456"})
    assert login.status_code == 200
    target_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=target_headers).status_code == 200

    revoke = client.post(f"/api/v1/admin/users/{user_id}/revoke-sessions", headers=admin_headers)
    assert revoke.status_code == 204

    denied = client.get("/api/v1/auth/me", headers=target_headers)
    assert denied.status_code == 401

    # A session issued after the force-logout cutoff must still work. The
    # revocation cutoff has whole-second precision (see
    # app.core.token_revocation), so a token minted in the very same
    # wall-clock second as the cutoff is conservatively treated as revoked
    # too -- sleep past the second boundary so this assertion exercises a
    # token that is unambiguously *after* the cutoff.
    import time
    time.sleep(1.1)
    relogin = client.post("/api/v1/auth/login", json={"username": "target-user", "password": "AnotherStrongPass!456"})
    fresh_headers = {"Authorization": f"Bearer {relogin.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=fresh_headers).status_code == 200


def test_force_logout_requires_admin(client, admin_headers):
    create = client.post(
        "/api/v1/admin/users", headers=admin_headers,
        json={
            "username": "plain-user", "password": "AnotherStrongPass!456", "display_name": "Plain User",
            "email": "plain@example.com", "role": "USER", "group_ids": [],
        },
    )
    user_id = create.json()["id"]
    login = client.post("/api/v1/auth/login", json={"username": "plain-user", "password": "AnotherStrongPass!456"})
    plain_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    response = client.post(f"/api/v1/admin/users/{user_id}/revoke-sessions", headers=plain_headers)
    assert response.status_code == 403


def test_force_logout_unknown_user_returns_404(client, admin_headers):
    import uuid
    response = client.post(f"/api/v1/admin/users/{uuid.uuid4()}/revoke-sessions", headers=admin_headers)
    assert response.status_code == 404
