import pyotp


def enroll(client, headers):
    return client.post("/api/v1/auth/mfa/enroll", headers=headers)


def enable(client, headers, secret):
    code = pyotp.TOTP(secret).now()
    return client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": code})


def test_enroll_returns_provisioning_uri_and_secret(client, admin_headers):
    response = enroll(client, admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["provisioning_uri"].startswith("otpauth://totp/")
    assert len(body["secret"]) >= 16


def test_enable_requires_a_valid_totp_code(client, admin_headers):
    secret = enroll(client, admin_headers).json()["secret"]
    wrong = client.post("/api/v1/auth/mfa/enable", headers=admin_headers, json={"code": "000000"})
    assert wrong.status_code == 400
    correct = enable(client, admin_headers, secret)
    assert correct.status_code == 200
    assert correct.json()["mfa_enabled"] is True


def test_login_with_mfa_enabled_requires_a_challenge(client, admin_headers):
    secret = enroll(client, admin_headers).json()["secret"]
    enable(client, admin_headers, secret)

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    assert login.status_code == 200
    body = login.json()
    assert body["mfa_required"] is True
    assert "mfa_token" in body
    assert "access_token" not in body

    # The pending token cannot access any other authenticated endpoint.
    denied = client.get("/api/v1/admin/applications", headers={"Authorization": f"Bearer {body['mfa_token']}"})
    assert denied.status_code in (401, 403)

    wrong_code = client.post(
        "/api/v1/auth/mfa/verify", headers={"Authorization": f"Bearer {body['mfa_token']}"},
        json={"code": "000000"},
    )
    assert wrong_code.status_code == 401

    correct_code = client.post(
        "/api/v1/auth/mfa/verify", headers={"Authorization": f"Bearer {body['mfa_token']}"},
        json={"code": pyotp.TOTP(secret).now()},
    )
    assert correct_code.status_code == 200
    assert "access_token" in correct_code.json()
    full_headers = {"Authorization": f"Bearer {correct_code.json()['access_token']}"}
    assert client.get("/api/v1/admin/applications", headers=full_headers).status_code == 200


def test_disable_mfa_requires_current_password(client, admin_headers):
    secret = enroll(client, admin_headers).json()["secret"]
    enable(client, admin_headers, secret)
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    verified = client.post(
        "/api/v1/auth/mfa/verify", headers={"Authorization": f"Bearer {login.json()['mfa_token']}"},
        json={"code": pyotp.TOTP(secret).now()},
    )
    headers = {"Authorization": f"Bearer {verified.json()['access_token']}"}

    wrong_password = client.post("/api/v1/auth/mfa/disable", headers=headers, json={"current_password": "wrong"})
    assert wrong_password.status_code == 400
    correct = client.post(
        "/api/v1/auth/mfa/disable", headers=headers, json={"current_password": "StrongTestPass!123"},
    )
    assert correct.status_code == 200
    assert correct.json()["mfa_enabled"] is False


def test_cannot_enable_mfa_twice(client, admin_headers):
    secret = enroll(client, admin_headers).json()["secret"]
    assert enable(client, admin_headers, secret).status_code == 200
    assert enroll(client, admin_headers).status_code == 409


def test_mfa_required_for_admins_blocks_portal_until_enrolled(client, admin_headers, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("MFA_REQUIRED_FOR_ADMINS", "true")
    get_settings.cache_clear()
    try:
        blocked = client.get("/api/v1/admin/applications", headers=admin_headers)
        assert blocked.status_code == 403
        assert "Multi-factor authentication" in blocked.json()["detail"]

        secret = enroll(client, admin_headers).json()["secret"]
        enable(client, admin_headers, secret)
        # A fresh session token is required after enabling, matching the
        # must_change_password flow (the pre-enrollment token is still valid
        # but current_user re-checks user.mfa_enabled on every request).
        assert client.get("/api/v1/admin/applications", headers=admin_headers).status_code == 200
    finally:
        monkeypatch.delenv("MFA_REQUIRED_FOR_ADMINS", raising=False)
        get_settings.cache_clear()


def test_admin_cannot_disable_mfa_while_required_by_policy(client, admin_headers, monkeypatch):
    from app.core.config import get_settings
    secret = enroll(client, admin_headers).json()["secret"]
    enable(client, admin_headers, secret)
    monkeypatch.setenv("MFA_REQUIRED_FOR_ADMINS", "true")
    get_settings.cache_clear()
    try:
        response = client.post(
            "/api/v1/auth/mfa/disable", headers=admin_headers, json={"current_password": "StrongTestPass!123"},
        )
        assert response.status_code == 409
    finally:
        monkeypatch.delenv("MFA_REQUIRED_FOR_ADMINS", raising=False)
        get_settings.cache_clear()
