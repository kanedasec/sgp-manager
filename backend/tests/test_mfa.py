import pyotp


def enroll(client, headers):
    return client.post("/api/v1/auth/mfa/enroll", headers=headers)


def enable(client, headers, secret):
    code = pyotp.TOTP(secret).now()
    return client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": code})


def enable_and_get_headers(client, headers, secret):
    """Enabling MFA revokes every other session for the user (see
    app.api.auth.issue_session_after_credential_change), so callers must
    switch to the freshly issued token to keep making authenticated
    requests as the same user."""
    response = enable(client, headers, secret)
    assert response.status_code == 200, response.text
    return response, {"Authorization": f"Bearer {response.json()['access_token']}"}


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
    correct, _ = enable_and_get_headers(client, admin_headers, secret)
    assert correct.json()["user"]["mfa_enabled"] is True


def test_enabling_mfa_revokes_prior_sessions(client, admin_headers):
    """Confirms the fix for the pentest finding that a token issued before
    MFA enrollment stayed fully authorized after another session enabled
    it -- see report finding F-02 (session/auth-strength revocation)."""
    secret = enroll(client, admin_headers).json()["secret"]
    _, fresh_headers = enable_and_get_headers(client, admin_headers, secret)
    stale = client.get("/api/v1/admin/applications", headers=admin_headers)
    assert stale.status_code == 401
    assert client.get("/api/v1/admin/applications", headers=fresh_headers).status_code == 200


def test_login_with_mfa_enabled_requires_a_challenge(client, admin_headers):
    secret = enroll(client, admin_headers).json()["secret"]
    enable_and_get_headers(client, admin_headers, secret)

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
    _, headers = enable_and_get_headers(client, admin_headers, secret)

    wrong_password = client.post("/api/v1/auth/mfa/disable", headers=headers, json={"current_password": "wrong"})
    assert wrong_password.status_code == 400
    correct = client.post(
        "/api/v1/auth/mfa/disable", headers=headers, json={"current_password": "StrongTestPass!123"},
    )
    assert correct.status_code == 200
    assert correct.json()["mfa_enabled"] is False


def test_cannot_enable_mfa_twice(client, admin_headers):
    secret = enroll(client, admin_headers).json()["secret"]
    _, headers = enable_and_get_headers(client, admin_headers, secret)
    assert enroll(client, headers).status_code == 409


def test_mfa_required_for_admins_blocks_portal_until_enrolled(client, admin_headers, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("MFA_REQUIRED_FOR_ADMINS", "true")
    get_settings.cache_clear()
    try:
        blocked = client.get("/api/v1/admin/applications", headers=admin_headers)
        assert blocked.status_code == 403
        assert "Multi-factor authentication" in blocked.json()["detail"]

        secret = enroll(client, admin_headers).json()["secret"]
        _, fresh_headers = enable_and_get_headers(client, admin_headers, secret)
        # A fresh session token is required after enabling: enabling MFA
        # now revokes every token issued before it (see
        # issue_session_after_credential_change), so the pre-enrollment
        # token from admin_headers is rejected and the newly issued one
        # from enable_and_get_headers must be used instead.
        assert client.get("/api/v1/admin/applications", headers=admin_headers).status_code == 401
        assert client.get("/api/v1/admin/applications", headers=fresh_headers).status_code == 200
    finally:
        monkeypatch.delenv("MFA_REQUIRED_FOR_ADMINS", raising=False)
        get_settings.cache_clear()


def test_admin_cannot_disable_mfa_while_required_by_policy(client, admin_headers, monkeypatch):
    from app.core.config import get_settings
    secret = enroll(client, admin_headers).json()["secret"]
    _, fresh_headers = enable_and_get_headers(client, admin_headers, secret)
    monkeypatch.setenv("MFA_REQUIRED_FOR_ADMINS", "true")
    get_settings.cache_clear()
    try:
        response = client.post(
            "/api/v1/auth/mfa/disable", headers=fresh_headers, json={"current_password": "StrongTestPass!123"},
        )
        assert response.status_code == 409
    finally:
        monkeypatch.delenv("MFA_REQUIRED_FOR_ADMINS", raising=False)
        get_settings.cache_clear()
