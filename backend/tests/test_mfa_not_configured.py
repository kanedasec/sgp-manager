def test_mfa_enroll_returns_503_when_secret_key_is_not_configured(client, admin_headers, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.delenv("MFA_SECRET_KEY", raising=False)
    get_settings.cache_clear()
    try:
        response = client.post("/api/v1/auth/mfa/enroll", headers=admin_headers)
        assert response.status_code == 503
        assert "not available" in response.json()["detail"].lower()
    finally:
        get_settings.cache_clear()


def test_mfa_enable_returns_503_when_secret_key_becomes_unconfigured(client, admin_headers, monkeypatch):
    from app.core.config import get_settings
    enroll = client.post("/api/v1/auth/mfa/enroll", headers=admin_headers)
    assert enroll.status_code == 200

    monkeypatch.delenv("MFA_SECRET_KEY", raising=False)
    get_settings.cache_clear()
    try:
        response = client.post("/api/v1/auth/mfa/enable", headers=admin_headers, json={"code": "000000"})
        assert response.status_code == 503
    finally:
        get_settings.cache_clear()


def test_mfa_verify_returns_503_when_secret_key_becomes_unconfigured(client, admin_headers, monkeypatch):
    import pyotp

    from app.core.config import get_settings

    enroll = client.post("/api/v1/auth/mfa/enroll", headers=admin_headers)
    secret = enroll.json()["secret"]
    code = pyotp.TOTP(secret).now()
    enable = client.post("/api/v1/auth/mfa/enable", headers=admin_headers, json={"code": code})
    assert enable.status_code == 200

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    mfa_headers = {"Authorization": f"Bearer {login.json()['mfa_token']}"}

    monkeypatch.delenv("MFA_SECRET_KEY", raising=False)
    get_settings.cache_clear()
    try:
        response = client.post(
            "/api/v1/auth/mfa/verify", headers=mfa_headers, json={"code": pyotp.TOTP(secret).now()},
        )
        assert response.status_code == 503
    finally:
        get_settings.cache_clear()
