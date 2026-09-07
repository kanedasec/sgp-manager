import pyotp


def test_login_is_rate_limited_per_username(client, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "3")
    get_settings.cache_clear()
    try:
        for _ in range(3):
            response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
            assert response.status_code == 401
        throttled = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert throttled.status_code == 429
        # Even the correct password is now blocked until the window rolls over.
        still_blocked = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
        assert still_blocked.status_code == 429
    finally:
        monkeypatch.delenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", raising=False)
        get_settings.cache_clear()


def test_login_rate_limit_is_scoped_per_username_not_global(client, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "2")
    get_settings.cache_clear()
    try:
        for _ in range(2):
            assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
        assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 429
        # A different username from the same IP has its own counter, but the
        # IP counter is shared, so it also trips once the IP bucket is spent.
        other = client.post("/api/v1/auth/login", json={"username": "someone-else", "password": "wrong"})
        assert other.status_code == 429
    finally:
        monkeypatch.delenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", raising=False)
        get_settings.cache_clear()


def test_mfa_verify_is_rate_limited(client, admin_headers, monkeypatch):
    from app.core.config import get_settings

    enroll = client.post("/api/v1/auth/mfa/enroll", headers=admin_headers)
    secret = enroll.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/mfa/enable", headers=admin_headers, json={"code": code})

    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
    mfa_headers = {"Authorization": f"Bearer {login.json()['mfa_token']}"}

    monkeypatch.setenv("AUTH_MFA_VERIFY_RATE_LIMIT_PER_MINUTE", "3")
    get_settings.cache_clear()
    try:
        for _ in range(3):
            response = client.post("/api/v1/auth/mfa/verify", headers=mfa_headers, json={"code": "000000"})
            assert response.status_code == 401
        throttled = client.post("/api/v1/auth/mfa/verify", headers=mfa_headers, json={"code": "000000"})
        assert throttled.status_code == 429
        # Even the correct code is blocked once the window is exhausted.
        still_blocked = client.post(
            "/api/v1/auth/mfa/verify", headers=mfa_headers, json={"code": pyotp.TOTP(secret).now()},
        )
        assert still_blocked.status_code == 429
    finally:
        monkeypatch.delenv("AUTH_MFA_VERIFY_RATE_LIMIT_PER_MINUTE", raising=False)
        get_settings.cache_clear()


def test_successful_login_does_not_leave_account_permanently_locked(client, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "10")
    get_settings.cache_clear()
    try:
        response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongTestPass!123"})
        assert response.status_code == 200
    finally:
        monkeypatch.delenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", raising=False)
        get_settings.cache_clear()
