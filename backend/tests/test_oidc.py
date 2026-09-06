import time

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import Response


ISSUER = "https://idp.example.com/realms/sgp-manager"


@pytest.fixture
def oidc_settings(monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OIDC_CLIENT_ID", "sgp-manager")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-oidc-client-secret-value")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost:3000/oidc/callback")
    monkeypatch.setenv("OIDC_ADMIN_GROUPS", "sgp-admins")
    get_settings.cache_clear()
    from app.core import oidc as oidc_module
    oidc_module._discovery_cache.clear()
    oidc_module._jwks_cache.clear()
    yield
    monkeypatch.delenv("OIDC_ENABLED", raising=False)
    get_settings.cache_clear()
    oidc_module._discovery_cache.clear()
    oidc_module._jwks_cache.clear()


@pytest.fixture
def rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _jwk_from_public_key(public_key, kid: str) -> dict:
    numbers = public_key.public_numbers()

    def b64url_uint(value: int) -> str:
        import base64
        byte_length = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).rstrip(b"=").decode("ascii")

    return {
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": b64url_uint(numbers.n), "e": b64url_uint(numbers.e),
    }


def _mock_idp(rsa_keypair, id_token_claims: dict):
    private_key, public_key = rsa_keypair
    kid = "test-signing-key"
    id_token = jwt.encode(id_token_claims, private_key, algorithm="RS256", headers={"kid": kid})
    respx.get(f"{ISSUER}/.well-known/openid-configuration").mock(
        return_value=Response(200, json={
            "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
            "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
            "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        })
    )
    respx.get(f"{ISSUER}/protocol/openid-connect/certs").mock(
        return_value=Response(200, json={"keys": [_jwk_from_public_key(public_key, kid)]})
    )
    respx.post(f"{ISSUER}/protocol/openid-connect/token").mock(
        return_value=Response(200, json={"id_token": id_token, "access_token": "irrelevant"})
    )


@respx.mock
def test_authorization_url_uses_discovered_endpoint(oidc_settings):
    from app.core import oidc
    respx.get(f"{ISSUER}/.well-known/openid-configuration").mock(
        return_value=Response(200, json={
            "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
            "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
            "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        })
    )
    url = oidc.authorization_url(state="s1", nonce="n1")
    assert url.startswith(f"{ISSUER}/protocol/openid-connect/auth?")
    assert "client_id=sgp-manager" in url
    assert "state=s1" in url


@respx.mock
def test_exchange_code_resolves_admin_role_from_group_claim(oidc_settings, rsa_keypair):
    from app.core import oidc
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": "sgp-manager", "sub": "oidc-subject-1",
        "iat": now, "exp": now + 300, "nonce": "expected-nonce",
        "email": "person@example.com", "name": "Person Example", "groups": ["sgp-admins"],
    }
    _mock_idp(rsa_keypair, claims)
    identity = oidc.exchange_code_for_identity("auth-code", "expected-nonce")
    assert identity.subject == "oidc-subject-1"
    assert identity.email == "person@example.com"
    assert oidc.resolve_role_for_groups(identity.groups) == "ADMIN"


@respx.mock
def test_exchange_code_rejects_nonce_mismatch(oidc_settings, rsa_keypair):
    from app.core import oidc
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": "sgp-manager", "sub": "oidc-subject-2",
        "iat": now, "exp": now + 300, "nonce": "actual-nonce", "groups": [],
    }
    _mock_idp(rsa_keypair, claims)
    with pytest.raises(oidc.OidcExchangeError):
        oidc.exchange_code_for_identity("auth-code", "expected-nonce")


@respx.mock
def test_exchange_code_rejects_wrong_audience(oidc_settings, rsa_keypair):
    from app.core import oidc
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": "someone-else", "sub": "oidc-subject-3",
        "iat": now, "exp": now + 300, "nonce": "n", "groups": [],
    }
    _mock_idp(rsa_keypair, claims)
    with pytest.raises(oidc.OidcExchangeError):
        oidc.exchange_code_for_identity("auth-code", "n")


def test_user_without_admin_group_resolves_to_user_role(oidc_settings):
    from app.core import oidc
    assert oidc.resolve_role_for_groups(["sgp-users"]) == "USER"
    assert oidc.resolve_role_for_groups([]) == "USER"


def test_oidc_login_endpoint_returns_authorization_url(client, oidc_settings):
    with respx.mock:
        respx.get(f"{ISSUER}/.well-known/openid-configuration").mock(
            return_value=Response(200, json={
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
            })
        )
        response = client.get("/api/v1/auth/oidc/login")
        assert response.status_code == 200
        assert "authorization_url" in response.json()


def test_oidc_login_endpoint_404_when_disabled(client, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.delenv("OIDC_ENABLED", raising=False)
    get_settings.cache_clear()
    assert client.get("/api/v1/auth/oidc/login").status_code == 404


def test_oidc_callback_provisions_a_new_local_user(client, oidc_settings, rsa_keypair):
    login_response = client.get("/api/v1/auth/oidc/login")
    with respx.mock:
        # oidc_login already consumed the discovery mock context in the fixture above;
        # register it again for this isolated `with respx.mock` block.
        pass
    state = None
    with respx.mock:
        respx.get(f"{ISSUER}/.well-known/openid-configuration").mock(
            return_value=Response(200, json={
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
            })
        )
        login_response = client.get("/api/v1/auth/oidc/login")
        assert login_response.status_code == 200
        auth_url = login_response.json()["authorization_url"]
        from urllib.parse import urlparse, parse_qs
        state = parse_qs(urlparse(auth_url).query)["state"][0]
        from app.api.auth import _oidc_pending
        nonce = _oidc_pending[state]

        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": "sgp-manager", "sub": "new-oidc-subject",
            "iat": now, "exp": now + 300, "nonce": nonce,
            "email": "new.person@example.com", "name": "New Person", "groups": ["sgp-users"],
        }
        _mock_idp(rsa_keypair, claims)
        callback = client.post(f"/api/v1/auth/oidc/callback?code=auth-code&state={state}")
        assert callback.status_code == 200
        body = callback.json()
        assert body["user"]["email"] == "new.person@example.com"
        assert body["user"]["role"] == "USER"
        assert body["user"]["auth_provider"] == "OIDC"


def test_oidc_callback_rejects_unknown_state(client, oidc_settings):
    response = client.post("/api/v1/auth/oidc/callback?code=x&state=never-issued")
    assert response.status_code == 400
