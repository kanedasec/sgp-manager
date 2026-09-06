"""OIDC federation for the administrative portal (authorization code flow).

Keycloak is the reference IdP used for local development and testing
(added to docker-compose.yml under the `dev` profile), but this module
only depends on the standard OIDC discovery document, token endpoint, and
JWKS — any spec-compliant IdP (Okta, Entra ID, Auth0, self-hosted
Keycloak) works without code changes, only configuration.

Local username/password login (app.core.security, Argon2id) remains the
break-glass path: OIDC is additive, never a replacement, so bootstrap
recovery is unaffected if the IdP is unreachable. A local ADMIN account
is still required to configure and troubleshoot OIDC in the first place.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import jwt
from jwt import PyJWK

from app.core.config import get_settings


class OidcConfigurationError(RuntimeError):
    pass


class OidcExchangeError(RuntimeError):
    pass


@dataclass
class OidcIdentity:
    subject: str
    email: str | None
    display_name: str | None
    groups: list[str]


_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


def _discovery_document(issuer: str) -> dict:
    settings = get_settings()
    cached = _discovery_cache.get(issuer)
    now = time.monotonic()
    if cached and now - cached[0] < settings.oidc_jwks_cache_seconds:
        return cached[1]
    response = httpx.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration", timeout=10.0)
    response.raise_for_status()
    document = response.json()
    _discovery_cache[issuer] = (now, document)
    return document


def _signing_key_for_token(issuer: str, jwks_uri: str, id_token: str) -> PyJWK:
    # Fetched over the shared httpx client (not PyJWKClient, which uses
    # urllib internally) so the whole OIDC flow is exercisable and
    # mockable through one HTTP library in tests.
    settings = get_settings()
    now = time.monotonic()
    cached = _jwks_cache.get(issuer)
    jwks = cached[1] if cached and now - cached[0] < settings.oidc_jwks_cache_seconds else None
    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")

    def find_key(keys: list[dict]) -> dict | None:
        for key in keys:
            if kid is None or key.get("kid") == kid:
                return key
        return None

    if jwks is not None:
        match = find_key(jwks.get("keys", []))
        if match is not None:
            return PyJWK.from_dict(match)

    response = httpx.get(jwks_uri, timeout=10.0)
    response.raise_for_status()
    jwks = response.json()
    _jwks_cache[issuer] = (now, jwks)
    match = find_key(jwks.get("keys", []))
    if match is None:
        raise OidcExchangeError("No matching signing key found in the IdP JWKS")
    return PyJWK.from_dict(match)


def authorization_url(state: str, nonce: str) -> str:
    settings = get_settings()
    if not settings.oidc_enabled or not settings.oidc_issuer:
        raise OidcConfigurationError("OIDC is not enabled or not fully configured")
    document = _discovery_document(settings.oidc_issuer)
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": "openid profile email groups",
        "state": state,
        "nonce": nonce,
    }
    query = httpx.QueryParams(params)
    return f"{document['authorization_endpoint']}?{query}"


def exchange_code_for_identity(code: str, nonce: str) -> OidcIdentity:
    settings = get_settings()
    if not settings.oidc_enabled or not settings.oidc_issuer:
        raise OidcConfigurationError("OIDC is not enabled or not fully configured")
    document = _discovery_document(settings.oidc_issuer)

    token_response = httpx.post(
        document["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret.get_secret_value(),
        },
        timeout=10.0,
    )
    if token_response.status_code != 200:
        raise OidcExchangeError(f"Token exchange failed: {token_response.status_code}")
    tokens = token_response.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise OidcExchangeError("IdP response did not include an id_token")

    try:
        signing_key = _signing_key_for_token(settings.oidc_issuer, document["jwks_uri"], id_token)
        claims = jwt.decode(
            id_token, signing_key.key, algorithms=["RS256", "ES256"],
            audience=settings.oidc_client_id, issuer=settings.oidc_issuer,
        )
    except jwt.PyJWTError as exc:
        raise OidcExchangeError(f"id_token verification failed: {exc}") from None
    if claims.get("nonce") != nonce:
        raise OidcExchangeError("id_token nonce mismatch")

    subject = claims.get("sub")
    if not subject:
        raise OidcExchangeError("id_token is missing a subject claim")
    groups = claims.get(settings.oidc_group_claim) or []
    if isinstance(groups, str):
        groups = [groups]
    return OidcIdentity(
        subject=subject,
        email=claims.get("email"),
        display_name=claims.get("name") or claims.get("preferred_username"),
        groups=[str(group) for group in groups],
    )


def resolve_role_for_groups(groups: list[str]) -> str:
    settings = get_settings()
    admin_groups = settings.oidc_admin_group_slugs
    normalized = {group.strip().lower() for group in groups}
    return "ADMIN" if admin_groups and (admin_groups & normalized) else "USER"
