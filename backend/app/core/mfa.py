"""TOTP-based multi-factor authentication for administrators.

A per-user TOTP secret is generated on enrollment, encrypted at rest with
a server-held Fernet key (`MFA_SECRET_KEY`/`MFA_SECRET_KEY_FILE`, same
secret-bootstrap pattern as the JWT signing key and API-key pepper — see
`docker/initialize-secrets.sh`), and only decrypted in-process to verify a
submitted code. The raw secret is never returned to the client after
enrollment except embedded in the one-time `otpauth://` provisioning URI,
matching how a raw API key is shown once at creation and never persisted
in plaintext.
"""

from __future__ import annotations

import base64
import hashlib

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class MfaNotConfiguredError(RuntimeError):
    """Raised when MFA_SECRET_KEY is not provisioned on this deployment.

    Every caller of _fernet() (enroll/enable/verify/disable) must catch
    this and turn it into a clean 503, matching the fail-closed
    convention used by /policies/resolve-pipeline and
    /policies/evaluate-enforcement for an invalid/unconfigured gate
    policy: a missing prerequisite must degrade to "the feature is
    unavailable", never crash into a 500 that also leaves MFA silently
    non-functional despite appearing enabled in the UI/API contract.
    """


def _fernet() -> Fernet:
    settings = get_settings()
    if settings.mfa_secret_key is None:
        raise MfaNotConfiguredError("MFA secret key is not configured")
    # Fernet requires a 32-byte urlsafe-base64 key; derive one deterministically
    # from the configured secret so operators supply an ordinary long random
    # string (matching JWT_SECRET/API_KEY_PEPPER conventions) rather than a
    # pre-encoded Fernet key.
    derived = hashlib.sha256(settings.mfa_secret_key.get_secret_value().encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_totp_secret(encrypted: str) -> str | None:
    try:
        return _fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def provisioning_uri(secret: str, account_name: str) -> str:
    settings = get_settings()
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=settings.mfa_issuer)


def verify_totp_code(encrypted_secret: str, code: str) -> bool:
    secret = decrypt_totp_secret(encrypted_secret)
    if not secret:
        return False
    # valid_window=1 tolerates one 30s step of clock drift on either side,
    # matching the tolerance most authenticator apps and IdPs use by default.
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)
