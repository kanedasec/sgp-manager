import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator


SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FINDING_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_:./-]{1,159}$")


def validate_slug(value: str) -> str:
    value = value.strip().lower()
    if not SLUG_PATTERN.fullmatch(value):
        raise ValueError("must contain lowercase letters, numbers, and single hyphens only")
    return value


def validate_finding_id(value: str) -> str:
    """A finding identifier from a scanner: a CVE ID (``CVE-2026-12345``) or a
    scanner-supplied fingerprint (for example ``semgrep:rule-id:path:line``
    or a hash). Accepts letters, digits, and ``_:./-`` separators only, so it
    cannot carry justification text, HTML, or other free-form content into
    audit metadata or the pipeline contract."""
    value = value.strip()
    if not FINDING_ID_PATTERN.fullmatch(value):
        raise ValueError(
            "must be 2-160 characters of letters, numbers, and the separators _ : . / -"
        )
    return value


Slug = Annotated[str, AfterValidator(validate_slug)]
FindingId = Annotated[str, AfterValidator(validate_finding_id)]


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timezone is required")
    return value.astimezone(UTC)

