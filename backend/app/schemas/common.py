import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator


SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def validate_slug(value: str) -> str:
    value = value.strip().lower()
    if not SLUG_PATTERN.fullmatch(value):
        raise ValueError("must contain lowercase letters, numbers, and single hyphens only")
    return value


Slug = Annotated[str, AfterValidator(validate_slug)]


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timezone is required")
    return value.astimezone(UTC)

