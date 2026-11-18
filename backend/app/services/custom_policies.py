import hashlib
import json
import tomllib
from typing import Any

import tomli_w
import yaml
from fastapi import HTTPException, Response, status


MAX_POLICY_BYTES = 256 * 1024
MAX_POLICY_DEPTH = 32
MAX_POLICY_NODES = 5000


class InvalidCustomPolicy(ValueError):
    pass


def _reject_json_constant(value: str) -> None:
    raise InvalidCustomPolicy(f"JSON constant '{value}' is not supported")


def _validate_json_compatible(value: Any, depth: int, ancestors: set[int], counter: list[int]) -> None:
    counter[0] += 1
    if counter[0] > MAX_POLICY_NODES:
        raise InvalidCustomPolicy(f"Policy document exceeds {MAX_POLICY_NODES} values")
    if depth > MAX_POLICY_DEPTH:
        raise InvalidCustomPolicy(f"Policy document exceeds maximum depth {MAX_POLICY_DEPTH}")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if not isinstance(value, (dict, list)):
        raise InvalidCustomPolicy("Policy values must be JSON-compatible primitives, objects, or arrays")
    identity = id(value)
    if identity in ancestors:
        raise InvalidCustomPolicy("Recursive YAML aliases are not supported")
    ancestors.add(identity)
    try:
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise InvalidCustomPolicy("Policy object keys must be strings")
                _validate_json_compatible(item, depth + 1, ancestors, counter)
        else:
            for item in value:
                _validate_json_compatible(item, depth + 1, ancestors, counter)
    finally:
        ancestors.remove(identity)


def parse_custom_policy(format: str, document: str) -> dict[str, Any]:
    try:
        document_size = len(document.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise InvalidCustomPolicy("Policy document must contain valid UTF-8 text") from exc
    if document_size > MAX_POLICY_BYTES:
        raise InvalidCustomPolicy(f"Policy document exceeds {MAX_POLICY_BYTES} UTF-8 bytes")
    try:
        if format == "json":
            parsed = json.loads(document, parse_constant=_reject_json_constant)
        elif format == "yaml":
            parsed = yaml.safe_load(document)
        elif format == "toml":
            parsed = tomllib.loads(document)
        else:
            raise InvalidCustomPolicy("Unsupported custom policy format")
    except InvalidCustomPolicy:
        raise
    except (ValueError, yaml.YAMLError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise InvalidCustomPolicy(f"Invalid {format.upper()} policy document") from exc
    if not isinstance(parsed, dict):
        raise InvalidCustomPolicy("Custom policy document must contain an object at its root")
    _validate_json_compatible(parsed, 0, set(), [0])
    try:
        return json.loads(json.dumps(parsed, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise InvalidCustomPolicy("Policy document is not JSON-compatible") from exc


POLICY_FORMATS = ("json", "yaml", "toml")
MEDIA_TYPES = {
    "json": "application/json",
    "yaml": "application/yaml",
    "toml": "application/toml",
}
TOML_INT_MIN = -(2**63)
TOML_INT_MAX = 2**63 - 1


class UnrenderableCustomPolicy(ValueError):
    pass


def canonical_digest(parsed: dict[str, Any]) -> str:
    """Format-independent SHA-256 of the canonical JSON document.

    The same logical policy has the same digest whether it was authored or
    is delivered as JSON, YAML, or TOML, so pipelines can pin or compare it.
    """
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_toml_compatible(value: Any, path: str) -> None:
    if value is None:
        raise UnrenderableCustomPolicy(f"TOML cannot represent the null value at {path}")
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not TOML_INT_MIN <= value <= TOML_INT_MAX:
        raise UnrenderableCustomPolicy(f"TOML cannot represent the integer at {path} (64-bit limit)")
    if isinstance(value, dict):
        for key, item in value.items():
            _check_toml_compatible(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_toml_compatible(item, f"{path}[{index}]")


def render_custom_policy(source_format: str, source_document: str, parsed: dict[str, Any], format: str) -> str:
    """Render a validated policy in the requested format.

    When the requested format equals the authoring format, the validated
    source text is returned unchanged so comments and layout are preserved.
    Other formats are generated from the canonical parsed document.
    """
    if format not in POLICY_FORMATS:
        raise UnrenderableCustomPolicy("Unsupported custom policy format")
    if format == source_format:
        return source_document
    if format == "json":
        return json.dumps(parsed, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    if format == "yaml":
        return yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True, default_flow_style=False)
    _check_toml_compatible(parsed, "$")
    try:
        rendered = tomli_w.dumps(parsed)
        round_trip = tomllib.loads(rendered)
    except (TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise UnrenderableCustomPolicy("Policy document cannot be represented as TOML") from exc
    if round_trip != parsed:
        raise UnrenderableCustomPolicy("Policy document cannot be represented as TOML without changing it")
    return rendered


def renderable_formats(source_format: str, source_document: str, parsed: dict[str, Any]) -> list[str]:
    result = []
    for format in POLICY_FORMATS:
        try:
            render_custom_policy(source_format, source_document, parsed, format)
        except UnrenderableCustomPolicy:
            continue
        result.append(format)
    return result


def policy_file_response(policy: Any, format: str) -> Response:
    """Serve a validated custom policy as a downloadable file.

    ``policy`` is a ``CustomPolicy`` row. The filename is derived only from
    the validated slug, so it never needs escaping.
    """
    try:
        content = render_custom_policy(policy.format, policy.document, policy.parsed_document, format)
    except UnrenderableCustomPolicy as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    return Response(
        content=content.encode("utf-8"),
        media_type=f"{MEDIA_TYPES[format]}; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{policy.slug}.{format}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Policy-Digest": canonical_digest(policy.parsed_document),
        },
    )
