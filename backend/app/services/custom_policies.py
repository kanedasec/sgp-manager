import json
from typing import Any

import yaml


MAX_POLICY_BYTES = 65536
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
        else:
            raise InvalidCustomPolicy("Unsupported custom policy format")
    except InvalidCustomPolicy:
        raise
    except (ValueError, yaml.YAMLError, RecursionError) as exc:
        raise InvalidCustomPolicy(f"Invalid {format.upper()} policy document") from exc
    if not isinstance(parsed, dict):
        raise InvalidCustomPolicy("Custom policy document must contain an object at its root")
    _validate_json_compatible(parsed, 0, set(), [0])
    try:
        return json.loads(json.dumps(parsed, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise InvalidCustomPolicy("Policy document is not JSON-compatible") from exc
