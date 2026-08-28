#!/usr/bin/env python3
"""Create a Trivy JSON report containing findings absent from a base report."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two Trivy JSON reports and emit only new vulnerabilities."
    )
    parser.add_argument("--base", required=True, type=Path, help="Base report")
    parser.add_argument("--head", required=True, type=Path, help="Head report")
    parser.add_argument("--output", required=True, type=Path, help="Delta report")
    parser.add_argument(
        "--fail-on",
        default="HIGH,CRITICAL",
        help="Comma-separated severities that make the command fail",
    )
    return parser.parse_args()


def load_report(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as report_file:
            report = json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read Trivy report {path}: {error}") from error

    if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
        raise ValueError(f"invalid Trivy JSON report: {path}")
    return report


def normalize_target(target: Any) -> str:
    normalized = str(target or "").replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def vulnerability_key(result: dict[str, Any], vulnerability: dict[str, Any]) -> tuple[str, ...]:
    package_identifier = vulnerability.get("PkgIdentifier") or {}
    if not isinstance(package_identifier, dict):
        package_identifier = {}

    return (
        normalize_target(result.get("Target")),
        str(result.get("Class") or ""),
        str(result.get("Type") or ""),
        str(vulnerability.get("VulnerabilityID") or ""),
        str(vulnerability.get("PkgName") or ""),
        str(vulnerability.get("InstalledVersion") or ""),
        str(package_identifier.get("PURL") or ""),
    )


def vulnerability_keys(report: dict[str, Any]) -> set[tuple[str, ...]]:
    keys: set[tuple[str, ...]] = set()
    for result in report.get("Results", []):
        if not isinstance(result, dict):
            continue
        for vulnerability in result.get("Vulnerabilities") or []:
            if isinstance(vulnerability, dict):
                keys.add(vulnerability_key(result, vulnerability))
    return keys


def build_delta(
    base_report: dict[str, Any], head_report: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    base_keys = vulnerability_keys(base_report)
    delta_report = copy.deepcopy(head_report)
    delta_results: list[dict[str, Any]] = []
    new_vulnerabilities: list[dict[str, Any]] = []

    for result in delta_report.get("Results", []):
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities") or []
        new_for_target = [
            vulnerability
            for vulnerability in vulnerabilities
            if isinstance(vulnerability, dict)
            and vulnerability_key(result, vulnerability) not in base_keys
        ]
        if new_for_target:
            result["Vulnerabilities"] = new_for_target
            delta_results.append(result)
            new_vulnerabilities.extend(new_for_target)

    delta_report["Results"] = delta_results
    return delta_report, new_vulnerabilities


def main() -> int:
    args = parse_args()
    fail_on = {
        severity.strip().upper()
        for severity in args.fail_on.split(",")
        if severity.strip()
    }

    try:
        base_report = load_report(args.base)
        head_report = load_report(args.head)
        delta_report, new_vulnerabilities = build_delta(base_report, head_report)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as output_file:
            json.dump(delta_report, output_file, indent=2)
            output_file.write("\n")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    blocking = [
        vulnerability
        for vulnerability in new_vulnerabilities
        if str(vulnerability.get("Severity") or "").upper() in fail_on
    ]

    print(f"New vulnerabilities: {len(new_vulnerabilities)}")
    print(f"New blocking vulnerabilities ({','.join(sorted(fail_on))}): {len(blocking)}")
    for vulnerability in blocking:
        print(
            "- "
            f"{vulnerability.get('Severity', 'UNKNOWN')} "
            f"{vulnerability.get('VulnerabilityID', 'UNKNOWN')} "
            f"in {vulnerability.get('PkgName', 'unknown package')}@"
            f"{vulnerability.get('InstalledVersion', 'unknown version')}"
        )

    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
