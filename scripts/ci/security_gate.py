#!/usr/bin/env python3
"""Apply an SGP Manager enforcement policy to a scanner JSON report."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


CANONICAL_SEVERITIES = ("low", "medium", "high", "critical")
SEMGREP_SEVERITIES = {
    "INFO": "low",
    "WARNING": "medium",
    "ERROR": "high",
    "CRITICAL": "critical",
}


class GateError(ValueError):
    """An operational or validation error that must fail the gate closed."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate scanner findings against an SGP Manager gate."
    )
    parser.add_argument("--manager-url", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument(
        "--scanner", required=True, choices=("semgrep", "gitleaks", "trivy")
    )
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--decision-output", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args()


def load_json(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as input_file:
            return json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read JSON report {path}: {error}") from error


def normalize_severity(value: Any) -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in CANONICAL_SEVERITIES else "critical"


def semgrep_findings(report: Any) -> list[str]:
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise GateError("invalid Semgrep JSON report")

    severities: list[str] = []
    for finding in report["results"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("extra"), dict):
            raise GateError("invalid Semgrep finding")
        scanner_severity = str(finding["extra"].get("severity") or "").upper()
        severities.append(SEMGREP_SEVERITIES.get(scanner_severity, "critical"))
    return severities


def gitleaks_findings(report: Any) -> list[str]:
    if not isinstance(report, list) or not all(isinstance(item, dict) for item in report):
        raise GateError("invalid Gitleaks JSON report")
    return ["critical"] * len(report)


def trivy_findings(report: Any) -> list[str]:
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise GateError("invalid Trivy JSON report")

    severities: list[str] = []
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise GateError("invalid Trivy result")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise GateError("invalid Trivy vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise GateError("invalid Trivy vulnerability")
            severities.append(normalize_severity(vulnerability.get("Severity")))
    return severities


def extract_findings(scanner: str, report: Any) -> list[str]:
    extractors = {
        "semgrep": semgrep_findings,
        "gitleaks": gitleaks_findings,
        "trivy": trivy_findings,
    }
    return extractors[scanner](report)


def enforcement_url(manager_url: str) -> str:
    parsed = urllib.parse.urlsplit(manager_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise GateError("SGP Manager URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise GateError("SGP Manager URL must not contain credentials, a query, or a fragment")
    base = manager_url.rstrip("/") + "/"
    return urllib.parse.urljoin(base, "api/v1/policies/evaluate-enforcement")


def fetch_policy(
    manager_url: str,
    api_key: str,
    application: str,
    gate: str,
    timeout: float,
) -> dict[str, Any]:
    payload = json.dumps({"application": application, "gate": gate}).encode()
    request = urllib.request.Request(
        enforcement_url(manager_url),
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "sgp-manager-ci-policy-gate/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise GateError(f"SGP Manager policy request failed: {error}") from error

    try:
        policy = json.loads(response_body)
    except json.JSONDecodeError as error:
        raise GateError("SGP Manager returned invalid JSON") from error
    if not isinstance(policy, dict):
        raise GateError("SGP Manager returned an invalid policy object")
    return policy


def validate_policy(
    policy: dict[str, Any], application: str, gate: str
) -> tuple[list[str], str]:
    if policy.get("application") != application:
        raise GateError("SGP Manager returned a different application")

    gates = policy.get("gates")
    if not isinstance(gates, list) or len(gates) != 1 or not isinstance(gates[0], dict):
        raise GateError("SGP Manager did not return exactly one gate")
    if gates[0].get("gate") != gate:
        raise GateError("SGP Manager returned a different gate")

    blocking = gates[0].get("blocking_severities")
    if not isinstance(blocking, list) or not all(
        isinstance(item, str) and item in CANONICAL_SEVERITIES for item in blocking
    ):
        raise GateError("SGP Manager returned invalid blocking severities")
    if len(set(blocking)) != len(blocking):
        raise GateError("SGP Manager returned duplicate blocking severities")

    generated_at = policy.get("generated_at")
    if not isinstance(generated_at, str):
        raise GateError("SGP Manager response has no generated_at timestamp")
    try:
        policy_time = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError("SGP Manager returned an invalid generated_at timestamp") from error
    if policy_time.tzinfo is None:
        raise GateError("SGP Manager generated_at timestamp has no timezone")
    age = (datetime.now(UTC) - policy_time.astimezone(UTC)).total_seconds()
    if age < -60 or age > 300:
        raise GateError("SGP Manager returned a stale or future policy response")

    return blocking, generated_at


def write_decision(path: Path, decision: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", encoding="utf-8") as output_file:
            json.dump(decision, output_file, indent=2)
            output_file.write("\n")
    except OSError as error:
        raise GateError(f"cannot write policy decision {path}: {error}") from error


def main() -> int:
    args = parse_args()
    api_key = os.environ.get("SGP_MANAGER_API_KEY", "")
    if not api_key:
        print("error: SGP_MANAGER_API_KEY is not configured", file=sys.stderr)
        return 2

    try:
        findings = extract_findings(args.scanner, load_json(args.report))
        policy = fetch_policy(
            args.manager_url,
            api_key,
            args.application,
            args.gate,
            args.timeout,
        )
        blocking_severities, generated_at = validate_policy(
            policy, args.application, args.gate
        )
        counts = Counter(findings)
        blocking_findings = [item for item in findings if item in blocking_severities]
        decision = {
            "application": args.application,
            "gate": args.gate,
            "scanner": args.scanner,
            "policy_generated_at": generated_at,
            "evaluated_at": datetime.now(UTC).isoformat(),
            "blocking_severities": blocking_severities,
            "finding_counts": {
                severity: counts.get(severity, 0) for severity in CANONICAL_SEVERITIES
            },
            "blocking_findings": len(blocking_findings),
            "decision": "BLOCK" if blocking_findings else "PASS",
        }
        write_decision(args.decision_output, decision)
    except GateError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"Application: {args.application}")
    print(f"Gate: {args.gate} ({args.scanner})")
    print(f"Blocking severities: {','.join(blocking_severities) or 'none'}")
    print(
        "Differential findings: "
        + ", ".join(
            f"{severity}={counts.get(severity, 0)}"
            for severity in CANONICAL_SEVERITIES
        )
    )
    print(f"Decision: {decision['decision']}")
    return 1 if blocking_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
