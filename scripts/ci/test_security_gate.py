#!/usr/bin/env python3

import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

import security_gate


class SecurityGateTests(unittest.TestCase):
    def test_semgrep_severities_are_normalized(self):
        report = {
            "results": [
                {"extra": {"severity": "INFO"}},
                {"extra": {"severity": "WARNING"}},
                {"extra": {"severity": "ERROR"}},
            ]
        }
        self.assertEqual(
            security_gate.semgrep_findings(report), ["low", "medium", "high"]
        )

    def test_gitleaks_findings_are_critical(self):
        self.assertEqual(
            security_gate.gitleaks_findings([{"RuleID": "example"}]), ["critical"]
        )

    def test_unknown_trivy_severity_fails_closed_as_critical(self):
        report = {
            "Results": [
                {"Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "Severity": "UNKNOWN"}]}
            ]
        }
        self.assertEqual(security_gate.trivy_findings(report), ["critical"])

    def test_policy_must_match_requested_application_and_gate(self):
        policy = {
            "application": "sgp-manager",
            "generated_at": datetime.now(UTC).isoformat(),
            "gates": [{"gate": "sca", "blocking_severities": ["high", "critical"]}],
        }
        blocking, _ = security_gate.validate_policy(policy, "sgp-manager", "sca")
        self.assertEqual(blocking, ["high", "critical"])
        with self.assertRaises(security_gate.GateError):
            security_gate.validate_policy(policy, "different-app", "sca")

    def test_stale_policy_is_rejected(self):
        policy = {
            "application": "sgp-manager",
            "generated_at": (datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
            "gates": [{"gate": "sast", "blocking_severities": ["high"]}],
        }
        with self.assertRaises(security_gate.GateError):
            security_gate.validate_policy(policy, "sgp-manager", "sast")


if __name__ == "__main__":
    unittest.main()
