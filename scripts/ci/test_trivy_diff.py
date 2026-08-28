#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

import trivy_diff


class TrivyDiffTests(unittest.TestCase):
    def test_only_new_vulnerability_is_emitted(self):
        existing = {
            "VulnerabilityID": "CVE-OLD",
            "PkgName": "old-package",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        }
        introduced = {
            "VulnerabilityID": "CVE-NEW",
            "PkgName": "new-package",
            "InstalledVersion": "2.0",
            "Severity": "CRITICAL",
        }
        base = {
            "Results": [
                {
                    "Target": "frontend/package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [existing],
                }
            ]
        }
        head = {
            "Results": [
                {
                    "Target": "./frontend/package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [existing, introduced],
                }
            ]
        }

        delta, findings = trivy_diff.build_delta(base, head)

        self.assertEqual(findings, [introduced])
        self.assertEqual(delta["Results"][0]["Vulnerabilities"], [introduced])


if __name__ == "__main__":
    unittest.main()
