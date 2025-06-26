#!/usr/bin/env python3

import json
from typing import Dict, List


def debug_severity_counting(vulnerabilities: List[Dict]) -> Dict:
    """Debug version of generate_comprehensive_report with detailed logging."""

    print(f"DEBUG: Processing {len(vulnerabilities)} vulnerabilities")

    if not vulnerabilities:
        return {
            "total_vulnerabilities": 0,
            "packages_affected": 0,
            "vulnerability_breakdown": {},
            "high_risk_packages": [],
            "vulnerabilities": [],
        }

    # Group by package and severity
    by_package = {}
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "unknown": 0}

    for i, vuln in enumerate(vulnerabilities):
        print(f"DEBUG: Processing vulnerability {i + 1}:")
        print(f"  Package: {vuln.get('affected_package', 'MISSING')}")
        print(f"  Severity: '{vuln.get('severity', 'MISSING')}'")
        print(f"  CVE: {vuln.get('cve_id', 'MISSING')}")

        # By package
        pkg = vuln["affected_package"]
        if pkg not in by_package:
            by_package[pkg] = {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            print(f"  Created new package entry for {pkg}")

        by_package[pkg]["total"] += 1
        severity = vuln.get("severity", "unknown").upper()
        print(f"  Normalized severity: '{severity}'")

        # Convert severity to lowercase for package counting
        severity_lower = severity.lower()
        print(f"  Lowercase severity: '{severity_lower}'")
        print(f"  Available keys in by_package[{pkg}]: {list(by_package[pkg].keys())}")

        if severity_lower in by_package[pkg]:
            by_package[pkg][severity_lower] += 1
            print(
                f"  ✓ Incremented {pkg}[{severity_lower}] to {by_package[pkg][severity_lower]}"
            )
        else:
            print(f"  ✗ '{severity_lower}' not found in package keys!")

        # By severity (keep uppercase for overall breakdown)
        if severity in by_severity:
            by_severity[severity] += 1
            print(f"  ✓ Incremented global {severity} to {by_severity[severity]}")
        else:
            by_severity["unknown"] += 1
            print(f"  ✓ Incremented global unknown to {by_severity['unknown']}")

        print()  # Empty line for readability

    print("DEBUG: Final package counts:")
    for pkg, counts in by_package.items():
        print(f"  {pkg}: {counts}")

    print(f"DEBUG: Final severity breakdown: {by_severity}")

    # Calculate risk scores
    high_risk_packages = []
    for pkg, counts in by_package.items():
        risk_score = (
            counts["critical"] * 20
            + counts["high"] * 10
            + counts["medium"] * 5
            + counts["low"] * 1
        )

        print(
            f"DEBUG: Risk score for {pkg}: {risk_score} (c:{counts['critical']}, h:{counts['high']}, m:{counts['medium']}, l:{counts['low']})"
        )

        high_risk_packages.append(
            {
                "package": pkg,
                "total_vulns": counts["total"],
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "risk_score": risk_score,
            }
        )

    high_risk_packages.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "total_vulnerabilities": len(vulnerabilities),
        "packages_affected": len(by_package),
        "vulnerability_breakdown": by_severity,
        "high_risk_packages": high_risk_packages,
        "vulnerabilities": vulnerabilities,
    }


def test_with_sample_data():
    """Test with sample data that matches your output format."""

    # Sample vulnerability that matches your output structure
    sample_vulnerabilities = [
        {
            "cve_id": "CVE-2019-9924",
            "definition_id": "oval:org.debian:def:59660616478713886489766168396582364833",
            "title": "CVE-2019-9924 bash",
            "description": "rbash in Bash before 4.4-beta2 did not prevent the shell user from modifying BASH_CMDS, thus allowing the user to execute any command with the permissions of the shell.",
            "affected_package": "bash",
            "installed_version": "4.3-14ubuntu1.4",
            "cvss_score": 7.8,
            "severity": "HIGH",
            "summary": "rbash in Bash before 4.4-beta2 did not prevent the shell user from modifying BASH_CMDS, thus allowing the user to execute any command with the permissions of the shell.",
            "published_date": "2019-03-22 08:29:00.467+00:00",
        },
        {
            "cve_id": "CVE-2020-1234",
            "affected_package": "bash",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
        },
        {
            "cve_id": "CVE-2021-5678",
            "affected_package": "bash",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
        },
    ]

    print("=== Testing with sample vulnerabilities ===")
    result = debug_severity_counting(sample_vulnerabilities)

    print("\n=== FINAL RESULT ===")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    test_with_sample_data()
