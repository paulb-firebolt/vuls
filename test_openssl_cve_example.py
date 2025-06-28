#!/usr/bin/env python3
"""
Test script to check how the system handles CVE-2024-6119 for OpenSSL.
"""

import sys
import os
sys.path.append('web-app/app')

from services.enhanced_vulnerability_service import EnhancedVulnerabilityChecker
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_openssl_cve_example():
    """Test the OpenSSL CVE-2024-6119 example."""

    print("=== Testing OpenSSL CVE-2024-6119 ===\n")

    # Create a mock vulnerability as it would come from GOST database
    gost_vulnerability = {
        "cve_id": "CVE-2024-6119",
        "source": "GOST",
        "affected_package": "openssl",
        "installed_version": "3.0.16-1~deb12u1",
        "fixed_version": "unknown",  # This is the problem!
        "priority": "high",
        "description": "",
        "public_date": "2024-09-03",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "summary": "Issue summary: Applications performing certificate name checks (e.g., TLS clients checking server certificates) may attempt to read an invalid memory address resulting in abnormal termination of the application process.",
        "published_date": "2024-09-03"
    }

    print("Original GOST vulnerability (problematic):")
    print(f"  CVE: {gost_vulnerability['cve_id']}")
    print(f"  Package: {gost_vulnerability['affected_package']}")
    print(f"  Installed: {gost_vulnerability['installed_version']}")
    print(f"  Fixed: {gost_vulnerability['fixed_version']}")
    print(f"  CVSS: {gost_vulnerability['cvss_score']}")
    print()

    # Create checker instance with actual database paths
    checker = EnhancedVulnerabilityChecker(
        oval_db_path="db/oval.sqlite3",
        gost_db_path="db/gost.sqlite3",
        cve_db_path="db/cve.sqlite3"
    )

    # Test the enhancement process
    print("=== Enhancement Process ===")

    # Test enhanced vulnerability
    enhanced_vuln = checker._enhance_vulnerability_with_cross_reference(gost_vulnerability)

    print("Enhanced vulnerability:")
    for key, value in enhanced_vuln.items():
        if key not in gost_vulnerability or enhanced_vuln[key] != gost_vulnerability[key]:
            print(f"  {key}: {value} (ENHANCED)")
        else:
            print(f"  {key}: {value}")

    # Test applicability check
    is_applicable = checker._is_vulnerability_actually_applicable(enhanced_vuln)

    print(f"\n=== Applicability Check ===")
    print(f"Is vulnerability actually applicable? {is_applicable}")

    if not is_applicable:
        print("✓ Correctly identified as FALSE POSITIVE")
        print("Reason: Installed version 3.0.16 is newer than fixed version")
    else:
        print("✗ Still showing as vulnerable")

        # Let's check what OVAL has for this CVE
        print("\n=== Manual OVAL Check ===")
        oval_info = checker._check_oval_for_cve("CVE-2024-6119", "openssl")
        if oval_info:
            print(f"OVAL has fix info: {oval_info}")

            # Manual version comparison
            installed_upstream = checker.parse_debian_version("3.0.16-1~deb12u1")["upstream"]
            fixed_version = oval_info.get("fixed_version", "")

            if fixed_version:
                # Extract upstream from OVAL version (might be Alpine format like 3.0.15-r0)
                oval_upstream = fixed_version.split("-")[0]
                print(f"Installed upstream: {installed_upstream}")
                print(f"OVAL fixed upstream: {oval_upstream}")

                try:
                    from packaging import version
                    is_vulnerable = version.parse(installed_upstream) < version.parse(oval_upstream)
                    print(f"Manual comparison: {installed_upstream} < {oval_upstream} = {is_vulnerable}")
                except Exception as e:
                    print(f"Error in manual comparison: {e}")
        else:
            print("No OVAL info found")

    # Test the full filtering process
    print(f"\n=== Final Result ===")

    vulnerabilities = [gost_vulnerability]
    filtered = checker._deduplicate_vulnerabilities(vulnerabilities)

    print(f"Original vulnerabilities: {len(vulnerabilities)}")
    print(f"After filtering: {len(filtered)}")

    if len(filtered) == 0:
        print("✓ SUCCESS: False positive correctly filtered out")
    else:
        print("✗ ISSUE: Vulnerability still present after filtering")
        for vuln in filtered:
            print(f"  Remaining: {vuln['cve_id']} for {vuln['affected_package']}")
            if vuln.get("fixed_version") != "unknown":
                print(f"    Fixed version: {vuln['fixed_version']}")


if __name__ == "__main__":
    test_openssl_cve_example()
