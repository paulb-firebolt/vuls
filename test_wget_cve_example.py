#!/usr/bin/env python3
"""
Test script to demonstrate how the enhanced vulnerability system handles
the wget CVE-2019-5953 example that was showing as a false positive.
"""

import sys
import os
sys.path.append('web-app/app')

from services.enhanced_vulnerability_service import EnhancedVulnerabilityChecker
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_wget_cve_example():
    """Test the wget CVE-2019-5953 example that was showing as false positive."""

    print("=== Testing wget CVE-2019-5953 False Positive ===\n")

    # Create a mock vulnerability as it would come from GOST database
    gost_vulnerability = {
        "cve_id": "CVE-2019-5953",
        "source": "GOST",
        "affected_package": "wget",
        "installed_version": "1.21.3-1+deb12u1",
        "fixed_version": "unknown",  # This is the problem!
        "priority": "high",
        "description": "",
        "public_date": "2019-01-01",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "summary": "Buffer overflow in GNU Wget 1.20.1 and earlier allows remote attackers to cause a denial-of-service (DoS) or may execute an arbitrary code via unspecified vectors.",
        "published_date": "2019-01-01"
    }

    print("Original GOST vulnerability (problematic):")
    print(f"  CVE: {gost_vulnerability['cve_id']}")
    print(f"  Package: {gost_vulnerability['affected_package']}")
    print(f"  Installed: {gost_vulnerability['installed_version']}")
    print(f"  Fixed: {gost_vulnerability['fixed_version']}")
    print(f"  Summary: {gost_vulnerability['summary']}")
    print(f"  CVSS: {gost_vulnerability['cvss_score']}")
    print()

    # Create checker instance (with dummy paths since we're testing logic)
    checker = EnhancedVulnerabilityChecker("", "", "")

    # Test the enhancement process
    print("=== Enhancement Process ===")

    # 1. Test version extraction from description
    version_info = checker._extract_version_from_description(
        gost_vulnerability["summary"],
        gost_vulnerability["cve_id"]
    )

    if version_info:
        print(f"✓ Extracted version info: {version_info}")
    else:
        print("✗ No version info extracted")

    # 2. Test enhanced vulnerability
    enhanced_vuln = checker._enhance_vulnerability_with_cross_reference(gost_vulnerability)

    print("\nEnhanced vulnerability:")
    for key, value in enhanced_vuln.items():
        if key not in gost_vulnerability or enhanced_vuln[key] != gost_vulnerability[key]:
            print(f"  {key}: {value} (ENHANCED)")
        else:
            print(f"  {key}: {value}")

    # 3. Test applicability check
    is_applicable = checker._is_vulnerability_actually_applicable(enhanced_vuln)

    print(f"\n=== Applicability Check ===")
    print(f"Is vulnerability actually applicable? {is_applicable}")

    if not is_applicable:
        print("✓ Correctly identified as FALSE POSITIVE")
        print("Reason: Installed version 1.21.3 is newer than affected version 1.20.1")
    else:
        print("✗ Still showing as vulnerable (needs investigation)")

    # 4. Test version comparison details
    print(f"\n=== Version Analysis ===")

    if enhanced_vuln.get("extracted_affected_version"):
        affected_version = enhanced_vuln["extracted_affected_version"]
        installed_upstream = checker.parse_debian_version(enhanced_vuln["installed_version"])["upstream"]

        print(f"Affected version: {affected_version} and earlier")
        print(f"Installed upstream: {installed_upstream}")
        print(f"Comparison: {installed_upstream} > {affected_version} = NOT VULNERABLE")

    # 5. Show what the final result would be
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


def test_version_parsing():
    """Test the Debian version parsing for the wget example."""

    print("\n" + "="*60)
    print("=== Testing Debian Version Parsing ===\n")

    checker = EnhancedVulnerabilityChecker("", "", "")

    test_version = "1.21.3-1+deb12u1"
    parsed = checker.parse_debian_version(test_version)

    print(f"Original version: {test_version}")
    print(f"Parsed components:")
    for key, value in parsed.items():
        print(f"  {key}: '{value}'")

    print(f"\nUpstream version for comparison: {parsed['upstream']}")


def test_description_parsing():
    """Test description parsing with various CVE description formats."""

    print("\n" + "="*60)
    print("=== Testing Description Parsing ===\n")

    checker = EnhancedVulnerabilityChecker("", "", "")

    test_descriptions = [
        ("CVE-2019-5953", "Buffer overflow in GNU Wget 1.20.1 and earlier allows remote attackers to cause a denial-of-service (DoS) or may execute an arbitrary code via unspecified vectors."),
        ("CVE-2021-31879", "GNU Wget before 1.21.1 allows remote attackers to cause a denial of service."),
        ("CVE-2020-13776", "systemd through v245 mishandles numerical usernames such as ones composed of decimal digits or 0x followed by hex digits, as demonstrated by use of root privileges when privileges of the 0x0 user account were intended. NOTE: this issue exists because of an incomplete fix for CVE-2017-1000082."),
        ("CVE-2019-3842", "In systemd before v242-rc4, it was discovered that pam_systemd does not properly sanitize the environment before using the XDG_SEAT variable. It is possible for an attacker, in some particular configurations, to set a XDG_SEAT environment variable which allows for commands to be checked against polkit policies using the \"allow_active\" element rather than \"allow_any\"."),
    ]

    for cve_id, description in test_descriptions:
        print(f"Testing {cve_id}:")
        print(f"  Description: {description[:100]}...")

        version_info = checker._extract_version_from_description(description, cve_id)
        if version_info:
            print(f"  ✓ Extracted: {version_info}")
        else:
            print(f"  ✗ No version info extracted")
        print()


if __name__ == "__main__":
    test_wget_cve_example()
    test_version_parsing()
    test_description_parsing()
