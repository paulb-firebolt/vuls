#!/usr/bin/env python3
"""
Test script to check how the system handles CVE-2023-47100 for Perl.
"""

import sys
import os
sys.path.append('web-app/app')

from services.enhanced_vulnerability_service import EnhancedVulnerabilityChecker
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_perl_cve_example():
    """Test the Perl CVE-2023-47100 example."""

    print("=== Testing Perl CVE-2023-47100 ===\n")

    # Create a mock vulnerability as it would come from GOST database
    gost_vulnerability = {
        "cve_id": "CVE-2023-47100",
        "source": "GOST",
        "affected_package": "perl",
        "installed_version": "5.36.0-7+deb12u2",
        "fixed_version": "5.38.2",  # GOST has this one
        "priority": "critical",
        "description": "",
        "public_date": "2023-12-02",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "summary": "In Perl before 5.38.2, S_parse_uniprop_string in regcomp.c can write to unallocated space because a property name associated with a \\p{...} regular expression construct is mishandled. The earliest affected version is 5.30.0.",
        "published_date": "2023-12-02"
    }

    print("Original GOST vulnerability:")
    print(f"  CVE: {gost_vulnerability['cve_id']}")
    print(f"  Package: {gost_vulnerability['affected_package']}")
    print(f"  Installed: {gost_vulnerability['installed_version']}")
    print(f"  Fixed: {gost_vulnerability['fixed_version']}")
    print(f"  CVSS: {gost_vulnerability['cvss_score']}")
    print(f"  Summary: {gost_vulnerability['summary']}")
    print()

    # Create checker instance with actual database paths
    checker = EnhancedVulnerabilityChecker(
        oval_db_path="db/oval.sqlite3",
        gost_db_path="db/gost.sqlite3",
        cve_db_path="db/cve.sqlite3"
    )

    # Test version comparison
    print("=== Version Analysis ===")

    # Parse versions
    installed_parts = checker.parse_debian_version("5.36.0-7+deb12u2")
    print(f"Installed version parts: {installed_parts}")
    print(f"Installed upstream: {installed_parts['upstream']}")

    # Manual comparison
    try:
        from packaging import version
        installed_upstream = installed_parts['upstream']
        fixed_version = "5.38.2"

        is_vulnerable = version.parse(installed_upstream) < version.parse(fixed_version)
        print(f"Version comparison: {installed_upstream} < {fixed_version} = {is_vulnerable}")

        if is_vulnerable:
            print("✗ VULNERABLE: Installed version is older than fixed version")
        else:
            print("✓ SAFE: Installed version is newer than or equal to fixed version")

    except Exception as e:
        print(f"Error in version comparison: {e}")

    # Test the enhancement process
    print("\n=== Enhancement Process ===")

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

    if is_applicable:
        print("✗ CONFIRMED VULNERABLE")
        print("This appears to be a legitimate vulnerability")
    else:
        print("✓ Identified as FALSE POSITIVE")

    # Check if this might be a backported fix case
    print(f"\n=== Backport Analysis ===")
    installed_version = "5.36.0-7+deb12u2"

    # Check if this is a Debian security update
    if "+deb12u" in installed_version:
        security_update = installed_version.split("+deb12u")[1]
        print(f"This is a Debian 12 security update: u{security_update}")
        print("Debian may have backported the fix to the 5.36.0 series")
        print("Check: https://security-tracker.debian.org/tracker/CVE-2023-47100")
    else:
        print("No Debian security update indicator found")

    # Test the full filtering process
    print(f"\n=== Final Result ===")

    vulnerabilities = [gost_vulnerability]
    filtered = checker._deduplicate_vulnerabilities(vulnerabilities)

    print(f"Original vulnerabilities: {len(vulnerabilities)}")
    print(f"After filtering: {len(filtered)}")

    if len(filtered) == 0:
        print("✓ Filtered out as false positive")
    else:
        print("✗ Vulnerability remains after filtering")
        for vuln in filtered:
            print(f"  Remaining: {vuln['cve_id']} for {vuln['affected_package']}")
            print(f"    Severity: {vuln.get('severity', 'unknown')}")
            print(f"    Fixed version: {vuln['fixed_version']}")


if __name__ == "__main__":
    test_perl_cve_example()
