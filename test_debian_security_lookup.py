#!/usr/bin/env python3
"""
Test script to demonstrate Debian Security Lookup functionality.
Tests the CVE-2023-47100 Perl example with web-based enhancement.
"""

import sys
import os
sys.path.append('web-app/app')

from services.enhanced_vulnerability_service import EnhancedVulnerabilityChecker
from services.debian_security_lookup import DebianSecurityLookup
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_debian_security_lookup():
    """Test the Debian Security Lookup functionality."""

    print("=== Testing Debian Security Lookup ===\n")

    # Create Debian Security Lookup instance
    debian_lookup = DebianSecurityLookup()

    # Test 1: Download and cache Debian security data
    print("1. Testing Debian Security Data Download...")
    success = debian_lookup.download_and_cache_debian_data()
    if success:
        print("✓ Successfully downloaded and cached Debian security data")
    else:
        print("✗ Failed to download Debian security data")
        return

    # Test 2: Get cache statistics
    print("\n2. Cache Statistics:")
    stats = debian_lookup.get_cache_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Test 3: Look up specific CVE
    print("\n3. Testing CVE-2023-47100 lookup for Perl...")
    cve_info = debian_lookup.lookup_debian_security_info("CVE-2023-47100", "perl", "bookworm")

    if cve_info:
        print("Debian Security Info:")
        for key, value in cve_info.items():
            print(f"  {key}: {value}")
    else:
        print("No Debian security info found")

    # Test 4: Test with enhanced vulnerability service
    print("\n4. Testing Enhanced Vulnerability Service Integration...")

    # Create a mock vulnerability as it would come from GOST
    gost_vulnerability = {
        "cve_id": "CVE-2023-47100",
        "source": "GOST",
        "affected_package": "perl",
        "installed_version": "5.36.0-7+deb12u2",
        "fixed_version": "5.38.2",  # GOST version
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
    print(f"  Fixed (GOST): {gost_vulnerability['fixed_version']}")
    print(f"  CVSS: {gost_vulnerability['cvss_score']}")

    # Test Debian enhancement
    enhanced_vuln = debian_lookup.enhance_vulnerability_with_debian_data(gost_vulnerability)

    print("\nAfter Debian Security Enhancement:")
    for key, value in enhanced_vuln.items():
        if key not in gost_vulnerability or enhanced_vuln[key] != gost_vulnerability[key]:
            print(f"  {key}: {value} (ENHANCED)")
        else:
            print(f"  {key}: {value}")

    # Test 5: Full enhanced vulnerability checker
    print("\n5. Testing Full Enhanced Vulnerability Checker...")

    checker = EnhancedVulnerabilityChecker(
        oval_db_path="db/oval.sqlite3",
        gost_db_path="db/gost.sqlite3",
        cve_db_path="db/cve.sqlite3"
    )

    # Test the enhancement process
    enhanced_vuln_full = checker._enhance_vulnerability_with_cross_reference(gost_vulnerability)

    print("Full enhancement result:")
    for key, value in enhanced_vuln_full.items():
        if key not in gost_vulnerability or enhanced_vuln_full[key] != gost_vulnerability[key]:
            print(f"  {key}: {value} (ENHANCED)")
        else:
            print(f"  {key}: {value}")

    # Test applicability
    is_applicable = checker._is_vulnerability_actually_applicable(enhanced_vuln_full)
    print(f"\nIs vulnerability applicable? {is_applicable}")

    if enhanced_vuln_full.get('debian_status'):
        debian_status = enhanced_vuln_full['debian_status']
        print(f"Debian status: {debian_status}")

        if debian_status in ['not-affected', 'fixed']:
            print("✓ According to Debian Security Tracker, this vulnerability is addressed")
        else:
            print("✗ According to Debian Security Tracker, this vulnerability is still present")

    # Test 6: Package security status
    print("\n6. Testing Package Security Status for Perl...")
    perl_security = debian_lookup.get_package_security_status("perl", "bookworm")

    print(f"Found {len(perl_security)} security issues for perl in Debian 12:")
    for issue in perl_security[:5]:  # Show first 5
        print(f"  {issue['cve_id']}: {issue['status']} (fixed: {issue['fixed_version']})")

    if len(perl_security) > 5:
        print(f"  ... and {len(perl_security) - 5} more")


def test_specific_cve_scenarios():
    """Test specific CVE scenarios that were problematic."""

    print("\n=== Testing Specific CVE Scenarios ===\n")

    debian_lookup = DebianSecurityLookup()

    # Ensure data is available
    debian_lookup.download_and_cache_debian_data()

    test_cases = [
        {
            "name": "Perl CVE-2023-47100 (suspected duplicate)",
            "cve_id": "CVE-2023-47100",
            "package": "perl",
            "installed": "5.36.0-7+deb12u2",
            "expected": "Should check if Debian has addressed this"
        },
        {
            "name": "OpenSSL CVE-2024-6119 (unknown fixed version)",
            "cve_id": "CVE-2024-6119",
            "package": "openssl",
            "installed": "3.0.16-1~deb12u1",
            "expected": "Should find Debian fixed version"
        },
        {
            "name": "wget CVE-2019-5953 (old CVE)",
            "cve_id": "CVE-2019-5953",
            "package": "wget",
            "installed": "1.21.3-1+deb12u1",
            "expected": "Should be not-affected or fixed"
        }
    ]

    for test_case in test_cases:
        print(f"Testing: {test_case['name']}")
        print(f"  CVE: {test_case['cve_id']}")
        print(f"  Package: {test_case['package']}")
        print(f"  Installed: {test_case['installed']}")
        print(f"  Expected: {test_case['expected']}")

        debian_info = debian_lookup.lookup_debian_security_info(
            test_case['cve_id'],
            test_case['package'],
            'bookworm'
        )

        if debian_info and debian_info.get('found'):
            print(f"  ✓ Found: {debian_info['status']}")
            if debian_info.get('fixed_version'):
                print(f"    Fixed in: {debian_info['fixed_version']}")
            print(f"    Vulnerable: {debian_info['is_vulnerable']}")
        else:
            print(f"  ✗ Not found in Debian Security Tracker")

        print()


if __name__ == "__main__":
    try:
        test_debian_security_lookup()
        test_specific_cve_scenarios()
        print("\n=== Test Complete ===")
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
