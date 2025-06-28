#!/usr/bin/env python3
"""
Test script for CVE-2025-4517 Python tarfile vulnerability.
Demonstrates web-based enhancement resolving "unknown" fixed version.
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


def test_python_cve_2025_4517():
    """Test CVE-2025-4517 Python tarfile vulnerability enhancement."""

    print("=== Testing CVE-2025-4517 Python Tarfile Vulnerability ===\n")

    # Create a mock GOST vulnerability as it would appear in scan results
    gost_vulnerability = {
        "cve_id": "CVE-2025-4517",
        "source": "GOST",
        "affected_package": "python3.11",
        "installed_version": "3.11.2-6+deb12u6",
        "fixed_version": "unknown",  # This is the problem we're solving
        "priority": "critical",
        "description": "",
        "public_date": "2025-01-15",
        "cvss_score": 9.4,
        "severity": "CRITICAL",
        "summary": "Allows arbitrary filesystem writes outside the extraction directory during extraction with filter=\"data\". You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of \"data\" or \"tar\".",
        "published_date": "2025-01-15"
    }

    print("=== Original GOST Vulnerability ===")
    print(f"CVE: {gost_vulnerability['cve_id']}")
    print(f"Package: {gost_vulnerability['affected_package']}")
    print(f"Installed: {gost_vulnerability['installed_version']}")
    print(f"Fixed (GOST): {gost_vulnerability['fixed_version']}")  # "unknown" - problematic!
    print(f"CVSS: {gost_vulnerability['cvss_score']}")
    print(f"Severity: {gost_vulnerability['severity']}")
    print(f"Summary: {gost_vulnerability['summary'][:100]}...")

    # Test Debian Security Lookup directly
    print("\n=== Debian Security Tracker Lookup ===")
    debian_lookup = DebianSecurityLookup()
    debian_info = debian_lookup.lookup_debian_security_info("CVE-2025-4517", "python3.11", "bookworm")

    if debian_info and debian_info.get('found'):
        print(f"✓ Found in Debian Security Tracker:")
        print(f"  Status: {debian_info['status']}")
        print(f"  Fixed version: {debian_info['fixed_version']}")
        print(f"  Vulnerable: {debian_info['is_vulnerable']}")
        print(f"  Confidence: {debian_info['confidence_score']}")
    else:
        print("✗ Not found in Debian Security Tracker")
        return

    # Test enhanced vulnerability service
    print("\n=== Enhanced Vulnerability Analysis ===")
    checker = EnhancedVulnerabilityChecker(
        oval_db_path="db/oval.sqlite3",
        gost_db_path="db/gost.sqlite3",
        cve_db_path="db/cve.sqlite3"
    )

    # Test the enhancement process
    enhanced_vuln = checker._enhance_vulnerability_with_cross_reference(gost_vulnerability)

    print("Enhanced vulnerability result:")
    for key, value in enhanced_vuln.items():
        if key not in gost_vulnerability or enhanced_vuln[key] != gost_vulnerability[key]:
            print(f"  {key}: {value} (ENHANCED)")
        else:
            print(f"  {key}: {value}")

    # Test applicability
    print("\n=== Vulnerability Applicability Assessment ===")
    is_applicable = checker._is_vulnerability_actually_applicable(enhanced_vuln)
    print(f"Is vulnerability applicable? {is_applicable}")

    # Analyze the enhancement
    if enhanced_vuln.get('debian_status'):
        debian_status = enhanced_vuln['debian_status']
        print(f"\nDebian Security Tracker says: {debian_status}")

        if debian_status in ['not-affected', 'fixed', 'resolved']:
            print("✓ According to Debian Security Tracker, this vulnerability is addressed")
            print("✓ The 'unknown' fixed version from GOST has been resolved!")

            if enhanced_vuln.get('debian_fixed_version') == '0':
                print("✓ Fixed version '0' means 'not affected' or 'resolved without version change'")
                print("  This often indicates:")
                print("  - Configuration issue (not code)")
                print("  - Documentation clarification")
                print("  - Issue doesn't apply to Debian's implementation")
                print("  - Already mitigated in Debian's packaging")
        else:
            print("✗ According to Debian Security Tracker, this vulnerability is still present")

    # Show the improvement
    print("\n=== Summary of Enhancement ===")
    print("BEFORE (GOST only):")
    print(f"  Fixed version: {gost_vulnerability['fixed_version']} (unknown - causes uncertainty)")
    print(f"  Assessment: Likely vulnerable (conservative approach)")

    print("\nAFTER (with Debian Security Tracker):")
    if enhanced_vuln.get('debian_status') == 'resolved':
        print(f"  Debian status: {enhanced_vuln['debian_status']}")
        print(f"  Assessment: NOT VULNERABLE (authoritative source)")
        print(f"  Confidence: {enhanced_vuln.get('confidence_score', 'N/A')}")
        print("  ✓ False positive eliminated!")

    # Test with other recent Python CVEs
    print("\n=== Other Recent Python CVEs ===")
    python_cves = debian_lookup.get_package_security_status("python3.11", "bookworm")
    recent_cves = [cve for cve in python_cves if '2025' in cve['cve_id']]

    print(f"Found {len(recent_cves)} Python CVEs from 2025:")
    for cve in recent_cves[:5]:
        status_emoji = "✓" if cve['status'] in ['resolved', 'fixed', 'not-affected'] else "✗"
        print(f"  {status_emoji} {cve['cve_id']}: {cve['status']} (fixed: {cve['fixed_version']})")


if __name__ == "__main__":
    try:
        test_python_cve_2025_4517()
        print("\n=== Test Complete ===")
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
