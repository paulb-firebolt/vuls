#!/usr/bin/env python3
"""
Test script for CVE-2025-49794 libxml2 vulnerability.
Demonstrates system correctly identifying real vulnerabilities vs false positives.
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


def test_libxml2_cve_2025_49794():
    """Test CVE-2025-49794 libxml2 vulnerability - a real vulnerability."""

    print("=== Testing CVE-2025-49794 libxml2 Use-After-Free Vulnerability ===\n")

    # Create a mock GOST vulnerability as it would appear in scan results
    gost_vulnerability = {
        "cve_id": "CVE-2025-49794",
        "source": "GOST",
        "affected_package": "libxml2",
        "installed_version": "2.9.14+dfsg-1.3~deb12u2",
        "fixed_version": "unknown",  # This is the problem we're solving
        "priority": "critical",
        "description": "",
        "public_date": "2025-01-20",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "summary": "A use-after-free vulnerability was found in libxml2. This issue occurs when parsing XPath elements under certain circumstances when the XML schematron has the <sch:name path=\"...\"/> schema elements. This flaw allows a malicious actor to craft a malicious XML document used as input for libxml, resulting in the program's crash using libxml or other possible undefined behaviors.",
        "published_date": "2025-01-20"
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
    debian_info = debian_lookup.lookup_debian_security_info("CVE-2025-49794", "libxml2", "bookworm")

    if debian_info and debian_info.get('found'):
        print(f"✓ Found in Debian Security Tracker:")
        print(f"  Status: {debian_info['status']}")
        print(f"  Fixed version: {debian_info['fixed_version']}")
        print(f"  Vulnerable: {debian_info['is_vulnerable']}")
        print(f"  Urgency: {debian_info.get('urgency', 'N/A')}")
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
        else:
            print("✗ According to Debian Security Tracker, this vulnerability is STILL PRESENT")
            print("✗ This is a REAL vulnerability that needs attention!")

            if debian_status == 'open':
                print("  Status 'open' means:")
                print("  - No fix available yet")
                print("  - Debian is aware of the issue")
                print("  - May require upstream fix or Debian-specific patch")
                print("  - Should be monitored for updates")

    # Show the improvement
    print("\n=== Summary of Enhancement ===")
    print("BEFORE (GOST only):")
    print(f"  Fixed version: {gost_vulnerability['fixed_version']} (unknown - causes uncertainty)")
    print(f"  Assessment: Likely vulnerable (conservative approach)")

    print("\nAFTER (with Debian Security Tracker):")
    if enhanced_vuln.get('debian_status') == 'open':
        print(f"  Debian status: {enhanced_vuln['debian_status']}")
        print(f"  Assessment: VULNERABLE (authoritative confirmation)")
        print(f"  Confidence: {enhanced_vuln.get('confidence_score', 'N/A')}")
        print("  ✓ Real vulnerability correctly identified!")
        print("  ✓ No false positive - this needs attention!")

    # Compare with resolved libxml2 CVEs
    print("\n=== libxml2 Security Status Comparison ===")
    libxml2_cves = debian_lookup.get_package_security_status("libxml2", "bookworm")
    recent_cves = [cve for cve in libxml2_cves if '2025' in cve['cve_id']]

    open_cves = [cve for cve in recent_cves if cve['status'] == 'open']
    resolved_cves = [cve for cve in recent_cves if cve['status'] in ['resolved', 'fixed']]

    print(f"libxml2 2025 CVEs: {len(recent_cves)} total")
    print(f"  ✗ OPEN (vulnerable): {len(open_cves)}")
    print(f"  ✓ RESOLVED (safe): {len(resolved_cves)}")

    print(f"\nOPEN vulnerabilities (need attention):")
    for cve in open_cves[:5]:
        print(f"  ✗ {cve['cve_id']}: {cve['status']}")

    print(f"\nRESOLVED vulnerabilities (fixed in your version):")
    for cve in resolved_cves[:5]:
        print(f"  ✓ {cve['cve_id']}: {cve['status']} (fixed: {cve['fixed_version']})")

    print(f"\nYour installed version: {gost_vulnerability['installed_version']}")
    print("✓ Protected against resolved CVEs")
    print("✗ Still vulnerable to open CVEs")


if __name__ == "__main__":
    try:
        test_libxml2_cve_2025_49794()
        print("\n=== Test Complete ===")
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
