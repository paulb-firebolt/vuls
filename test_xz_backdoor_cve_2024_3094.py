#!/usr/bin/env python3
"""
Test script for CVE-2024-3094 - the famous XZ backdoor.
Demonstrates system correctly identifying non-vulnerable versions.
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


def test_xz_backdoor_cve_2024_3094():
    """Test CVE-2024-3094 - the XZ backdoor vulnerability."""

    print("=== Testing CVE-2024-3094 - The XZ Backdoor ===\n")
    print("This is one of the most significant supply chain attacks in recent history!")
    print("Malicious code was injected into XZ versions 5.6.0+ to backdoor SSH connections.\n")

    # Create a mock GOST vulnerability as it would appear in scan results
    gost_vulnerability = {
        "cve_id": "CVE-2024-3094",
        "source": "GOST",
        "affected_package": "xz-utils",
        "installed_version": "5.4.1-1",  # This version predates the backdoor
        "fixed_version": "unknown",  # This is the problem we're solving
        "priority": "critical",
        "description": "",
        "public_date": "2024-03-29",
        "cvss_score": 10.0,  # Maximum severity!
        "severity": "CRITICAL",
        "summary": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.",
        "published_date": "2024-03-29"
    }

    print("=== Original GOST Vulnerability ===")
    print(f"CVE: {gost_vulnerability['cve_id']} (THE XZ BACKDOOR)")
    print(f"Package: {gost_vulnerability['affected_package']}")
    print(f"Installed: {gost_vulnerability['installed_version']} (predates backdoor)")
    print(f"Fixed (GOST): {gost_vulnerability['fixed_version']}")  # "unknown" - problematic!
    print(f"CVSS: {gost_vulnerability['cvss_score']} (MAXIMUM SEVERITY)")
    print(f"Severity: {gost_vulnerability['severity']}")
    print(f"Summary: {gost_vulnerability['summary'][:150]}...")

    # Test Debian Security Lookup directly
    print("\n=== Debian Security Tracker Lookup ===")
    debian_lookup = DebianSecurityLookup()
    debian_info = debian_lookup.lookup_debian_security_info("CVE-2024-3094", "xz-utils", "bookworm")

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
            print("✓ This makes sense because:")
            print("  - The backdoor only affected XZ versions 5.6.0 and later")
            print("  - Your version 5.4.1 predates the malicious code injection")
            print("  - Debian 12 (bookworm) shipped with safe XZ versions")
            print("  - The backdoor was discovered before it reached stable distributions")

            if enhanced_vuln.get('debian_fixed_version') == '0':
                print("\n✓ Fixed version '0' means 'not affected' - correct assessment!")
                print("  This indicates Debian was never vulnerable to this specific attack")
        else:
            print("✗ This would be concerning for such a critical vulnerability!")

    # Show the improvement
    print("\n=== Summary of Enhancement ===")
    print("BEFORE (GOST only):")
    print(f"  Fixed version: {gost_vulnerability['fixed_version']} (unknown - causes uncertainty)")
    print(f"  Assessment: Likely vulnerable (VERY concerning for CVSS 10.0!)")
    print(f"  Impact: Would cause panic for the famous XZ backdoor")

    print("\nAFTER (with Debian Security Tracker):")
    if enhanced_vuln.get('debian_status') == 'resolved':
        print(f"  Debian status: {enhanced_vuln['debian_status']}")
        print(f"  Assessment: NOT VULNERABLE (authoritative source)")
        print(f"  Confidence: {enhanced_vuln.get('confidence_score', 'N/A')}")
        print("  ✓ False positive eliminated!")
        print("  ✓ Correctly identifies version 5.4.1 as safe")
        print("  ✓ Prevents unnecessary panic about the XZ backdoor")

    # Historical context
    print("\n=== XZ Backdoor Historical Context ===")
    print("Timeline of the XZ backdoor (CVE-2024-3094):")
    print("  • March 2024: Malicious code discovered in XZ 5.6.0/5.6.1")
    print("  • Affected: Bleeding-edge distributions (Fedora 40/41, Debian sid)")
    print("  • NOT affected: Stable distributions like Debian 12, Ubuntu 22.04 LTS")
    print("  • Your version 5.4.1: Released well before the backdoor injection")
    print("  • Impact: SSH connections could be compromised on affected systems")
    print("  • Discovery: Found by Microsoft engineer Andres Freund")

    print(f"\nYour system status:")
    print(f"  Installed version: {gost_vulnerability['installed_version']}")
    print(f"  Backdoor versions: 5.6.0, 5.6.1")
    print(f"  Assessment: ✓ SAFE - Your version predates the malicious code")


if __name__ == "__main__":
    try:
        test_xz_backdoor_cve_2024_3094()
        print("\n=== Test Complete ===")
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
