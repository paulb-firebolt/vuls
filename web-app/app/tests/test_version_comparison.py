#!/usr/bin/env python3
"""
Test script to demonstrate the curl version analysis issue.
"""

from app.services.enhanced_vulnerability_service_pg import EnhancedVulnerabilityCheckerPG

def test_curl_version_comparison():
    """Test curl version comparison for CVE-2023-38546."""

    print("Testing curl version analysis for CVE-2023-38546")
    print("=" * 60)

    # Your actual curl version
    installed_version = "8.5.0-2ubuntu10.6"
    print(f"Installed version: {installed_version}")

    # CVE-2023-38546 was fixed in curl 8.4.0
    # Ubuntu 22.04 (jammy) fixed it in 8.5.0-2ubuntu10.1
    # So 8.5.0-2ubuntu10.6 should NOT be vulnerable

    checker = EnhancedVulnerabilityCheckerPG()

    # Test Ubuntu release detection
    release = checker._detect_ubuntu_release(installed_version)
    print(f"Detected Ubuntu release: {release}")

    # Test version comparison
    fixed_version = "8.5.0-2ubuntu10.1"  # This is when it was actually fixed
    print(f"Fixed version: {fixed_version}")

    # Test the current comparison logic
    is_vulnerable = checker._is_version_vulnerable(installed_version, fixed_version, False)
    print(f"Current logic says vulnerable: {is_vulnerable}")
    print(f"Expected: False (since 8.5.0-2ubuntu10.6 > 8.5.0-2ubuntu10.1)")

    # Test Ubuntu version comparison specifically
    comparison = checker.compare_debian_versions(installed_version, fixed_version)
    print(f"Version comparison result: {comparison}")
    print(f"  -1 = installed < fixed (vulnerable)")
    print(f"   0 = installed = fixed (not vulnerable)")
    print(f"   1 = installed > fixed (not vulnerable)")

    # Parse the versions to see what's happening
    inst_parts = checker.parse_debian_version(installed_version)
    fixed_parts = checker.parse_debian_version(fixed_version)

    print(f"\nInstalled version parts: {inst_parts}")
    print(f"Fixed version parts: {fixed_parts}")

    # Test the security update extraction
    inst_security = checker._extract_security_update_number(inst_parts["build"])
    fixed_security = checker._extract_security_update_number(fixed_parts["build"])

    print(f"\nInstalled security update (build): {inst_security}")
    print(f"Fixed security update (build): {fixed_security}")

    # Test Ubuntu security number extraction from debian revision
    inst_ubuntu_security = checker._extract_ubuntu_security_number(inst_parts["debian"])
    fixed_ubuntu_security = checker._extract_ubuntu_security_number(fixed_parts["debian"])

    print(f"Installed Ubuntu security (debian): {inst_ubuntu_security}")
    print(f"Fixed Ubuntu security (debian): {fixed_ubuntu_security}")

    # The test should pass - 8.5.0-2ubuntu10.6 should NOT be vulnerable
    # because 10.6 > 10.1
    assert not is_vulnerable, f"Version {installed_version} should NOT be vulnerable to CVE-2023-38546 (fixed in {fixed_version})"

if __name__ == "__main__":
    test_curl_version_comparison()
