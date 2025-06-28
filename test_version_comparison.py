#!/usr/bin/env python3
"""
Test script to verify version comparison logic for vulnerability analysis.
This will help identify potential false positives in curl vulnerability detection.
"""

import re
from packaging import version
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def clean_debian_version(version_str: str) -> str:
    """
    Clean Debian version string for comparison.
    Examples:
    - "7.88.1-10+deb12u12" -> "7.88.1"
    - "7.61.0-1" -> "7.61.0"
    - "5.2.15-2+b8" -> "5.2.15"
    - "5.1~rc1-2" -> "5.1.0rc1"
    - "3.11.2-6+deb12u6" -> "3.11.2"
    - "3.11.0~b4-1" -> "3.11.0b4"
    """
    if not version_str:
        return "0"

    # Handle special Debian version characters
    # Replace ~ with . for pre-release versions (5.1~rc1 -> 5.1.rc1)
    cleaned = version_str.replace("~", ".")

    # Remove everything after the first dash (Debian revision)
    base_version = cleaned.split("-")[0]

    # Handle special cases for pre-release versions
    # Convert rc, alpha, beta to formats that packaging can understand
    base_version = re.sub(r"\.rc(\d+)", r"rc\1", base_version)  # .rc1 -> rc1
    base_version = re.sub(r"\.b(\d+)", r"b\1", base_version)    # .b4 -> b4
    base_version = re.sub(r"\.a(\d+)", r"a\1", base_version)    # .a1 -> a1

    # Remove any remaining non-version characters except rc, a, b for pre-releases
    cleaned = re.sub(r"[^0-9.rcab]", "", base_version)

    # Ensure we have a valid version string
    if not cleaned or cleaned == ".":
        return "0"

    return cleaned


def is_version_vulnerable(installed_version: str, fixed_version: str) -> bool:
    """
    Check if the installed version is vulnerable compared to the fixed version.
    Returns True if installed version is older (vulnerable), False if newer/equal (safe).
    """
    try:
        # Clean up version strings for comparison
        installed_clean = clean_debian_version(installed_version)
        fixed_clean = clean_debian_version(fixed_version)

        # Use packaging library for version comparison
        installed_ver = version.parse(installed_clean)
        fixed_ver = version.parse(fixed_clean)

        # If installed version is less than fixed version, it's vulnerable
        is_vulnerable = installed_ver < fixed_ver

        return is_vulnerable

    except Exception as e:
        logger.warning(f"Error comparing versions {installed_version} vs {fixed_version}: {e}")
        # If we can't compare versions, err on the side of caution and include it
        return True


def test_curl_versions():
    """Test curl version comparisons with common scenarios."""

    print("=== Testing Curl Version Comparisons ===\n")

    # Common curl versions and their vulnerability scenarios
    test_cases = [
        # Format: (installed_version, fixed_version, expected_vulnerable, description)
        ("7.88.1-10+deb12u12", "7.88.1-10+deb12u5", False, "Installed version is newer patch"),
        ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", True, "Installed version is older patch"),
        ("7.88.1-10+deb12u12", "7.89.0", True, "Major version difference"),
        ("7.89.0-1", "7.88.1-10+deb12u12", False, "Newer major version installed"),
        ("7.61.0-1", "7.88.1", True, "Much older version installed"),
        ("8.0.0-1", "7.88.1", False, "Newer major version installed"),
        ("7.88.1", "7.88.1", False, "Same version"),
        ("7.88.0", "7.88.1", True, "Minor version behind"),
        ("7.88.1-10+deb12u12", "7.88.1", False, "Debian packaging vs upstream"),
        ("7.74.0-1.3+deb11u11", "7.74.0-1.3+deb11u7", False, "Newer Debian patch"),
        ("7.74.0-1.3+deb11u7", "7.74.0-1.3+deb11u11", True, "Older Debian patch"),
    ]

    print("Testing version comparison logic:\n")

    for installed, fixed, expected, description in test_cases:
        try:
            result = is_version_vulnerable(installed, fixed)
            status = "✓" if result == expected else "✗"

            installed_clean = clean_debian_version(installed)
            fixed_clean = clean_debian_version(fixed)

            print(f"{status} {description}")
            print(f"   Installed: {installed} -> {installed_clean}")
            print(f"   Fixed:     {fixed} -> {fixed_clean}")
            print(f"   Expected:  {'Vulnerable' if expected else 'Safe'}")
            print(f"   Got:       {'Vulnerable' if result else 'Safe'}")

            if result != expected:
                print(f"   ⚠️  MISMATCH! This could be a false positive/negative")
            print()

        except Exception as e:
            print(f"✗ Error testing {description}: {e}")
            print(f"   Installed: {installed}")
            print(f"   Fixed:     {fixed}")
            print()


def test_version_cleaning():
    """Test the version cleaning function with various Debian version formats."""

    print("=== Testing Version Cleaning Function ===\n")

    test_versions = [
        ("7.88.1-10+deb12u12", "7.88.1"),
        ("7.61.0-1", "7.61.0"),
        ("5.2.15-2+b8", "5.2.15"),
        ("5.1~rc1-2", "5.1.rc1"),
        ("3.11.2-6+deb12u6", "3.11.2"),
        ("3.11.0~b4-1", "3.11.0b4"),
        ("1.2.3+dfsg-1", "1.2.3"),
        ("2.0.0~git20210101-1", "2.0.0.git20210101"),
        ("1.0", "1.0"),
        ("", "0"),
        ("invalid-version", "0"),
    ]

    print("Testing version cleaning:")

    for original, expected in test_versions:
        cleaned = clean_debian_version(original)
        status = "✓" if cleaned == expected else "✗"

        print(f"{status} '{original}' -> '{cleaned}' (expected: '{expected}')")

        if cleaned != expected:
            print(f"   ⚠️  Unexpected result!")


def analyze_potential_issues():
    """Analyze potential issues with the current version comparison logic."""

    print("=== Analysis of Potential Issues ===\n")

    issues = [
        {
            "issue": "Debian Package Revisions",
            "description": "Debian package revisions (e.g., +deb12u12) are stripped, which could miss security patches",
            "example": "7.88.1-10+deb12u12 vs 7.88.1-10+deb12u5",
            "risk": "False negatives - missing that newer Debian patches fix vulnerabilities"
        },
        {
            "issue": "Pre-release Version Handling",
            "description": "Pre-release versions (~rc, ~beta) might not be handled consistently",
            "example": "7.88.0~rc1 vs 7.88.0",
            "risk": "False positives/negatives with pre-release versions"
        },
        {
            "issue": "Epoch Versions",
            "description": "Debian epoch versions (1:version) are not handled",
            "example": "1:7.88.1 vs 7.89.0",
            "risk": "Incorrect version comparisons with epoch versions"
        },
        {
            "issue": "Version Parsing Errors",
            "description": "When version parsing fails, it defaults to vulnerable (True)",
            "example": "Malformed version strings",
            "risk": "False positives when version strings can't be parsed"
        },
        {
            "issue": "CVE Database Matching",
            "description": "CVE fixed versions might not match actual Debian package versions",
            "example": "CVE lists upstream version, but Debian backports fixes",
            "risk": "False positives when Debian backports security fixes"
        }
    ]

    for i, issue in enumerate(issues, 1):
        print(f"{i}. {issue['issue']}")
        print(f"   Description: {issue['description']}")
        print(f"   Example: {issue['example']}")
        print(f"   Risk: {issue['risk']}")
        print()


def main():
    """Run all tests and analysis."""
    test_version_cleaning()
    print("\n" + "="*60 + "\n")
    test_curl_versions()
    print("\n" + "="*60 + "\n")
    analyze_potential_issues()

    print("=== Recommendations ===\n")
    print("1. Implement more sophisticated Debian version comparison")
    print("2. Handle epoch versions (1:version format)")
    print("3. Consider Debian security tracker data for backported fixes")
    print("4. Add logging for version comparison decisions")
    print("5. Implement whitelist for known false positives")
    print("6. Cross-reference with Debian security advisories")


if __name__ == "__main__":
    main()
