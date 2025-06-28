#!/usr/bin/env python3
"""Test script to verify the enhanced vulnerability analysis integration"""

import sys
import os
sys.path.append('web-app')

from app.services.enhanced_vulnerability_service import EnhancedVulnerabilityChecker

def test_integration():
    """Test the enhanced vulnerability analysis with real Vuls data"""

    # Use the same file that worked with the standalone script
    vuls_result_file = "results/d7245692/2025-06-28T13-08-17+0000/anisette_v3.json"

    if not os.path.exists(vuls_result_file):
        print(f"❌ Test file not found: {vuls_result_file}")
        return False

    print(f"✅ Found test file: {vuls_result_file}")

    # Initialize the enhanced checker
    checker = EnhancedVulnerabilityChecker(
        oval_db_path="db/oval.sqlite3",
        gost_db_path="db/gost.sqlite3",
        cve_db_path="db/cve.sqlite3"
    )

    # Test package extraction
    print("\n📦 Extracting packages...")
    packages = checker.get_installed_packages(vuls_result_file)
    print(f"Found {len(packages)} total installed packages")

    if len(packages) == 0:
        print("❌ No packages found - integration failed")
        return False

    # Test vulnerability analysis
    print("\n🔍 Running enhanced vulnerability analysis...")
    vulnerabilities = checker.check_enhanced_vulnerabilities(packages)
    print(f"Found {len(vulnerabilities)} vulnerabilities")

    # Generate report
    print("\n📊 Generating report...")
    report = checker.generate_enhanced_report(vulnerabilities)

    print(f"\n🔍 ENHANCED VULNERABILITY SCAN RESULTS:")
    print(f"   Total vulnerabilities: {report['total_vulnerabilities']}")
    print(f"   Packages affected: {report['packages_affected']}")
    print(f"   Severity breakdown: {report['vulnerability_breakdown']}")
    print(f"   Source breakdown: {report['source_breakdown']}")

    # Check if we got similar results to the standalone script
    expected_vulns = 409  # From your standalone test
    if report['total_vulnerabilities'] >= expected_vulns * 0.9:  # Allow 10% variance
        print("✅ Integration test PASSED - found expected number of vulnerabilities")
        return True
    else:
        print(f"❌ Integration test FAILED - expected ~{expected_vulns} vulnerabilities, got {report['total_vulnerabilities']}")
        return False

if __name__ == "__main__":
    success = test_integration()
    sys.exit(0 if success else 1)
