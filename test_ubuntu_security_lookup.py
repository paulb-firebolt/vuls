#!/usr/bin/env python3
"""
Test Ubuntu Security Notices (USN) integration
"""

import sys
import os
sys.path.append('web-app')

from web_app.app.services.ubuntu_security_lookup import UbuntuSecurityLookup

def test_ubuntu_security_lookup():
    """Test Ubuntu Security Lookup functionality"""

    print("🧪 Testing Ubuntu Security Notices (USN) Integration")
    print("=" * 60)

    # Initialize Ubuntu Security Lookup
    lookup = UbuntuSecurityLookup()

    # Test 1: Download and cache Ubuntu data
    print("\n1. Testing Ubuntu data download and caching...")
    try:
        success = lookup.download_and_cache_ubuntu_data()
        if success:
            print("✅ Ubuntu Security Notices data downloaded and cached successfully")
        else:
            print("❌ Failed to download Ubuntu data")
            return
    except Exception as e:
        print(f"❌ Error downloading Ubuntu data: {e}")
        return

    # Test 2: Get cache statistics
    print("\n2. Getting Ubuntu cache statistics...")
    try:
        stats = lookup.get_cache_stats()
        print(f"✅ Ubuntu cache statistics:")
        print(f"   - Total USNs: {stats.get('total_usns', 0)}")
        print(f"   - Total CVEs: {stats.get('total_cves', 0)}")
        print(f"   - Total records: {stats.get('total_records', 0)}")
        print(f"   - Unique packages: {stats.get('unique_packages', 0)}")
        print(f"   - Last download: {stats.get('last_download', 'Never')}")
    except Exception as e:
        print(f"❌ Error getting cache stats: {e}")

    # Test 3: Test CVE-2024-3094 lookup (XZ backdoor)
    print("\n3. Testing CVE-2024-3094 lookup (XZ backdoor)...")
    try:
        result = lookup.lookup_ubuntu_security_info('CVE-2024-3094', 'xz-utils', 'jammy')
        if result and result.get('found'):
            print(f"✅ Found Ubuntu data for CVE-2024-3094:")
            print(f"   - Status: {result.get('status')}")
            print(f"   - Fixed version: {result.get('fixed_version')}")
            print(f"   - Priority: {result.get('priority')}")
            print(f"   - USN ID: {result.get('usn_id')}")
            print(f"   - Is vulnerable: {result.get('is_vulnerable')}")
            print(f"   - Confidence: {result.get('confidence_score')}")
        else:
            print(f"ℹ️  No Ubuntu data found for CVE-2024-3094 in xz-utils")
            print(f"   Reason: {result.get('reason', 'Unknown') if result else 'No result'}")
    except Exception as e:
        print(f"❌ Error looking up CVE-2024-3094: {e}")

    # Test 4: Test vulnerability enhancement
    print("\n4. Testing vulnerability enhancement...")
    try:
        test_vulnerability = {
            'cve_id': 'CVE-2024-3094',
            'affected_package': 'xz-utils',
            'installed_version': '5.4.1-1ubuntu1',
            'fixed_version': 'unknown',
            'source': 'GOST',
            'severity': 'CRITICAL',
            'cvss_score': 10.0
        }

        enhanced = lookup.enhance_vulnerability_with_ubuntu_data(test_vulnerability)

        if enhanced.get('enhanced_by_ubuntu'):
            print("✅ Vulnerability enhanced with Ubuntu data:")
            print(f"   - Ubuntu status: {enhanced.get('ubuntu_status')}")
            print(f"   - Ubuntu fixed version: {enhanced.get('ubuntu_fixed_version')}")
            print(f"   - Ubuntu priority: {enhanced.get('ubuntu_priority')}")
            print(f"   - Ubuntu USN ID: {enhanced.get('ubuntu_usn_id')}")
            print(f"   - Ubuntu release: {enhanced.get('ubuntu_release')}")
            print(f"   - Is vulnerable (Ubuntu): {enhanced.get('is_vulnerable_ubuntu')}")
        else:
            print("ℹ️  Vulnerability not enhanced with Ubuntu data")

    except Exception as e:
        print(f"❌ Error testing vulnerability enhancement: {e}")

    # Test 5: Test release detection
    print("\n5. Testing Ubuntu release detection...")
    test_versions = [
        '5.4.1-1ubuntu1',
        '7.88.1-10ubuntu1.22.04.1',
        '1.2.3-4ubuntu20.04.1',
        '2.0.0-1ubuntu24.04.1',
        '3.1.4-2'
    ]

    for version in test_versions:
        detected = lookup._detect_ubuntu_release(version)
        print(f"   - {version} → {detected}")

    print("\n🎉 Ubuntu Security Lookup test completed!")

if __name__ == "__main__":
    test_ubuntu_security_lookup()
