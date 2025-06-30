#!/usr/bin/env python3
"""
Test script for Ubuntu OVAL integration
Demonstrates downloading and processing OVAL data into PostgreSQL
"""

import sys
import os
import asyncio
import logging
from datetime import datetime

# Add the web-app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web-app'))

from app.services.unified_ubuntu_security import unified_ubuntu_security
from app.services.ubuntu_oval_source import UbuntuOVALSource
from app.services.ubuntu_security_lookup import UbuntuSecurityLookup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_oval_source():
    """Test the OVAL source directly."""
    print("=" * 60)
    print("Testing Ubuntu OVAL Source")
    print("=" * 60)

    oval_source = UbuntuOVALSource()

    # Test URL generation
    print("\n1. Testing URL generation:")
    for release in ['22.04', '24.04']:
        try:
            url = oval_source.get_oval_url(release)
            print(f"   Ubuntu {release}: {url}")
        except Exception as e:
            print(f"   Ubuntu {release}: ERROR - {e}")

    # Test update check
    print("\n2. Testing update check:")
    for release in ['22.04', '24.04']:
        try:
            should_update = oval_source.should_update_data(release=release)
            print(f"   Ubuntu {release} needs update: {should_update}")
        except Exception as e:
            print(f"   Ubuntu {release}: ERROR - {e}")

    # Test cache stats (before any data)
    print("\n3. Testing cache stats (before download):")
    try:
        stats = oval_source.get_cache_stats()
        print(f"   Cache stats: {stats}")
    except Exception as e:
        print(f"   ERROR getting stats: {e}")


def test_usn_source():
    """Test the USN source."""
    print("\n" + "=" * 60)
    print("Testing Ubuntu USN Source")
    print("=" * 60)

    usn_source = UbuntuSecurityLookup()

    # Test update check
    print("\n1. Testing USN update check:")
    try:
        should_update = usn_source.should_update_data()
        print(f"   USN needs update: {should_update}")
    except Exception as e:
        print(f"   ERROR: {e}")

    # Test cache stats
    print("\n2. Testing USN cache stats:")
    try:
        stats = usn_source.get_cache_stats()
        print(f"   USN stats: {stats}")
    except Exception as e:
        print(f"   ERROR getting USN stats: {e}")


def test_unified_service():
    """Test the unified service."""
    print("\n" + "=" * 60)
    print("Testing Unified Ubuntu Security Service")
    print("=" * 60)

    # Test comprehensive stats
    print("\n1. Testing comprehensive stats:")
    try:
        stats = unified_ubuntu_security.get_comprehensive_stats()
        print(f"   Comprehensive stats: {stats}")
    except Exception as e:
        print(f"   ERROR getting comprehensive stats: {e}")

    # Test vulnerability lookup (example)
    print("\n2. Testing vulnerability lookup:")
    try:
        # Example lookup - this will likely return no data initially
        result = unified_ubuntu_security.lookup_vulnerability(
            'CVE-2023-47100', 'perl', '22.04'
        )
        print(f"   Lookup result: {result}")
    except Exception as e:
        print(f"   ERROR in lookup: {e}")


def test_download_small_sample():
    """Test downloading a small sample of OVAL data."""
    print("\n" + "=" * 60)
    print("Testing OVAL Data Download (Ubuntu 22.04 only)")
    print("=" * 60)

    oval_source = UbuntuOVALSource()

    print("\nAttempting to download Ubuntu 22.04 OVAL data...")
    print("This may take several minutes depending on file size and connection speed.")
    print("Press Ctrl+C to cancel if needed.")

    try:
        success = oval_source.download_and_cache_data(release='22.04')
        if success:
            print("✅ Successfully downloaded and cached Ubuntu 22.04 OVAL data!")

            # Get updated stats
            stats = oval_source.get_cache_stats()
            print(f"\nUpdated cache stats: {stats}")

            # Test a lookup
            print("\nTesting lookup after download:")
            result = oval_source.lookup_vulnerability_info('CVE-2023-47100', 'perl', '22.04')
            print(f"Lookup result: {result}")

        else:
            print("❌ Failed to download OVAL data")

    except KeyboardInterrupt:
        print("\n⚠️  Download cancelled by user")
    except Exception as e:
        print(f"❌ Error during download: {e}")


def main():
    """Main test function."""
    print("Ubuntu OVAL Integration Test")
    print("=" * 60)
    print(f"Test started at: {datetime.now()}")
    print()

    try:
        # Test individual components
        test_oval_source()
        test_usn_source()
        test_unified_service()

        # Ask user if they want to test actual download
        print("\n" + "=" * 60)
        response = input("Do you want to test downloading OVAL data? This will download ~50MB+ (y/N): ")

        if response.lower().startswith('y'):
            test_download_small_sample()
        else:
            print("Skipping download test.")

        print("\n" + "=" * 60)
        print("✅ All tests completed!")
        print(f"Test finished at: {datetime.now()}")

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
