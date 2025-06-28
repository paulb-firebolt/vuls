#!/usr/bin/env python3
"""
Debug script to examine Debian Security Tracker data structure.
"""

import requests
import json

def debug_debian_data():
    """Debug the Debian Security Tracker data structure."""

    print("=== Debugging Debian Security Tracker Data ===\n")

    url = "https://security-tracker.debian.org/tracker/data/json"

    print("1. Downloading sample data...")
    response = requests.get(url, timeout=30)
    response.raise_for_status()

    data = response.json()
    print(f"Downloaded {len(data)} entries")

    # Look at the first few entries
    print("\n2. Sample data structure:")
    count = 0
    for key, value in data.items():
        if count >= 3:
            break
        print(f"\nKey: {key}")
        print(f"Type: {type(value)}")
        if isinstance(value, dict):
            print(f"Keys: {list(value.keys())}")

            # Look at releases structure
            if 'releases' in value:
                releases = value['releases']
                print(f"Releases: {list(releases.keys())}")

                # Look at bookworm data
                if 'bookworm' in releases:
                    bookworm = releases['bookworm']
                    print(f"Bookworm packages: {list(bookworm.keys())[:5]}...")

                    # Look at first package
                    if bookworm:
                        first_pkg = list(bookworm.keys())[0]
                        pkg_info = bookworm[first_pkg]
                        print(f"Sample package '{first_pkg}': {pkg_info}")

        count += 1

    # Look for specific CVEs
    print("\n3. Looking for specific CVEs...")
    test_cves = ["CVE-2023-47100", "CVE-2024-6119", "CVE-2019-5953"]

    for cve in test_cves:
        if cve in data:
            print(f"\nFound {cve}:")
            cve_data = data[cve]
            print(f"  Keys: {list(cve_data.keys())}")

            if 'releases' in cve_data:
                releases = cve_data['releases']
                print(f"  Releases: {list(releases.keys())}")

                if 'bookworm' in releases:
                    bookworm = releases['bookworm']
                    print(f"  Bookworm packages: {list(bookworm.keys())}")

                    # Check for perl, openssl, wget
                    for pkg in ['perl', 'openssl', 'wget']:
                        if pkg in bookworm:
                            print(f"    {pkg}: {bookworm[pkg]}")
        else:
            print(f"\n{cve}: NOT FOUND")

    # Count CVEs vs other entries
    print("\n4. Entry type analysis:")
    cve_count = 0
    other_count = 0

    for key in data.keys():
        if key.startswith('CVE-'):
            cve_count += 1
        else:
            other_count += 1

    print(f"CVE entries: {cve_count}")
    print(f"Other entries: {other_count}")

    # Show some non-CVE entries
    print("\n5. Non-CVE entries (first 10):")
    non_cve_keys = [k for k in data.keys() if not k.startswith('CVE-')][:10]
    for key in non_cve_keys:
        print(f"  {key}")


if __name__ == "__main__":
    debug_debian_data()
