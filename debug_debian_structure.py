#!/usr/bin/env python3
"""
Debug script to examine the exact structure of Debian Security Tracker data.
"""

import requests
import json

def debug_structure():
    """Debug the exact structure."""

    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url, timeout=30)
    data = response.json()

    # Look at perl specifically
    if 'perl' in data:
        print("=== PERL PACKAGE STRUCTURE ===")
        perl_data = data['perl']
        print(f"Perl has {len(perl_data)} entries")

        # Look for our specific CVEs
        test_cves = ["CVE-2023-47100", "CVE-2024-6119", "CVE-2019-5953"]

        for cve in test_cves:
            if cve in perl_data:
                print(f"\n{cve} found in perl:")
                cve_data = perl_data[cve]
                print(f"  Type: {type(cve_data)}")
                print(f"  Keys: {list(cve_data.keys()) if isinstance(cve_data, dict) else 'Not a dict'}")

                if isinstance(cve_data, dict) and 'releases' in cve_data:
                    releases = cve_data['releases']
                    print(f"  Releases: {list(releases.keys())}")

                    if 'bookworm' in releases:
                        bookworm = releases['bookworm']
                        print(f"  Bookworm: {bookworm}")

                        if 'perl' in bookworm:
                            perl_info = bookworm['perl']
                            print(f"  Perl info: {perl_info}")
            else:
                print(f"\n{cve} NOT found in perl")

    # Look at openssl
    if 'openssl' in data:
        print("\n=== OPENSSL PACKAGE STRUCTURE ===")
        openssl_data = data['openssl']
        print(f"OpenSSL has {len(openssl_data)} entries")

        if "CVE-2024-6119" in openssl_data:
            print("\nCVE-2024-6119 found in openssl:")
            cve_data = openssl_data["CVE-2024-6119"]
            print(f"  Type: {type(cve_data)}")
            print(f"  Keys: {list(cve_data.keys()) if isinstance(cve_data, dict) else 'Not a dict'}")

            if isinstance(cve_data, dict) and 'releases' in cve_data:
                releases = cve_data['releases']
                print(f"  Releases: {list(releases.keys())}")

                if 'bookworm' in releases:
                    bookworm = releases['bookworm']
                    print(f"  Bookworm: {bookworm}")

                    if 'openssl' in bookworm:
                        openssl_info = bookworm['openssl']
                        print(f"  OpenSSL info: {openssl_info}")
        else:
            print("\nCVE-2024-6119 NOT found in openssl")

    # Look at wget
    if 'wget' in data:
        print("\n=== WGET PACKAGE STRUCTURE ===")
        wget_data = data['wget']
        print(f"wget has {len(wget_data)} entries")

        if "CVE-2019-5953" in wget_data:
            print("\nCVE-2019-5953 found in wget:")
            cve_data = wget_data["CVE-2019-5953"]
            print(f"  Type: {type(cve_data)}")
            print(f"  Keys: {list(cve_data.keys()) if isinstance(cve_data, dict) else 'Not a dict'}")

            if isinstance(cve_data, dict) and 'releases' in cve_data:
                releases = cve_data['releases']
                print(f"  Releases: {list(releases.keys())}")

                if 'bookworm' in releases:
                    bookworm = releases['bookworm']
                    print(f"  Bookworm: {bookworm}")

                    if 'wget' in bookworm:
                        wget_info = bookworm['wget']
                        print(f"  wget info: {wget_info}")
        else:
            print("\nCVE-2019-5953 NOT found in wget")

    # Show a sample of what's actually in the data
    print("\n=== SAMPLE PACKAGE WITH CVE ===")
    for pkg_name, pkg_data in list(data.items())[:3]:
        if isinstance(pkg_data, dict) and len(pkg_data) > 0:
            print(f"\nPackage: {pkg_name}")
            first_cve = list(pkg_data.keys())[0]
            if first_cve.startswith('CVE-'):
                print(f"  First CVE: {first_cve}")
                cve_data = pkg_data[first_cve]
                print(f"  CVE data type: {type(cve_data)}")
                if isinstance(cve_data, dict):
                    print(f"  CVE keys: {list(cve_data.keys())}")
                    if 'releases' in cve_data:
                        releases = cve_data['releases']
                        print(f"  Releases: {list(releases.keys())}")
                        if releases:
                            first_release = list(releases.keys())[0]
                            release_data = releases[first_release]
                            print(f"  {first_release} packages: {list(release_data.keys())}")
                            if pkg_name in release_data:
                                print(f"  {pkg_name} info: {release_data[pkg_name]}")
                break

if __name__ == "__main__":
    debug_structure()
