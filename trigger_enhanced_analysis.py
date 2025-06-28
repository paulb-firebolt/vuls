#!/usr/bin/env python3
"""
Script to trigger enhanced vulnerability analysis with Debian Security Lookup.
This will re-analyze existing scans with the new enhancement capabilities.
"""

import requests
import json
import sys
import time

def trigger_enhanced_analysis():
    """Trigger enhanced vulnerability analysis via the web API."""

    # Web application URL
    base_url = "http://localhost:8000"

    print("=== Triggering Enhanced Vulnerability Analysis ===\n")

    try:
        # First, get the list of scans
        print("1. Getting list of scans...")
        response = requests.get(f"{base_url}/api/scans")

        if response.status_code != 200:
            print(f"Error getting scans: {response.status_code}")
            return False

        scans = response.json()
        print(f"Found {len(scans)} scans")

        if not scans:
            print("No scans found. Please run a scan first.")
            return False

        # Get the most recent scan
        latest_scan = max(scans, key=lambda x: x.get('created_at', ''))
        scan_id = latest_scan['id']
        host_name = latest_scan.get('host', {}).get('name', 'Unknown')

        print(f"2. Using latest scan: ID {scan_id} for host '{host_name}'")

        # Trigger enhanced analysis
        print("3. Triggering enhanced vulnerability analysis...")

        # The enhanced analysis is typically triggered automatically,
        # but we can force it by making a request to the scan endpoint
        analysis_response = requests.post(
            f"{base_url}/api/scans/{scan_id}/enhanced-analysis",
            headers={'Content-Type': 'application/json'}
        )

        if analysis_response.status_code == 200:
            print("✓ Enhanced analysis triggered successfully!")
            print("✓ The system will now:")
            print("  - Download Debian Security Tracker data")
            print("  - Apply web-based enhancement to high-severity CVEs")
            print("  - Update vulnerability assessments")
            print("  - Filter false positives like CVE-2024-3094")

            print("\n4. Monitoring analysis progress...")

            # Monitor progress
            for i in range(30):  # Wait up to 30 seconds
                time.sleep(1)

                # Check scan status
                status_response = requests.get(f"{base_url}/api/scans/{scan_id}")
                if status_response.status_code == 200:
                    scan_data = status_response.json()
                    if scan_data.get('enhanced_analysis_completed'):
                        print("✓ Enhanced analysis completed!")

                        # Get vulnerability count
                        vuln_response = requests.get(f"{base_url}/api/scans/{scan_id}/vulnerabilities")
                        if vuln_response.status_code == 200:
                            vulns = vuln_response.json()
                            print(f"✓ Found {len(vulns)} vulnerabilities after enhancement")

                            # Check if CVE-2024-3094 is still present
                            xz_cve = None
                            for vuln in vulns:
                                if vuln.get('cve_id') == 'CVE-2024-3094':
                                    xz_cve = vuln
                                    break

                            if xz_cve:
                                print(f"⚠️  CVE-2024-3094 still present:")
                                print(f"   Fixed version: {xz_cve.get('fixed_version', 'unknown')}")
                                print(f"   Source: {xz_cve.get('source', 'unknown')}")
                                print("   This may need manual filtering or the enhancement didn't apply")
                            else:
                                print("✓ CVE-2024-3094 successfully filtered out!")

                        return True

                print(f"   Waiting... ({i+1}/30)")

            print("⚠️  Analysis is taking longer than expected")
            print("   Check the web interface for results")
            return True

        else:
            print(f"✗ Failed to trigger enhanced analysis: {analysis_response.status_code}")
            print(f"Response: {analysis_response.text}")
            return False

    except requests.exceptions.ConnectionError:
        print("✗ Could not connect to web application at http://localhost:8000")
        print("   Make sure the web application is running")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def check_debian_lookup_status():
    """Check if Debian Security Lookup is working."""
    print("=== Checking Debian Security Lookup Status ===\n")

    try:
        # Test the Debian lookup directly
        import sys
        sys.path.append('web-app/app')
        from services.debian_security_lookup import DebianSecurityLookup

        lookup = DebianSecurityLookup()

        # Test CVE-2024-3094
        result = lookup.lookup_debian_security_info('CVE-2024-3094', 'xz-utils', 'bookworm')

        if result and result.get('found'):
            print("✓ Debian Security Lookup is working!")
            print(f"  CVE-2024-3094 status: {result['status']}")
            print(f"  Vulnerable: {result['is_vulnerable']}")
            print(f"  Confidence: {result['confidence_score']}")
            return True
        else:
            print("✗ Debian Security Lookup not finding data")
            return False

    except Exception as e:
        print(f"✗ Debian Security Lookup error: {e}")
        return False

if __name__ == "__main__":
    print("Enhanced Vulnerability Analysis Trigger\n")

    # Check Debian lookup first
    if not check_debian_lookup_status():
        print("Debian Security Lookup is not working properly")
        sys.exit(1)

    print()

    # Trigger analysis
    if trigger_enhanced_analysis():
        print("\n=== Success ===")
        print("Enhanced vulnerability analysis has been triggered.")
        print("Check the web interface to see the updated results.")
        print("CVE-2024-3094 should now be properly assessed.")
    else:
        print("\n=== Failed ===")
        print("Could not trigger enhanced analysis.")
        sys.exit(1)
