#!/usr/bin/env python3
"""Test NVD enrichment functionality."""

import sys
import os
sys.path.append('web-app')

from app.services.enhanced_vulnerability_service_pg import EnhancedVulnerabilityCheckerPG

def test_nvd_enrichment():
    """Test NVD enrichment with a sample package."""

    # Create test packages with curl (known to have CVEs)
    test_packages = {
        "curl": "8.5.0-2ubuntu10.6",
        "openssl": "3.0.13-1ubuntu1.2"
    }

    print("Testing NVD enrichment with sample packages...")
    print(f"Test packages: {test_packages}")

    # Initialize the enhanced vulnerability checker
    checker = EnhancedVulnerabilityCheckerPG()

    # Check vulnerabilities
    print("\nChecking vulnerabilities...")
    vulnerabilities = checker.check_enhanced_vulnerabilities(test_packages, "ubuntu")

    print(f"\nFound {len(vulnerabilities)} vulnerabilities")

    # Show results
    nvd_enriched_count = 0
    for vuln in vulnerabilities:
        print(f"\n--- {vuln.get('cve_id')} ---")
        print(f"Package: {vuln.get('affected_package')}")
        print(f"Source: {vuln.get('source')}")
        print(f"Severity: {vuln.get('severity')}")
        print(f"CVSS Score: {vuln.get('cvss_score')}")
        print(f"CVSS Vector: {vuln.get('cvss_vector', 'N/A')}")
        print(f"Enhanced by NVD: {vuln.get('enhanced_by_nvd', False)}")

        if vuln.get('enhanced_by_nvd'):
            nvd_enriched_count += 1
            print(f"CVSS Version: {vuln.get('cvss_version')}")
            print(f"NVD Published: {vuln.get('nvd_published_date', 'N/A')}")

    print(f"\n=== Summary ===")
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"NVD enriched: {nvd_enriched_count}")
    print(f"Enrichment rate: {nvd_enriched_count/len(vulnerabilities)*100:.1f}%" if vulnerabilities else "0%")

    # Test specific CVE lookup
    print(f"\n=== Testing specific CVE lookup ===")
    if vulnerabilities:
        test_cve = vulnerabilities[0].get('cve_id')
        print(f"Testing lookup for {test_cve}")

        # Test the NVD cache directly
        from app.models.base import get_db
        from app.models.nvd_cve_cache import NVDCVECache

        db = next(get_db())
        cached_cve = db.query(NVDCVECache).filter(NVDCVECache.cve_id == test_cve).first()

        if cached_cve:
            print(f"Found in cache: {cached_cve.cve_id}")
            print(f"CVSS Score: {cached_cve.get_best_cvss_score()}")
            print(f"Severity: {cached_cve.get_best_severity()}")
            print(f"Access count: {cached_cve.access_count}")
            print(f"Cached at: {cached_cve.cached_at}")
        else:
            print(f"Not found in cache")

        db.close()

if __name__ == "__main__":
    test_nvd_enrichment()
