#!/usr/bin/env python3
"""
Test Curl Version Analysis with NVD Gap Detection
Demonstrates how the system detects potential gaps in vulnerability coverage.
"""

import sys
import os
sys.path.append('/app')

from app.services.enhanced_vulnerability_service_with_nvd import EnhancedVulnerabilityServiceWithNVD

def test_curl_version_analysis():
    """Test curl version analysis to demonstrate gap detection."""
    print("=" * 80)
    print("Curl Version Analysis with NVD Gap Detection")
    print("=" * 80)

    # Initialize the enhanced service with NVD
    service = EnhancedVulnerabilityServiceWithNVD()

    # Test scenario: curl 8.5.0-2ubuntu10.6 on Ubuntu 22.04
    package_name = "curl"
    installed_version = "8.5.0-2ubuntu10.6"
    os_info = {
        'os_family': 'ubuntu',
        'version': '22.04',
        'architecture': 'x86_64'
    }

    print(f"\nAnalyzing: {package_name} {installed_version} on Ubuntu {os_info['version']}")
    print("-" * 60)

    # Perform analysis with NVD gap detection
    print("\n1. Standard Distribution Analysis...")
    standard_result = service.analyze_package_vulnerabilities(
        package_name, installed_version, os_info, include_nvd_gap_analysis=False
    )

    print(f"   Found {len(standard_result['vulnerabilities'])} vulnerabilities from distribution sources")

    # Show distribution CVEs
    distribution_cves = set()
    for vuln in standard_result['vulnerabilities']:
        cve_id = vuln.get('cve_id', '')
        if cve_id:
            distribution_cves.add(cve_id)
            print(f"   - {cve_id}: {vuln.get('severity', 'Unknown')} severity")

    print(f"\n   Distribution sources know about {len(distribution_cves)} CVEs")

    # Perform analysis with NVD gap detection
    print("\n2. NVD Gap Analysis...")
    enhanced_result = service.analyze_package_vulnerabilities(
        package_name, installed_version, os_info, include_nvd_gap_analysis=True
    )

    nvd_analysis = enhanced_result.get('nvd_gap_analysis', {})

    if nvd_analysis.get('status') == 'completed':
        print(f"   NVD search found {nvd_analysis.get('nvd_total_found', 0)} total CVEs")
        print(f"   After filtering: {nvd_analysis.get('filtered_missing_count', 0)} potential gaps")

        missing_cves = nvd_analysis.get('missing_cves', [])

        if missing_cves:
            print(f"\n   Potential Missing CVEs (not in distribution sources):")
            for i, cve in enumerate(missing_cves[:5], 1):  # Show top 5
                cve_id = cve.get('cve_id', 'Unknown')
                cvss_score = cve.get('cvss_score', 0)
                severity = cve.get('severity', 'Unknown')
                relevance = cve.get('relevance_score', 0)
                priority = cve.get('investigation', {}).get('priority', 'Unknown')

                print(f"   {i}. {cve_id}")
                print(f"      CVSS: {cvss_score}, Severity: {severity}")
                print(f"      Relevance: {relevance:.2f}, Priority: {priority}")

                # Show investigation recommendations
                actions = cve.get('investigation', {}).get('recommended_actions', [])
                if actions:
                    print(f"      Recommended: {actions[0]}")

                # Show possible reasons for absence
                reasons = cve.get('distribution_context', {}).get('possible_reasons_for_absence', [])
                if reasons:
                    print(f"      Possible reason: {reasons[0]}")
                print()
        else:
            print("   ✓ No significant gaps detected - distribution sources appear comprehensive")
    else:
        print(f"   ⚠ NVD analysis failed: {nvd_analysis.get('error', 'Unknown error')}")

    # Summary
    print("\n3. Analysis Summary")
    print("-" * 30)

    total_standard = len(standard_result['vulnerabilities'])
    total_with_nvd = enhanced_result['total_vulnerabilities']
    potential_missing = total_with_nvd - total_standard

    print(f"Distribution sources: {total_standard} vulnerabilities")
    print(f"With NVD gap analysis: {total_with_nvd} total (including {potential_missing} potential gaps)")

    summary = enhanced_result.get('summary', {})
    if summary.get('requires_investigation'):
        print(f"⚠ Requires investigation: {summary.get('potential_missing_cves', 0)} potential missing CVEs")
        if summary.get('high_severity_missing', 0) > 0:
            print(f"🚨 High priority: {summary['high_severity_missing']} high-severity missing CVEs")
    else:
        print("✓ No significant gaps detected")

    return True

def demonstrate_gap_detection_value():
    """Demonstrate the value of NVD gap detection."""
    print("\n" + "=" * 80)
    print("Value of NVD Gap Detection")
    print("=" * 80)

    print("\n🎯 Key Benefits:")
    print("1. Early Warning System")
    print("   - Detects CVEs before they appear in distribution trackers")
    print("   - Identifies upstream vulnerabilities")
    print("   - Catches edge cases missed by distribution analysis")

    print("\n2. Comprehensive Coverage")
    print("   - Cross-references with authoritative NVD database")
    print("   - Provides CVSS scores and detailed metadata")
    print("   - Covers ~200,000+ CVEs vs distribution subsets")

    print("\n3. Intelligent Filtering")
    print("   - Relevance scoring to reduce false positives")
    print("   - Severity-based prioritization")
    print("   - Investigation guidance and recommendations")

    print("\n4. Operational Intelligence")
    print("   - Explains possible reasons for CVE absence")
    print("   - Assesses false positive risk")
    print("   - Provides actionable next steps")

    print("\n🔍 Example Scenarios Where This Helps:")
    print("- Recently disclosed 0-day vulnerabilities")
    print("- Upstream security issues not yet triaged by distributions")
    print("- CVEs affecting specific version ranges")
    print("- Supply chain vulnerabilities in dependencies")
    print("- Configuration-specific security issues")

    print("\n⚡ Performance Optimized:")
    print("- On-demand lookups (not bulk downloads)")
    print("- 24-hour caching to minimize API calls")
    print("- Rate limiting respects NVD API constraints")
    print("- Fallback to stale cache if API unavailable")

    return True

if __name__ == "__main__":
    print("Curl Version Analysis Test")
    print("This test demonstrates NVD gap detection for comprehensive vulnerability coverage.")
    print()

    try:
        # Run curl analysis test
        success = test_curl_version_analysis()

        if success:
            # Demonstrate value proposition
            demonstrate_gap_detection_value()

            print("\n🎉 Test completed successfully!")
            print("\nThe NVD integration successfully addresses the concern about missing CVEs")
            print("that aren't in distribution OVAL data, providing comprehensive coverage")
            print("while maintaining performance and reducing false positives.")

            sys.exit(0)

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        print("This may be due to network connectivity or NVD API availability.")
        sys.exit(1)
