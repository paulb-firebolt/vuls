#!/usr/bin/env python3

import json
import re
import logging
from typing import Dict, List, Set
from datetime import datetime
from packaging import version

logger = logging.getLogger(__name__)


class VulsReportProcessor:
    """Process Vuls JSON output to extract comprehensive vulnerability data from all sources."""

    def __init__(self):
        self.critical_packages = {
            "openssl", "openssh-server", "openssh-client", "sudo", "systemd",
            "libc6", "libc-bin", "glibc", "bash", "curl", "wget", "git",
            "nginx", "apache", "mysql", "postgresql", "docker", "kernel"
        }

    def process_vuls_report(self, vuls_json_file: str) -> Dict:
        """Process Vuls JSON report and extract vulnerability data from all sources."""
        try:
            with open(vuls_json_file, 'r') as f:
                vuls_data = json.load(f)

            logger.info(f"Processing Vuls report for {vuls_data.get('serverName', 'unknown server')}")

            # Extract vulnerabilities from scannedCves (contains data from all sources)
            vulnerabilities = self._extract_vulnerabilities(vuls_data)

            # Generate comprehensive report
            report = self._generate_comprehensive_report(vulnerabilities, vuls_data)

            return report

        except Exception as e:
            logger.error(f"Error processing Vuls report: {e}")
            return self._empty_report()

    def _extract_vulnerabilities(self, vuls_data: Dict) -> List[Dict]:
        """Extract vulnerability data from Vuls scannedCves section."""
        vulnerabilities = []
        scanned_cves = vuls_data.get('scannedCves', {})
        packages = vuls_data.get('packages', {})

        logger.info(f"Found {len(scanned_cves)} CVEs in scan results")

        for cve_id, cve_data in scanned_cves.items():
            try:
                # Extract affected packages for this CVE
                affected_packages = self._get_affected_packages(cve_data, packages)

                for package_info in affected_packages:
                    vulnerability = self._create_vulnerability_record(
                        cve_id, cve_data, package_info, packages
                    )
                    if vulnerability:
                        vulnerabilities.append(vulnerability)

            except Exception as e:
                logger.warning(f"Error processing CVE {cve_id}: {e}")
                continue

        logger.info(f"Extracted {len(vulnerabilities)} vulnerability records")
        return vulnerabilities

    def _get_affected_packages(self, cve_data: Dict, packages: Dict) -> List[Dict]:
        """Extract affected package information from CVE data."""
        affected_packages = []

        # Check AffectedPackages section (from OVAL/GOST)
        for pkg_info in cve_data.get('AffectedPackages', []):
            package_name = pkg_info.get('Name', '')
            if package_name and package_name in packages:
                affected_packages.append({
                    'name': package_name,
                    'installed_version': packages[package_name].get('version', ''),
                    'fixed_version': pkg_info.get('FixedIn', ''),
                    'source': 'AffectedPackages'
                })

        # Check CpeNames section (additional package references)
        for cpe_info in cve_data.get('CpeNames', []):
            cpe_name = cpe_info.get('Name', '')
            # Extract package name from CPE
            package_name = self._extract_package_from_cpe(cpe_name)
            if package_name and package_name in packages:
                affected_packages.append({
                    'name': package_name,
                    'installed_version': packages[package_name].get('version', ''),
                    'fixed_version': '',
                    'source': 'CpeNames'
                })

        # If no specific packages found, check if this affects critical packages
        if not affected_packages:
            affected_packages = self._infer_affected_packages(cve_data, packages)

        return affected_packages

    def _extract_package_from_cpe(self, cpe_name: str) -> str:
        """Extract package name from CPE string."""
        # CPE format: cpe:2.3:a:vendor:product:version:...
        try:
            parts = cpe_name.split(':')
            if len(parts) >= 5:
                return parts[4]  # product name
        except:
            pass
        return ''

    def _infer_affected_packages(self, cve_data: Dict, packages: Dict) -> List[Dict]:
        """Infer affected packages from CVE description and summary."""
        affected_packages = []

        # Get text to search
        summary = cve_data.get('Summary', '').lower()

        # Look for package names in summary
        for package_name in packages.keys():
            if package_name.lower() in summary:
                # Only include if it's a critical package or commonly vulnerable
                if (package_name in self.critical_packages or
                    self._is_commonly_vulnerable_package(package_name)):
                    affected_packages.append({
                        'name': package_name,
                        'installed_version': packages[package_name].get('version', ''),
                        'fixed_version': '',
                        'source': 'inferred'
                    })

        return affected_packages

    def _is_commonly_vulnerable_package(self, package_name: str) -> bool:
        """Check if package is commonly vulnerable based on patterns."""
        vulnerable_patterns = [
            r'.*ssl.*', r'.*tls.*', r'.*crypto.*', r'.*ssh.*',
            r'.*http.*', r'.*web.*', r'.*server.*', r'.*daemon.*',
            r'.*lib.*', r'.*dev.*', r'.*python.*', r'.*java.*',
            r'.*php.*', r'.*perl.*', r'.*ruby.*', r'.*node.*'
        ]

        for pattern in vulnerable_patterns:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        return False

    def _create_vulnerability_record(self, cve_id: str, cve_data: Dict,
                                   package_info: Dict, packages: Dict) -> Dict:
        """Create a standardized vulnerability record."""
        try:
            # Extract CVSS information
            cvss_score = self._extract_cvss_score(cve_data)
            severity = self._determine_severity(cvss_score, cve_data)

            # Get package details
            package_name = package_info['name']
            installed_version = package_info['installed_version']
            fixed_version = package_info['fixed_version']

            # Skip if version comparison shows not vulnerable
            if fixed_version and not self._is_version_vulnerable(installed_version, fixed_version):
                logger.debug(f"Skipping {cve_id} for {package_name}: version {installed_version} >= {fixed_version}")
                return None

            vulnerability = {
                'cve_id': cve_id,
                'title': cve_data.get('Title', f"{cve_id} vulnerability"),
                'description': cve_data.get('Summary', ''),
                'affected_package': package_name,
                'installed_version': installed_version,
                'fixed_version': fixed_version,
                'cvss_score': cvss_score,
                'severity': severity,
                'published_date': self._extract_published_date(cve_data),
                'source': package_info.get('source', 'unknown'),
                'references': self._extract_references(cve_data)
            }

            return vulnerability

        except Exception as e:
            logger.warning(f"Error creating vulnerability record for {cve_id}: {e}")
            return None

    def _extract_cvss_score(self, cve_data: Dict) -> float:
        """Extract CVSS score from CVE data."""
        # Try CVSS v3 first
        cvss3 = cve_data.get('Cvss3', {})
        if cvss3.get('BaseScore'):
            try:
                return float(cvss3['BaseScore'])
            except:
                pass

        # Try CVSS v2
        cvss2 = cve_data.get('Cvss2', {})
        if cvss2.get('BaseScore'):
            try:
                return float(cvss2['BaseScore'])
            except:
                pass

        return 0.0

    def _determine_severity(self, cvss_score: float, cve_data: Dict) -> str:
        """Determine severity level from CVSS score and other indicators."""
        # Check if severity is explicitly provided
        for cvss_section in ['Cvss3', 'Cvss2']:
            cvss_data = cve_data.get(cvss_section, {})
            if cvss_data.get('BaseSeverity'):
                return cvss_data['BaseSeverity'].upper()

        # Determine from CVSS score
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        elif cvss_score > 0:
            return 'LOW'
        else:
            return 'unknown'

    def _extract_published_date(self, cve_data: Dict) -> str:
        """Extract published date from CVE data."""
        # Try different date fields
        for date_field in ['PublishedDate', 'LastModifiedDate']:
            date_str = cve_data.get(date_field, '')
            if date_str:
                try:
                    # Parse and reformat date
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    return dt.isoformat()
                except:
                    return date_str

        return ''

    def _extract_references(self, cve_data: Dict) -> List[str]:
        """Extract reference URLs from CVE data."""
        references = []

        # Extract from References section
        for ref in cve_data.get('References', []):
            if isinstance(ref, dict):
                url = ref.get('Link', ref.get('URL', ''))
                if url:
                    references.append(url)
            elif isinstance(ref, str):
                references.append(ref)

        return references

    def _is_version_vulnerable(self, installed_version: str, fixed_version: str) -> bool:
        """Check if installed version is vulnerable compared to fixed version."""
        if not fixed_version:
            return True  # No fix available, assume vulnerable

        try:
            # Clean version strings
            installed_clean = self._clean_version(installed_version)
            fixed_clean = self._clean_version(fixed_version)

            # Compare versions
            installed_ver = version.parse(installed_clean)
            fixed_ver = version.parse(fixed_clean)

            return installed_ver < fixed_ver

        except Exception as e:
            logger.debug(f"Version comparison error: {e}")
            return True  # Err on side of caution

    def _clean_version(self, version_str: str) -> str:
        """Clean version string for comparison."""
        if not version_str:
            return "0"

        # Remove Debian/Ubuntu specific suffixes
        cleaned = re.sub(r'-\d+ubuntu.*$', '', version_str)
        cleaned = re.sub(r'-\d+\+deb.*$', '', cleaned)
        cleaned = re.sub(r'-\d+build\d+$', '', cleaned)

        # Handle epoch (1:version)
        if ':' in cleaned:
            cleaned = cleaned.split(':', 1)[1]

        # Replace ~ with . for pre-release versions
        cleaned = cleaned.replace('~', '.')

        # Remove everything after first dash for Debian revision
        if '-' in cleaned:
            cleaned = cleaned.split('-')[0]

        return cleaned

    def _generate_comprehensive_report(self, vulnerabilities: List[Dict], vuls_data: Dict) -> Dict:
        """Generate comprehensive vulnerability report."""
        if not vulnerabilities:
            return self._empty_report()

        # Calculate statistics
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'unknown': 0}
        by_package = {}

        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.get('severity', 'unknown')
            if severity in by_severity:
                by_severity[severity] += 1
            else:
                by_severity['unknown'] += 1

            # Count by package
            package = vuln['affected_package']
            if package not in by_package:
                by_package[package] = {
                    'total': 0, 'critical': 0, 'high': 0,
                    'medium': 0, 'low': 0, 'package': package
                }

            by_package[package]['total'] += 1
            severity_key = severity.lower()
            if severity_key in by_package[package]:
                by_package[package][severity_key] += 1

        # Calculate risk scores for packages
        high_risk_packages = []
        for pkg_name, counts in by_package.items():
            risk_score = (
                counts['critical'] * 20 +
                counts['high'] * 10 +
                counts['medium'] * 5 +
                counts['low'] * 1
            )

            pkg_info = {
                'package': pkg_name,
                'total_vulns': counts['total'],
                'critical': counts['critical'],
                'high': counts['high'],
                'medium': counts['medium'],
                'low': counts['low'],
                'risk_score': risk_score
            }
            high_risk_packages.append(pkg_info)

        # Sort by risk score
        high_risk_packages.sort(key=lambda x: x['risk_score'], reverse=True)

        # Generate report
        report = {
            'total_vulnerabilities': len(vulnerabilities),
            'packages_affected': len(by_package),
            'vulnerability_breakdown': by_severity,
            'high_risk_packages': high_risk_packages,
            'vulnerabilities': vulnerabilities,
            'scan_metadata': {
                'server_name': vuls_data.get('serverName', 'unknown'),
                'scanned_at': vuls_data.get('scannedAt', ''),
                'scan_mode': vuls_data.get('scanMode', ''),
                'family': vuls_data.get('family', ''),
                'release': vuls_data.get('release', ''),
                'total_packages': len(vuls_data.get('packages', {})),
                'total_cves_found': len(vuls_data.get('scannedCves', {}))
            }
        }

        return report

    def _empty_report(self) -> Dict:
        """Return empty report structure."""
        return {
            'total_vulnerabilities': 0,
            'packages_affected': 0,
            'vulnerability_breakdown': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'unknown': 0},
            'high_risk_packages': [],
            'vulnerabilities': [],
            'scan_metadata': {}
        }


def main():
    """CLI interface for Vuls report processor."""
    import argparse

    parser = argparse.ArgumentParser(description="Process Vuls JSON reports")
    parser.add_argument('--input', '-i', required=True, help='Input Vuls JSON file')
    parser.add_argument('--output', '-o', required=True, help='Output JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Process report
    processor = VulsReportProcessor()

    try:
        logger.info(f"Processing Vuls report: {args.input}")
        report = processor.process_vuls_report(args.input)

        # Save report
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report saved to: {args.output}")
        logger.info(f"Found {report['total_vulnerabilities']} vulnerabilities affecting {report['packages_affected']} packages")

        # Print summary
        breakdown = report['vulnerability_breakdown']
        print(f"\n🔍 VULNERABILITY SCAN RESULTS:")
        print(f"   Total vulnerabilities: {report['total_vulnerabilities']}")
        print(f"   Packages affected: {report['packages_affected']}")
        print(f"   Breakdown: Critical={breakdown['CRITICAL']}, High={breakdown['HIGH']}, Medium={breakdown['MEDIUM']}, Low={breakdown['LOW']}")

        return 0

    except Exception as e:
        logger.error(f"Error processing report: {e}")
        return 1


if __name__ == '__main__':
    exit(main())
