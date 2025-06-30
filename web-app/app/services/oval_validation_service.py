"""
OVAL Validation Service
Compares results between current OVAL engine and schema-based engine for validation.
"""

import logging
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path
from .ubuntu_oval_source import UbuntuOVALSource
from .ubuntu_oval_schema_source import SchemaBasedOVALSource

logger = logging.getLogger(__name__)


class OVALValidationService:
    """Service to validate schema-based OVAL engine against current working engine."""

    def __init__(self):
        self.current_engine = UbuntuOVALSource()
        self.schema_engine = SchemaBasedOVALSource()
        self.validation_results = []

        logger.info("OVAL Validation Service initialized")

    def validate_vulnerability_lookup(self, cve_id: str, package_name: str,
                                    release: str = '22.04') -> Dict:
        """Compare vulnerability lookup between both engines."""
        try:
            # Get results from both engines
            current_result = self.current_engine.lookup_vulnerability_info(
                cve_id, package_name, release
            )
            schema_result = self.schema_engine.lookup_vulnerability_info(
                cve_id, package_name, release
            )

            # Compare results
            comparison = self._compare_vulnerability_results(
                current_result, schema_result, cve_id, package_name, release
            )

            self.validation_results.append(comparison)
            return comparison

        except Exception as e:
            logger.error(f"Error validating {cve_id} for {package_name}: {e}")
            return {
                'cve_id': cve_id,
                'package_name': package_name,
                'release': release,
                'status': 'error',
                'error': str(e)
            }

    def _compare_vulnerability_results(self, current: Optional[Dict],
                                     schema: Optional[Dict], cve_id: str,
                                     package_name: str, release: str) -> Dict:
        """Compare results from both engines."""
        comparison = {
            'cve_id': cve_id,
            'package_name': package_name,
            'release': release,
            'timestamp': datetime.now().isoformat(),
            'current_engine': current,
            'schema_engine': schema,
            'status': 'unknown',
            'differences': [],
            'agreement': False
        }

        # Handle None results
        if current is None and schema is None:
            comparison['status'] = 'both_failed'
            return comparison
        elif current is None:
            comparison['status'] = 'current_failed'
            return comparison
        elif schema is None:
            comparison['status'] = 'schema_failed'
            return comparison

        # Compare found status
        current_found = current.get('found', False)
        schema_found = schema.get('found', False)

        if current_found != schema_found:
            comparison['differences'].append({
                'field': 'found',
                'current': current_found,
                'schema': schema_found
            })

        # If both found, compare details
        if current_found and schema_found:
            # Compare fixed version
            current_fixed = current.get('fixed_version')
            schema_fixed = schema.get('fixed_version')

            if current_fixed != schema_fixed:
                comparison['differences'].append({
                    'field': 'fixed_version',
                    'current': current_fixed,
                    'schema': schema_fixed
                })

            # Compare severity
            current_severity = current.get('severity')
            schema_severity = schema.get('severity')

            if current_severity != schema_severity:
                comparison['differences'].append({
                    'field': 'severity',
                    'current': current_severity,
                    'schema': schema_severity
                })

        # Determine overall agreement
        comparison['agreement'] = len(comparison['differences']) == 0

        if comparison['agreement']:
            comparison['status'] = 'agreement'
        else:
            comparison['status'] = 'disagreement'

        return comparison

    def validate_package_vulnerabilities(self, package_name: str,
                                       release: str = '22.04') -> Dict:
        """Compare package vulnerability lists between both engines."""
        try:
            # Get results from both engines
            current_vulns = self.current_engine.get_package_vulnerabilities(
                package_name, release
            )
            schema_vulns = self.schema_engine.get_package_vulnerabilities(
                package_name, release
            )

            # Compare lists
            comparison = {
                'package_name': package_name,
                'release': release,
                'timestamp': datetime.now().isoformat(),
                'current_count': len(current_vulns),
                'schema_count': len(schema_vulns),
                'current_cves': [v.get('cve_id') for v in current_vulns],
                'schema_cves': [v.get('cve_id') for v in schema_vulns],
                'agreement': False,
                'differences': []
            }

            # Find differences
            current_set = set(comparison['current_cves'])
            schema_set = set(comparison['schema_cves'])

            only_current = current_set - schema_set
            only_schema = schema_set - current_set

            if only_current:
                comparison['differences'].append({
                    'type': 'only_in_current',
                    'cves': list(only_current)
                })

            if only_schema:
                comparison['differences'].append({
                    'type': 'only_in_schema',
                    'cves': list(only_schema)
                })

            comparison['agreement'] = len(comparison['differences']) == 0

            return comparison

        except Exception as e:
            logger.error(f"Error validating package {package_name}: {e}")
            return {
                'package_name': package_name,
                'release': release,
                'status': 'error',
                'error': str(e)
            }

    def validate_against_vuls_report(self, vuls_report_path: str) -> Dict:
        """Validate both engines against a Vuls vulnerability report."""
        try:
            # Load Vuls report
            with open(vuls_report_path, 'r') as f:
                vuls_data = json.load(f)

            validation_summary = {
                'report_path': vuls_report_path,
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': 0,
                'validated_count': 0,
                'agreement_count': 0,
                'disagreement_count': 0,
                'error_count': 0,
                'agreement_rate': 0.0,
                'validations': []
            }

            # Extract vulnerabilities from Vuls report
            vulnerabilities = self._extract_vulnerabilities_from_vuls_report(vuls_data)
            validation_summary['total_vulnerabilities'] = len(vulnerabilities)

            # Validate each vulnerability
            for vuln in vulnerabilities:
                cve_id = vuln.get('cve_id')
                package_name = vuln.get('package_name')
                release = vuln.get('release', '22.04')

                if cve_id and package_name:
                    validation = self.validate_vulnerability_lookup(
                        cve_id, package_name, release
                    )
                    validation_summary['validations'].append(validation)
                    validation_summary['validated_count'] += 1

                    if validation.get('status') == 'agreement':
                        validation_summary['agreement_count'] += 1
                    elif validation.get('status') == 'disagreement':
                        validation_summary['disagreement_count'] += 1
                    else:
                        validation_summary['error_count'] += 1

            # Calculate agreement rate
            if validation_summary['validated_count'] > 0:
                validation_summary['agreement_rate'] = (
                    validation_summary['agreement_count'] /
                    validation_summary['validated_count']
                )

            return validation_summary

        except Exception as e:
            logger.error(f"Error validating against Vuls report: {e}")
            return {
                'report_path': vuls_report_path,
                'status': 'error',
                'error': str(e)
            }

    def _extract_vulnerabilities_from_vuls_report(self, vuls_data: Dict) -> List[Dict]:
        """Extract vulnerability information from Vuls report."""
        vulnerabilities = []

        try:
            # Navigate Vuls report structure
            for server_name, server_data in vuls_data.get('servers', {}).items():
                packages = server_data.get('packages', {})

                for package_name, package_data in packages.items():
                    # Check if package has vulnerabilities
                    if 'vulnerabilities' in package_data:
                        for vuln_id, vuln_data in package_data['vulnerabilities'].items():
                            if vuln_id.startswith('CVE-'):
                                vulnerabilities.append({
                                    'cve_id': vuln_id,
                                    'package_name': package_name,
                                    'server_name': server_name,
                                    'installed_version': package_data.get('version', ''),
                                    'release': self._detect_ubuntu_release(
                                        server_data.get('release', '')
                                    )
                                })

            # Also check scanned CVEs section
            scanned_cves = vuls_data.get('scannedCves', {})
            for cve_id, cve_data in scanned_cves.items():
                if cve_id.startswith('CVE-'):
                    affected_packages = cve_data.get('affectedPackages', [])
                    for pkg in affected_packages:
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'package_name': pkg.get('name', ''),
                            'installed_version': pkg.get('version', ''),
                            'release': '22.04'  # Default
                        })

        except Exception as e:
            logger.error(f"Error extracting vulnerabilities from Vuls report: {e}")

        return vulnerabilities

    def _detect_ubuntu_release(self, release_info: str) -> str:
        """Detect Ubuntu release from release information."""
        if '24.04' in release_info or 'noble' in release_info.lower():
            return '24.04'
        elif '22.04' in release_info or 'jammy' in release_info.lower():
            return '22.04'
        elif '20.04' in release_info or 'focal' in release_info.lower():
            return '20.04'
        elif '18.04' in release_info or 'bionic' in release_info.lower():
            return '18.04'
        else:
            return '22.04'  # Default to current LTS

    def generate_validation_report(self, output_path: str = None) -> Dict:
        """Generate a comprehensive validation report."""
        if not output_path:
            output_path = f"/tmp/oval_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'generated_at': datetime.now().isoformat(),
            'total_validations': len(self.validation_results),
            'summary': {
                'agreement': 0,
                'disagreement': 0,
                'errors': 0,
                'agreement_rate': 0.0
            },
            'validations': self.validation_results,
            'engine_comparison': {
                'current_engine': {
                    'name': self.current_engine.source_name,
                    'type': self.current_engine.source_type
                },
                'schema_engine': {
                    'name': self.schema_engine.source_name,
                    'type': self.schema_engine.source_type
                }
            }
        }

        # Calculate summary statistics
        for validation in self.validation_results:
            status = validation.get('status', 'error')
            if status == 'agreement':
                report['summary']['agreement'] += 1
            elif status == 'disagreement':
                report['summary']['disagreement'] += 1
            else:
                report['summary']['errors'] += 1

        if report['total_validations'] > 0:
            report['summary']['agreement_rate'] = (
                report['summary']['agreement'] / report['total_validations']
            )

        # Save report
        try:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Validation report saved to: {output_path}")
        except Exception as e:
            logger.error(f"Error saving validation report: {e}")

        return report

    def clear_results(self):
        """Clear validation results."""
        self.validation_results = []
        logger.info("Validation results cleared")
