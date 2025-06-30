"""
Unified Ubuntu Security Service
Combines USN and OVAL data sources for comprehensive vulnerability analysis.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
from .base_vulnerability_source import vulnerability_source_registry
from .ubuntu_security_lookup import UbuntuSecurityLookup
from .ubuntu_oval_source import UbuntuOVALSource
from .ubuntu_oval_schema_source import SchemaBasedOVALSource

logger = logging.getLogger(__name__)


class UnifiedUbuntuSecurity:
    """Unified service that combines USN and OVAL data sources."""

    def __init__(self, use_schema_oval: bool = False):
        self.usn_source = UbuntuSecurityLookup()

        # Choose OVAL engine based on configuration
        if use_schema_oval:
            self.oval_source = SchemaBasedOVALSource()
            logger.info("Using Schema-Based OVAL Engine")
        else:
            self.oval_source = UbuntuOVALSource()
            logger.info("Using Traditional OVAL Engine")

        self.use_schema_oval = use_schema_oval

        # Register sources in the global registry
        vulnerability_source_registry.register_source(self.usn_source)
        vulnerability_source_registry.register_source(self.oval_source)

        logger.info("Unified Ubuntu Security Service initialized")

    def update_all_data(self, force: bool = False) -> Dict[str, bool]:
        """Update data from all sources."""
        results = {}

        try:
            # Update USN data
            if force or self.usn_source.should_update_data():
                logger.info("Updating USN data...")
                results['usn'] = self.usn_source.download_and_cache_ubuntu_data()
            else:
                results['usn'] = True
                logger.info("USN data is up to date")

            # Update OVAL data for all supported releases
            oval_results = []
            for release in ['16.04', '18.04', '20.04', '22.04', '24.04']:
                if force or self.oval_source.should_update_data(release=release):
                    logger.info(f"Updating OVAL data for Ubuntu {release}...")
                    oval_results.append(self.oval_source.download_and_cache_data(release=release))
                else:
                    oval_results.append(True)
                    logger.info(f"OVAL data for Ubuntu {release} is up to date")

            results['oval'] = all(oval_results)

        except Exception as e:
            logger.error(f"Error updating Ubuntu security data: {e}")
            results['error'] = str(e)

        return results

    def lookup_vulnerability(self, cve_id: str, package_name: str,
                           release: str = '22.04', prefer_source: str = 'usn') -> Dict:
        """
        Look up vulnerability information from multiple sources.

        Args:
            cve_id: CVE identifier
            package_name: Package name
            release: Ubuntu release version
            prefer_source: Preferred source ('usn' or 'oval')

        Returns:
            Combined vulnerability information
        """
        results = {
            'cve_id': cve_id,
            'package_name': package_name,
            'release': release,
            'sources': {},
            'combined': {}
        }

        # Get data from USN source
        try:
            usn_info = self.usn_source.lookup_ubuntu_security_info(cve_id, package_name, release)
            if usn_info:
                results['sources']['usn'] = usn_info
        except Exception as e:
            logger.error(f"Error looking up USN data: {e}")
            results['sources']['usn'] = {'error': str(e)}

        # Get data from OVAL source
        try:
            oval_info = self.oval_source.lookup_vulnerability_info(cve_id, package_name, release)
            if oval_info:
                results['sources']['oval'] = oval_info
        except Exception as e:
            logger.error(f"Error looking up OVAL data: {e}")
            results['sources']['oval'] = {'error': str(e)}

        # Combine results
        results['combined'] = self._combine_vulnerability_data(
            results['sources'], prefer_source
        )

        return results

    def get_package_vulnerabilities(self, package_name: str,
                                  release: str = '22.04') -> Dict:
        """Get all vulnerabilities for a package from all sources."""
        results = {
            'package_name': package_name,
            'release': release,
            'sources': {},
            'combined': []
        }

        # Get USN vulnerabilities
        try:
            usn_vulns = self.usn_source.get_package_security_status(package_name, release)
            results['sources']['usn'] = usn_vulns
        except Exception as e:
            logger.error(f"Error getting USN vulnerabilities: {e}")
            results['sources']['usn'] = []

        # Get OVAL vulnerabilities
        try:
            oval_vulns = self.oval_source.get_package_vulnerabilities(package_name, release)
            results['sources']['oval'] = oval_vulns
        except Exception as e:
            logger.error(f"Error getting OVAL vulnerabilities: {e}")
            results['sources']['oval'] = []

        # Combine and deduplicate
        results['combined'] = self._combine_package_vulnerabilities(results['sources'])

        return results

    def enhance_vulnerability_report(self, vulnerability: Dict) -> Dict:
        """Enhance a vulnerability report with data from all sources."""
        enhanced = vulnerability.copy()

        # Enhance with USN data
        try:
            enhanced = self.usn_source.enhance_vulnerability_with_ubuntu_data(enhanced)
        except Exception as e:
            logger.error(f"Error enhancing with USN data: {e}")

        # Enhance with OVAL data
        try:
            enhanced = self.oval_source.enhance_vulnerability(enhanced)
        except Exception as e:
            logger.error(f"Error enhancing with OVAL data: {e}")

        return enhanced

    def get_comprehensive_stats(self) -> Dict:
        """Get comprehensive statistics from all sources."""
        stats = {
            'last_updated': datetime.now().isoformat(),
            'sources': {}
        }

        # USN stats
        try:
            stats['sources']['usn'] = self.usn_source.get_cache_stats()
        except Exception as e:
            logger.error(f"Error getting USN stats: {e}")
            stats['sources']['usn'] = {'error': str(e)}

        # OVAL stats
        try:
            stats['sources']['oval'] = self.oval_source.get_cache_stats()
        except Exception as e:
            logger.error(f"Error getting OVAL stats: {e}")
            stats['sources']['oval'] = {'error': str(e)}

        # Combined stats
        stats['summary'] = self._calculate_combined_stats(stats['sources'])

        return stats

    def _combine_vulnerability_data(self, sources: Dict, prefer_source: str) -> Dict:
        """Combine vulnerability data from multiple sources."""
        combined = {
            'found': False,
            'confidence_score': 0.0,
            'sources_consulted': list(sources.keys()),
            'primary_source': None
        }

        # Check if any source found the vulnerability
        found_sources = []
        for source_name, data in sources.items():
            if isinstance(data, dict) and data.get('found'):
                found_sources.append((source_name, data))

        if not found_sources:
            combined['reason'] = 'No vulnerability data found in any source'
            return combined

        # Determine primary source
        primary_source = None
        primary_data = None

        # Prefer the specified source if it has data
        if prefer_source in [s[0] for s in found_sources]:
            primary_source = prefer_source
            primary_data = next(data for name, data in found_sources if name == prefer_source)
        else:
            # Use the source with highest confidence
            primary_source, primary_data = max(found_sources,
                                             key=lambda x: x[1].get('confidence_score', 0))

        # Build combined result
        combined.update({
            'found': True,
            'primary_source': primary_source,
            'confidence_score': primary_data.get('confidence_score', 0.8)
        })

        # Copy primary source data
        for key, value in primary_data.items():
            if key not in ['found', 'confidence_score']:
                combined[key] = value

        # Add supplementary data from other sources
        combined['supplementary'] = {}
        for source_name, data in found_sources:
            if source_name != primary_source:
                combined['supplementary'][source_name] = data

        # Resolve conflicts and enhance data
        combined = self._resolve_data_conflicts(combined, found_sources)

        return combined

    def _combine_package_vulnerabilities(self, sources: Dict) -> List[Dict]:
        """Combine and deduplicate package vulnerabilities from multiple sources."""
        combined = {}  # Use dict to deduplicate by CVE ID

        for source_name, vulnerabilities in sources.items():
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                cve_id = vuln.get('cve_id')
                if not cve_id:
                    continue

                if cve_id not in combined:
                    combined[cve_id] = {
                        'cve_id': cve_id,
                        'sources': {},
                        'primary_source': source_name
                    }

                combined[cve_id]['sources'][source_name] = vuln

                # Update primary data with highest confidence source
                current_confidence = combined[cve_id].get('confidence_score', 0)
                new_confidence = vuln.get('confidence_score', 0.8)

                if new_confidence > current_confidence:
                    combined[cve_id]['primary_source'] = source_name
                    # Copy primary data
                    for key, value in vuln.items():
                        if key not in ['sources', 'primary_source']:
                            combined[cve_id][key] = value

        return list(combined.values())

    def _resolve_data_conflicts(self, combined: Dict, found_sources: List) -> Dict:
        """Resolve conflicts between different data sources."""
        # Priority rules for different fields

        # For status, prefer USN over OVAL
        usn_data = next((data for name, data in found_sources if name == 'usn'), None)
        oval_data = next((data for name, data in found_sources if name == 'oval'), None)

        if usn_data and oval_data:
            # If USN says it's fixed but OVAL says not fixed, prefer USN
            if (usn_data.get('status') in ['released', 'not-affected'] and
                oval_data.get('not_fixed_yet')):
                combined['status'] = usn_data.get('status')
                combined['fixed_version'] = usn_data.get('fixed_version')
                combined['resolution_note'] = 'USN indicates fix available despite OVAL not_fixed_yet flag'

            # Combine severity information
            usn_priority = usn_data.get('priority', '').lower()
            oval_severity = oval_data.get('severity', '').lower()

            if usn_priority and oval_severity and usn_priority != oval_severity:
                combined['severity_note'] = f'USN: {usn_priority}, OVAL: {oval_severity}'

        return combined

    def _calculate_combined_stats(self, sources: Dict) -> Dict:
        """Calculate combined statistics from all sources."""
        summary = {
            'total_sources': len(sources),
            'active_sources': 0,
            'total_vulnerabilities': 0,
            'last_update': None
        }

        for source_name, stats in sources.items():
            if isinstance(stats, dict) and not stats.get('error'):
                summary['active_sources'] += 1

                # Add vulnerability counts
                if source_name == 'usn':
                    summary['total_vulnerabilities'] += stats.get('unique_cves', 0)
                elif source_name == 'oval':
                    releases = stats.get('releases', {})
                    for release_stats in releases.values():
                        summary['total_vulnerabilities'] += release_stats.get('cves_count', 0)

                # Track most recent update
                last_download = None
                if source_name == 'usn':
                    last_download = stats.get('last_download')
                elif source_name == 'oval':
                    releases = stats.get('releases', {})
                    for release_stats in releases.values():
                        if release_stats.get('last_download'):
                            if not last_download or release_stats['last_download'] > last_download:
                                last_download = release_stats['last_download']

                if last_download:
                    if not summary['last_update'] or last_download > summary['last_update']:
                        summary['last_update'] = last_download

        return summary

    def force_update_all(self) -> Dict[str, bool]:
        """Force update of all data sources."""
        return self.update_all_data(force=True)


# Global instances
unified_ubuntu_security = UnifiedUbuntuSecurity()  # Traditional OVAL engine
unified_ubuntu_security_schema = UnifiedUbuntuSecurity(use_schema_oval=True)  # Schema-based OVAL engine
