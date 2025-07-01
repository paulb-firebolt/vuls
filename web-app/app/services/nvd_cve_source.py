"""
NVD CVE Source
On-demand CVE lookups using the National Vulnerability Database API.
Designed to catch vulnerabilities that may not be in distribution OVAL data.
"""

import logging
import requests
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set
from urllib.parse import quote
import json
from pathlib import Path
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models.base import get_db
from .base_vulnerability_source import BaseVulnerabilitySource

logger = logging.getLogger(__name__)


class NVDCVESource(BaseVulnerabilitySource):
    """NVD CVE source for comprehensive vulnerability detection."""

    def __init__(self):
        super().__init__("nvd_cve", "NVD")

        # NVD API configuration
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept': 'application/json'
        })

        # Rate limiting (NVD allows 5 requests per 30 seconds without API key)
        self.rate_limit_delay = 6  # seconds between requests
        self.last_request_time = 0

        # Cache configuration
        self.cache_dir = Path("/tmp/nvd_cache")
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_max_age_hours = 24

        # Common package name mappings to help with NVD searches
        self.package_mappings = {
            'libssl3': 'openssl',
            'libssl1.1': 'openssl',
            'libcurl4': 'curl',
            'libcurl3': 'curl',
            'python3': 'python',
            'python3.9': 'python',
            'python3.10': 'python',
            'python3.11': 'python',
            'nodejs': 'node.js',
            'apache2': 'apache_http_server',
            'nginx': 'nginx',
            'mysql-server': 'mysql',
            'postgresql': 'postgresql',
            'redis-server': 'redis',
        }

        logger.info("NVD CVE Source initialized")

    def _rate_limit(self):
        """Enforce rate limiting for NVD API requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path for a given key."""
        # Create a safe filename from the cache key
        safe_key = "".join(c for c in cache_key if c.isalnum() or c in ('-', '_', '.'))
        return self.cache_dir / f"nvd_{safe_key}.json"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cached data is still valid."""
        if not cache_path.exists():
            return False

        file_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        max_age = timedelta(hours=self.cache_max_age_hours)

        return file_age < max_age

    def _save_to_cache(self, data: Dict, cache_path: Path) -> bool:
        """Save data to cache file."""
        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved data to cache: {cache_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving to cache {cache_path}: {e}")
            return False

    def _load_from_cache(self, cache_path: Path) -> Optional[Dict]:
        """Load data from cache file."""
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            logger.debug(f"Loaded data from cache: {cache_path}")
            return data
        except Exception as e:
            logger.error(f"Error loading from cache {cache_path}: {e}")
            return None

    def _normalize_package_name(self, package_name: str) -> str:
        """Normalize package name for NVD searches."""
        # Remove version suffixes and common prefixes
        normalized = package_name.lower()

        # Remove common prefixes
        for prefix in ['lib', 'python3-', 'python-']:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break

        # Remove version suffixes
        for suffix in ['-dev', '-dbg', '-doc', '-common']:
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break

        # Apply known mappings
        if normalized in self.package_mappings:
            normalized = self.package_mappings[normalized]

        return normalized

    def search_nvd_cves(self, package_name: str, limit: int = 50) -> List[Dict]:
        """Search NVD for CVEs related to a package."""
        normalized_name = self._normalize_package_name(package_name)
        cache_key = f"search_{normalized_name}_{limit}"
        cache_path = self._get_cache_path(cache_key)

        # Try cache first
        if self._is_cache_valid(cache_path):
            cached_data = self._load_from_cache(cache_path)
            if cached_data:
                logger.debug(f"Using cached NVD data for {package_name}")
                return cached_data.get('vulnerabilities', [])

        try:
            # Rate limit the request
            self._rate_limit()

            # Search NVD API
            params = {
                'keywordSearch': normalized_name,
                'resultsPerPage': min(limit, 2000),  # NVD max is 2000
                'startIndex': 0
            }

            logger.info(f"Searching NVD for package: {package_name} (normalized: {normalized_name})")
            response = self.session.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = []

            if 'vulnerabilities' in data:
                for vuln_data in data['vulnerabilities']:
                    cve = vuln_data.get('cve', {})
                    cve_id = cve.get('id', '')

                    if not cve_id:
                        continue

                    # Extract basic information
                    descriptions = cve.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break

                    # Extract CVSS scores
                    metrics = cve.get('metrics', {})
                    cvss_score = None
                    cvss_vector = None
                    severity = 'Unknown'

                    # Try CVSS v3.1 first, then v3.0, then v2.0
                    for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if cvss_version in metrics and metrics[cvss_version]:
                            cvss_data = metrics[cvss_version][0].get('cvssData', {})
                            cvss_score = cvss_data.get('baseScore')
                            cvss_vector = cvss_data.get('vectorString')
                            severity = cvss_data.get('baseSeverity', 'Unknown')
                            break

                    # Extract publication dates
                    published = cve.get('published', '')
                    last_modified = cve.get('lastModified', '')

                    # Check if this CVE is relevant to the package
                    relevance_score = self._calculate_relevance(cve_id, description, normalized_name, package_name)

                    vulnerability = {
                        'cve_id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'cvss_vector': cvss_vector,
                        'severity': severity,
                        'published': published,
                        'last_modified': last_modified,
                        'source': 'NVD',
                        'package_name': package_name,
                        'normalized_name': normalized_name,
                        'relevance_score': relevance_score,
                        'confidence_score': 0.7 + (relevance_score * 0.2)  # Base 0.7, up to 0.9 with high relevance
                    }

                    vulnerabilities.append(vulnerability)

            # Sort by relevance and CVSS score
            vulnerabilities.sort(key=lambda x: (x['relevance_score'], x.get('cvss_score', 0)), reverse=True)

            # Cache the results
            cache_data = {
                'package_name': package_name,
                'normalized_name': normalized_name,
                'search_time': datetime.now().isoformat(),
                'total_results': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }
            self._save_to_cache(cache_data, cache_path)

            logger.info(f"Found {len(vulnerabilities)} CVEs for {package_name} in NVD")
            return vulnerabilities

        except Exception as e:
            logger.error(f"Error searching NVD for {package_name}: {e}")

            # Try to return stale cache as fallback
            if cache_path.exists():
                logger.warning(f"Using stale cache for {package_name}")
                cached_data = self._load_from_cache(cache_path)
                if cached_data:
                    return cached_data.get('vulnerabilities', [])

            return []

    def _calculate_relevance(self, cve_id: str, description: str, normalized_name: str, original_name: str) -> float:
        """Calculate how relevant a CVE is to the given package."""
        relevance = 0.0
        description_lower = description.lower()

        # Exact package name match in description
        if normalized_name in description_lower:
            relevance += 0.8

        if original_name.lower() in description_lower:
            relevance += 0.6

        # Partial matches
        name_parts = normalized_name.split('-')
        for part in name_parts:
            if len(part) > 2 and part in description_lower:
                relevance += 0.2

        # Common vulnerability keywords that increase relevance
        high_relevance_keywords = [
            'remote code execution', 'buffer overflow', 'sql injection',
            'cross-site scripting', 'privilege escalation', 'denial of service'
        ]

        for keyword in high_relevance_keywords:
            if keyword in description_lower:
                relevance += 0.1

        # Cap at 1.0
        return min(relevance, 1.0)

    def lookup_vulnerability_info(self, cve_id: str, package_name: str, **kwargs) -> Optional[Dict]:
        """Look up specific CVE information from NVD."""
        cache_key = f"cve_{cve_id}"
        cache_path = self._get_cache_path(cache_key)

        # Try cache first
        if self._is_cache_valid(cache_path):
            cached_data = self._load_from_cache(cache_path)
            if cached_data:
                logger.debug(f"Using cached NVD data for {cve_id}")
                return cached_data

        try:
            # Rate limit the request
            self._rate_limit()

            # Query specific CVE
            params = {'cveId': cve_id}

            logger.info(f"Looking up CVE {cve_id} in NVD")
            response = self.session.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()

            data = response.json()

            if 'vulnerabilities' in data and data['vulnerabilities']:
                vuln_data = data['vulnerabilities'][0]
                cve = vuln_data.get('cve', {})

                # Extract detailed information
                descriptions = cve.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # Extract CVSS scores
                metrics = cve.get('metrics', {})
                cvss_score = None
                cvss_vector = None
                severity = 'Unknown'

                for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if cvss_version in metrics and metrics[cvss_version]:
                        cvss_data = metrics[cvss_version][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                        severity = cvss_data.get('baseSeverity', 'Unknown')
                        break

                # Extract references
                references = []
                for ref in cve.get('references', []):
                    references.append({
                        'url': ref.get('url', ''),
                        'source': ref.get('source', ''),
                        'tags': ref.get('tags', [])
                    })

                result = {
                    'found': True,
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'severity': severity,
                    'published': cve.get('published', ''),
                    'last_modified': cve.get('lastModified', ''),
                    'references': references,
                    'source': 'NVD',
                    'confidence_score': 0.85
                }

                # Cache the result
                self._save_to_cache(result, cache_path)

                return result

            return {
                'found': False,
                'reason': f'CVE {cve_id} not found in NVD',
                'confidence_score': 0.9
            }

        except Exception as e:
            logger.error(f"Error looking up CVE {cve_id} in NVD: {e}")

            # Try stale cache
            if cache_path.exists():
                cached_data = self._load_from_cache(cache_path)
                if cached_data:
                    return cached_data

            return None

    def get_package_vulnerabilities(self, package_name: str, **kwargs) -> List[Dict]:
        """Get vulnerabilities for a package from NVD."""
        return self.search_nvd_cves(package_name, limit=100)

    def find_missing_cves(self, package_name: str, known_cves: Set[str]) -> List[Dict]:
        """Find CVEs in NVD that are not in the known CVE set."""
        nvd_cves = self.search_nvd_cves(package_name, limit=200)

        missing_cves = []
        for cve in nvd_cves:
            cve_id = cve.get('cve_id', '')
            if cve_id and cve_id not in known_cves:
                # Mark as potentially missing from distribution sources
                cve['gap_analysis'] = {
                    'missing_from_distributions': True,
                    'potential_risk': 'High' if cve.get('cvss_score', 0) >= 7.0 else 'Medium',
                    'requires_investigation': True
                }
                missing_cves.append(cve)

        logger.info(f"Found {len(missing_cves)} potentially missing CVEs for {package_name}")
        return missing_cves

    def enhance_vulnerability(self, vulnerability: Dict) -> Dict:
        """Enhance vulnerability data with NVD information."""
        enhanced = vulnerability.copy()
        cve_id = vulnerability.get('cve_id', '')

        if cve_id:
            nvd_info = self.lookup_vulnerability_info(cve_id, vulnerability.get('package_name', ''))
            if nvd_info and nvd_info.get('found'):
                # Add NVD-specific data
                enhanced['nvd_data'] = {
                    'cvss_score': nvd_info.get('cvss_score'),
                    'cvss_vector': nvd_info.get('cvss_vector'),
                    'severity': nvd_info.get('severity'),
                    'published': nvd_info.get('published'),
                    'last_modified': nvd_info.get('last_modified'),
                    'references': nvd_info.get('references', [])
                }

                # Enhance existing fields if missing
                if not enhanced.get('description') and nvd_info.get('description'):
                    enhanced['description'] = nvd_info['description']

                if not enhanced.get('severity') and nvd_info.get('severity'):
                    enhanced['severity'] = nvd_info['severity']

        return enhanced

    def should_update_data(self, **kwargs) -> bool:
        """NVD is queried on-demand, so no bulk updates needed."""
        return False

    def download_and_cache_data(self, **kwargs) -> bool:
        """NVD is queried on-demand, so no bulk downloads needed."""
        return True

    def get_cache_stats(self) -> Dict:
        """Get statistics about NVD cache."""
        cache_files = list(self.cache_dir.glob("nvd_*.json"))

        total_size = sum(f.stat().st_size for f in cache_files)

        return {
            'source_name': self.source_name,
            'source_type': self.source_type,
            'backend': 'NVD API v2.0',
            'cache_files': len(cache_files),
            'cache_size_mb': round(total_size / (1024 * 1024), 2),
            'cache_directory': str(self.cache_dir),
            'rate_limit_delay': self.rate_limit_delay,
            'status': 'Active'
        }
