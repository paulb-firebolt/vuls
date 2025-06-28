"""
Debian Security Tracker integration for enhanced vulnerability analysis.
Downloads and caches Debian security data locally for fast lookups.
"""

import sqlite3
import json
import logging
import requests
import gzip
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class DebianSecurityLookup:
    """Debian Security Tracker data integration with local caching."""

    def __init__(self, cache_db_path: str = "db/debian_security_cache.sqlite3"):
        self.cache_db_path = cache_db_path
        self.json_url = "https://security-tracker.debian.org/tracker/data/json"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept-Encoding': 'gzip, deflate'
        })

        self._init_cache_db()

    def _init_cache_db(self):
        """Initialize the Debian security cache database."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS debian_security_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT NOT NULL,
                        package_name TEXT NOT NULL,
                        release_name TEXT NOT NULL, -- bookworm, bullseye, etc.
                        status TEXT NOT NULL, -- fixed, not-affected, vulnerable, etc.
                        fixed_version TEXT,
                        urgency TEXT,
                        description TEXT,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(cve_id, package_name, release_name)
                    );

                    CREATE INDEX IF NOT EXISTS idx_debian_cve_package
                    ON debian_security_data(cve_id, package_name);

                    CREATE INDEX IF NOT EXISTS idx_debian_package_release
                    ON debian_security_data(package_name, release_name);

                    CREATE TABLE IF NOT EXISTS debian_data_meta (
                        id INTEGER PRIMARY KEY,
                        last_download TIMESTAMP,
                        data_size INTEGER,
                        cve_count INTEGER
                    );
                """)
                logger.info("Debian security cache database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Debian cache database: {e}")

    def should_update_data(self) -> bool:
        """Check if we should download fresh data from Debian Security Tracker."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT last_download FROM debian_data_meta ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()

                if not row:
                    return True  # No data yet

                last_download = datetime.fromisoformat(row[0])
                # Update daily
                return datetime.now() - last_download > timedelta(days=1)

        except Exception as e:
            logger.error(f"Error checking update status: {e}")
            return True

    def download_and_cache_debian_data(self) -> bool:
        """Download Debian Security Tracker data and cache it locally."""
        if not self.should_update_data():
            logger.info("Debian security data is up to date")
            return True

        try:
            logger.info("Downloading Debian Security Tracker data...")
            response = self.session.get(self.json_url, timeout=300)
            response.raise_for_status()

            # Handle response - try JSON first, then gzip if needed
            try:
                data = response.json()
            except json.JSONDecodeError:
                # Try gzipped content
                try:
                    data = json.loads(gzip.decompress(response.content).decode('utf-8'))
                except Exception as e:
                    logger.error(f"Failed to parse response as JSON or gzipped JSON: {e}")
                    return False

            logger.info(f"Downloaded {len(data)} CVE entries from Debian Security Tracker")

            # Clear old data and insert new
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()

                # Clear existing data
                cursor.execute("DELETE FROM debian_security_data")
                cursor.execute("DELETE FROM debian_data_meta")

                # Insert new data - data is organized by package, then CVE
                cve_count = 0
                record_count = 0

                for package_name, package_data in data.items():
                    if not isinstance(package_data, dict):
                        continue

                    # Each package contains CVE entries
                    for cve_id, cve_data in package_data.items():
                        if not cve_id.startswith('CVE-'):
                            continue

                        cve_count += 1

                        # CVE data contains releases information
                        if isinstance(cve_data, dict) and 'releases' in cve_data:
                            releases = cve_data['releases']
                            for release_name, release_info in releases.items():
                                # release_info contains the package status directly
                                if isinstance(release_info, dict):
                                    cursor.execute("""
                                        INSERT OR REPLACE INTO debian_security_data
                                        (cve_id, package_name, release_name, status, fixed_version, urgency, description)
                                        VALUES (?, ?, ?, ?, ?, ?, ?)
                                    """, (
                                        cve_id,
                                        package_name,
                                        release_name,
                                        release_info.get('status', 'unknown'),
                                        release_info.get('fixed_version', ''),
                                        release_info.get('urgency', ''),
                                        cve_data.get('description', '')
                                    ))
                                    record_count += 1

                # Update metadata
                cursor.execute("""
                    INSERT INTO debian_data_meta (last_download, data_size, cve_count)
                    VALUES (?, ?, ?)
                """, (datetime.now(), len(response.content), cve_count))

                logger.info(f"Cached {cve_count} CVEs with Debian security data")
                return True

        except Exception as e:
            logger.error(f"Error downloading/caching Debian data: {e}")
            return False

    def lookup_debian_security_info(self, cve_id: str, package_name: str,
                                  release: str = 'bookworm') -> Optional[Dict]:
        """
        Look up Debian security information for a specific CVE and package.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-47100')
            package_name: Debian package name (e.g., 'perl')
            release: Debian release name (default: 'bookworm' for Debian 12)

        Returns:
            Dict with security information or None if not found
        """
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT status, fixed_version, urgency, description, last_updated
                    FROM debian_security_data
                    WHERE cve_id = ? AND package_name = ? AND release_name = ?
                """, (cve_id, package_name, release))

                row = cursor.fetchone()
                if row:
                    status, fixed_version, urgency, description, last_updated = row
                    return {
                        'found': True,
                        'status': status,
                        'fixed_version': fixed_version if fixed_version else None,
                        'urgency': urgency,
                        'description': description,
                        'release': release,
                        'last_updated': last_updated,
                        'is_vulnerable': status not in ['not-affected', 'fixed', 'resolved'],
                        'confidence_score': 0.95  # High confidence for official Debian data
                    }

                return {
                    'found': False,
                    'reason': f'No Debian security data found for {cve_id} in package {package_name}',
                    'confidence_score': 0.8
                }

        except Exception as e:
            logger.error(f"Error looking up Debian security info: {e}")
            return None

    def get_package_security_status(self, package_name: str,
                                  release: str = 'bookworm') -> List[Dict]:
        """Get all security issues for a specific package in a release."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT cve_id, status, fixed_version, urgency, description
                    FROM debian_security_data
                    WHERE package_name = ? AND release_name = ?
                    ORDER BY cve_id DESC
                """, (package_name, release))

                results = []
                for row in cursor.fetchall():
                    cve_id, status, fixed_version, urgency, description = row
                    results.append({
                        'cve_id': cve_id,
                        'status': status,
                        'fixed_version': fixed_version,
                        'urgency': urgency,
                        'description': description,
                        'is_vulnerable': status not in ['not-affected', 'fixed']
                    })

                return results

        except Exception as e:
            logger.error(f"Error getting package security status: {e}")
            return []

    def enhance_vulnerability_with_debian_data(self, vulnerability: Dict) -> Dict:
        """
        Enhance a vulnerability with Debian security data.

        This is the main integration point with the vulnerability analysis system.
        """
        cve_id = vulnerability.get('cve_id', '')
        package_name = vulnerability.get('affected_package', '')
        installed_version = vulnerability.get('installed_version', '')

        # Determine Debian release from installed version
        release = self._detect_debian_release(installed_version)

        # Look up Debian security data
        debian_info = self.lookup_debian_security_info(cve_id, package_name, release)

        if debian_info and debian_info.get('found'):
            # Enhance the vulnerability with Debian data
            enhanced = vulnerability.copy()
            enhanced.update({
                'debian_status': debian_info['status'],
                'debian_fixed_version': debian_info['fixed_version'],
                'debian_urgency': debian_info['urgency'],
                'debian_release': release,
                'enhanced_by_debian': True
            })

            # Override vulnerability status if Debian says it's fixed/not-affected/resolved
            if debian_info['status'] in ['not-affected', 'fixed', 'resolved']:
                enhanced['is_vulnerable_debian'] = False
                enhanced['confidence_score'] = debian_info['confidence_score']

                # If Debian has a fixed version, use it
                if debian_info['fixed_version']:
                    enhanced['fixed_version'] = debian_info['fixed_version']
            else:
                enhanced['is_vulnerable_debian'] = True

            logger.info(f"Enhanced {cve_id} with Debian data: {debian_info['status']}")
            return enhanced

        return vulnerability

    def _detect_debian_release(self, installed_version: str) -> str:
        """Detect Debian release from package version string."""
        if '+deb12' in installed_version:
            return 'bookworm'  # Debian 12
        elif '+deb11' in installed_version:
            return 'bullseye'  # Debian 11
        elif '+deb10' in installed_version:
            return 'buster'    # Debian 10
        else:
            return 'bookworm'  # Default to current stable

    def get_cache_stats(self) -> Dict:
        """Get statistics about the cached Debian data."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                cursor = conn.cursor()

                # Get metadata
                cursor.execute("SELECT last_download, cve_count FROM debian_data_meta ORDER BY id DESC LIMIT 1")
                meta_row = cursor.fetchone()

                # Get record counts
                cursor.execute("SELECT COUNT(*) FROM debian_security_data")
                total_records = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(DISTINCT cve_id) FROM debian_security_data")
                unique_cves = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(DISTINCT package_name) FROM debian_security_data")
                unique_packages = cursor.fetchone()[0]

                return {
                    'last_download': meta_row[0] if meta_row else None,
                    'total_cves': meta_row[1] if meta_row else 0,
                    'total_records': total_records,
                    'unique_cves': unique_cves,
                    'unique_packages': unique_packages,
                    'cache_file': self.cache_db_path
                }

        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}

    def force_update(self) -> bool:
        """Force an update of Debian security data."""
        try:
            with sqlite3.connect(self.cache_db_path) as conn:
                conn.execute("DELETE FROM debian_data_meta")
            return self.download_and_cache_debian_data()
        except Exception as e:
            logger.error(f"Error forcing update: {e}")
            return False
