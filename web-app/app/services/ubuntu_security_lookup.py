"""
Ubuntu Security Notices (USN) integration for enhanced vulnerability analysis.
Downloads and caches Ubuntu security data in PostgreSQL for fast lookups.
"""

import json
import logging
import requests
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models.base import get_db

logger = logging.getLogger(__name__)


class UbuntuSecurityLookup:
    """Ubuntu Security Notices (USN) data integration with PostgreSQL caching."""

    def __init__(self):
        self.usn_json_url = "https://usn.ubuntu.com/usn.json"
        self.cve_tracker_base = "https://people.canonical.com/~ubuntu-security/cve"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept-Encoding': 'gzip, deflate'
        })

        logger.info("Ubuntu Security Lookup initialized with PostgreSQL backend")

    def should_update_data(self) -> bool:
        """Check if we should download fresh data from Ubuntu Security."""
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT last_download FROM ubuntu_data_meta
                ORDER BY id DESC LIMIT 1
            """))
            row = result.fetchone()

            if not row:
                return True  # No data yet

            last_download = row[0]
            if last_download:
                # Update daily
                return datetime.now(timezone.utc) - last_download > timedelta(days=1)

            return True

        except Exception as e:
            logger.error(f"Error checking Ubuntu update status: {e}")
            return True
        finally:
            db.close()

    def download_and_cache_ubuntu_data(self) -> bool:
        """Download Ubuntu Security Notices data and cache it in PostgreSQL."""
        if not self.should_update_data():
            logger.info("Ubuntu security data is up to date")
            return True

        try:
            logger.info("Downloading Ubuntu Security Notices data...")
            response = self.session.get(self.usn_json_url, timeout=300)
            response.raise_for_status()

            data = response.json()
            logger.info(f"Downloaded {len(data)} USN entries from Ubuntu Security")

            db = next(get_db())

            # Clear old data
            db.execute(text("DELETE FROM ubuntu_security_data"))
            db.execute(text("DELETE FROM ubuntu_data_meta"))

            # Insert new data - data is organized by USN ID
            usn_count = 0
            cve_count = 0
            record_count = 0

            for usn_id, usn_data in data.items():
                if not isinstance(usn_data, dict):
                    continue

                usn_count += 1

                # Extract CVEs from this USN
                cves = usn_data.get('cves', [])
                if isinstance(cves, str):
                    cves = [cves]

                # Extract releases and packages
                releases = usn_data.get('releases', {})
                priority = usn_data.get('priority', 'unknown')
                description = usn_data.get('description', '')

                for cve_id in cves:
                    if not cve_id.startswith('CVE-'):
                        continue

                    cve_count += 1

                    # Process each release (focal, jammy, etc.)
                    for release_name, release_data in releases.items():
                        if not isinstance(release_data, dict):
                            continue

                        # Process packages in this release
                        sources = release_data.get('sources', {})
                        for package_name, package_data in sources.items():
                            if not isinstance(package_data, dict):
                                continue

                            db.execute(text("""
                                INSERT INTO ubuntu_security_data
                                (cve_id, package_name, release_name, status, fixed_version,
                                 priority, usn_id, description)
                                VALUES (:cve_id, :package_name, :release_name, :status,
                                        :fixed_version, :priority, :usn_id, :description)
                                ON CONFLICT (cve_id, package_name, release_name)
                                DO UPDATE SET
                                    status = EXCLUDED.status,
                                    fixed_version = EXCLUDED.fixed_version,
                                    priority = EXCLUDED.priority,
                                    usn_id = EXCLUDED.usn_id,
                                    description = EXCLUDED.description,
                                    last_updated = NOW()
                            """), {
                                'cve_id': cve_id,
                                'package_name': package_name,
                                'release_name': release_name,
                                'status': package_data.get('status', 'unknown'),
                                'fixed_version': package_data.get('version', ''),
                                'priority': priority,
                                'usn_id': usn_id,
                                'description': description
                            })
                            record_count += 1

            # Update metadata
            db.execute(text("""
                INSERT INTO ubuntu_data_meta (last_download, data_size, usn_count, cve_count)
                VALUES (:last_download, :data_size, :usn_count, :cve_count)
            """), {
                'last_download': datetime.now(timezone.utc),
                'data_size': len(response.content),
                'usn_count': usn_count,
                'cve_count': cve_count
            })

            db.commit()
            logger.info(f"Cached {usn_count} USNs with {cve_count} CVEs and {record_count} package records")
            return True

        except Exception as e:
            logger.error(f"Error downloading/caching Ubuntu data: {e}")
            if 'db' in locals():
                db.rollback()
            return False
        finally:
            if 'db' in locals():
                db.close()

    def lookup_ubuntu_security_info(self, cve_id: str, package_name: str,
                                   release: str = 'jammy') -> Optional[Dict]:
        """
        Look up Ubuntu security information for a specific CVE and package.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-47100')
            package_name: Ubuntu package name (e.g., 'perl')
            release: Ubuntu release name (default: 'jammy' for Ubuntu 22.04)

        Returns:
            Dict with security information or None if not found
        """
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT status, fixed_version, priority, usn_id, description, last_updated
                FROM ubuntu_security_data
                WHERE cve_id = :cve_id AND package_name = :package_name AND release_name = :release_name
            """), {
                'cve_id': cve_id,
                'package_name': package_name,
                'release_name': release
            })

            row = result.fetchone()
            if row:
                status, fixed_version, priority, usn_id, description, last_updated = row
                return {
                    'found': True,
                    'status': status,
                    'fixed_version': fixed_version if fixed_version else None,
                    'priority': priority,
                    'usn_id': usn_id,
                    'description': description,
                    'release': release,
                    'last_updated': last_updated,
                    'is_vulnerable': status not in ['not-affected', 'released'],
                    'confidence_score': 0.95  # High confidence for official Ubuntu data
                }

            return {
                'found': False,
                'reason': f'No Ubuntu security data found for {cve_id} in package {package_name}',
                'confidence_score': 0.8
            }

        except Exception as e:
            logger.error(f"Error looking up Ubuntu security info: {e}")
            return None
        finally:
            if 'db' in locals():
                db.close()

    def get_package_security_status(self, package_name: str,
                                  release: str = 'jammy') -> List[Dict]:
        """Get all security issues for a specific package in a release."""
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT cve_id, status, fixed_version, priority, usn_id, description
                FROM ubuntu_security_data
                WHERE package_name = :package_name AND release_name = :release_name
                ORDER BY cve_id DESC
            """), {
                'package_name': package_name,
                'release_name': release
            })

            results = []
            for row in result.fetchall():
                cve_id, status, fixed_version, priority, usn_id, description = row
                results.append({
                    'cve_id': cve_id,
                    'status': status,
                    'fixed_version': fixed_version,
                    'priority': priority,
                    'usn_id': usn_id,
                    'description': description,
                    'is_vulnerable': status not in ['not-affected', 'released']
                })

            return results

        except Exception as e:
            logger.error(f"Error getting Ubuntu package security status: {e}")
            return []
        finally:
            if 'db' in locals():
                db.close()

    def enhance_vulnerability_with_ubuntu_data(self, vulnerability: Dict) -> Dict:
        """
        Enhance a vulnerability with Ubuntu security data.

        This is the main integration point with the vulnerability analysis system.
        """
        cve_id = vulnerability.get('cve_id', '')
        package_name = vulnerability.get('affected_package', '')
        installed_version = vulnerability.get('installed_version', '')

        # Determine Ubuntu release from installed version
        release = self._detect_ubuntu_release(installed_version)

        # Look up Ubuntu security data
        ubuntu_info = self.lookup_ubuntu_security_info(cve_id, package_name, release)

        if ubuntu_info and ubuntu_info.get('found'):
            # Enhance the vulnerability with Ubuntu data
            enhanced = vulnerability.copy()
            enhanced.update({
                'ubuntu_status': ubuntu_info['status'],
                'ubuntu_fixed_version': ubuntu_info['fixed_version'],
                'ubuntu_priority': ubuntu_info['priority'],
                'ubuntu_usn_id': ubuntu_info['usn_id'],
                'ubuntu_release': release,
                'enhanced_by_ubuntu': True
            })

            # Override vulnerability status if Ubuntu says it's not-affected/released
            if ubuntu_info['status'] in ['not-affected', 'released']:
                enhanced['is_vulnerable_ubuntu'] = False
                enhanced['confidence_score'] = ubuntu_info['confidence_score']

                # If Ubuntu has a fixed version, use it
                if ubuntu_info['fixed_version']:
                    enhanced['fixed_version'] = ubuntu_info['fixed_version']
            else:
                enhanced['is_vulnerable_ubuntu'] = True

            logger.info(f"Enhanced {cve_id} with Ubuntu data: {ubuntu_info['status']}")
            return enhanced

        return vulnerability

    def _detect_ubuntu_release(self, installed_version: str) -> str:
        """Detect Ubuntu release from package version string."""
        # Ubuntu version patterns
        if 'ubuntu' in installed_version.lower():
            # Look for ubuntu version indicators
            if '24.04' in installed_version or 'noble' in installed_version:
                return 'noble'    # Ubuntu 24.04
            elif '22.04' in installed_version or 'jammy' in installed_version:
                return 'jammy'    # Ubuntu 22.04
            elif '20.04' in installed_version or 'focal' in installed_version:
                return 'focal'    # Ubuntu 20.04
            elif '18.04' in installed_version or 'bionic' in installed_version:
                return 'bionic'   # Ubuntu 18.04

        # Check for Ubuntu-specific version suffixes
        if 'ubuntu' in installed_version:
            # Extract ubuntu version number
            match = re.search(r'ubuntu(\d+\.\d+)', installed_version)
            if match:
                ubuntu_ver = match.group(1)
                if ubuntu_ver >= '24.04':
                    return 'noble'
                elif ubuntu_ver >= '22.04':
                    return 'jammy'
                elif ubuntu_ver >= '20.04':
                    return 'focal'
                elif ubuntu_ver >= '18.04':
                    return 'bionic'

        # Default to current LTS
        return 'jammy'  # Ubuntu 22.04 LTS

    def get_cache_stats(self) -> Dict:
        """Get statistics about the cached Ubuntu data."""
        try:
            db = next(get_db())

            # Get metadata
            result = db.execute(text("""
                SELECT last_download, usn_count, cve_count
                FROM ubuntu_data_meta
                ORDER BY id DESC LIMIT 1
            """))
            meta_row = result.fetchone()

            # Get record counts
            result = db.execute(text("SELECT COUNT(*) FROM ubuntu_security_data"))
            total_records = result.scalar()

            result = db.execute(text("SELECT COUNT(DISTINCT cve_id) FROM ubuntu_security_data"))
            unique_cves = result.scalar()

            result = db.execute(text("SELECT COUNT(DISTINCT package_name) FROM ubuntu_security_data"))
            unique_packages = result.scalar()

            result = db.execute(text("SELECT COUNT(DISTINCT usn_id) FROM ubuntu_security_data"))
            unique_usns = result.scalar()

            return {
                'last_download': meta_row[0] if meta_row else None,
                'total_usns': meta_row[1] if meta_row else 0,
                'total_cves': meta_row[2] if meta_row else 0,
                'total_records': total_records,
                'unique_cves': unique_cves,
                'unique_packages': unique_packages,
                'unique_usns': unique_usns,
                'backend': 'PostgreSQL'
            }

        except Exception as e:
            logger.error(f"Error getting Ubuntu cache stats: {e}")
            return {}
        finally:
            if 'db' in locals():
                db.close()

    def force_update(self) -> bool:
        """Force an update of Ubuntu security data."""
        try:
            db = next(get_db())
            db.execute(text("DELETE FROM ubuntu_data_meta"))
            db.commit()
            return self.download_and_cache_ubuntu_data()
        except Exception as e:
            logger.error(f"Error forcing Ubuntu update: {e}")
            return False
        finally:
            if 'db' in locals():
                db.close()
