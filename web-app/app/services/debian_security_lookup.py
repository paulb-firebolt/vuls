"""
Debian Security Tracker integration for enhanced vulnerability analysis.
Downloads and caches Debian security data in PostgreSQL for fast lookups.
"""

import json
import logging
import requests
import gzip
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models.base import get_db

logger = logging.getLogger(__name__)


class DebianSecurityLookup:
    """Debian Security Tracker data integration with PostgreSQL caching."""

    def __init__(self):
        self.json_url = "https://security-tracker.debian.org/tracker/data/json"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept-Encoding': 'gzip, deflate'
        })

        logger.info("Debian Security Lookup initialized with PostgreSQL backend")

    def should_update_data(self) -> bool:
        """Check if we should download fresh data from Debian Security Tracker."""
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT last_download FROM debian_data_meta
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
            logger.error(f"Error checking Debian update status: {e}")
            return True
        finally:
            db.close()

    def download_and_cache_debian_data(self) -> bool:
        """Download Debian Security Tracker data and cache it in PostgreSQL."""
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

            db = next(get_db())

            # Clear old data
            db.execute(text("DELETE FROM debian_security_data"))
            db.execute(text("DELETE FROM debian_data_meta"))

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
                        description = cve_data.get('description', '')

                        for release_name, release_info in releases.items():
                            # release_info contains the package status directly
                            if isinstance(release_info, dict):
                                db.execute(text("""
                                    INSERT INTO debian_security_data
                                    (cve_id, package_name, release_name, status, fixed_version, urgency, description)
                                    VALUES (:cve_id, :package_name, :release_name, :status,
                                            :fixed_version, :urgency, :description)
                                    ON CONFLICT (cve_id, package_name, release_name)
                                    DO UPDATE SET
                                        status = EXCLUDED.status,
                                        fixed_version = EXCLUDED.fixed_version,
                                        urgency = EXCLUDED.urgency,
                                        description = EXCLUDED.description,
                                        last_updated = NOW()
                                """), {
                                    'cve_id': cve_id,
                                    'package_name': package_name,
                                    'release_name': release_name,
                                    'status': release_info.get('status', 'unknown'),
                                    'fixed_version': release_info.get('fixed_version', ''),
                                    'urgency': release_info.get('urgency', ''),
                                    'description': description
                                })
                                record_count += 1

            # Update metadata
            db.execute(text("""
                INSERT INTO debian_data_meta (last_download, data_size, cve_count)
                VALUES (:last_download, :data_size, :cve_count)
            """), {
                'last_download': datetime.now(timezone.utc),
                'data_size': len(response.content),
                'cve_count': cve_count
            })

            db.commit()
            logger.info(f"Cached {cve_count} CVEs with Debian security data")
            return True

        except Exception as e:
            logger.error(f"Error downloading/caching Debian data: {e}")
            if 'db' in locals():
                db.rollback()
            return False
        finally:
            if 'db' in locals():
                db.close()

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
            db = next(get_db())
            result = db.execute(text("""
                SELECT status, fixed_version, urgency, description, last_updated
                FROM debian_security_data
                WHERE cve_id = :cve_id AND package_name = :package_name AND release_name = :release_name
            """), {
                'cve_id': cve_id,
                'package_name': package_name,
                'release_name': release
            })

            row = result.fetchone()
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
        finally:
            if 'db' in locals():
                db.close()

    def get_package_security_status(self, package_name: str,
                                  release: str = 'bookworm') -> List[Dict]:
        """Get all security issues for a specific package in a release."""
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT cve_id, status, fixed_version, urgency, description
                FROM debian_security_data
                WHERE package_name = :package_name AND release_name = :release_name
                ORDER BY cve_id DESC
            """), {
                'package_name': package_name,
                'release_name': release
            })

            results = []
            for row in result.fetchall():
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
            logger.error(f"Error getting Debian package security status: {e}")
            return []
        finally:
            if 'db' in locals():
                db.close()

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
            db = next(get_db())

            # Get metadata
            result = db.execute(text("""
                SELECT last_download, cve_count
                FROM debian_data_meta
                ORDER BY id DESC LIMIT 1
            """))
            meta_row = result.fetchone()

            # Get record counts
            result = db.execute(text("SELECT COUNT(*) FROM debian_security_data"))
            total_records = result.scalar()

            result = db.execute(text("SELECT COUNT(DISTINCT cve_id) FROM debian_security_data"))
            unique_cves = result.scalar()

            result = db.execute(text("SELECT COUNT(DISTINCT package_name) FROM debian_security_data"))
            unique_packages = result.scalar()

            return {
                'last_download': meta_row[0] if meta_row else None,
                'total_cves': meta_row[1] if meta_row else 0,
                'total_records': total_records,
                'unique_cves': unique_cves,
                'unique_packages': unique_packages,
                'backend': 'PostgreSQL'
            }

        except Exception as e:
            logger.error(f"Error getting Debian cache stats: {e}")
            return {}
        finally:
            if 'db' in locals():
                db.close()

    def force_update(self) -> bool:
        """Force an update of Debian security data."""
        try:
            db = next(get_db())
            db.execute(text("DELETE FROM debian_data_meta"))
            db.commit()
            return self.download_and_cache_debian_data()
        except Exception as e:
            logger.error(f"Error forcing Debian update: {e}")
            return False
        finally:
            if 'db' in locals():
                db.close()
