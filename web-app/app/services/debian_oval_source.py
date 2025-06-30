"""
Debian OVAL Database Downloader and PostgreSQL Integration
Downloads OVAL XML databases from Debian and processes them into PostgreSQL.
"""

import logging
import requests
import bz2
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models.base import get_db
from .base_vulnerability_source import BaseOVALSource

logger = logging.getLogger(__name__)


class DebianOVALSource(BaseOVALSource):
    """Downloads and processes Debian OVAL databases into PostgreSQL."""

    def __init__(self):
        super().__init__("debian_oval", "Debian")
        self.oval_base_url = "https://www.debian.org/security/oval"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept-Encoding': 'gzip, deflate'
        })

        # Debian release mapping
        self.debian_releases = {
            '12': {
                'codename': 'bookworm',
                'filename': 'oval-definitions-bookworm.xml.bz2',
                'version': '12'
            },
            '11': {
                'codename': 'bullseye',
                'filename': 'oval-definitions-bullseye.xml.bz2',
                'version': '11'
            },
            '10': {
                'codename': 'buster',
                'filename': 'oval-definitions-buster.xml.bz2',
                'version': '10'
            },
            '9': {
                'codename': 'stretch',
                'filename': 'oval-definitions-stretch.xml.bz2',
                'version': '9'
            },
            '8': {
                'codename': 'jessie',
                'filename': 'oval-definitions-jessie.xml.bz2',
                'version': '8'
            },
            '7': {
                'codename': 'wheezy',
                'filename': 'oval-definitions-wheezy.xml.bz2',
                'version': '7'
            }
        }

        logger.info("Debian OVAL Source initialized")

    def get_oval_url(self, release: str) -> str:
        """Get the OVAL download URL for a specific release."""
        if release not in self.debian_releases:
            raise ValueError(f"Unsupported Debian release: {release}")

        filename = self.debian_releases[release]['filename']
        return f"{self.oval_base_url}/{filename}"

    def should_update_data(self, release: str = None, **kwargs) -> bool:
        """Check if we should download fresh OVAL data for a release."""
        if not release:
            # Check if any release needs updating
            for rel in self.debian_releases.keys():
                if self.should_update_data(release=rel):
                    return True
            return False

        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT last_download FROM debian_oval_meta
                WHERE release_version = :release
                ORDER BY id DESC LIMIT 1
            """), {'release': release})
            row = result.fetchone()

            if not row:
                return True  # No data yet

            last_download = row[0]
            if last_download:
                # Update weekly for OVAL data
                return datetime.now(timezone.utc) - last_download > timedelta(days=7)

            return True

        except Exception as e:
            logger.error(f"Error checking OVAL update status for {release}: {e}")
            return True
        finally:
            db.close()

    def download_oval_file(self, release: str) -> Optional[bytes]:
        """Download and decompress OVAL file for a specific release."""
        try:
            url = self.get_oval_url(release)
            logger.info(f"Downloading OVAL data for Debian {release} from {url}")

            response = self.session.get(url, timeout=600)  # 10 minutes timeout
            response.raise_for_status()

            # Decompress bz2 data
            decompressed_data = bz2.decompress(response.content)
            logger.info(f"Downloaded and decompressed {len(decompressed_data)} bytes for Debian {release}")

            return decompressed_data

        except Exception as e:
            logger.error(f"Error downloading OVAL file for Debian {release}: {e}")
            return None

    def parse_oval_definition(self, definition_element: Any) -> Dict:
        """Parse an OVAL definition element."""
        try:
            def_id = definition_element.get('id', '')

            # Extract metadata
            metadata = definition_element.find('oval-def:metadata', self.namespaces)
            if metadata is None:
                return {}

            title_elem = metadata.find('oval-def:title', self.namespaces)
            title = title_elem.text if title_elem is not None else ''

            description_elem = metadata.find('oval-def:description', self.namespaces)
            description = description_elem.text if description_elem is not None else ''

            # Extract affected information
            affected = metadata.find('oval-def:affected', self.namespaces)
            family = ''
            if affected is not None:
                family = affected.get('family', '')

            # Extract severity from advisory if present
            advisory = metadata.find('oval-def:advisory', self.namespaces)
            severity = ''
            issued = None
            updated = None

            if advisory is not None:
                severity_elem = advisory.find('oval-def:severity', self.namespaces)
                if severity_elem is not None:
                    severity = severity_elem.text

                issued_elem = advisory.find('oval-def:issued', self.namespaces)
                if issued_elem is not None:
                    try:
                        issued = datetime.fromisoformat(issued_elem.get('date', '').replace('Z', '+00:00'))
                    except:
                        pass

                updated_elem = advisory.find('oval-def:updated', self.namespaces)
                if updated_elem is not None:
                    try:
                        updated = datetime.fromisoformat(updated_elem.get('date', '').replace('Z', '+00:00'))
                    except:
                        pass

            return {
                'definition_id': def_id,
                'title': title,
                'description': description,
                'severity': severity,
                'family': family,
                'class_type': definition_element.get('class', ''),
                'advisory_issued': issued,
                'advisory_updated': updated,
                'metadata': metadata
            }

        except Exception as e:
            logger.error(f"Error parsing OVAL definition: {e}")
            return {}

    def extract_package_info(self, definition: Dict) -> List[Dict]:
        """Extract package information from an OVAL definition."""
        packages = []

        try:
            metadata = definition.get('metadata')
            if metadata is None:
                return packages

            # Find affected packages
            affected = metadata.find('oval-def:affected', self.namespaces)
            if affected is not None:
                for product in affected.findall('oval-def:product', self.namespaces):
                    package_name = product.text
                    if package_name:
                        packages.append({
                            'package_name': package_name,
                            'version': None,  # OVAL doesn't always specify fixed version directly
                            'architecture': None,
                            'not_fixed_yet': False
                        })

        except Exception as e:
            logger.error(f"Error extracting package info: {e}")

        return packages

    def extract_references(self, definition: Dict) -> List[Dict]:
        """Extract references (CVEs, DSAs) from an OVAL definition."""
        references = []

        try:
            metadata = definition.get('metadata')
            if metadata is None:
                return references

            # Extract references
            for ref in metadata.findall('oval-def:reference', self.namespaces):
                source = ref.get('source', '')
                ref_id = ref.get('ref_id', '')
                ref_url = ref.get('ref_url', '')

                if ref_id:
                    references.append({
                        'source': source,
                        'ref_id': ref_id,
                        'ref_url': ref_url
                    })

        except Exception as e:
            logger.error(f"Error extracting references: {e}")

        return references

    def download_and_cache_data(self, release: str = None, **kwargs) -> bool:
        """Download and cache OVAL data for specified release(s)."""
        releases_to_update = []

        if release:
            if release not in self.debian_releases:
                logger.error(f"Unsupported Debian release: {release}")
                return False
            releases_to_update = [release]
        else:
            # Update all releases that need updating
            for rel in self.debian_releases.keys():
                if self.should_update_data(release=rel):
                    releases_to_update.append(rel)

        if not releases_to_update:
            logger.info("All Debian OVAL data is up to date")
            return True

        success = True
        for rel in releases_to_update:
            if not self._download_and_cache_release(rel):
                success = False

        return success

    def _download_and_cache_release(self, release: str) -> bool:
        """Download and cache OVAL data for a specific release."""
        try:
            # Download OVAL file
            oval_data = self.download_oval_file(release)
            if not oval_data:
                return False

            # Parse XML
            logger.info(f"Parsing OVAL XML for Debian {release}")
            root = ET.fromstring(oval_data)

            # Find definitions
            definitions_elem = root.find('oval-def:definitions', self.namespaces)
            if definitions_elem is None:
                logger.error(f"No definitions found in OVAL file for Debian {release}")
                return False

            db = next(get_db())

            # Clear old data for this release
            db.execute(text("""
                DELETE FROM debian_oval_definitions WHERE release_version = :release
            """), {'release': release})

            # Process definitions
            definitions_count = 0
            packages_count = 0
            cves_count = 0

            for definition_elem in definitions_elem.findall('oval-def:definition', self.namespaces):
                definition = self.parse_oval_definition(definition_elem)
                if not definition.get('definition_id'):
                    continue

                # Insert definition
                result = db.execute(text("""
                    INSERT INTO debian_oval_definitions
                    (definition_id, release_version, title, description, severity, family, class_type)
                    VALUES (:definition_id, :release_version, :title, :description, :severity, :family, :class_type)
                    RETURNING id
                """), {
                    'definition_id': definition['definition_id'],
                    'release_version': release,
                    'title': definition['title'],
                    'description': definition['description'],
                    'severity': definition['severity'],
                    'family': definition['family'],
                    'class_type': definition['class_type']
                })

                def_db_id = result.scalar()
                definitions_count += 1

                # Insert packages
                packages = self.extract_package_info(definition)
                for package in packages:
                    db.execute(text("""
                        INSERT INTO debian_oval_packages
                        (definition_id, package_name, version, architecture, not_fixed_yet)
                        VALUES (:definition_id, :package_name, :version, :architecture, :not_fixed_yet)
                    """), {
                        'definition_id': def_db_id,
                        'package_name': package['package_name'],
                        'version': package['version'],
                        'architecture': package['architecture'],
                        'not_fixed_yet': package['not_fixed_yet']
                    })
                    packages_count += 1

                # Insert references
                references = self.extract_references(definition)
                for reference in references:
                    db.execute(text("""
                        INSERT INTO debian_oval_references
                        (definition_id, source, ref_id, ref_url)
                        VALUES (:definition_id, :source, :ref_id, :ref_url)
                    """), {
                        'definition_id': def_db_id,
                        'source': reference['source'],
                        'ref_id': reference['ref_id'],
                        'ref_url': reference['ref_url']
                    })

                    if reference['ref_id'].startswith('CVE-'):
                        cves_count += 1

                # Insert advisory if present
                if definition.get('advisory_issued') or definition.get('advisory_updated'):
                    db.execute(text("""
                        INSERT INTO debian_oval_advisories
                        (definition_id, severity, issued, updated)
                        VALUES (:definition_id, :severity, :issued, :updated)
                    """), {
                        'definition_id': def_db_id,
                        'severity': definition['severity'],
                        'issued': definition.get('advisory_issued'),
                        'updated': definition.get('advisory_updated')
                    })

            # Update metadata
            db.execute(text("""
                INSERT INTO debian_oval_meta
                (release_version, last_download, file_size, definitions_count, packages_count, cves_count, download_url)
                VALUES (:release_version, :last_download, :file_size, :definitions_count, :packages_count, :cves_count, :download_url)
                ON CONFLICT (release_version) DO UPDATE SET
                    last_download = EXCLUDED.last_download,
                    file_size = EXCLUDED.file_size,
                    definitions_count = EXCLUDED.definitions_count,
                    packages_count = EXCLUDED.packages_count,
                    cves_count = EXCLUDED.cves_count,
                    download_url = EXCLUDED.download_url
            """), {
                'release_version': release,
                'last_download': datetime.now(timezone.utc),
                'file_size': len(oval_data),
                'definitions_count': definitions_count,
                'packages_count': packages_count,
                'cves_count': cves_count,
                'download_url': self.get_oval_url(release)
            })

            db.commit()
            logger.info(f"Cached Debian {release} OVAL data: {definitions_count} definitions, {packages_count} packages, {cves_count} CVEs")
            return True

        except Exception as e:
            logger.error(f"Error caching OVAL data for Debian {release}: {e}")
            if 'db' in locals():
                db.rollback()
            return False
        finally:
            if 'db' in locals():
                db.close()

    def lookup_vulnerability_info(self, cve_id: str, package_name: str, release: str = '12', **kwargs) -> Optional[Dict]:
        """Look up vulnerability information from OVAL data."""
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT d.definition_id, d.title, d.description, d.severity, p.version, p.not_fixed_yet
                FROM debian_oval_definitions d
                JOIN debian_oval_packages p ON d.id = p.definition_id
                JOIN debian_oval_references r ON d.id = r.definition_id
                WHERE r.ref_id = :cve_id AND p.package_name = :package_name AND d.release_version = :release
                LIMIT 1
            """), {
                'cve_id': cve_id,
                'package_name': package_name,
                'release': release
            })

            row = result.fetchone()
            if row:
                definition_id, title, description, severity, version, not_fixed_yet = row
                return {
                    'found': True,
                    'source': 'OVAL',
                    'definition_id': definition_id,
                    'title': title,
                    'description': description,
                    'severity': severity,
                    'fixed_version': version,
                    'not_fixed_yet': not_fixed_yet,
                    'release': release,
                    'confidence_score': 0.90
                }

            return {
                'found': False,
                'reason': f'No OVAL data found for {cve_id} in package {package_name}',
                'confidence_score': 0.80
            }

        except Exception as e:
            logger.error(f"Error looking up OVAL vulnerability info: {e}")
            return None
        finally:
            if 'db' in locals():
                db.close()

    def get_package_vulnerabilities(self, package_name: str, release: str = '12', **kwargs) -> List[Dict]:
        """Get all vulnerabilities for a specific package from OVAL data."""
        try:
            db = next(get_db())
            result = db.execute(text("""
                SELECT r.ref_id, d.definition_id, d.title, d.severity, p.version, p.not_fixed_yet
                FROM debian_oval_definitions d
                JOIN debian_oval_packages p ON d.id = p.definition_id
                JOIN debian_oval_references r ON d.id = r.definition_id
                WHERE p.package_name = :package_name AND d.release_version = :release
                AND r.ref_id LIKE 'CVE-%'
                ORDER BY r.ref_id DESC
            """), {
                'package_name': package_name,
                'release': release
            })

            vulnerabilities = []
            for row in result.fetchall():
                cve_id, definition_id, title, severity, version, not_fixed_yet = row
                vulnerabilities.append({
                    'cve_id': cve_id,
                    'definition_id': definition_id,
                    'title': title,
                    'severity': severity,
                    'fixed_version': version,
                    'not_fixed_yet': not_fixed_yet,
                    'source': 'OVAL'
                })

            return vulnerabilities

        except Exception as e:
            logger.error(f"Error getting OVAL package vulnerabilities: {e}")
            return []
        finally:
            if 'db' in locals():
                db.close()

    def get_cache_stats(self) -> Dict:
        """Get statistics about cached OVAL data."""
        try:
            db = next(get_db())

            stats = {}
            for release in self.debian_releases.keys():
                result = db.execute(text("""
                    SELECT last_download, definitions_count, packages_count, cves_count, file_size
                    FROM debian_oval_meta
                    WHERE release_version = :release
                """), {'release': release})

                row = result.fetchone()
                if row:
                    last_download, definitions_count, packages_count, cves_count, file_size = row
                    stats[release] = {
                        'last_download': last_download,
                        'definitions_count': definitions_count,
                        'packages_count': packages_count,
                        'cves_count': cves_count,
                        'file_size': file_size
                    }
                else:
                    stats[release] = {
                        'last_download': None,
                        'definitions_count': 0,
                        'packages_count': 0,
                        'cves_count': 0,
                        'file_size': 0
                    }

            return {
                'source_name': self.source_name,
                'source_type': self.source_type,
                'releases': stats,
                'backend': 'PostgreSQL'
            }

        except Exception as e:
            logger.error(f"Error getting OVAL cache stats: {e}")
            return {}
        finally:
            if 'db' in locals():
                db.close()

    def enhance_vulnerability(self, vulnerability: Dict) -> Dict:
        """Enhance a vulnerability with OVAL data."""
        cve_id = vulnerability.get('cve_id', '')
        package_name = vulnerability.get('affected_package', '')

        # Detect Debian release
        release = self._detect_debian_release(vulnerability.get('installed_version', ''))

        # Look up OVAL data
        oval_info = self.lookup_vulnerability_info(cve_id, package_name, release)

        if oval_info and oval_info.get('found'):
            enhanced = vulnerability.copy()
            enhanced.update({
                'oval_definition_id': oval_info['definition_id'],
                'oval_title': oval_info['title'],
                'oval_severity': oval_info['severity'],
                'oval_fixed_version': oval_info['fixed_version'],
                'oval_not_fixed_yet': oval_info['not_fixed_yet'],
                'enhanced_by_oval': True
            })

            logger.info(f"Enhanced {cve_id} with OVAL data: {oval_info['definition_id']}")
            return enhanced

        return vulnerability

    def _detect_debian_release(self, installed_version: str) -> str:
        """Detect Debian release from package version string."""
        # Debian version patterns
        if '+deb12' in installed_version or 'bookworm' in installed_version.lower():
            return '12'
        elif '+deb11' in installed_version or 'bullseye' in installed_version.lower():
            return '11'
        elif '+deb10' in installed_version or 'buster' in installed_version.lower():
            return '10'
        elif '+deb9' in installed_version or 'stretch' in installed_version.lower():
            return '9'
        elif '+deb8' in installed_version or 'jessie' in installed_version.lower():
            return '8'
        elif '+deb7' in installed_version or 'wheezy' in installed_version.lower():
            return '7'

        # Default to current stable (Debian 12)
        return '12'
