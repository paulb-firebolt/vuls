"""NVD Bulk CVE Import Service using pagination API."""

import logging
import requests
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models.base import get_db
from ..models.nvd_cve_cache import NVDCVECache

logger = logging.getLogger(__name__)


class NVDBulkImporter:
    """Bulk import CVEs from NVD API using pagination."""

    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/1.0 (Security Research)',
            'Accept': 'application/json'
        })

        # Rate limiting - NVD allows 5 requests per 30 seconds without API key
        self.rate_limit_delay = 6  # seconds between requests
        self.last_request_time = 0

        logger.info("NVD Bulk Importer initialized")

    def _rate_limit(self, show_progress=False):
        """Enforce rate limiting for NVD API requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            if show_progress:
                logger.info(f"Rate limiting: waiting {sleep_time:.1f}s before next API call...")
            else:
                logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def bulk_import_recent_cves(self, days_back: int = 30, max_cves: int = 10000) -> Dict:
        """
        Import recent CVEs from NVD using bulk pagination.

        Args:
            days_back: Number of days back to import CVEs from
            max_cves: Maximum number of CVEs to import in this run

        Returns:
            Dict with import statistics
        """
        logger.info(f"Starting bulk import of CVEs from last {days_back} days")

        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)

        # Format dates for NVD API
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        stats = {
            "start_time": datetime.now(timezone.utc),
            "date_range": f"{start_date_str} to {end_date_str}",
            "total_processed": 0,
            "newly_cached": 0,
            "already_cached": 0,
            "errors": 0,
            "api_calls": 0,
            "pages_processed": 0
        }

        try:
            db = next(get_db())

            # Start pagination
            start_index = 0
            results_per_page = 2000  # Maximum allowed by NVD

            while stats["total_processed"] < max_cves:
                # Rate limit with progress indication
                self._rate_limit(show_progress=True)

                # Build API request
                params = {
                    "pubStartDate": start_date_str,
                    "pubEndDate": end_date_str,
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "noRejected": ""  # Exclude rejected CVEs
                }

                logger.info(f"🔄 Fetching CVEs: page {stats['pages_processed'] + 1}, startIndex={start_index}")
                logger.info(f"📊 Progress: {stats['newly_cached']} new, {stats['already_cached']} cached, {stats['errors']} errors")

                try:
                    response = self.session.get(self.nvd_api_base, params=params, timeout=60)

                    # Handle rate limiting specifically
                    if response.status_code == 429:
                        logger.warning("⚠️  Rate limited by NVD API, waiting longer...")
                        time.sleep(30)  # Wait longer for rate limit
                        continue

                    response.raise_for_status()
                    stats["api_calls"] += 1

                    data = response.json()

                    # Extract pagination info
                    total_results = data.get("totalResults", 0)
                    vulnerabilities = data.get("vulnerabilities", [])

                    logger.info(f"✅ Received {len(vulnerabilities)} CVEs (total available: {total_results:,})")

                    if not vulnerabilities:
                        logger.info("🏁 No more CVEs to process")
                        break

                    # Process each CVE
                    for vuln_data in vulnerabilities:
                        if stats["total_processed"] >= max_cves:
                            logger.info(f"🎯 Reached max CVEs limit ({max_cves})")
                            break

                        cve_result = self._process_cve(vuln_data, db)

                        if cve_result == "newly_cached":
                            stats["newly_cached"] += 1
                        elif cve_result == "already_cached":
                            stats["already_cached"] += 1
                        elif cve_result == "error":
                            stats["errors"] += 1

                        stats["total_processed"] += 1

                        if stats["total_processed"] % 100 == 0:
                            elapsed = (datetime.now(timezone.utc) - stats["start_time"]).total_seconds()
                            rate = stats["total_processed"] / elapsed if elapsed > 0 else 0
                            logger.info(f"📈 Processed {stats['total_processed']:,} CVEs ({rate:.1f} CVEs/sec)")

                    stats["pages_processed"] += 1

                    # Check if we've processed all available results
                    if start_index + len(vulnerabilities) >= total_results:
                        logger.info("🏁 Reached end of available CVEs")
                        break

                    # Update start index for next page
                    start_index += len(vulnerabilities)

                except requests.exceptions.RequestException as e:
                    if "429" in str(e):
                        logger.warning(f"⚠️  Rate limited: {e}, waiting 60s...")
                        time.sleep(60)
                        continue
                    else:
                        logger.error(f"❌ API request failed: {e}")
                        stats["errors"] += 1
                        break
                except Exception as e:
                    logger.error(f"❌ Error processing API response: {e}")
                    stats["errors"] += 1
                    break

            # Commit any pending transactions
            db.commit()

        except Exception as e:
            logger.error(f"Error in bulk import: {e}")
            stats["errors"] += 1
            if 'db' in locals():
                db.rollback()
        finally:
            if 'db' in locals():
                db.close()

        stats["end_time"] = datetime.now(timezone.utc)
        stats["duration"] = (stats["end_time"] - stats["start_time"]).total_seconds()

        logger.info(f"Bulk import completed: {stats}")
        return stats

    def _process_cve(self, vuln_data: Dict, db: Session) -> str:
        """
        Process a single CVE from NVD API response.

        Returns:
            str: "newly_cached", "already_cached", or "error"
        """
        try:
            cve = vuln_data.get("cve", {})
            cve_id = cve.get("id", "")

            if not cve_id:
                return "error"

            # Check if already cached
            existing = db.query(NVDCVECache).filter(NVDCVECache.cve_id == cve_id).first()
            if existing:
                return "already_cached"

            # Extract CVE data
            cve_data = self._extract_cve_data(cve)

            # Create cache entry
            cache_entry = NVDCVECache(
                cve_id=cve_id,
                description=cve_data["description"],
                cvss_v31_score=cve_data.get("cvss_v31_score"),
                cvss_v31_vector=cve_data.get("cvss_v31_vector"),
                cvss_v31_severity=cve_data.get("cvss_v31_severity"),
                cvss_v30_score=cve_data.get("cvss_v30_score"),
                cvss_v30_vector=cve_data.get("cvss_v30_vector"),
                cvss_v30_severity=cve_data.get("cvss_v30_severity"),
                cvss_v2_score=cve_data.get("cvss_v2_score"),
                cvss_v2_vector=cve_data.get("cvss_v2_vector"),
                cvss_v2_severity=cve_data.get("cvss_v2_severity"),
                published_date=cve_data.get("published_date"),
                last_modified_date=cve_data.get("last_modified_date"),
                source_data=vuln_data,  # Store full response
                cached_at=datetime.now(timezone.utc),
                last_accessed=datetime.now(timezone.utc),
                access_count=0  # Bulk import, not accessed yet
            )

            db.add(cache_entry)

            return "newly_cached"

        except Exception as e:
            logger.error(f"Error processing CVE {cve_id}: {e}")
            return "error"

    def _extract_cve_data(self, cve: Dict) -> Dict:
        """Extract relevant data from CVE JSON."""
        data = {
            "description": "",
            "published_date": None,
            "last_modified_date": None
        }

        # Extract description
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                data["description"] = desc.get("value", "")
                break

        # Extract dates
        if cve.get("published"):
            try:
                data["published_date"] = datetime.fromisoformat(
                    cve["published"].replace("Z", "+00:00")
                )
            except:
                pass

        if cve.get("lastModified"):
            try:
                data["last_modified_date"] = datetime.fromisoformat(
                    cve["lastModified"].replace("Z", "+00:00")
                )
            except:
                pass

        # Extract CVSS scores
        metrics = cve.get("metrics", {})

        # CVSS v3.1 (preferred)
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_v31 = metrics["cvssMetricV31"][0].get("cvssData", {})
            data["cvss_v31_score"] = cvss_v31.get("baseScore")
            data["cvss_v31_vector"] = cvss_v31.get("vectorString")
            data["cvss_v31_severity"] = cvss_v31.get("baseSeverity")

        # CVSS v3.0 (fallback)
        if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_v30 = metrics["cvssMetricV30"][0].get("cvssData", {})
            data["cvss_v30_score"] = cvss_v30.get("baseScore")
            data["cvss_v30_vector"] = cvss_v30.get("vectorString")
            data["cvss_v30_severity"] = cvss_v30.get("baseSeverity")

        # CVSS v2 (legacy)
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
            data["cvss_v2_score"] = cvss_v2.get("baseScore")
            data["cvss_v2_vector"] = cvss_v2.get("vectorString")
            data["cvss_v2_severity"] = cvss_v2.get("baseSeverity")

        return data

    def import_missing_cves_for_oval(self, limit: int = 5000) -> Dict:
        """
        Import CVEs that are referenced in OVAL data but missing from NVD cache.

        Args:
            limit: Maximum number of CVEs to import

        Returns:
            Dict with import statistics
        """
        logger.info(f"Importing missing CVEs referenced in OVAL data (limit: {limit})")

        stats = {
            "start_time": datetime.now(timezone.utc),
            "total_missing": 0,
            "processed": 0,
            "successfully_cached": 0,
            "not_found_in_nvd": 0,
            "errors": 0,
            "api_calls": 0
        }

        try:
            db = next(get_db())

            # Find CVEs from OVAL that aren't in NVD cache
            result = db.execute(text("""
                SELECT DISTINCT r.ref_id as cve_id
                FROM debian_oval_references r
                LEFT JOIN nvd_cve_cache n ON r.ref_id = n.cve_id
                WHERE r.ref_id LIKE 'CVE-%'
                AND n.cve_id IS NULL
                AND r.ref_id >= 'CVE-2020-'  -- Focus on recent CVEs
                ORDER BY r.ref_id DESC
                LIMIT :limit
            """), {"limit": limit})

            missing_cves = [row[0] for row in result.fetchall()]
            stats["total_missing"] = len(missing_cves)

            logger.info(f"Found {len(missing_cves)} CVEs missing from NVD cache")

            for i, cve_id in enumerate(missing_cves):
                # Rate limit with progress
                self._rate_limit(show_progress=True)

                # Show detailed progress
                progress_pct = (i + 1) / len(missing_cves) * 100
                logger.info(f"🔍 Processing CVE {i+1}/{len(missing_cves)} ({progress_pct:.1f}%): {cve_id}")

                try:
                    # Query single CVE
                    params = {"cveId": cve_id}
                    response = self.session.get(self.nvd_api_base, params=params, timeout=30)

                    # Handle rate limiting
                    if response.status_code == 429:
                        logger.warning(f"⚠️  Rate limited on {cve_id}, waiting 30s...")
                        time.sleep(30)
                        continue

                    response.raise_for_status()
                    stats["api_calls"] += 1

                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    if vulnerabilities:
                        result = self._process_cve(vulnerabilities[0], db)
                        if result == "newly_cached":
                            stats["successfully_cached"] += 1
                            logger.info(f"✅ Cached {cve_id}")
                        elif result == "error":
                            stats["errors"] += 1
                            logger.warning(f"❌ Error processing {cve_id}")
                    else:
                        stats["not_found_in_nvd"] += 1
                        logger.info(f"🔍 {cve_id} not found in NVD")

                    stats["processed"] += 1

                    # Show progress every 10 CVEs
                    if stats["processed"] % 10 == 0:
                        elapsed = (datetime.now(timezone.utc) - stats["start_time"]).total_seconds()
                        rate = stats["processed"] / elapsed if elapsed > 0 else 0
                        logger.info(f"📊 Progress: {stats['processed']}/{stats['total_missing']} ({rate:.1f} CVEs/sec)")
                        logger.info(f"📈 Results: {stats['successfully_cached']} cached, {stats['not_found_in_nvd']} not found, {stats['errors']} errors")
                        db.commit()  # Commit periodically

                except Exception as e:
                    if "429" in str(e):
                        logger.warning(f"⚠️  Rate limited on {cve_id}: {e}, waiting 60s...")
                        time.sleep(60)
                        continue
                    else:
                        logger.error(f"❌ Error fetching {cve_id}: {e}")
                        stats["errors"] += 1

            db.commit()

        except Exception as e:
            logger.error(f"Error in missing CVE import: {e}")
            stats["errors"] += 1
            if 'db' in locals():
                db.rollback()
        finally:
            if 'db' in locals():
                db.close()

        stats["end_time"] = datetime.now(timezone.utc)
        stats["duration"] = (stats["end_time"] - stats["start_time"]).total_seconds()

        logger.info(f"Missing CVE import completed: {stats}")
        return stats

    def bulk_import_from_oldest_oval_cve(self, max_cves: int = 10000) -> Dict:
        """
        Smart bulk import: Find oldest CVE in OVAL data and import from that date forward.
        This is much more efficient than individual CVE lookups.

        Args:
            max_cves: Maximum number of CVEs to import in this run

        Returns:
            Dict with import statistics
        """
        logger.info("Starting smart bulk import from oldest OVAL CVE date")

        stats = {
            "start_time": datetime.now(timezone.utc),
            "oldest_cve_found": None,
            "date_range_used": None,
            "total_processed": 0,
            "newly_cached": 0,
            "already_cached": 0,
            "errors": 0,
            "api_calls": 0,
            "pages_processed": 0
        }

        try:
            db = next(get_db())

            # Find the oldest CVE in OVAL data
            result = db.execute(text("""
                SELECT MIN(r.ref_id) as oldest_cve
                FROM debian_oval_references r
                WHERE r.ref_id LIKE 'CVE-%'
                AND r.ref_id >= 'CVE-2020-'  -- Don't go too far back
            """))

            oldest_cve = result.scalar()
            if not oldest_cve:
                logger.warning("No CVEs found in OVAL data")
                return stats

            stats["oldest_cve_found"] = oldest_cve

            # Extract year from CVE ID (CVE-YYYY-NNNNN)
            import re
            year_match = re.search(r'CVE-(\d{4})-', oldest_cve)
            if not year_match:
                logger.error(f"Could not extract year from CVE {oldest_cve}")
                return stats

            start_year = int(year_match.group(1))

            # Create date range from start of that year to now
            start_date = datetime(start_year, 1, 1, tzinfo=timezone.utc)
            end_date = datetime.now(timezone.utc)

            # Format dates for NVD API
            start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

            stats["date_range_used"] = f"{start_date_str} to {end_date_str}"
            logger.info(f"Importing CVEs from {start_date_str} to {end_date_str} (based on oldest CVE: {oldest_cve})")

            # Start pagination
            start_index = 0
            results_per_page = 2000  # Maximum allowed by NVD

            while stats["total_processed"] < max_cves:
                # Rate limit
                self._rate_limit()

                # Build API request
                params = {
                    "pubStartDate": start_date_str,
                    "pubEndDate": end_date_str,
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "noRejected": ""  # Exclude rejected CVEs
                }

                logger.info(f"Fetching CVEs: page {stats['pages_processed'] + 1}, startIndex={start_index}")

                try:
                    response = self.session.get(self.nvd_api_base, params=params, timeout=60)
                    response.raise_for_status()
                    stats["api_calls"] += 1

                    data = response.json()

                    # Extract pagination info
                    total_results = data.get("totalResults", 0)
                    vulnerabilities = data.get("vulnerabilities", [])

                    logger.info(f"Received {len(vulnerabilities)} CVEs (total available: {total_results})")

                    if not vulnerabilities:
                        logger.info("No more CVEs to process")
                        break

                    # Process each CVE
                    for vuln_data in vulnerabilities:
                        if stats["total_processed"] >= max_cves:
                            break

                        cve_result = self._process_cve(vuln_data, db)

                        if cve_result == "newly_cached":
                            stats["newly_cached"] += 1
                        elif cve_result == "already_cached":
                            stats["already_cached"] += 1
                        elif cve_result == "error":
                            stats["errors"] += 1

                        stats["total_processed"] += 1

                        if stats["total_processed"] % 100 == 0:
                            logger.info(f"Processed {stats['total_processed']} CVEs...")

                    stats["pages_processed"] += 1

                    # Check if we've processed all available results
                    if start_index + len(vulnerabilities) >= total_results:
                        logger.info("Reached end of available CVEs")
                        break

                    # Update start index for next page
                    start_index += len(vulnerabilities)

                except requests.exceptions.RequestException as e:
                    logger.error(f"API request failed: {e}")
                    stats["errors"] += 1
                    break
                except Exception as e:
                    logger.error(f"Error processing API response: {e}")
                    stats["errors"] += 1
                    break

            # Commit any pending transactions
            db.commit()

        except Exception as e:
            logger.error(f"Error in smart bulk import: {e}")
            stats["errors"] += 1
            if 'db' in locals():
                db.rollback()
        finally:
            if 'db' in locals():
                db.close()

        stats["end_time"] = datetime.now(timezone.utc)
        stats["duration"] = (stats["end_time"] - stats["start_time"]).total_seconds()

        logger.info(f"Smart bulk import completed: {stats}")
        return stats


# Global instance
nvd_bulk_importer = NVDBulkImporter()
