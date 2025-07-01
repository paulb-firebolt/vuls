"""NVD CVE update tasks for Celery scheduler."""

import logging
from datetime import datetime, timezone, timedelta
from celery import shared_task
from sqlalchemy import text
from ..models.base import get_db
from ..services.nvd_bulk_import import nvd_bulk_importer

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="update_nvd_cve_cache")
def update_nvd_cve_cache(self, max_cves: int = 2000):
    """
    Weekly task to update NVD CVE cache with new CVEs.
    Fetches CVEs from the last cached date to present.
    """
    logger.info("Starting weekly NVD CVE cache update")

    try:
        db = next(get_db())

        # Find the most recent CVE in our cache
        result = db.execute(text("""
            SELECT MAX(cached_at) as last_cached_date
            FROM nvd_cve_cache
        """))

        last_cached = result.scalar()

        if last_cached:
            # Start from last cached date
            start_date = last_cached.date()
            logger.info(f"Updating from last cached date: {start_date}")
        else:
            # No cache yet, start from 7 days ago
            start_date = (datetime.now(timezone.utc) - timedelta(days=7)).date()
            logger.info(f"No cache found, starting from: {start_date}")

        db.close()

        # Calculate days back from start_date to now
        days_back = (datetime.now(timezone.utc).date() - start_date).days

        # Use the bulk importer to get recent CVEs
        result = nvd_bulk_importer.bulk_import_recent_cves(
            days_back=max(days_back, 7),  # At least 7 days
            max_cves=max_cves
        )

        logger.info(f"NVD update completed: {result}")

        return {
            "status": "success",
            "newly_cached": result.get("newly_cached", 0),
            "already_cached": result.get("already_cached", 0),
            "total_processed": result.get("total_processed", 0),
            "duration": result.get("duration", 0),
            "start_date": str(start_date)
        }

    except Exception as e:
        logger.error(f"Error in NVD update task: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@shared_task(bind=True, name="backfill_historical_nvd_cves")
def backfill_historical_nvd_cves(self, start_year: int = 2020, max_cves: int = 5000):
    """
    One-time task to backfill historical CVEs.
    Can be run manually to populate cache with older CVEs.
    """
    logger.info(f"Starting historical NVD CVE backfill from {start_year}")

    try:
        # Use the smart bulk import to get historical CVEs
        result = nvd_bulk_importer.bulk_import_from_oldest_oval_cve(max_cves=max_cves)

        logger.info(f"Historical backfill completed: {result}")

        return {
            "status": "success",
            "newly_cached": result.get("newly_cached", 0),
            "already_cached": result.get("already_cached", 0),
            "total_processed": result.get("total_processed", 0),
            "duration": result.get("duration", 0),
            "oldest_cve_found": result.get("oldest_cve_found"),
            "date_range_used": result.get("date_range_used")
        }

    except Exception as e:
        logger.error(f"Error in historical backfill task: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@shared_task(bind=True, name="nvd_cache_maintenance")
def nvd_cache_maintenance(self):
    """
    Monthly maintenance task for NVD cache.
    Updates access counts and cleans up old entries if needed.
    """
    logger.info("Starting NVD cache maintenance")

    try:
        db = next(get_db())

        # Get cache statistics
        stats_result = db.execute(text("""
            SELECT
                COUNT(*) as total_cves,
                COUNT(CASE WHEN cvss_v31_score IS NOT NULL THEN 1 END) as with_cvss_v31,
                COUNT(CASE WHEN cvss_v30_score IS NOT NULL THEN 1 END) as with_cvss_v30,
                COUNT(CASE WHEN cvss_v2_score IS NOT NULL THEN 1 END) as with_cvss_v2,
                MIN(cached_at) as oldest_cached,
                MAX(cached_at) as newest_cached,
                SUM(access_count) as total_accesses
            FROM nvd_cve_cache
        """))

        stats = stats_result.fetchone()

        # Update last maintenance timestamp
        maintenance_result = db.execute(text("""
            UPDATE nvd_cve_cache
            SET last_accessed = CURRENT_TIMESTAMP
            WHERE access_count > 0
            AND last_accessed < CURRENT_TIMESTAMP - INTERVAL '30 days'
        """))

        db.commit()
        db.close()

        cache_stats = {
            "total_cves": stats[0] if stats else 0,
            "with_cvss_v31": stats[1] if stats else 0,
            "with_cvss_v30": stats[2] if stats else 0,
            "with_cvss_v2": stats[3] if stats else 0,
            "oldest_cached": str(stats[4]) if stats and stats[4] else None,
            "newest_cached": str(stats[5]) if stats and stats[5] else None,
            "total_accesses": stats[6] if stats else 0,
            "maintenance_updated": maintenance_result.rowcount
        }

        logger.info(f"Cache maintenance completed: {cache_stats}")

        return {
            "status": "success",
            "cache_stats": cache_stats
        }

    except Exception as e:
        logger.error(f"Error in cache maintenance: {e}")
        return {
            "status": "error",
            "error": str(e)
        }
