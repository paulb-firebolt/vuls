"""Celery tasks for updating security vulnerability data (USN and OVAL)"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from ..celery_app import celery_app
from ..services.unified_ubuntu_security import unified_ubuntu_security
from ..services.ubuntu_security_lookup import UbuntuSecurityLookup
from ..services.ubuntu_oval_source import UbuntuOVALSource
from .task_utils import update_task_status

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def update_ubuntu_security_data(self, source: str = "all", release: Optional[str] = None,
                               force: bool = False, task_run_id: Optional[int] = None):
    """
    Update Ubuntu security data from USN and OVAL sources

    Args:
        source: Data source to update ('all', 'usn', 'oval')
        release: Ubuntu release for OVAL updates ('22.04', '24.04', or None for all)
        force: Force update even if data is current
        task_run_id: Associated task run ID for status updates
    """
    try:
        logger.info(f"Starting Ubuntu security data update - source: {source}, release: {release}, force: {force}")

        results = {}

        if source == "all":
            # Update all sources
            logger.info("Updating all Ubuntu security data sources")
            update_results = unified_ubuntu_security.update_all_data(force=force)
            results.update(update_results)

        elif source == "usn":
            # Update USN data only
            logger.info("Updating Ubuntu USN data")
            usn_source = UbuntuSecurityLookup()
            if force:
                success = usn_source.force_update()
            else:
                success = usn_source.download_and_cache_ubuntu_data()
            results["usn"] = success

        elif source == "oval":
            # Update OVAL data only
            logger.info(f"Updating Ubuntu OVAL data for release: {release or 'all'}")
            oval_source = UbuntuOVALSource()

            if release:
                # Update specific release
                success = oval_source.download_and_cache_data(release=release)
                results[f"oval_{release}"] = success
            else:
                # Update all supported releases
                oval_results = []
                for rel in ['16.04', '18.04', '20.04', '22.04', '24.04']:
                    if force or oval_source.should_update_data(release=rel):
                        success = oval_source.download_and_cache_data(release=rel)
                        results[f"oval_{rel}"] = success
                        oval_results.append(success)
                    else:
                        logger.info(f"OVAL data for Ubuntu {rel} is up to date")
                        results[f"oval_{rel}"] = True
                        oval_results.append(True)

                results["oval"] = all(oval_results)
        else:
            error_msg = f"Unknown source type: {source}"
            logger.error(error_msg)
            if task_run_id:
                update_task_status.delay(task_run_id, "failed", error_message=error_msg)
            return {"status": "error", "error": error_msg}

        # Check for failures
        failed_sources = []
        for key, result in results.items():
            if not result:
                failed_sources.append(key)

        if failed_sources:
            error_msg = f"Failed to update sources: {', '.join(failed_sources)}"
            logger.error(error_msg)
            if task_run_id:
                update_task_status.delay(task_run_id, "failed", error_message=error_msg, result_data=results)
            return {"status": "partial_failure", "results": results, "failed": failed_sources}
        else:
            logger.info("Ubuntu security data update completed successfully")
            if task_run_id:
                update_task_status.delay(task_run_id, "success", result_data=results)
            return {"status": "success", "results": results}

    except Exception as e:
        error_msg = f"Error updating Ubuntu security data: {str(e)}"
        logger.error(error_msg)
        if task_run_id:
            update_task_status.delay(task_run_id, "failed", error_message=error_msg)
        return {"status": "error", "error": error_msg}


@celery_app.task(bind=True)
def update_usn_data(self, force: bool = False, task_run_id: Optional[int] = None):
    """Update Ubuntu Security Notices (USN) data"""
    return update_ubuntu_security_data(source="usn", force=force, task_run_id=task_run_id)


@celery_app.task(bind=True)
def update_oval_data(self, release: Optional[str] = None, force: bool = False,
                    task_run_id: Optional[int] = None):
    """Update Ubuntu OVAL data"""
    return update_ubuntu_security_data(source="oval", release=release, force=force, task_run_id=task_run_id)


@celery_app.task(bind=True)
def update_all_ubuntu_security_data(self, force: bool = False, task_run_id: Optional[int] = None):
    """Update all Ubuntu security data sources (USN and OVAL)"""
    return update_ubuntu_security_data(source="all", force=force, task_run_id=task_run_id)


@celery_app.task(bind=True)
def get_security_data_stats(self, task_run_id: Optional[int] = None):
    """Get comprehensive statistics about security data"""
    try:
        logger.info("Gathering security data statistics")

        stats = unified_ubuntu_security.get_comprehensive_stats()

        if task_run_id:
            update_task_status.delay(task_run_id, "success", result_data=stats)

        return {"status": "success", "stats": stats}

    except Exception as e:
        error_msg = f"Error getting security data stats: {str(e)}"
        logger.error(error_msg)
        if task_run_id:
            update_task_status.delay(task_run_id, "failed", error_message=error_msg)
        return {"status": "error", "error": error_msg}


@celery_app.task(bind=True)
def check_security_data_freshness(self, task_run_id: Optional[int] = None):
    """Check if security data needs updating and report status"""
    try:
        logger.info("Checking security data freshness")

        usn_source = UbuntuSecurityLookup()
        oval_source = UbuntuOVALSource()

        freshness_report = {
            "usn": {
                "needs_update": usn_source.should_update_data(),
                "last_update": None
            },
            "oval": {}
        }

        # Check USN stats
        try:
            usn_stats = usn_source.get_cache_stats()
            freshness_report["usn"]["last_update"] = usn_stats.get("last_download")
            freshness_report["usn"]["record_count"] = usn_stats.get("total_records", 0)
        except Exception as e:
            logger.warning(f"Could not get USN stats: {e}")

        # Check OVAL stats for each release
        for release in ['22.04', '24.04']:
            try:
                needs_update = oval_source.should_update_data(release=release)
                freshness_report["oval"][release] = {
                    "needs_update": needs_update,
                    "last_update": None
                }
            except Exception as e:
                logger.warning(f"Could not check OVAL freshness for {release}: {e}")
                freshness_report["oval"][release] = {
                    "needs_update": True,
                    "error": str(e)
                }

        # Get OVAL stats
        try:
            oval_stats = oval_source.get_cache_stats()
            releases = oval_stats.get("releases", {})
            for release, release_stats in releases.items():
                if release in freshness_report["oval"]:
                    freshness_report["oval"][release]["last_update"] = release_stats.get("last_download")
                    freshness_report["oval"][release]["definitions_count"] = release_stats.get("definitions_count", 0)
                    freshness_report["oval"][release]["cves_count"] = release_stats.get("cves_count", 0)
        except Exception as e:
            logger.warning(f"Could not get OVAL stats: {e}")

        # Determine if any updates are needed
        needs_any_update = (
            freshness_report["usn"]["needs_update"] or
            any(release_info.get("needs_update", False) for release_info in freshness_report["oval"].values())
        )

        result = {
            "needs_update": needs_any_update,
            "freshness_report": freshness_report,
            "checked_at": datetime.now(timezone.utc).isoformat()
        }

        if task_run_id:
            update_task_status.delay(task_run_id, "success", result_data=result)

        return {"status": "success", "result": result}

    except Exception as e:
        error_msg = f"Error checking security data freshness: {str(e)}"
        logger.error(error_msg)
        if task_run_id:
            update_task_status.delay(task_run_id, "failed", error_message=error_msg)
        return {"status": "error", "error": error_msg}


@celery_app.task(bind=True)
def vulnerability_lookup_task(self, cve_id: str, package_name: str, release: str = "22.04",
                             prefer_source: str = "usn", task_run_id: Optional[int] = None):
    """Perform vulnerability lookup as a background task"""
    try:
        logger.info(f"Looking up vulnerability {cve_id} in package {package_name} (Ubuntu {release})")

        result = unified_ubuntu_security.lookup_vulnerability(
            cve_id=cve_id,
            package_name=package_name,
            release=release,
            prefer_source=prefer_source
        )

        if task_run_id:
            update_task_status.delay(task_run_id, "success", result_data=result)

        return {"status": "success", "lookup_result": result}

    except Exception as e:
        error_msg = f"Error in vulnerability lookup: {str(e)}"
        logger.error(error_msg)
        if task_run_id:
            update_task_status.delay(task_run_id, "failed", error_message=error_msg)
        return {"status": "error", "error": error_msg}


@celery_app.task(bind=True)
def package_vulnerability_analysis_task(self, package_name: str, release: str = "22.04",
                                       task_run_id: Optional[int] = None):
    """Analyze all vulnerabilities for a package as a background task"""
    try:
        logger.info(f"Analyzing vulnerabilities for package {package_name} (Ubuntu {release})")

        result = unified_ubuntu_security.get_package_vulnerabilities(
            package_name=package_name,
            release=release
        )

        if task_run_id:
            update_task_status.delay(task_run_id, "success", result_data=result)

        return {"status": "success", "analysis_result": result}

    except Exception as e:
        error_msg = f"Error in package vulnerability analysis: {str(e)}"
        logger.error(error_msg)
        if task_run_id:
            update_task_status.delay(task_run_id, "failed", error_message=error_msg)
        return {"status": "error", "error": error_msg}
