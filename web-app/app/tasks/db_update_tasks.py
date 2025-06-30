"""Celery tasks for updating vulnerability databases"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional
from ..celery_app import celery_app
from ..config import settings
from ..utils.executor_client import sync_update_database, sync_wait_for_job_completion, sync_health_check
from .task_utils import update_task_status
from .security_data_tasks import update_all_ubuntu_security_data

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def update_vulnerability_database(self, database_type: str = "all", task_run_id: Optional[int] = None):
    """Update vulnerability databases"""
    try:
        logger.info(f"Starting database update for type: {database_type}")

        results = {}

        if database_type == "all":
            # Update all databases
            results["nvd"] = update_nvd_database()
            results["ubuntu"] = update_ubuntu_database()
            results["debian"] = update_debian_database()
            results["redhat"] = update_redhat_database()
            results["amazon"] = update_amazon_database()
            results["alpine"] = update_alpine_database()
            results["gost_ubuntu"] = update_gost_ubuntu_database()
            results["gost_debian"] = update_gost_debian_database()
            results["gost_redhat"] = update_gost_redhat_database()
        else:
            # Update specific database
            if database_type == "nvd":
                results["nvd"] = update_nvd_database()
            elif database_type == "ubuntu":
                results["ubuntu"] = update_ubuntu_database()
            elif database_type == "debian":
                results["debian"] = update_debian_database()
            elif database_type == "redhat":
                results["redhat"] = update_redhat_database()
            elif database_type == "amazon":
                results["amazon"] = update_amazon_database()
            elif database_type == "alpine":
                results["alpine"] = update_alpine_database()
            elif database_type == "gost_ubuntu":
                results["gost_ubuntu"] = update_gost_ubuntu_database()
            elif database_type == "gost_debian":
                results["gost_debian"] = update_gost_debian_database()
            elif database_type == "gost_redhat":
                results["gost_redhat"] = update_gost_redhat_database()
            else:
                error_msg = f"Unknown database type: {database_type}"
                logger.error(error_msg)
                if task_run_id:
                    update_task_status.delay(task_run_id, "failed", error_message=error_msg)
                return {"status": "error", "error": error_msg}

        # Check if any updates failed
        failed_updates = [db for db, result in results.items() if result.get("status") != "success"]

        if failed_updates:
            error_msg = f"Failed to update databases: {', '.join(failed_updates)}"
            logger.error(error_msg)
            if task_run_id:
                update_task_status.delay(task_run_id, "failed", error_message=error_msg, result_data=results)
            return {"status": "partial_failure", "results": results, "failed": failed_updates}
        else:
            logger.info("All database updates completed successfully")
            if task_run_id:
                update_task_status.delay(task_run_id, "success", result_data=results)
            return {"status": "success", "results": results}

    except Exception as e:
        logger.error(f"Error in database update: {str(e)}")
        if task_run_id:
            update_task_status.delay(task_run_id, "failed", error_message=str(e))
        return {"status": "error", "error": str(e)}


def call_executor_api(database: str) -> dict:
    """Call the executor sidecar to update a specific database"""
    try:
        # Check if executor service is healthy
        if not sync_health_check():
            return {
                "status": "error",
                "database": database,
                "error": "Docker executor service is not available"
            }

        logger.info(f"Starting database update via executor for: {database}")

        # Start the database update job
        job_response = sync_update_database(database)
        job_id = job_response["job_id"]

        logger.info(f"Database update job started: {job_id}")

        # Wait for completion
        result = sync_wait_for_job_completion(job_id, timeout=1800)  # 30 minutes

        if result["status"] == "completed":
            logger.info(f"Database {database} updated successfully")
            return {
                "status": "success",
                "database": database,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "job_id": job_id,
                "result": result.get("result")
            }
        else:
            error_msg = result.get("error", "Unknown error from executor")
            logger.error(f"Database {database} update failed: {error_msg}")
            return {
                "status": "error",
                "database": database,
                "error": error_msg,
                "job_id": job_id
            }

    except Exception as e:
        error_msg = f"Error calling executor API for {database}: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "database": database, "error": error_msg}


def update_nvd_database() -> dict:
    """Update NVD (National Vulnerability Database)"""
    return call_executor_api("nvd")


def update_ubuntu_database() -> dict:
    """Update Ubuntu security data (USN and OVAL)"""
    try:
        logger.info("Updating Ubuntu security data using new PostgreSQL system")

        # Import the unified service directly to avoid Celery task issues
        from ..services.unified_ubuntu_security import unified_ubuntu_security

        # Update all data directly
        result = unified_ubuntu_security.update_all_data()

        if result.get("usn", False) or result.get("oval", False):
            return {
                "status": "success",
                "database": "ubuntu",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "result": result
            }
        else:
            error_msg = "Failed to update Ubuntu security data"
            logger.error(error_msg)
            return {
                "status": "error",
                "database": "ubuntu",
                "error": error_msg
            }

    except Exception as e:
        error_msg = f"Error updating Ubuntu security data: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "database": "ubuntu", "error": error_msg}


def update_debian_database() -> dict:
    """Update Debian security data (Security Tracker and OVAL)"""
    try:
        logger.info("Updating Debian security data using new PostgreSQL system")

        # Import the unified service directly to avoid Celery task issues
        from ..services.unified_debian_security import unified_debian_security

        # Update all data directly
        result = unified_debian_security.update_all_data()

        if result.get("security_tracker", False) or result.get("oval", False):
            return {
                "status": "success",
                "database": "debian",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "result": result
            }
        else:
            error_msg = "Failed to update Debian security data"
            logger.error(error_msg)
            return {
                "status": "error",
                "database": "debian",
                "error": error_msg
            }

    except Exception as e:
        error_msg = f"Error updating Debian security data: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "database": "debian", "error": error_msg}


def update_redhat_database() -> dict:
    """Update Red Hat/CentOS OVAL database"""
    return call_executor_api("redhat")


def update_amazon_database() -> dict:
    """Update Amazon Linux OVAL database"""
    return call_executor_api("amazon")


def update_alpine_database() -> dict:
    """Update Alpine OVAL database"""
    return call_executor_api("alpine")


def update_gost_ubuntu_database() -> dict:
    """Update GOST Ubuntu database"""
    return call_executor_api("gost_ubuntu")


def update_gost_debian_database() -> dict:
    """Update GOST Debian database"""
    return call_executor_api("gost_debian")


def update_gost_redhat_database() -> dict:
    """Update GOST Red Hat database"""
    return call_executor_api("gost_redhat")


@celery_app.task(bind=True)
def update_all_databases(self):
    """Convenience task to update all vulnerability databases"""
    return update_vulnerability_database(database_type="all")
