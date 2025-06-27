"""Celery tasks for updating vulnerability databases"""

import logging
import requests
import os
from datetime import datetime, timezone
from typing import Optional
from ..celery_app import celery_app
from ..config import settings
from .task_utils import update_task_status

logger = logging.getLogger(__name__)

# Executor service configuration
EXECUTOR_URL = os.getenv("EXECUTOR_URL", "http://vuls-executor:8080")
EXECUTOR_API_KEY = os.getenv("EXECUTOR_API_KEY", "change-me-in-production")


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


@celery_app.task(bind=True, max_retries=180, default_retry_delay=10)
def monitor_database_update(self, database: str, job_id: str):
    """Monitor a database update job until completion"""
    try:
        headers = {
            'X-API-Key': EXECUTOR_API_KEY,
            'Content-Type': 'application/json'
        }

        # Check job status
        response = requests.get(
            f"{EXECUTOR_URL}/jobs/{job_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            error_msg = f"Failed to check job status: {response.status_code} - {response.text}"
            logger.error(error_msg)
            return {"status": "error", "database": database, "error": error_msg}

        status_data = response.json()
        job_status = status_data['status']

        if job_status == 'completed':
            logger.info(f"Database {database} updated successfully")
            return {
                "status": "success",
                "database": database,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "job_id": job_id,
                "result": status_data.get('result')
            }
        elif job_status == 'failed':
            error_msg = status_data.get('error', 'Unknown error')
            logger.error(f"Database {database} update failed: {error_msg}")
            return {
                "status": "error",
                "database": database,
                "error": error_msg,
                "job_id": job_id
            }
        elif job_status in ['starting', 'running']:
            # Job still in progress, retry after delay
            logger.info(f"Database {database} update still in progress (attempt {self.request.retries + 1}/180)")
            raise self.retry(countdown=10)
        else:
            error_msg = f"Unknown job status: {job_status}"
            logger.error(error_msg)
            return {"status": "error", "database": database, "error": error_msg}

    except Exception as e:
        # Check if it's a retry exception
        if hasattr(e, 'retry') or 'retry' in str(type(e)).lower():
            raise e
        error_msg = f"Error monitoring job {job_id} for {database}: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "database": database, "error": error_msg}


def call_executor_api(database: str) -> dict:
    """Call the executor sidecar to update a specific database"""
    try:
        headers = {
            'X-API-Key': EXECUTOR_API_KEY,
            'Content-Type': 'application/json'
        }

        payload = {'database': database}

        logger.info(f"Calling executor API for database: {database}")

        # Start the database update job
        response = requests.post(
            f"{EXECUTOR_URL}/database/update",
            json=payload,
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:
            error_msg = f"Executor API error: {response.status_code} - {response.text}"
            logger.error(error_msg)
            return {"status": "error", "database": database, "error": error_msg}

        job_data = response.json()
        job_id = job_data['job_id']

        logger.info(f"Database update job started: {job_id}")

        # Start monitoring task and wait for result
        monitor_result = monitor_database_update.apply_async(args=[database, job_id])

        # Wait for the monitoring task to complete (this will handle retries automatically)
        result = monitor_result.get(timeout=1900)  # 31+ minutes timeout

        return result

    except Exception as e:
        error_msg = f"Error calling executor API for {database}: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "database": database, "error": error_msg}


def update_nvd_database() -> dict:
    """Update NVD (National Vulnerability Database)"""
    return call_executor_api("nvd")


def update_ubuntu_database() -> dict:
    """Update Ubuntu OVAL database"""
    return call_executor_api("ubuntu")


def update_debian_database() -> dict:
    """Update Debian OVAL database"""
    return call_executor_api("debian")


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
