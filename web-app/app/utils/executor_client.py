"""HTTP client for communicating with the Docker Executor service"""

import logging
import httpx
import asyncio
from typing import Dict, Any, Optional
from ..config import settings

logger = logging.getLogger(__name__)


class ExecutorClient:
    """Client for communicating with the Docker Executor service"""

    def __init__(self):
        self.base_url = settings.executor_url
        self.api_key = settings.executor_api_key
        self.headers = {"X-API-Key": self.api_key}

    async def health_check(self) -> bool:
        """Check if executor service is healthy"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/health", timeout=10.0)
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Executor health check failed: {e}")
            return False

    async def start_scan(self, server_name: str, scan_type: str = "fast", ssh_key: Optional[str] = None) -> Dict[str, Any]:
        """Start a vulnerability scan"""
        try:
            payload = {
                "server_name": server_name,
                "scan_type": scan_type
            }
            if ssh_key:
                payload["ssh_key"] = ssh_key

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/scan",
                    json=payload,
                    headers=self.headers,
                    timeout=30.0
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            raise

    async def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get job status"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/jobs/{job_id}",
                    headers=self.headers,
                    timeout=10.0
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
            raise

    async def wait_for_job_completion(self, job_id: str, timeout: int = 1800) -> Dict[str, Any]:
        """Wait for job to complete with polling"""
        start_time = asyncio.get_event_loop().time()

        while True:
            try:
                status = await self.get_job_status(job_id)

                if status["status"] in ["completed", "failed"]:
                    return status

                # Check timeout
                if asyncio.get_event_loop().time() - start_time > timeout:
                    raise TimeoutError(f"Job {job_id} timed out after {timeout} seconds")

                # Wait before next poll
                await asyncio.sleep(10)

            except Exception as e:
                logger.error(f"Error polling job status: {e}")
                raise

    async def update_database(self, database: str) -> Dict[str, Any]:
        """Update vulnerability database"""
        try:
            payload = {"database": database}

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/database/update",
                    json=payload,
                    headers=self.headers,
                    timeout=30.0
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Failed to start database update: {e}")
            raise


# Synchronous wrapper functions for use in Celery tasks
def sync_start_scan(server_name: str, scan_type: str = "fast", ssh_key: Optional[str] = None) -> Dict[str, Any]:
    """Synchronous wrapper for start_scan"""
    client = ExecutorClient()
    return asyncio.run(client.start_scan(server_name, scan_type, ssh_key))


def sync_wait_for_job_completion(job_id: str, timeout: int = 1800) -> Dict[str, Any]:
    """Synchronous wrapper for wait_for_job_completion"""
    client = ExecutorClient()
    return asyncio.run(client.wait_for_job_completion(job_id, timeout))


def sync_get_job_status(job_id: str) -> Dict[str, Any]:
    """Synchronous wrapper for get_job_status"""
    client = ExecutorClient()
    return asyncio.run(client.get_job_status(job_id))


def sync_health_check() -> bool:
    """Synchronous wrapper for health_check"""
    client = ExecutorClient()
    return asyncio.run(client.health_check())


def sync_update_database(database: str) -> Dict[str, Any]:
    """Synchronous wrapper for update_database"""
    client = ExecutorClient()
    return asyncio.run(client.update_database(database))
