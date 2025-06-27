"""
Docker Executor Sidecar Service
Provides secure, function-based endpoints for Docker operations
"""

import os
import logging
import subprocess
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, validator
import docker
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vuls Docker Executor", version="1.0.0")

# Docker client - initialize lazily
docker_client = None

def get_docker_client():
    """Get Docker client, initializing if needed"""
    global docker_client
    if docker_client is None:
        try:
            docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Could not initialize Docker client: {e}")
            docker_client = None
    return docker_client

# Configuration
API_KEY = os.getenv("EXECUTOR_API_KEY", "change-me-in-production")
COMPOSE_PROJECT_DIR = "/project"
HOST_PROJECT_PATH = os.getenv("HOST_PROJECT_PATH", "/project")
HOST_USER_HOME = os.getenv("HOST_USER_HOME", "/home/user")

# Job tracking
active_jobs: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    server_name: str
    scan_type: str = "fast"
    ssh_key: Optional[str] = None

    @validator('server_name')
    def validate_server_name(cls, v):
        # Basic server name validation - allow alphanumeric, underscore, and hyphen
        if not v.replace('_', 'a').replace('-', 'a').isalnum():
            raise ValueError('Invalid server name format')
        return v

    @validator('scan_type')
    def validate_scan_type(cls, v):
        if v not in ['fast', 'full', 'config-only']:
            raise ValueError('Invalid scan type')
        return v


class DatabaseUpdateRequest(BaseModel):
    database: str

    @validator('database')
    def validate_database(cls, v):
        allowed = ['nvd', 'ubuntu', 'debian', 'redhat', 'amazon', 'alpine',
                  'gost_ubuntu', 'gost_debian', 'gost_redhat', 'all']
        if v not in allowed:
            raise ValueError(f'Invalid database type. Allowed: {allowed}')
        return v


class JobResponse(BaseModel):
    job_id: str
    status: str
    message: str


class JobStatus(BaseModel):
    job_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def verify_api_key(x_api_key: str = Header(...)):
    """Verify API key from header"""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@app.get("/health")
async def health_check():
    """Health check endpoint (no auth required)"""
    return {"status": "healthy", "service": "docker-executor"}


@app.post("/scan", response_model=JobResponse)
async def start_scan(request: ScanRequest, api_key: str = Depends(verify_api_key)):
    """Start a vulnerability scan"""
    job_id = str(uuid.uuid4())

    logger.info(f"Starting scan job {job_id} for server {request.server_name}")

    # Track job
    active_jobs[job_id] = {
        "status": "starting",
        "started_at": datetime.utcnow(),
        "type": "scan",
        "request": request.dict()
    }

    # Start scan asynchronously
    asyncio.create_task(execute_scan(job_id, request))

    return JobResponse(
        job_id=job_id,
        status="starting",
        message=f"Scan started for server {request.server_name}"
    )


@app.post("/database/update", response_model=JobResponse)
async def update_database(request: DatabaseUpdateRequest, api_key: str = Depends(verify_api_key)):
    """Update vulnerability databases"""
    job_id = str(uuid.uuid4())

    logger.info(f"Starting database update job {job_id} for {request.database}")

    # Track job
    active_jobs[job_id] = {
        "status": "starting",
        "started_at": datetime.utcnow(),
        "type": "database_update",
        "request": request.dict()
    }

    # Start update asynchronously
    asyncio.create_task(execute_database_update(job_id, request))

    return JobResponse(
        job_id=job_id,
        status="starting",
        message=f"Database update started for {request.database}"
    )


@app.get("/jobs/{job_id}", response_model=JobStatus)
async def get_job_status(job_id: str, api_key: str = Depends(verify_api_key)):
    """Get job status"""
    if job_id not in active_jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = active_jobs[job_id]

    # Return current status immediately without blocking
    return JobStatus(
        job_id=job_id,
        status=job["status"],
        started_at=job["started_at"],
        completed_at=job.get("completed_at"),
        result=job.get("result"),
        error=job.get("error")
    )


@app.get("/jobs/{job_id}/logs")
async def get_job_logs(job_id: str, api_key: str = Depends(verify_api_key)):
    """Get job logs"""
    if job_id not in active_jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = active_jobs[job_id]
    return {"job_id": job_id, "logs": job.get("logs", [])}


async def execute_scan(job_id: str, request: ScanRequest):
    """Execute vulnerability scan"""
    try:
        active_jobs[job_id]["status"] = "running"

        # Generate unique container name for this scan
        container_name = f"vuls-scan-{job_id[:8]}-{request.server_name}"

        # Build direct docker run command with absolute host paths
        cmd = [
            "docker", "run", "--rm",
            # Unique container name to avoid conflicts
            "--name", container_name,
            # Volume mounts using host paths
            "-v", f"{HOST_PROJECT_PATH}/config/config.toml:/vuls/config.toml:rw",
            "-v", f"{HOST_PROJECT_PATH}/logs:/vuls/logs:rw",
            "-v", f"{HOST_PROJECT_PATH}/results:/vuls/results:rw",
            "-v", f"{HOST_PROJECT_PATH}/db:/vuls/db:rw",
            "-v", f"{HOST_PROJECT_PATH}/.ssh:/root/.ssh:rw",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            # Credential mounts (conditional)
            "-v", f"{HOST_USER_HOME}/.config/gcloud:/root/.config/gcloud:rw",
            "-v", f"{HOST_USER_HOME}/.aws:/root/.aws:ro",
            # Environment variables
            "-e", "VULS_CONFIG_PATH=/vuls/config.toml",
            "-e", "AWS_PROFILE=default",
            "-e", "AWS_REGION=eu-west-2",
            "-e", "AWS_CONFIG_FILE=/root/.aws/config",
            "-e", "AWS_SHARED_CREDENTIALS_FILE=/root/.aws/credentials",
            "-e", "GOOGLE_APPLICATION_CREDENTIALS=/root/.config/gcloud/application_default_credentials.json",
            "-e", "CLOUDSDK_CONFIG=/root/.config/gcloud",
            # Network connectivity
            "--network", "vuls_default",
            # Use the vuls image
            "vuls-vuls:latest",
            # Command
            "scan", "-config=/vuls/config.toml"
        ]

        # Add scan type flags (note: fast scan is controlled by config, not flags)
        if request.scan_type == "config-only":
            # For config test, we would use configtest command instead of scan
            # But for now, just do a regular scan
            pass

        # Add server name last
        cmd.append(request.server_name)

        logger.info(f"Executing scan command: {' '.join(cmd)}")

        # Use async subprocess to avoid blocking
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=3600  # 1 hour timeout
            )
            returncode = process.returncode
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            stdout, stderr = b"", b"Timeout after 1 hour"
            returncode = -1

        # Update job status
        active_jobs[job_id].update({
            "status": "completed" if returncode == 0 else "failed",
            "completed_at": datetime.utcnow(),
            "result": {
                "returncode": returncode,
                "stdout": stdout.decode() if stdout else "",
                "stderr": stderr.decode() if stderr else ""
            }
        })

        if returncode != 0:
            active_jobs[job_id]["error"] = f"Scan failed with code {returncode}: {stderr.decode() if stderr else 'Unknown error'}"

        logger.info(f"Scan job {job_id} completed with status: {active_jobs[job_id]['status']}")

    except Exception as e:
        logger.error(f"Error in scan job {job_id}: {str(e)}")
        active_jobs[job_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow(),
            "error": str(e)
        })


async def execute_database_update(job_id: str, request: DatabaseUpdateRequest):
    """Execute database update"""
    try:
        active_jobs[job_id]["status"] = "running"

        # Map database types to compose services
        service_map = {
            "nvd": "vuls-nvd",
            "ubuntu": "vuls-ubuntu",
            "debian": "vuls-debian",
            "redhat": "vuls-redhat",
            "amazon": "vuls-amazon",
            "alpine": "vuls-alpine",
            "gost_ubuntu": "vuls-gost-ubuntu",
            "gost_debian": "vuls-gost-debian",
            "gost_redhat": "vuls-gost-redhat"
        }

        results = {}

        if request.database == "all":
            # Update all databases
            services = list(service_map.values())
        else:
            # Update specific database
            services = [service_map[request.database]]

        for service in services:
            logger.info(f"Updating database via service: {service}")

            cmd = [
                "docker", "compose",
                "-f", f"{COMPOSE_PROJECT_DIR}/compose.yml",
                "run", "--rm", service
            ]

            # Use async subprocess to avoid blocking
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=COMPOSE_PROJECT_DIR
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=1800  # 30 minutes per service
                )
                returncode = process.returncode
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                stdout, stderr = b"", b"Timeout after 30 minutes"
                returncode = -1

            results[service] = {
                "returncode": returncode,
                "stdout": stdout.decode() if stdout else "",
                "stderr": stderr.decode() if stderr else ""
            }

        # Determine overall status
        failed_services = [s for s, r in results.items() if r["returncode"] != 0]
        overall_status = "failed" if failed_services else "completed"

        # Update job status
        active_jobs[job_id].update({
            "status": overall_status,
            "completed_at": datetime.utcnow(),
            "result": {
                "services": results,
                "failed_services": failed_services
            }
        })

        if failed_services:
            active_jobs[job_id]["error"] = f"Failed services: {', '.join(failed_services)}"

        logger.info(f"Database update job {job_id} completed with status: {overall_status}")

    except Exception as e:
        logger.error(f"Error in database update job {job_id}: {str(e)}")
        active_jobs[job_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow(),
            "error": str(e)
        })


if __name__ == "__main__":
    logger.info("Starting Docker Executor service...")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
