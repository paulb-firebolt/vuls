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
COMPOSE_PROJECT_DIR = "/compose"

# Job tracking
active_jobs: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "fast"
    ssh_key: Optional[str] = None

    @validator('target')
    def validate_target(cls, v):
        # Basic IP validation - extend as needed
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Could be hostname - basic validation
            if not v.replace('.', '').replace('-', '').isalnum():
                raise ValueError('Invalid target format')
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

    logger.info(f"Starting scan job {job_id} for target {request.target}")

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
        message=f"Scan started for target {request.target}"
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

        # Build scan command
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{COMPOSE_PROJECT_DIR}/config:/vuls/config:ro",
            "-v", f"{COMPOSE_PROJECT_DIR}/results:/vuls/results:rw",
            "-v", f"{COMPOSE_PROJECT_DIR}/db:/vuls/db:ro",
            "-v", f"{COMPOSE_PROJECT_DIR}/logs:/vuls/logs:rw"
        ]

        # Add SSH key if provided
        if request.ssh_key:
            cmd.extend(["-v", f"{COMPOSE_PROJECT_DIR}/.ssh:/root/.ssh:ro"])

        # Add scan image and command
        cmd.extend([
            "vuls/vuls:latest",
            "scan",
            "-config=/vuls/config/config.toml",
            f"-target={request.target}"
        ])

        # Add scan type flags
        if request.scan_type == "fast":
            cmd.append("-fast-scan")
        elif request.scan_type == "config-only":
            cmd.append("-config-test")

        logger.info(f"Executing scan command: {' '.join(cmd)}")

        # Execute scan
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )

        # Update job status
        active_jobs[job_id].update({
            "status": "completed" if result.returncode == 0 else "failed",
            "completed_at": datetime.utcnow(),
            "result": {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        })

        if result.returncode != 0:
            active_jobs[job_id]["error"] = f"Scan failed with code {result.returncode}: {result.stderr}"

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
