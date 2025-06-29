"""
Docker Executor Sidecar Service
Provides secure, function-based endpoints for Docker operations
"""

import os
import logging
import subprocess
import asyncio
import shutil
from typing import Dict, Any, Optional
from datetime import datetime
import uuid
import stat
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, field_validator
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
CF_ACCESS_CLIENT_ID = os.getenv("CF_ACCESS_CLIENT_ID", "Cloudflare ID")
CF_ACCESS_CLIENT_SECRET = os.getenv("CF_ACCESS_CLIENT_SECRET", "Cloudflare Secret")

# Job tracking
active_jobs: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    server_name: str
    scan_type: str = "fast"
    ssh_key: Optional[str] = None

    @field_validator('server_name')
    @classmethod
    def validate_server_name(cls, v):
        # Basic server name validation - allow alphanumeric, underscore, and hyphen
        if not v.replace('_', 'a').replace('-', 'a').isalnum():
            raise ValueError('Invalid server name format')
        return v

    @field_validator('scan_type')
    @classmethod
    def validate_scan_type(cls, v):
        if v not in ['fast', 'full', 'config-only']:
            raise ValueError('Invalid scan type')
        return v


class DatabaseUpdateRequest(BaseModel):
    database: str

    @field_validator('database')
    @classmethod
    def validate_database(cls, v):
        allowed = ['nvd', 'ubuntu', 'debian', 'redhat', 'amazon', 'alpine',
                  'gost_ubuntu', 'gost_debian', 'gost_redhat', 'all']
        if v not in allowed:
            raise ValueError(f'Invalid database type. Allowed: {allowed}')
        return v


class SSHConfigRequest(BaseModel):
    content: str

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if not v.strip():
            raise ValueError('SSH config content cannot be empty')
        return v


class SSHKeyRequest(BaseModel):
    filename: str
    content: str
    key_type: str

    @field_validator('filename')
    @classmethod
    def validate_filename(cls, v):
        # Sanitize filename to prevent path traversal
        if not v or '/' in v or v.startswith('.') or '..' in v:
            raise ValueError('Invalid filename')
        return v

    @field_validator('key_type')
    @classmethod
    def validate_key_type(cls, v):
        if v not in ['private', 'public']:
            raise ValueError('Key type must be private or public')
        return v

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if not v.strip():
            raise ValueError('Key content cannot be empty')
        return v


class LynisScanRequest(BaseModel):
    host: Dict[str, Any]
    scan_id: int
    lynis_script: str
    report_path: str = "/var/log/lynis-report.dat"
    local_report_path: str

    @field_validator('host')
    @classmethod
    def validate_host(cls, v):
        required_fields = ['hostname', 'port', 'username']
        for field in required_fields:
            if field not in v:
                raise ValueError(f'Missing required host field: {field}')
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


@app.post("/lynis/scan", response_model=JobResponse)
async def start_lynis_scan(request: LynisScanRequest, api_key: str = Depends(verify_api_key)):
    """Start a Lynis security audit"""
    job_id = str(uuid.uuid4())

    logger.info(f"Starting Lynis scan job {job_id} for host {request.host['hostname']}")

    # Track job
    active_jobs[job_id] = {
        "status": "starting",
        "started_at": datetime.utcnow(),
        "type": "lynis_scan",
        "request": request.dict()
    }

    # Start scan asynchronously
    asyncio.create_task(execute_lynis_scan(job_id, request))

    return JobResponse(
        job_id=job_id,
        status="starting",
        message=f"Lynis scan started for host {request.host['hostname']}"
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


# SSH Management Endpoints

@app.get("/ssh/config")
async def get_ssh_config(api_key: str = Depends(verify_api_key)):
    """Get SSH config content"""
    try:
        ssh_config_path = Path(COMPOSE_PROJECT_DIR) / ".ssh" / "config"

        if ssh_config_path.exists():
            with open(ssh_config_path, 'r') as f:
                content = f.read()
        else:
            content = "# SSH Config for Vuls\n# Add your host configurations here\n"

        return {
            "content": content,
            "path": str(ssh_config_path),
            "exists": ssh_config_path.exists()
        }
    except Exception as e:
        logger.error(f"Error reading SSH config: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to read SSH config: {str(e)}")


@app.post("/ssh/config")
async def write_ssh_config(request: SSHConfigRequest, api_key: str = Depends(verify_api_key)):
    """Write SSH config with proper permissions and validation"""
    try:
        ssh_dir = Path(COMPOSE_PROJECT_DIR) / ".ssh"
        ssh_config_path = ssh_dir / "config"
        temp_config_path = ssh_dir / "config.tmp"

        # Ensure .ssh directory exists
        ssh_dir.mkdir(mode=0o700, exist_ok=True)

        # Write config to temporary file first for validation
        with open(temp_config_path, 'w') as f:
            f.write(request.content)

        # Set proper permissions on temp file
        os.chown(temp_config_path, 0, 0)  # root:root
        os.chmod(temp_config_path, 0o600)  # 600 permissions

        # Validate SSH config syntax using ssh -G
        validation_results = await validate_ssh_config_syntax(temp_config_path)

        if not validation_results["valid"]:
            # Remove temp file on validation failure
            temp_config_path.unlink()
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "SSH config validation failed",
                    "validation_errors": validation_results["errors"],
                    "validation_warnings": validation_results.get("warnings", [])
                }
            )

        # If validation passes, move temp file to final location
        if ssh_config_path.exists():
            # Create backup of existing config
            backup_path = ssh_dir / f"config.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(ssh_config_path, backup_path)
            logger.info(f"Created backup at {backup_path}")

        # Move validated config to final location
        shutil.move(str(temp_config_path), str(ssh_config_path))

        # Ensure final permissions are correct
        os.chown(ssh_config_path, 0, 0)  # root:root
        os.chmod(ssh_config_path, 0o600)  # 600 permissions

        logger.info(f"SSH config written and validated successfully to {ssh_config_path}")

        return {
            "success": True,
            "message": "SSH config written and validated successfully",
            "path": str(ssh_config_path),
            "permissions": "600",
            "owner": "root:root",
            "validation": validation_results
        }
    except HTTPException:
        raise
    except Exception as e:
        # Clean up temp file if it exists
        if 'temp_config_path' in locals() and temp_config_path.exists():
            temp_config_path.unlink()
        logger.error(f"Error writing SSH config: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to write SSH config: {str(e)}")


async def validate_ssh_config_syntax(config_path: Path) -> dict:
    """Validate SSH config syntax using ssh -G command"""
    validation_result = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "tested_hosts": []
    }

    try:
        # First, do a basic syntax check by parsing the config
        with open(config_path, 'r') as f:
            content = f.read()

        # Extract host patterns from the config for testing
        host_patterns = []
        for line in content.split('\n'):
            line = line.strip()
            if line.lower().startswith('host ') and not line.lower().startswith('hostname'):
                # Extract host pattern
                pattern = line[5:].strip()
                # Skip wildcard patterns for validation (they can't be tested with -G)
                if '*' not in pattern and '?' not in pattern and pattern not in ['*', '!*']:
                    host_patterns.append(pattern)

        # Test a few representative hosts (limit to avoid delays)
        test_hosts = host_patterns[:3]  # Test max 3 hosts to avoid delays

        for host in test_hosts:
            try:
                # Use ssh -G to validate config for this host
                # This will parse the config and show what SSH would actually use
                cmd = ["ssh", "-F", str(config_path), "-G", host]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=5  # 5 second timeout per host
                    )
                    returncode = process.returncode
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    validation_result["warnings"].append(f"Validation timeout for host '{host}'")
                    continue

                if returncode == 0:
                    validation_result["tested_hosts"].append({
                        "host": host,
                        "status": "valid"
                    })
                    logger.info(f"SSH config validation passed for host: {host}")
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown SSH config error"
                    validation_result["errors"].append(f"Host '{host}': {error_msg}")
                    validation_result["tested_hosts"].append({
                        "host": host,
                        "status": "error",
                        "error": error_msg
                    })
                    logger.warning(f"SSH config validation failed for host {host}: {error_msg}")

            except Exception as e:
                validation_result["warnings"].append(f"Could not validate host '{host}': {str(e)}")
                logger.warning(f"Exception during SSH validation for {host}: {str(e)}")

        # If we have errors, mark as invalid
        if validation_result["errors"]:
            validation_result["valid"] = False

        # Add summary info
        validation_result["summary"] = {
            "total_hosts_found": len(host_patterns),
            "hosts_tested": len(test_hosts),
            "validation_time": "< 5s per host"
        }

    except Exception as e:
        validation_result["valid"] = False
        validation_result["errors"].append(f"Config validation failed: {str(e)}")
        logger.error(f"SSH config validation exception: {str(e)}")

    return validation_result


@app.get("/ssh/keys")
async def list_ssh_keys(api_key: str = Depends(verify_api_key)):
    """List SSH keys in .ssh directory"""
    try:
        ssh_dir = Path(COMPOSE_PROJECT_DIR) / ".ssh"
        keys = []

        if ssh_dir.exists():
            for key_file in ssh_dir.iterdir():
                if key_file.is_file() and key_file.name not in ['config', 'known_hosts', 'known_hosts.old']:
                    stat_info = key_file.stat()

                    # Determine key type
                    key_type = "unknown"
                    if key_file.name.endswith('.pub'):
                        key_type = "public"
                    elif not '.' in key_file.name or key_file.name.endswith(('_rsa', '_ed25519', '_ecdsa')):
                        key_type = "private"

                    keys.append({
                        "filename": key_file.name,
                        "key_type": key_type,
                        "size": stat_info.st_size,
                        "permissions": oct(stat_info.st_mode)[-3:],
                        "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                        "path": str(key_file)
                    })

        # Sort by filename
        keys.sort(key=lambda x: x['filename'])

        return {"keys": keys}
    except Exception as e:
        logger.error(f"Error listing SSH keys: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list SSH keys: {str(e)}")


@app.post("/ssh/keys/{filename}")
async def write_ssh_key(filename: str, request: SSHKeyRequest, api_key: str = Depends(verify_api_key)):
    """Write SSH key with proper permissions"""
    try:
        # Validate filename matches request
        if filename != request.filename:
            raise HTTPException(status_code=400, detail="Filename mismatch")

        ssh_dir = Path(COMPOSE_PROJECT_DIR) / ".ssh"
        key_path = ssh_dir / filename

        # Ensure .ssh directory exists
        ssh_dir.mkdir(mode=0o700, exist_ok=True)

        # Basic key format validation
        content = request.content.strip()
        if request.key_type == "public":
            if not (content.startswith(('ssh-rsa', 'ssh-ed25519', 'ssh-ecdsa', 'ecdsa-sha2-')) or 'ssh-' in content):
                raise HTTPException(status_code=400, detail="Invalid public key format")
        elif request.key_type == "private":
            if not (content.startswith('-----BEGIN') or 'PRIVATE KEY' in content):
                raise HTTPException(status_code=400, detail="Invalid private key format")

        # Write key file
        with open(key_path, 'w') as f:
            f.write(content)
            if not content.endswith('\n'):
                f.write('\n')

        # Set proper permissions and ownership
        os.chown(key_path, 0, 0)  # root:root
        if request.key_type == "private":
            os.chmod(key_path, 0o600)  # Private keys: 600
            permissions = "600"
        else:
            os.chmod(key_path, 0o644)  # Public keys: 644
            permissions = "644"

        logger.info(f"SSH key '{filename}' written successfully with {permissions} permissions")

        return {
            "success": True,
            "message": f"SSH key '{filename}' written successfully",
            "filename": filename,
            "key_type": request.key_type,
            "permissions": permissions,
            "owner": "root:root"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error writing SSH key '{filename}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to write SSH key: {str(e)}")


@app.delete("/ssh/keys/{filename}")
async def delete_ssh_key(filename: str, api_key: str = Depends(verify_api_key)):
    """Delete SSH key file"""
    try:
        # Validate filename for security
        if not filename or '/' in filename or filename.startswith('.') or '..' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")

        # Prevent deletion of critical files
        if filename in ['config', 'known_hosts', 'known_hosts.old']:
            raise HTTPException(status_code=400, detail="Cannot delete system SSH files")

        ssh_dir = Path(COMPOSE_PROJECT_DIR) / ".ssh"
        key_path = ssh_dir / filename

        if not key_path.exists():
            raise HTTPException(status_code=404, detail="SSH key file not found")

        # Delete the file
        key_path.unlink()

        logger.info(f"SSH key '{filename}' deleted successfully")

        return {
            "success": True,
            "message": f"SSH key '{filename}' deleted successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting SSH key '{filename}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete SSH key: {str(e)}")


@app.post("/ssh/permissions/reset")
async def reset_ssh_permissions(api_key: str = Depends(verify_api_key)):
    """Reset all SSH file permissions to proper values"""
    try:
        ssh_dir = Path(COMPOSE_PROJECT_DIR) / ".ssh"

        if not ssh_dir.exists():
            raise HTTPException(status_code=404, detail="SSH directory not found")

        results = []

        # Set directory permissions
        os.chown(ssh_dir, 0, 0)  # root:root
        os.chmod(ssh_dir, 0o700)  # 700 for directory
        results.append({"path": str(ssh_dir), "type": "directory", "permissions": "700", "owner": "root:root"})

        # Process all files in .ssh directory
        for item in ssh_dir.iterdir():
            if item.is_file():
                os.chown(item, 0, 0)  # root:root

                if item.name == 'config':
                    os.chmod(item, 0o600)  # 600 for config
                    results.append({"path": str(item), "type": "config", "permissions": "600", "owner": "root:root"})
                elif item.name.endswith('.pub'):
                    os.chmod(item, 0o644)  # 644 for public keys
                    results.append({"path": str(item), "type": "public_key", "permissions": "644", "owner": "root:root"})
                else:
                    os.chmod(item, 0o600)  # 600 for private keys and other files
                    results.append({"path": str(item), "type": "private_key", "permissions": "600", "owner": "root:root"})

        logger.info(f"SSH permissions reset for {len(results)} items")

        return {
            "success": True,
            "message": f"SSH permissions reset for {len(results)} items",
            "results": results
        }
    except Exception as e:
        logger.error(f"Error resetting SSH permissions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to reset SSH permissions: {str(e)}")


async def fix_scan_result_permissions(job_id: str):
    """Fix permissions on scan result files so worker container can read them"""
    try:
        results_dir = Path(COMPOSE_PROJECT_DIR) / "results" / job_id[:8]

        if not results_dir.exists():
            logger.warning(f"Results directory not found: {results_dir}")
            return

        # Recursively fix permissions on all files and directories
        for root, dirs, files in os.walk(results_dir):
            # Fix directory permissions
            for dir_name in dirs:
                dir_path = Path(root) / dir_name
                os.chmod(dir_path, 0o755)  # rwxr-xr-x
                logger.debug(f"Fixed directory permissions: {dir_path}")

            # Fix file permissions
            for file_name in files:
                file_path = Path(root) / file_name
                os.chmod(file_path, 0o644)  # rw-r--r--
                logger.debug(f"Fixed file permissions: {file_path}")

        # Also fix the parent directory permissions
        os.chmod(results_dir, 0o755)

        logger.info(f"Fixed permissions for scan results directory: {results_dir}")

    except Exception as e:
        logger.error(f"Error fixing scan result permissions: {e}")
        raise


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
            "-v", f"{HOST_USER_HOME}/.cloudflared:/root/.cloudflared:rw",
            # Environment variables
            "-e", "VULS_CONFIG_PATH=/vuls/config.toml",
            "-e", "AWS_PROFILE=default",
            "-e", "AWS_REGION=eu-west-2",
            "-e", "AWS_CONFIG_FILE=/root/.aws/config",
            "-e", "AWS_SHARED_CREDENTIALS_FILE=/root/.aws/credentials",
            "-e", "GOOGLE_APPLICATION_CREDENTIALS=/root/.config/gcloud/application_default_credentials.json",
            "-e", "CLOUDSDK_CONFIG=/root/.config/gcloud",
            "-e", f"CF_ACCESS_CLIENT_ID={CF_ACCESS_CLIENT_ID}",
            "-e", f"CF_ACCESS_CLIENT_SECRET={CF_ACCESS_CLIENT_SECRET}",
            # Network connectivity
            "--network", "vuls_default",
            # Use the vuls image
            "vuls-vuls:latest",
            # Command with server name
            "scan", "-config=/vuls/config.toml", f"-results-dir=/vuls/results/{job_id[:8]}", request.server_name
        ]

        # Add scan type flags (note: fast scan is controlled by config, not flags)
        if request.scan_type == "config-only":
            # For config test, we would use configtest command instead of scan
            # But for now, just do a regular scan
            pass

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

        # Fix permissions on scan results so worker container can read them
        if returncode == 0:
            try:
                await fix_scan_result_permissions(job_id)
                logger.info(f"Fixed permissions for scan results: {job_id}")
            except Exception as perm_error:
                logger.warning(f"Failed to fix permissions for scan {job_id}: {perm_error}")

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


async def execute_lynis_scan(job_id: str, request: LynisScanRequest):
    """Execute Lynis security audit on remote host"""
    try:
        active_jobs[job_id]["status"] = "running"
        host = request.host

        logger.info(f"Starting Lynis scan for host {host['hostname']}")

        # Create temporary script file
        script_path = Path(COMPOSE_PROJECT_DIR) / "logs" / f"lynis-script-{job_id[:8]}.sh"
        with open(script_path, 'w') as f:
            f.write(request.lynis_script)
        os.chmod(script_path, 0o755)

        # Build SSH connection command
        ssh_cmd = _build_ssh_command_for_lynis(host)

        # Generate unique container name
        container_name = f"ssh-client-{job_id[:8]}"

        # Build docker run command for SSH client
        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            # Mount SSH directory and script
            "-v", f"{HOST_PROJECT_PATH}/.ssh:/root/.ssh:ro",
            "-v", f"{HOST_PROJECT_PATH}/logs:/tmp/scripts:rw",
            # Mount credentials for cloud proxies
            "-v", f"{HOST_USER_HOME}/.config/gcloud:/root/.config/gcloud:ro",
            "-v", f"{HOST_USER_HOME}/.aws:/root/.aws:ro",
            "-v", f"{HOST_USER_HOME}/.cloudflared:/root/.cloudflared:ro",
            # Environment variables
            "-e", f"CF_ACCESS_CLIENT_ID={CF_ACCESS_CLIENT_ID}",
            "-e", f"CF_ACCESS_CLIENT_SECRET={CF_ACCESS_CLIENT_SECRET}",
            # Network connectivity
            "--network", "vuls_default",
            # Use SSH client image
            "ssh-client:latest",
            # Execute the scan
            "/bin/bash", "-c", f"""
set -e

# Function to log messages
log() {{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}}

log "Starting Lynis scan execution"

# Build SSH command
SSH_CMD="{ssh_cmd}"

log "Uploading and executing Lynis script on remote host"

# Upload script to remote host
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /tmp/scripts/lynis-script-{job_id[:8]}.sh {host['username']}@{host['hostname']}:/tmp/lynis-install.sh

# Execute script on remote host
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {host['username']}@{host['hostname']} 'chmod +x /tmp/lynis-install.sh && /tmp/lynis-install.sh'

log "Downloading Lynis report"

# Download report file
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {host['username']}@{host['hostname']}:{request.report_path} /tmp/scripts/lynis-report-{request.scan_id}.dat

log "Lynis scan completed successfully"
"""
        ]

        logger.info(f"Executing Lynis scan command for host {host['hostname']}")

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

        # Clean up script file
        try:
            script_path.unlink()
        except:
            pass

        # Update job status
        if returncode == 0:
            # Copy report to final location
            report_source = Path(COMPOSE_PROJECT_DIR) / "logs" / f"lynis-report-{request.scan_id}.dat"
            if report_source.exists():
                # Ensure the target directory exists
                target_path = Path(request.local_report_path)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(report_source, target_path)
                report_source.unlink()  # Clean up temp file

                active_jobs[job_id].update({
                    "status": "completed",
                    "completed_at": datetime.utcnow(),
                    "result": {
                        "returncode": returncode,
                        "stdout": stdout.decode() if stdout else "",
                        "stderr": stderr.decode() if stderr else "",
                        "report_path": request.local_report_path
                    }
                })
            else:
                active_jobs[job_id].update({
                    "status": "failed",
                    "completed_at": datetime.utcnow(),
                    "error": "Lynis report file not found after scan",
                    "result": {
                        "returncode": returncode,
                        "stdout": stdout.decode() if stdout else "",
                        "stderr": stderr.decode() if stderr else ""
                    }
                })
        else:
            active_jobs[job_id].update({
                "status": "failed",
                "completed_at": datetime.utcnow(),
                "error": f"Lynis scan failed with code {returncode}: {stderr.decode() if stderr else 'Unknown error'}",
                "result": {
                    "returncode": returncode,
                    "stdout": stdout.decode() if stdout else "",
                    "stderr": stderr.decode() if stderr else ""
                }
            })

        logger.info(f"Lynis scan job {job_id} completed with status: {active_jobs[job_id]['status']}")

    except Exception as e:
        logger.error(f"Error in Lynis scan job {job_id}: {str(e)}")
        active_jobs[job_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow(),
            "error": str(e)
        })


def _build_ssh_command_for_lynis(host: Dict[str, Any]) -> str:
    """Build SSH command for Lynis scan"""
    cmd_parts = []

    # Handle cloud proxies
    if host.get('use_aws_proxy') and host.get('aws_instance_id'):
        # AWS Session Manager
        cmd_parts = [
            "aws", "ssm", "start-session",
            "--target", host['aws_instance_id'],
            "--region", host.get('aws_region', 'us-east-1')
        ]
        return " ".join(cmd_parts)

    elif host.get('use_gcp_proxy') and host.get('gcp_instance_name'):
        # GCP IAP tunnel
        cmd_parts = [
            "gcloud", "compute", "ssh",
            host['gcp_instance_name'],
            "--zone", host.get('gcp_zone', 'us-central1-a'),
            "--project", host.get('gcp_project', 'default')
        ]
        return " ".join(cmd_parts)

    else:
        # Standard SSH
        cmd_parts = ["ssh"]

        # Add SSH options
        cmd_parts.extend([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=30"
        ])

        # Add key if specified
        if host.get('ssh_key_path'):
            cmd_parts.extend(["-i", host['ssh_key_path']])

        # Add port if not default
        if host.get('port', 22) != 22:
            cmd_parts.extend(["-p", str(host['port'])])

        # Add user and host
        if host.get('username'):
            cmd_parts.append(f"{host['username']}@{host['hostname']}")
        else:
            cmd_parts.append(host['hostname'])

        return " ".join(cmd_parts)


if __name__ == "__main__":
    logger.info("Starting Docker Executor service...")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
