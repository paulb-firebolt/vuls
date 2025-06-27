"""SSH Configuration Management API"""

import os
import re
import shutil
import httpx
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_active_user_from_cookie
from ..models.base import get_db
from ..models.user import User
from ..tasks.host_sync_tasks import sync_hosts_from_config_task

router = APIRouter()

# Docker Executor configuration
EXECUTOR_URL = os.getenv("EXECUTOR_URL", "http://vuls-executor:8080")
EXECUTOR_API_KEY = os.getenv("EXECUTOR_API_KEY", "change-me-in-production")

# SSH config paths
SSH_CONFIG_PATH = Path("/app/.ssh/config")
SSH_BACKUP_DIR = Path("/tmp/ssh_backups")
CONFIG_DIR = Path("/vuls")

# Ensure backup directory exists
SSH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)


async def call_executor(method: str, endpoint: str, json_data: dict = None) -> dict:
    """Call docker executor API"""
    url = f"{EXECUTOR_URL}{endpoint}"
    headers = {"X-API-Key": EXECUTOR_API_KEY}

    async with httpx.AsyncClient() as client:
        if method.upper() == "GET":
            response = await client.get(url, headers=headers)
        elif method.upper() == "POST":
            response = await client.post(url, headers=headers, json=json_data)
        elif method.upper() == "DELETE":
            response = await client.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Executor API error: {response.text}"
            )

        return response.json()


class SSHConfigContent(BaseModel):
    content: str


class SSHKeyContent(BaseModel):
    filename: str
    content: str
    key_type: str  # "private" or "public"


class SSHHost(BaseModel):
    name: str
    hostname: Optional[str] = None
    user: Optional[str] = None
    port: Optional[int] = None
    identity_file: Optional[str] = None
    proxy_command: Optional[str] = None
    connection_type: str = "direct"  # aws_ssm, gcp_iap, cloudflare, direct


class ValidationResult(BaseModel):
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    hosts: List[SSHHost] = []


def parse_ssh_config(content: str) -> List[SSHHost]:
    """Parse SSH config content and extract host definitions"""
    hosts = []
    current_host = None

    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Host or Match directive
        if line.lower().startswith('host ') or line.lower().startswith('match host'):
            if current_host:
                hosts.append(current_host)

            # Extract hostname pattern
            if line.lower().startswith('match host'):
                # Match host pattern
                match = re.search(r'match host\s+(.+?)(?:\s+exec|$)', line, re.IGNORECASE)
                hostname_pattern = match.group(1) if match else line.split()[2]
            else:
                # Regular Host
                hostname_pattern = ' '.join(line.split()[1:])

            current_host = SSHHost(name=hostname_pattern)

            # Detect connection type from patterns
            if 'glimpse' in hostname_pattern and ('glimpse.network' in hostname_pattern or 'firebolt.network' in hostname_pattern):
                current_host.connection_type = "cloudflare"
            elif any(keyword in line.lower() for keyword in ['ssm', 'aws']):
                current_host.connection_type = "aws_ssm"
            elif 'gcloud' in line.lower() or 'iap' in line.lower():
                current_host.connection_type = "gcp_iap"

        elif current_host:
            # Parse host options
            if line.lower().startswith('hostname '):
                current_host.hostname = line.split(None, 1)[1]
            elif line.lower().startswith('user '):
                current_host.user = line.split(None, 1)[1]
            elif line.lower().startswith('port '):
                try:
                    current_host.port = int(line.split()[1])
                except ValueError:
                    pass
            elif line.lower().startswith('identityfile '):
                current_host.identity_file = line.split(None, 1)[1]
            elif line.lower().startswith('proxycommand '):
                current_host.proxy_command = line.split(None, 1)[1]

                # Detect connection type from ProxyCommand
                if 'aws ssm start-session' in current_host.proxy_command:
                    current_host.connection_type = "aws_ssm"
                elif 'gcloud compute ssh' in current_host.proxy_command and 'tunnel-through-iap' in current_host.proxy_command:
                    current_host.connection_type = "gcp_iap"
                elif 'cloudflared access ssh' in current_host.proxy_command:
                    current_host.connection_type = "cloudflare"

    # Add the last host
    if current_host:
        hosts.append(current_host)

    return hosts


def validate_ssh_config(content: str) -> ValidationResult:
    """Validate SSH config syntax and content"""
    errors = []
    warnings = []

    try:
        hosts = parse_ssh_config(content)
    except Exception as e:
        return ValidationResult(
            valid=False,
            errors=[f"Failed to parse SSH config: {str(e)}"],
            hosts=[]
        )

    # Basic syntax validation
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Check for common syntax errors
        if line and not any(line.lower().startswith(keyword) for keyword in [
            'host', 'match', 'hostname', 'user', 'port', 'identityfile',
            'proxycommand', 'identitiesonly', 'forwardagent', 'compression',
            'stricthostkeychecking', 'controlpersist', 'certificatefile'
        ]):
            warnings.append(f"Line {i}: Unknown directive '{line.split()[0] if line.split() else line}'")

    # Check for missing required fields
    for host in hosts:
        if not host.hostname and host.connection_type == "direct":
            warnings.append(f"Host '{host.name}': No hostname specified for direct connection")

        if host.connection_type == "aws_ssm" and not host.proxy_command:
            errors.append(f"Host '{host.name}': AWS SSM connection requires ProxyCommand")

        if host.connection_type == "gcp_iap" and not host.proxy_command:
            errors.append(f"Host '{host.name}': GCP IAP connection requires ProxyCommand")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        hosts=hosts
    )


def create_backup(content: str) -> str:
    """Create a timestamped backup of SSH config"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_path = SSH_BACKUP_DIR / f"ssh_config_{timestamp}.backup"

    with open(backup_path, 'w') as f:
        f.write(content)

    return str(backup_path)


def update_vuls_config(hosts: List[SSHHost]) -> None:
    """Update config.toml with hosts from SSH config"""
    import toml

    config_path = CONFIG_DIR / "config" / "config.toml"

    # Read existing config
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = toml.load(f)
    else:
        config = {}

    # Ensure servers section exists
    if 'servers' not in config:
        config['servers'] = {}

    # Clear existing servers and rebuild from SSH config
    config['servers'] = {}

    for host in hosts:
        # Skip wildcard/pattern hosts for now
        if '*' in host.name or '?' in host.name:
            continue

        server_config = {
            'host': host.name
        }

        # Add scan mode based on connection type
        if host.connection_type == "aws_ssm":
            server_config['scanMode'] = ["fast"]
        elif host.connection_type == "gcp_iap":
            server_config['scanMode'] = ["fast"]
        elif host.connection_type == "cloudflare":
            server_config['scanMode'] = ["offline"]
        else:
            server_config['scanMode'] = ["fast", "offline"]

        config['servers'][host.name.replace('-', '_').replace('.', '_')] = server_config

    # Write updated config
    with open(config_path, 'w') as f:
        toml.dump(config, f)


@router.get("/ssh-config")
async def get_ssh_config(
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Get current SSH config content"""
    try:
        # Get SSH config from executor
        executor_response = await call_executor("GET", "/ssh/config")
        content = executor_response.get("content", "")

        validation = validate_ssh_config(content)

        return {
            "content": content,
            "validation": validation.dict(),
            "path": executor_response.get("path", ""),
            "exists": executor_response.get("exists", False)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read SSH config: {str(e)}")


@router.post("/ssh-config")
async def update_ssh_config(
    config_data: SSHConfigContent,
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Update SSH config with validation and backup"""
    try:
        # Validate the new config
        validation = validate_ssh_config(config_data.content)

        if not validation.valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "SSH config validation failed",
                    "errors": validation.errors,
                    "warnings": validation.warnings
                }
            )

        # Create backup of current config
        try:
            current_config = await call_executor("GET", "/ssh/config")
            if current_config.get("exists", False):
                backup_path = create_backup(current_config.get("content", ""))
            else:
                backup_path = None
        except Exception:
            backup_path = None

        # Write new config via executor
        executor_response = await call_executor("POST", "/ssh/config", {
            "content": config_data.content
        })

        # Update Vuls config.toml
        update_vuls_config(validation.hosts)

        # Trigger host synchronization in the background
        try:
            sync_hosts_from_config_task.delay()
        except Exception as e:
            # Log the error but don't fail the SSH config update
            print(f"Warning: Failed to trigger host sync task: {e}")

        return {
            "success": True,
            "message": "SSH config updated successfully",
            "backup_path": backup_path,
            "validation": validation.dict(),
            "hosts_updated": len(validation.hosts),
            "host_sync_triggered": True,
            "executor_response": executor_response
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update SSH config: {str(e)}")


@router.get("/ssh-config/backups")
async def list_backups(
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """List available SSH config backups"""
    try:
        backups = []
        if SSH_BACKUP_DIR.exists():
            for backup_file in sorted(SSH_BACKUP_DIR.glob("ssh_config_*.backup"), reverse=True):
                stat = backup_file.stat()
                backups.append({
                    "filename": backup_file.name,
                    "path": str(backup_file),
                    "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "size": stat.st_size
                })

        return {"backups": backups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")


@router.post("/ssh-config/restore/{backup_filename}")
async def restore_backup(
    backup_filename: str,
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Restore SSH config from backup"""
    try:
        backup_path = SSH_BACKUP_DIR / backup_filename

        if not backup_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")

        # Read backup content
        with open(backup_path, 'r') as f:
            backup_content = f.read()

        # Validate backup content
        validation = validate_ssh_config(backup_content)

        if not validation.valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Backup content is invalid",
                    "errors": validation.errors
                }
            )

        # Create backup of current config before restore
        if SSH_CONFIG_PATH.exists():
            with open(SSH_CONFIG_PATH, 'r') as f:
                current_content = f.read()
            current_backup = create_backup(current_content)
        else:
            current_backup = None

        # Restore from backup
        with open(SSH_CONFIG_PATH, 'w') as f:
            f.write(backup_content)

        # Set proper permissions
        os.chmod(SSH_CONFIG_PATH, 0o644)

        # Update Vuls config.toml
        update_vuls_config(validation.hosts)

        # Trigger host synchronization in the background
        try:
            sync_hosts_from_config_task.delay()
        except Exception as e:
            # Log the error but don't fail the restore operation
            print(f"Warning: Failed to trigger host sync task: {e}")

        return {
            "success": True,
            "message": f"SSH config restored from {backup_filename}",
            "current_backup": current_backup,
            "validation": validation.dict(),
            "host_sync_triggered": True
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restore backup: {str(e)}")


@router.get("/ssh-config/templates")
async def get_templates(
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Get SSH config templates for different connection types"""
    templates = {
        "aws_ssm": {
            "name": "AWS SSM Session Manager",
            "description": "Connect to EC2 instances via AWS Systems Manager",
            "template": """Host {hostname}
  User {user}
  Hostname {instance_id}
  ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"
  ControlPersist 72h"""
        },
        "gcp_iap": {
            "name": "Google Cloud IAP Tunnel",
            "description": "Connect to GCP instances via Identity-Aware Proxy",
            "template": """Host {hostname}
  User {user}
  HostName {instance_id}
  ProxyCommand gcloud compute ssh %h --tunnel-through-iap --zone={zone} --project={project} -- -W %h:%p"""
        },
        "cloudflare": {
            "name": "Cloudflare Access",
            "description": "Connect via Cloudflare Zero Trust",
            "template": """Match host {hostname_pattern}
  User {user}
  IdentitiesOnly yes
  ProxyCommand /usr/local/bin/cloudflared access ssh --hostname %h
  IdentityFile ~/.ssh/id_ed25519
  CertificateFile ~/.cloudflared/%h-cf_key-cert.pub
  ForwardAgent no
  Compression yes
  StrictHostKeyChecking no"""
        },
        "direct": {
            "name": "Direct SSH",
            "description": "Standard SSH connection",
            "template": """Host {hostname}
  User {user}
  HostName {ip_or_hostname}
  Port {port}
  IdentityFile ~/.ssh/{key_file}"""
        }
    }

    return {"templates": templates}


@router.get("/ssh-keys")
async def list_ssh_keys(
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """List SSH keys in the .ssh directory"""
    try:
        # Get SSH keys from executor
        executor_response = await call_executor("GET", "/ssh/keys")
        return executor_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list SSH keys: {str(e)}")


@router.post("/ssh-keys")
async def upload_ssh_key(
    key_data: SSHKeyContent,
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Upload/save SSH key content"""
    try:
        # Upload SSH key via executor
        executor_response = await call_executor("POST", f"/ssh/keys/{key_data.filename}", {
            "filename": key_data.filename,
            "content": key_data.content,
            "key_type": key_data.key_type
        })
        return executor_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload SSH key: {str(e)}")


@router.delete("/ssh-keys/{filename}")
async def delete_ssh_key(
    filename: str,
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Delete SSH key file"""
    try:
        # Delete SSH key via executor
        executor_response = await call_executor("DELETE", f"/ssh/keys/{filename}")
        return executor_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete SSH key: {str(e)}")


@router.get("/ssh-keys/{filename}")
async def get_ssh_key_content(
    filename: str,
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Get SSH key content (for public keys only)"""
    try:
        # Only allow viewing public keys for security
        if not filename.endswith('.pub'):
            raise HTTPException(status_code=403, detail="Can only view public key content")

        # Get SSH key content from executor
        executor_response = await call_executor("GET", f"/ssh/keys/{filename}")
        return {
            "filename": filename,
            "content": executor_response.get("content", ""),
            "key_type": "public"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read SSH key: {str(e)}")


@router.post("/ssh/permissions/reset")
async def reset_ssh_permissions(
    request: Request,
    current_user: User = Depends(get_current_active_user_from_cookie),
    db: Session = Depends(get_db)
):
    """Reset all SSH file permissions to proper values"""
    try:
        # Reset SSH permissions via executor
        executor_response = await call_executor("POST", "/ssh/permissions/reset")
        return executor_response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset SSH permissions: {str(e)}")
