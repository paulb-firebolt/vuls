"""Celery tasks for Lynis security audits"""

import os
import json
import logging
import tempfile
from typing import Dict, Optional
from celery import current_app
from sqlalchemy.orm import sessionmaker
from ..models.base import engine
from ..models import Host, LynisScan
# from ..services.lynis_service import LynisService  # Temporarily commented out

logger = logging.getLogger(__name__)

# Create database session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@current_app.task(bind=True)
def run_lynis_scan(self, host_id: int, scan_options: Optional[Dict] = None):
    """
    Run Lynis security audit on a remote host

    Args:
        host_id: ID of the host to scan
        scan_options: Optional scan configuration
    """
    from ..models import TaskRun
    from datetime import datetime, timezone

    db = SessionLocal()
    task_run = None

    try:
        logger.info(f"Starting Lynis scan for host {host_id} - REDIS FIXED & HOT RELOAD WORKING!")

        # Find the task_run record for this execution
        task_run = db.query(TaskRun).filter(TaskRun.celery_task_id == self.request.id).first()
        if task_run:
            task_run.status = 'running'
            task_run.started_at = datetime.now(timezone.utc)
            db.commit()

        # Simple test implementation
        self.update_state(
            state='PROGRESS',
            meta={'host_id': host_id, 'status': 'Starting scan', 'progress': 10}
        )

        # Simulate work
        import time
        time.sleep(2)

        self.update_state(
            state='PROGRESS',
            meta={'host_id': host_id, 'status': 'Running Lynis', 'progress': 50}
        )

        time.sleep(2)

        # Mark as completed
        if task_run:
            task_run.status = 'completed'
            task_run.completed_at = datetime.now(timezone.utc)
            task_run.result_data = {'host_id': host_id, 'status': 'completed', 'message': 'Test scan completed'}

            # Calculate duration safely, handling timezone differences
            if task_run.started_at:
                try:
                    # If started_at is timezone-naive, make it timezone-aware
                    if task_run.started_at.tzinfo is None:
                        started_at_utc = task_run.started_at.replace(tzinfo=timezone.utc)
                    else:
                        started_at_utc = task_run.started_at
                    task_run.duration_seconds = int((task_run.completed_at - started_at_utc).total_seconds())
                except Exception as e:
                    logger.warning(f"Could not calculate duration: {e}")
                    task_run.duration_seconds = 4  # Default to the sleep time

            db.commit()

        self.update_state(
            state='SUCCESS',
            meta={'host_id': host_id, 'status': 'Completed', 'progress': 100}
        )

        logger.info(f"Lynis scan completed for host {host_id}")
        return {'host_id': host_id, 'status': 'completed', 'message': 'Test scan completed'}

    except Exception as e:
        logger.error(f"Lynis scan failed for host {host_id}: {e}")

        # Mark as failed
        if task_run:
            task_run.status = 'failed'
            task_run.completed_at = datetime.now(timezone.utc)
            task_run.error_message = str(e)
            if task_run.started_at:
                try:
                    # If started_at is timezone-naive, make it timezone-aware
                    if task_run.started_at.tzinfo is None:
                        started_at_utc = task_run.started_at.replace(tzinfo=timezone.utc)
                    else:
                        started_at_utc = task_run.started_at
                    task_run.duration_seconds = int((task_run.completed_at - started_at_utc).total_seconds())
                except Exception:
                    task_run.duration_seconds = 0  # Default for failed tasks
            db.commit()

        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'host_id': host_id}
        )
        raise
    finally:
        db.close()


def _execute_lynis_scan(host: Host, scan: LynisScan, options: Dict) -> Dict:
    """
    Execute Lynis scan on remote host using Docker executor

    Args:
        host: Host object with connection details
        scan: LynisScan object
        options: Scan options

    Returns:
        Dict with success status and results
    """
    try:
        # Build SSH connection command
        ssh_cmd = _build_ssh_command(host)

        # Create temporary directory for results
        with tempfile.TemporaryDirectory() as temp_dir:
            local_report_path = os.path.join(temp_dir, f"lynis-report-{scan.id}.dat")

            # Build Lynis installation and execution script
            lynis_script = _build_lynis_script(options)

            # Execute via Docker executor
            executor_payload = {
                "action": "run_lynis_scan",
                "host": {
                    "hostname": host.hostname,
                    "port": host.port,
                    "username": host.username,
                    "ssh_key_path": host.key_path,
                    "use_aws_proxy": host.use_aws_proxy,
                    "aws_instance_id": host.aws_instance_id,
                    "aws_region": host.aws_region,
                    "use_gcp_proxy": host.use_gcp_proxy,
                    "gcp_instance_name": host.gcp_instance_name,
                    "gcp_zone": host.gcp_zone,
                    "gcp_project": host.gcp_project
                },
                "scan_id": scan.id,
                "lynis_script": lynis_script,
                "report_path": scan.remote_report_path,
                "local_report_path": local_report_path
            }

            # Send to executor (this would be implemented in the executor service)
            result = _send_to_executor(executor_payload)

            if result['success']:
                # Update scan with local report path
                scan.local_report_path = local_report_path
                return {
                    'success': True,
                    'report_path': local_report_path
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Unknown error during scan execution')
                }

    except Exception as e:
        logger.error(f"Error executing Lynis scan: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def _build_ssh_command(host: Host) -> str:
    """Build SSH command for connecting to host"""
    cmd_parts = ["ssh"]

    # Add SSH options
    cmd_parts.extend([
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=30"
    ])

    # Add key if specified
    if host.key_path:
        cmd_parts.extend(["-i", host.key_path])

    # Add port if not default
    if host.port != 22:
        cmd_parts.extend(["-p", str(host.port)])

    # Add user and host
    if host.username:
        cmd_parts.append(f"{host.username}@{host.hostname}")
    else:
        cmd_parts.append(host.hostname)

    return " ".join(cmd_parts)


def _build_lynis_script(options: Dict) -> str:
    """Build Lynis installation and execution script"""
    script = """#!/bin/bash
set -e

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

log "Starting Lynis installation and scan"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    log "Cannot detect OS version"
    exit 1
fi

log "Detected OS: $OS $VERSION"

# Install Lynis based on OS
case $OS in
    ubuntu|debian)
        log "Installing Lynis on Debian/Ubuntu"
        sudo apt-get update -qq
        sudo apt-get install -y lynis
        ;;
    centos|rhel|fedora)
        log "Installing Lynis on RHEL/CentOS/Fedora"
        if command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y lynis
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y lynis
        else
            log "No package manager found"
            exit 1
        fi
        ;;
    alpine)
        log "Installing Lynis on Alpine"
        sudo apk add --no-cache lynis
        ;;
    *)
        log "Installing Lynis from source"
        cd /tmp
        wget -q https://downloads.cisofy.com/lynis/lynis-3.0.9.tar.gz
        tar xzf lynis-3.0.9.tar.gz
        cd lynis
        LYNIS_CMD="./lynis"
        ;;
esac

# Set Lynis command if not set
if [ -z "$LYNIS_CMD" ]; then
    LYNIS_CMD="lynis"
fi

log "Running Lynis audit"

# Run Lynis audit
sudo $LYNIS_CMD audit system --no-colors --quiet --report-file /var/log/lynis-report.dat

log "Lynis scan completed"

# Ensure report file is readable
sudo chmod 644 /var/log/lynis-report.dat

log "Report file permissions updated"
"""

    # Add any custom options
    if options.get('quick_scan'):
        script = script.replace('audit system', 'audit system --quick')

    if options.get('tests'):
        tests = ','.join(options['tests'])
        script = script.replace('audit system', f'audit system --tests {tests}')

    return script


def _send_to_executor(payload: Dict) -> Dict:
    """
    Send scan request to Docker executor

    This is a placeholder - the actual implementation would send
    the request to the executor service via HTTP API
    """
    # TODO: Implement actual executor communication
    # For now, return a mock response
    logger.info(f"Would send to executor: {payload['action']} for host {payload['host']['hostname']}")

    return {
        'success': True,
        'message': 'Scan completed successfully'
    }


@current_app.task
def cleanup_old_lynis_reports(days_old: int = 30):
    """Clean up old Lynis report files"""
    db = SessionLocal()

    try:
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)

        # Find old scans
        old_scans = (
            db.query(LynisScan)
            .filter(LynisScan.completed_at < cutoff_date)
            .filter(LynisScan.local_report_path.isnot(None))
            .all()
        )

        cleaned_count = 0
        for scan in old_scans:
            if scan.local_report_path and os.path.exists(scan.local_report_path):
                try:
                    os.remove(scan.local_report_path)
                    scan.local_report_path = None
                    cleaned_count += 1
                except OSError as e:
                    logger.warning(f"Could not remove report file {scan.local_report_path}: {e}")

        db.commit()
        logger.info(f"Cleaned up {cleaned_count} old Lynis report files")

    except Exception as e:
        logger.error(f"Error cleaning up old reports: {e}")
        db.rollback()
    finally:
        db.close()
