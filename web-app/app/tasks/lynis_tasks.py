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
from ..services.lynis_service import LynisService

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
    db = SessionLocal()
    lynis_service = LynisService(db)

    try:
        # Get host information
        host = db.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise ValueError(f"Host {host_id} not found")

        logger.info(f"Starting Lynis scan for host {host.name} ({host.hostname})")

        # Create scan record
        scan = lynis_service.create_scan(host_id)

        # Update task state
        self.update_state(
            state='PROGRESS',
            meta={'scan_id': scan.id, 'status': 'Installing Lynis', 'progress': 10}
        )

        # Install and run Lynis
        result = _execute_lynis_scan(host, scan, scan_options or {})

        if result['success']:
            # Update task state
            self.update_state(
                state='PROGRESS',
                meta={'scan_id': scan.id, 'status': 'Parsing results', 'progress': 80}
            )

            # Parse and store results
            report_data = lynis_service.parse_lynis_report(result['report_path'], scan.id)
            scan = lynis_service.update_scan_with_results(scan.id, report_data)

            # Update task state
            self.update_state(
                state='SUCCESS',
                meta={
                    'scan_id': scan.id,
                    'status': 'Completed',
                    'progress': 100,
                    'hardening_index': scan.hardening_index,
                    'warnings': scan.total_warnings,
                    'suggestions': scan.total_suggestions
                }
            )

            logger.info(f"Lynis scan completed for host {host.name}. Hardening index: {scan.hardening_index}")
            return {
                'scan_id': scan.id,
                'hardening_index': scan.hardening_index,
                'warnings': scan.total_warnings,
                'suggestions': scan.total_suggestions
            }
        else:
            # Mark scan as failed
            lynis_service.mark_scan_failed(scan.id, result['error'])
            raise Exception(result['error'])

    except Exception as e:
        logger.error(f"Lynis scan failed for host {host_id}: {e}")

        # Try to mark scan as failed if we have a scan ID
        try:
            if 'scan' in locals():
                lynis_service.mark_scan_failed(scan.id, str(e))
        except:
            pass

        # Update task state
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'scan_id': getattr(scan, 'id', None) if 'scan' in locals() else None}
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
