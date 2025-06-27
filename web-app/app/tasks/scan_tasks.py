"""Celery tasks for vulnerability scanning"""

import logging
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..models.base import get_db
from ..models.host import Host
from ..models.scan import Scan
from ..models.vulnerability import Vulnerability
from ..config import settings
from .task_utils import update_task_status

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def run_vulnerability_scan(self, host_id: int, scan_type: str = "fast", task_run_id: Optional[int] = None):
    """Run a vulnerability scan for a specific host"""
    try:
        db = next(get_db())

        # Get the host
        host = db.query(Host).filter(Host.id == host_id).first()
        if not host:
            error_msg = f"Host with ID {host_id} not found"
            logger.error(error_msg)
            if task_run_id:
                update_task_status.delay(task_run_id, "failed", error_message=error_msg)
            return {"status": "error", "error": error_msg}

        # Create scan record
        scan = Scan(
            host_id=host_id,
            scan_type=scan_type,
            status="running",
            started_at=datetime.now(timezone.utc)
        )
        db.add(scan)
        db.commit()

        logger.info(f"Starting {scan_type} scan for host {host.name} (ID: {host_id})")

        try:
            # Generate Vuls config for this specific host
            config_content = generate_vuls_config(host, scan_type)
            config_path = f"{settings.vuls_config_dir}/scan_{scan.id}_config.toml"

            with open(config_path, 'w') as f:
                f.write(config_content)

            # Run the scan using Docker
            result = run_vuls_scan(scan.id, config_path, scan_type)

            if result["status"] == "success":
                # Process scan results
                scan_results = process_scan_results(scan.id, result["output_path"])

                # Update scan record
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.vuls_output_path = result["output_path"]
                scan.total_packages = scan_results.get("total_packages", 0)
                scan.total_vulnerabilities = scan_results.get("total_vulnerabilities", 0)
                scan.critical_count = scan_results.get("critical_count", 0)
                scan.high_count = scan_results.get("high_count", 0)
                scan.medium_count = scan_results.get("medium_count", 0)
                scan.low_count = scan_results.get("low_count", 0)

                # Update host last scan info
                host.last_scan_at = scan.completed_at
                host.last_scan_status = "success"

                db.commit()

                # Update task run status if this was scheduled
                if task_run_id:
                    update_task_status.delay(
                        task_run_id,
                        "success",
                        result_data={
                            "scan_id": scan.id,
                            "vulnerabilities": scan.total_vulnerabilities,
                            "critical": scan.critical_count,
                            "high": scan.high_count,
                            "medium": scan.medium_count,
                            "low": scan.low_count
                        }
                    )

                logger.info(f"Scan completed successfully for host {host.name}")

                return {
                    "status": "success",
                    "scan_id": scan.id,
                    "vulnerabilities_found": scan.total_vulnerabilities,
                    "severity_breakdown": {
                        "critical": scan.critical_count,
                        "high": scan.high_count,
                        "medium": scan.medium_count,
                        "low": scan.low_count
                    }
                }

            else:
                # Scan failed
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.error_message = result.get("error", "Unknown error")

                host.last_scan_status = "failed"

                db.commit()

                if task_run_id:
                    update_task_status.delay(task_run_id, "failed", error_message=result.get("error"))

                return {"status": "error", "error": result.get("error")}

        except Exception as e:
            # Update scan record with error
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.error_message = str(e)

            host.last_scan_status = "failed"

            db.commit()

            if task_run_id:
                update_task_status.delay(task_run_id, "failed", error_message=str(e))

            raise e

        finally:
            # Clean up temporary config file
            if 'config_path' in locals() and os.path.exists(config_path):
                os.remove(config_path)

            db.close()

    except Exception as e:
        logger.error(f"Error in vulnerability scan: {str(e)}")
        return {"status": "error", "error": str(e)}


def generate_vuls_config(host: Host, scan_type: str) -> str:
    """Generate Vuls configuration for a specific host"""
    config_lines = [
        "[default]",
        "port = \"22\"",
        "user = \"root\"",
        "",
        f"[servers.{host.name}]",
        f"host = \"{host.hostname}\"",
        f"port = \"{host.port}\"",
        f"user = \"{host.username}\"",
    ]

    # Add SSH key if specified
    if host.key_path:
        config_lines.append(f"keyPath = \"{host.key_path}\"")

    # Add AWS proxy settings if enabled
    if host.use_aws_proxy and host.aws_instance_id:
        config_lines.extend([
            "[servers.{}.aws]".format(host.name),
            f"instanceID = \"{host.aws_instance_id}\"",
            f"region = \"{host.aws_region or 'us-east-1'}\"",
        ])

    # Add GCP proxy settings if enabled
    if host.use_gcp_proxy and host.gcp_instance_name:
        config_lines.extend([
            "[servers.{}.gcp]".format(host.name),
            f"instanceName = \"{host.gcp_instance_name}\"",
            f"zone = \"{host.gcp_zone}\"",
            f"project = \"{host.gcp_project}\"",
        ])

    # Add scan-specific options
    if scan_type == "fast":
        config_lines.append("scanMode = [\"fast\"]")
    elif scan_type == "full":
        config_lines.append("scanMode = [\"fast\", \"deep\"]")

    return "\n".join(config_lines)


def run_vuls_scan(scan_id: int, config_path: str, scan_type: str) -> dict:
    """Execute the Vuls scan using Docker"""
    try:
        output_dir = f"{settings.vuls_results_dir}/scan_{scan_id}"
        os.makedirs(output_dir, exist_ok=True)

        # Docker command to run Vuls scan
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{config_path}:/vuls/config.toml:ro",
            "-v", f"{output_dir}:/vuls/results:rw",
            "-v", f"{settings.vuls_db_dir}:/vuls/db:ro",
            "-v", f"{settings.vuls_logs_dir}:/vuls/logs:rw",
            "-v", "/root/.ssh:/root/.ssh:ro",
            "vuls/vuls:latest",
            "scan", "-config=/vuls/config.toml", "-results-dir=/vuls/results"
        ]

        # Run the scan
        logger.info(f"Running Vuls scan with command: {' '.join(docker_cmd)}")
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=1800  # 30 minutes timeout
        )

        if result.returncode == 0:
            # Look for JSON output file
            json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
            if json_files:
                output_path = os.path.join(output_dir, json_files[0])
                return {
                    "status": "success",
                    "output_path": output_path,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
            else:
                return {
                    "status": "error",
                    "error": "No JSON output file found",
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
        else:
            return {
                "status": "error",
                "error": f"Vuls scan failed with return code {result.returncode}",
                "stdout": result.stdout,
                "stderr": result.stderr
            }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Scan timed out after 30 minutes"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def process_scan_results(scan_id: int, output_path: str) -> dict:
    """Process Vuls JSON output and store vulnerabilities in database"""
    try:
        with open(output_path, 'r') as f:
            scan_data = json.load(f)

        db = next(get_db())

        total_packages = 0
        total_vulnerabilities = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Process each server in the scan results
        for server_name, server_data in scan_data.items():
            if isinstance(server_data, dict):
                # Count packages
                packages = server_data.get("packages", {})
                total_packages += len(packages)

                # Process vulnerabilities
                vulnerabilities = server_data.get("scannedCves", {})
                for cve_id, vuln_data in vulnerabilities.items():
                    total_vulnerabilities += 1

                    # Determine severity
                    severity = determine_severity(vuln_data)
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                    # Create vulnerability record
                    vulnerability = Vulnerability(
                        scan_id=scan_id,
                        cve_id=cve_id,
                        severity=severity,
                        score=vuln_data.get("cvss3Score", vuln_data.get("cvss2Score")),
                        summary=vuln_data.get("summary", ""),
                        affected_packages=json.dumps(vuln_data.get("affectedPackages", [])),
                        published_date=parse_date(vuln_data.get("publishedDate")),
                        last_modified_date=parse_date(vuln_data.get("lastModifiedDate"))
                    )
                    db.add(vulnerability)

        db.commit()
        db.close()

        return {
            "total_packages": total_packages,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"]
        }

    except Exception as e:
        logger.error(f"Error processing scan results: {str(e)}")
        return {
            "total_packages": 0,
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }


def determine_severity(vuln_data: dict) -> str:
    """Determine vulnerability severity from CVSS score"""
    cvss3_score = vuln_data.get("cvss3Score")
    cvss2_score = vuln_data.get("cvss2Score")

    score = cvss3_score or cvss2_score or 0

    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    else:
        return "low"


def parse_date(date_string: str) -> Optional[datetime]:
    """Parse date string to datetime object"""
    if not date_string:
        return None

    try:
        # Try different date formats
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
            try:
                return datetime.strptime(date_string, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
    except Exception:
        return None
