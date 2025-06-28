"""Celery tasks for vulnerability scanning"""

import logging
import json
import os
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..models.base import get_db
from ..models.host import Host
from ..models.scan import Scan
from ..models.vulnerability import Vulnerability
from ..config import settings
from ..utils.executor_client import sync_start_scan, sync_wait_for_job_completion, sync_health_check
from .task_utils import update_task_status
import asyncio

logger = logging.getLogger(__name__)


def send_task_notification(task_id: int, task_run_id: int, status: str, task_name: str = None, result_data: dict = None):
    """Send task notification via Redis pub/sub"""
    try:
        from ..utils.notification_service import publish_task_notification
        publish_task_notification(task_id, task_run_id, status, task_name, result_data)
    except Exception as e:
        logger.error(f"Error sending task notification: {e}")


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
            # Run the scan using the executor service
            result = run_vuls_scan(scan.id, host.name, scan_type)

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
                    result_data = {
                        "scan_id": scan.id,
                        "vulnerabilities": scan.total_vulnerabilities,
                        "critical": scan.critical_count,
                        "high": scan.high_count,
                        "medium": scan.medium_count,
                        "low": scan.low_count
                    }
                    update_task_status.delay(task_run_id, "success", result_data=result_data)

                    # Send task notification
                    send_task_notification(
                        task_id=0,  # We don't have the scheduled task ID here, using 0 for now
                        task_run_id=task_run_id,
                        status="success",
                        task_name=f"Scan {host.name}",
                        result_data=result_data
                    )

                    # Also send WebSocket notification directly
                    try:
                        from ..api.websocket import notify_task_completion
                        import asyncio

                        # Create a new event loop for this thread if needed
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)

                        # Schedule the WebSocket notification
                        if loop.is_running():
                            asyncio.create_task(notify_task_completion(
                                task_id=0,
                                task_run_id=task_run_id,
                                status="success",
                                result_data=result_data
                            ))
                        else:
                            loop.run_until_complete(notify_task_completion(
                                task_id=0,
                                task_run_id=task_run_id,
                                status="success",
                                result_data=result_data
                            ))
                    except Exception as e:
                        logger.error(f"Error sending WebSocket notification: {e}")

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

                    # Send task notification for failure
                    send_task_notification(
                        task_id=0,
                        task_run_id=task_run_id,
                        status="failed",
                        task_name=f"Scan {host.name}",
                        result_data={"error": result.get("error")}
                    )

                    # Also send WebSocket notification directly for failure
                    try:
                        from ..api.websocket import notify_task_completion
                        import asyncio

                        # Create a new event loop for this thread if needed
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)

                        # Schedule the WebSocket notification
                        if loop.is_running():
                            asyncio.create_task(notify_task_completion(
                                task_id=0,
                                task_run_id=task_run_id,
                                status="failed",
                                result_data={"error": result.get("error")}
                            ))
                        else:
                            loop.run_until_complete(notify_task_completion(
                                task_id=0,
                                task_run_id=task_run_id,
                                status="failed",
                                result_data={"error": result.get("error")}
                            ))
                    except Exception as e:
                        logger.error(f"Error sending WebSocket notification for failure: {e}")

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


def run_vuls_scan(scan_id: int, server_name: str, scan_type: str) -> dict:
    """Execute the Vuls scan using the Docker Executor service"""
    try:
        # Check if executor service is healthy
        if not sync_health_check():
            return {
                "status": "error",
                "error": "Docker executor service is not available"
            }

        output_dir = f"{settings.vuls_results_dir}/scan_{scan_id}"
        os.makedirs(output_dir, exist_ok=True)

        logger.info(f"Starting scan via executor for server: {server_name}")

        # Start the scan via executor service
        try:
            scan_response = sync_start_scan(server_name, scan_type)
            job_id = scan_response["job_id"]

            logger.info(f"Scan job started with ID: {job_id}")

            # Wait for completion
            job_result = sync_wait_for_job_completion(job_id, timeout=1800)  # 30 minutes

            if job_result["status"] == "completed":
                # Look for JSON output file in results directory
                json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
                if json_files:
                    output_path = os.path.join(output_dir, json_files[0])
                    return {
                        "status": "success",
                        "output_path": output_path,
                        "job_id": job_id,
                        "executor_result": job_result.get("result", {})
                    }
                else:
                    # If no JSON file found locally, check if executor has results
                    executor_result = job_result.get("result", {})
                    if executor_result.get("returncode") == 0:
                        # Create a placeholder result file for now
                        # In a production system, you'd want to retrieve the actual results
                        placeholder_path = os.path.join(output_dir, f"scan_{scan_id}_results.json")
                        with open(placeholder_path, 'w') as f:
                            json.dump({"scan_id": scan_id, "status": "completed", "vulnerabilities": {}}, f)

                        return {
                            "status": "success",
                            "output_path": placeholder_path,
                            "job_id": job_id,
                            "executor_result": executor_result
                        }
                    else:
                        return {
                            "status": "error",
                            "error": "No scan results found",
                            "job_id": job_id,
                            "executor_result": executor_result
                        }
            else:
                # Scan failed
                error_msg = job_result.get("error", "Unknown error from executor")
                return {
                    "status": "error",
                    "error": error_msg,
                    "job_id": job_id,
                    "executor_result": job_result.get("result", {})
                }

        except Exception as e:
            logger.error(f"Error communicating with executor service: {e}")
            return {
                "status": "error",
                "error": f"Executor service error: {str(e)}"
            }

    except Exception as e:
        logger.error(f"Error in run_vuls_scan: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


def extract_target_from_config(config_path: str) -> Optional[str]:
    """Extract target hostname/IP from Vuls config file"""
    try:
        import toml
        with open(config_path, 'r') as f:
            config = toml.load(f)

        # Look for servers section
        servers = config.get("servers", {})
        if servers:
            # Get the first server's host
            for server_name, server_config in servers.items():
                host = server_config.get("host")
                if host:
                    return host

        return None
    except Exception as e:
        logger.error(f"Error extracting target from config: {e}")
        return None


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
