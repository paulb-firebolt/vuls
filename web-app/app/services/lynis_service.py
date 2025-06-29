"""Lynis security audit service"""

import os
import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from ..models import LynisScan, LynisControl, LynisFinding, Host
from ..models.lynis_finding import FindingType, FindingStatus

logger = logging.getLogger(__name__)


class LynisService:
    """Service for managing Lynis security audits"""

    def __init__(self, db: Session):
        self.db = db

    def create_scan(self, host_id: int) -> LynisScan:
        """Create a new Lynis scan record"""
        scan = LynisScan(
            host_id=host_id,
            status="running"
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def parse_lynis_report(self, report_path: str, scan_id: int) -> Dict:
        """Parse Lynis report file and extract findings"""
        if not os.path.exists(report_path):
            raise FileNotFoundError(f"Lynis report not found: {report_path}")

        findings = []
        scan_info = {}

        try:
            with open(report_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Parse key=value pairs
                    if '=' in line:
                        key, value = line.split('=', 1)

                        # Extract scan metadata
                        if key == 'lynis_version':
                            scan_info['lynis_version'] = value
                        elif key == 'scan_date':
                            scan_info['scan_date'] = value
                        elif key == 'hardening_index':
                            scan_info['hardening_index'] = int(value) if value.isdigit() else 0
                        elif key == 'os_name':
                            scan_info['os_name'] = value
                        elif key == 'os_version':
                            scan_info['os_version'] = value
                        elif key == 'kernel_version':
                            scan_info['kernel_version'] = value
                        elif key == 'git_commit':
                            scan_info['git_commit'] = value
                        elif key == 'git_date':
                            scan_info['git_date'] = value

                        # Parse findings
                        elif key.startswith('warning['):
                            control_id = self._extract_control_id(key)
                            if control_id:
                                findings.append({
                                    'control_id': control_id,
                                    'type': FindingType.WARNING,
                                    'status': FindingStatus.FOUND,
                                    'details': value
                                })

                        elif key.startswith('suggestion['):
                            control_id = self._extract_control_id(key)
                            if control_id:
                                findings.append({
                                    'control_id': control_id,
                                    'type': FindingType.SUGGESTION,
                                    'status': FindingStatus.FOUND,
                                    'details': value
                                })

                        elif key.startswith('manual['):
                            control_id = self._extract_control_id(key)
                            if control_id:
                                findings.append({
                                    'control_id': control_id,
                                    'type': FindingType.FINDING,
                                    'status': FindingStatus.FOUND,
                                    'details': value,
                                    'manual_check': True
                                })

            return {
                'scan_info': scan_info,
                'findings': findings
            }

        except Exception as e:
            logger.error(f"Error parsing Lynis report {report_path}: {e}")
            raise

    def _extract_control_id(self, key: str) -> Optional[str]:
        """Extract control ID from Lynis report key"""
        # Extract control ID from keys like "warning[AUTH-9262]" or "suggestion[BOOT-5122]"
        match = re.search(r'\[([A-Z]+-\d+)\]', key)
        return match.group(1) if match else None

    def update_scan_with_results(self, scan_id: int, report_data: Dict) -> LynisScan:
        """Update scan with parsed results"""
        scan = self.db.query(LynisScan).filter(LynisScan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Update scan metadata
        scan_info = report_data.get('scan_info', {})
        scan.lynis_version = scan_info.get('lynis_version')
        scan.hardening_index = scan_info.get('hardening_index', 0)
        scan.os_name = scan_info.get('os_name')
        scan.os_version = scan_info.get('os_version')
        scan.kernel_version = scan_info.get('kernel_version')
        scan.git_commit = scan_info.get('git_commit')
        scan.git_date = scan_info.get('git_date')

        # Parse scan date
        if scan_info.get('scan_date'):
            try:
                scan.scan_date = datetime.strptime(scan_info['scan_date'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                logger.warning(f"Could not parse scan date: {scan_info['scan_date']}")

        # Process findings
        findings_data = report_data.get('findings', [])
        warning_count = 0
        suggestion_count = 0

        for finding_data in findings_data:
            control_id = finding_data['control_id']

            # Ensure control exists
            control = self._get_or_create_control(control_id)

            # Create finding
            finding = LynisFinding(
                scan_id=scan_id,
                control_id=control_id,
                finding_type=finding_data['type'],
                status=finding_data['status'],
                details=finding_data.get('details'),
                manual_check=finding_data.get('manual_check', False)
            )

            self.db.add(finding)

            # Count findings by type
            if finding_data['type'] == FindingType.WARNING:
                warning_count += 1
            elif finding_data['type'] == FindingType.SUGGESTION:
                suggestion_count += 1

        # Update counts
        scan.total_tests = len(findings_data)
        scan.total_warnings = warning_count
        scan.total_suggestions = suggestion_count
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(scan)
        return scan

    def _get_or_create_control(self, control_id: str) -> LynisControl:
        """Get existing control or create new one"""
        control = self.db.query(LynisControl).filter(LynisControl.control_id == control_id).first()

        if not control:
            # Extract category from control ID (e.g., "AUTH" from "AUTH-9262")
            category = control_id.split('-')[0] if '-' in control_id else 'MISC'

            control = LynisControl(
                control_id=control_id,
                category=category,
                description=f"Security control {control_id}",
                test_description=f"Test for {control_id}"
            )
            self.db.add(control)
            self.db.commit()
            self.db.refresh(control)

        return control

    def mark_scan_failed(self, scan_id: int, error_message: str) -> LynisScan:
        """Mark scan as failed with error message"""
        scan = self.db.query(LynisScan).filter(LynisScan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        scan.status = "failed"
        scan.error_message = error_message
        scan.completed_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_scan_by_id(self, scan_id: int) -> Optional[LynisScan]:
        """Get scan by ID"""
        return self.db.query(LynisScan).filter(LynisScan.id == scan_id).first()

    def get_scans_for_host(self, host_id: int, limit: int = 10) -> List[LynisScan]:
        """Get recent scans for a host"""
        return (
            self.db.query(LynisScan)
            .filter(LynisScan.host_id == host_id)
            .order_by(LynisScan.created_at.desc())
            .limit(limit)
            .all()
        )

    def get_latest_scan_for_host(self, host_id: int) -> Optional[LynisScan]:
        """Get the latest completed scan for a host"""
        return (
            self.db.query(LynisScan)
            .filter(LynisScan.host_id == host_id, LynisScan.status == "completed")
            .order_by(LynisScan.completed_at.desc())
            .first()
        )

    def get_findings_summary(self, scan_id: int) -> Dict:
        """Get summary of findings for a scan"""
        findings = (
            self.db.query(LynisFinding)
            .filter(LynisFinding.scan_id == scan_id)
            .all()
        )

        summary = {
            'total': len(findings),
            'warnings': len([f for f in findings if f.finding_type == FindingType.WARNING]),
            'suggestions': len([f for f in findings if f.finding_type == FindingType.SUGGESTION]),
            'manual_checks': len([f for f in findings if f.manual_check]),
            'by_category': {}
        }

        # Group by category
        for finding in findings:
            category = finding.control.category if finding.control else 'MISC'
            if category not in summary['by_category']:
                summary['by_category'][category] = {
                    'total': 0,
                    'warnings': 0,
                    'suggestions': 0
                }

            summary['by_category'][category]['total'] += 1
            if finding.finding_type == FindingType.WARNING:
                summary['by_category'][category]['warnings'] += 1
            elif finding.finding_type == FindingType.SUGGESTION:
                summary['by_category'][category]['suggestions'] += 1

        return summary
