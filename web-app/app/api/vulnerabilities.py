"""API endpoints for vulnerability management"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from ..models.base import get_db
from ..models.host import Host
from ..models.scan import Scan
from ..models.vulnerability import Vulnerability, VulnerabilityAnalysis
from ..services.vulnerability_report_service import VulnerabilityReportService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


@router.get("/hosts/{host_id}/vulnerabilities")
async def get_host_latest_vulnerabilities(
    host_id: int,
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    source: Optional[str] = Query(None, description="Filter by source (OVAL, GOST, BASIC)"),
    limit: Optional[int] = Query(100, description="Limit number of results")
):
    """Get vulnerabilities from the latest scan for a host"""

    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    latest_scan = host.latest_scan
    if not latest_scan:
        return {
            "host": {
                "id": host.id,
                "name": host.name,
                "hostname": host.hostname
            },
            "scan": None,
            "vulnerabilities": [],
            "analysis": None,
            "total_count": 0
        }

    # Build query for vulnerabilities
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == latest_scan.id)

    # Apply filters
    if severity:
        query = query.filter(Vulnerability.severity.ilike(severity))

    if source:
        query = query.filter(Vulnerability.source.ilike(source))

    # Get total count before applying limit
    total_count = query.count()

    # Apply limit and ordering
    vulnerabilities = query.order_by(desc(Vulnerability.cvss_score)).limit(limit).all()

    return {
        "host": {
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname,
            "last_scan_at": host.last_scan_at,
            "last_scan_status": host.last_scan_status
        },
        "scan": {
            "id": latest_scan.id,
            "scan_type": latest_scan.scan_type,
            "status": latest_scan.status,
            "completed_at": latest_scan.completed_at,
            "enhanced_analysis_completed": latest_scan.enhanced_analysis_completed,
            "total_vulnerabilities": latest_scan.total_vulnerabilities,
            "critical_count": latest_scan.critical_count,
            "high_count": latest_scan.high_count,
            "medium_count": latest_scan.medium_count,
            "low_count": latest_scan.low_count
        },
        "vulnerabilities": [
            {
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "source": vuln.source,
                "affected_package": vuln.affected_package,
                "installed_version": vuln.installed_version,
                "fixed_version": vuln.fixed_version,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "priority": vuln.priority,
                "title": vuln.title,
                "summary": vuln.summary,
                "published_date": vuln.published_date
            }
            for vuln in vulnerabilities
        ],
        "analysis": latest_scan.vulnerability_analysis.__dict__ if latest_scan.vulnerability_analysis else None,
        "total_count": total_count,
        "filtered_count": len(vulnerabilities)
    }


@router.get("/hosts/{host_id}/scans")
async def get_host_scans(
    host_id: int,
    db: Session = Depends(get_db),
    limit: Optional[int] = Query(10, description="Limit number of scans")
):
    """Get all scans for a host (historical view)"""

    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    scans = db.query(Scan).filter(
        Scan.host_id == host_id,
        Scan.status == "completed"
    ).order_by(desc(Scan.completed_at)).limit(limit).all()

    return {
        "host": {
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname
        },
        "scans": [
            {
                "id": scan.id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "total_packages": scan.total_packages,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "enhanced_analysis_completed": scan.enhanced_analysis_completed,
                "enhanced_analysis_completed_at": scan.enhanced_analysis_completed_at
            }
            for scan in scans
        ]
    }


@router.get("/scans/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: int,
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    source: Optional[str] = Query(None, description="Filter by source"),
    package: Optional[str] = Query(None, description="Filter by package name"),
    limit: Optional[int] = Query(100, description="Limit number of results"),
    offset: Optional[int] = Query(0, description="Offset for pagination")
):
    """Get all vulnerabilities for a specific scan"""

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build query
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)

    # Apply filters
    if severity:
        query = query.filter(Vulnerability.severity.ilike(severity))

    if source:
        query = query.filter(Vulnerability.source.ilike(source))

    if package:
        query = query.filter(Vulnerability.affected_package.ilike(f"%{package}%"))

    # Get total count
    total_count = query.count()

    # Apply pagination and ordering
    vulnerabilities = query.order_by(
        desc(Vulnerability.cvss_score),
        Vulnerability.cve_id
    ).offset(offset).limit(limit).all()

    return {
        "scan": {
            "id": scan.id,
            "host_id": scan.host_id,
            "host_name": scan.host.name,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "completed_at": scan.completed_at,
            "enhanced_analysis_completed": scan.enhanced_analysis_completed
        },
        "vulnerabilities": [
            {
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "source": vuln.source,
                "affected_package": vuln.affected_package,
                "installed_version": vuln.installed_version,
                "fixed_version": vuln.fixed_version,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "priority": vuln.priority,
                "title": vuln.title,
                "description": vuln.description,
                "summary": vuln.summary,
                "published_date": vuln.published_date,
                "definition_id": vuln.definition_id
            }
            for vuln in vulnerabilities
        ],
        "analysis": scan.vulnerability_analysis.__dict__ if scan.vulnerability_analysis else None,
        "pagination": {
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": (offset + limit) < total_count
        }
    }


@router.get("/vulnerabilities/{vuln_id}")
async def get_vulnerability_details(vuln_id: int, db: Session = Depends(get_db)):
    """Get detailed information about a specific vulnerability"""

    vulnerability = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return {
        "vulnerability": {
            "id": vulnerability.id,
            "cve_id": vulnerability.cve_id,
            "source": vulnerability.source,
            "affected_package": vulnerability.affected_package,
            "installed_version": vulnerability.installed_version,
            "fixed_version": vulnerability.fixed_version,
            "severity": vulnerability.severity,
            "cvss_score": vulnerability.cvss_score,
            "priority": vulnerability.priority,
            "title": vulnerability.title,
            "description": vulnerability.description,
            "summary": vulnerability.summary,
            "published_date": vulnerability.published_date,
            "definition_id": vulnerability.definition_id,
            "created_at": vulnerability.created_at
        },
        "scan": {
            "id": vulnerability.scan.id,
            "host_id": vulnerability.scan.host_id,
            "host_name": vulnerability.scan.host.name,
            "scan_type": vulnerability.scan.scan_type,
            "completed_at": vulnerability.scan.completed_at
        }
    }


@router.get("/scans/{scan_id}/vulnerability-report", response_class=HTMLResponse)
async def get_vulnerability_report_html(scan_id: int, db: Session = Depends(get_db)):
    """Generate and return HTML vulnerability report for a scan"""

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulnerabilities = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).order_by(desc(Vulnerability.cvss_score)).all()

    try:
        # Generate HTML report
        report_service = VulnerabilityReportService()
        html_content = report_service.generate_scan_report(scan, vulnerabilities)

        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error(f"Error generating vulnerability report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate vulnerability report")


@router.get("/hosts/{host_id}/vulnerability-summary")
async def get_host_vulnerability_summary(host_id: int, db: Session = Depends(get_db)):
    """Get vulnerability summary for a host across all scans"""

    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    # Get latest scan summary
    latest_scan = host.latest_scan
    latest_summary = None

    if latest_scan and latest_scan.vulnerability_analysis:
        analysis = latest_scan.vulnerability_analysis
        latest_summary = {
            "scan_id": latest_scan.id,
            "scan_date": latest_scan.completed_at,
            "total_vulnerabilities": analysis.total_vulnerabilities,
            "packages_analyzed": analysis.packages_analyzed,
            "severity_breakdown": analysis.severity_breakdown,
            "source_breakdown": analysis.source_breakdown,
            "enhanced_analysis_completed": latest_scan.enhanced_analysis_completed
        }

    # Get historical trend (last 5 scans)
    recent_scans = db.query(Scan).filter(
        Scan.host_id == host_id,
        Scan.status == "completed"
    ).order_by(desc(Scan.completed_at)).limit(5).all()

    trend_data = [
        {
            "scan_id": scan.id,
            "scan_date": scan.completed_at,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count
        }
        for scan in recent_scans
    ]

    return {
        "host": {
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname
        },
        "latest_summary": latest_summary,
        "trend_data": trend_data
    }


@router.get("/vulnerability-statistics")
async def get_vulnerability_statistics(db: Session = Depends(get_db)):
    """Get overall vulnerability statistics across all hosts"""

    # Get total counts
    total_hosts = db.query(Host).filter(Host.is_active == True).count()
    total_scans = db.query(Scan).filter(Scan.status == "completed").count()

    # Get latest vulnerability counts across all active hosts
    latest_scans_subquery = db.query(
        Scan.host_id,
        func.max(Scan.completed_at).label('latest_completed_at')
    ).filter(
        Scan.status == "completed"
    ).group_by(Scan.host_id).subquery()

    latest_scans = db.query(Scan).join(
        latest_scans_subquery,
        (Scan.host_id == latest_scans_subquery.c.host_id) &
        (Scan.completed_at == latest_scans_subquery.c.latest_completed_at)
    ).all()

    total_vulnerabilities = sum(scan.total_vulnerabilities or 0 for scan in latest_scans)
    total_critical = sum(scan.critical_count or 0 for scan in latest_scans)
    total_high = sum(scan.high_count or 0 for scan in latest_scans)
    total_medium = sum(scan.medium_count or 0 for scan in latest_scans)
    total_low = sum(scan.low_count or 0 for scan in latest_scans)

    # Get hosts with enhanced analysis completed
    enhanced_analysis_completed = sum(
        1 for scan in latest_scans if scan.enhanced_analysis_completed
    )

    return {
        "overview": {
            "total_hosts": total_hosts,
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "enhanced_analysis_coverage": f"{enhanced_analysis_completed}/{len(latest_scans)}"
        },
        "severity_breakdown": {
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low
        },
        "hosts_summary": [
            {
                "host_id": scan.host_id,
                "host_name": scan.host.name,
                "scan_date": scan.completed_at,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "enhanced_analysis_completed": scan.enhanced_analysis_completed
            }
            for scan in latest_scans
        ]
    }
