"""Hosts API routes"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from ..models.base import get_db
from ..models.host import Host
from ..models.user import User
from ..auth import get_current_active_user, get_current_active_user_from_cookie, get_current_user_flexible
from ..utils.vuls_config import sync_hosts_from_vuls_config, get_vuls_config_info

router = APIRouter()


class HostCreate(BaseModel):
    name: str
    hostname: str
    port: int = 22
    username: Optional[str] = None
    key_path: Optional[str] = None
    password: Optional[str] = None
    use_aws_proxy: bool = False
    aws_instance_id: Optional[str] = None
    aws_region: Optional[str] = None
    use_gcp_proxy: bool = False
    gcp_instance_name: Optional[str] = None
    gcp_zone: Optional[str] = None
    gcp_project: Optional[str] = None
    scan_schedule: Optional[str] = None
    scan_type: str = "fast"
    scan_enabled: bool = True
    tags: Optional[dict] = None
    description: Optional[str] = None


class HostUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    key_path: Optional[str] = None
    password: Optional[str] = None
    use_aws_proxy: Optional[bool] = None
    aws_instance_id: Optional[str] = None
    aws_region: Optional[str] = None
    use_gcp_proxy: Optional[bool] = None
    gcp_instance_name: Optional[str] = None
    gcp_zone: Optional[str] = None
    gcp_project: Optional[str] = None
    scan_schedule: Optional[str] = None
    scan_type: Optional[str] = None
    scan_enabled: Optional[bool] = None
    tags: Optional[dict] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class HostResponse(BaseModel):
    id: int
    name: str
    hostname: str
    port: int
    username: Optional[str]
    use_aws_proxy: bool
    aws_instance_id: Optional[str]
    aws_region: Optional[str]
    use_gcp_proxy: bool
    gcp_instance_name: Optional[str]
    gcp_zone: Optional[str]
    gcp_project: Optional[str]
    scan_schedule: Optional[str]
    scan_type: str
    scan_mode: Optional[str]
    scan_enabled: bool
    vuls_config: Optional[dict]
    tags: Optional[dict]
    description: Optional[str]
    is_active: bool
    last_scan_at: Optional[datetime]
    last_scan_status: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


@router.get("/", response_model=List[HostResponse])
async def list_hosts(
    request: Request,
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_flexible)
):
    """List all hosts"""
    query = db.query(Host)
    if active_only:
        query = query.filter(Host.is_active == True)

    hosts = query.offset(skip).limit(limit).all()
    return hosts


@router.post("/", response_model=HostResponse)
async def create_host(
    host_data: HostCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new host"""
    # Check if host name already exists
    if db.query(Host).filter(Host.name == host_data.name).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Host name already exists"
        )

    # Create new host
    db_host = Host(**host_data.dict())
    db.add(db_host)
    db.commit()
    db.refresh(db_host)

    return db_host


@router.get("/detailed")
async def get_hosts_with_vulnerability_data(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_flexible)
):
    """Get hosts with detailed vulnerability information from latest scans"""
    from sqlalchemy import func, desc
    from ..models.scan import Scan
    from ..models.vulnerability import Vulnerability

    # Get all active hosts
    hosts = db.query(Host).filter(Host.is_active == True).all()

    hosts_data = []

    for host in hosts:
        # Get latest completed scan
        latest_scan = db.query(Scan).filter(
            Scan.host_id == host.id,
            Scan.status == "completed"
        ).order_by(desc(Scan.completed_at)).first()

        host_data = {
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname,
            "is_active": host.is_active,
            "last_scan_at": host.last_scan_at,
            "last_scan_status": host.last_scan_status,
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "highest_cvss": 0.0,
            "enhanced_analysis_completed": False,
            "scan_date": None,
            "scan_id": None
        }

        if latest_scan:
            # Get vulnerability counts from the scan
            host_data.update({
                "total_vulnerabilities": latest_scan.total_vulnerabilities or 0,
                "critical_count": latest_scan.critical_count or 0,
                "high_count": latest_scan.high_count or 0,
                "medium_count": latest_scan.medium_count or 0,
                "low_count": latest_scan.low_count or 0,
                "enhanced_analysis_completed": latest_scan.enhanced_analysis_completed or False,
                "scan_date": latest_scan.completed_at,
                "scan_id": latest_scan.id
            })

            # Get highest CVSS score from vulnerabilities
            highest_cvss = db.query(func.max(Vulnerability.cvss_score)).filter(
                Vulnerability.scan_id == latest_scan.id,
                Vulnerability.cvss_score.isnot(None)
            ).scalar()

            if highest_cvss:
                host_data["highest_cvss"] = float(highest_cvss)

        hosts_data.append(host_data)

    # Calculate summary statistics
    total_hosts = len(hosts_data)
    active_hosts = len([h for h in hosts_data if h["is_active"]])
    hosts_with_vulns = len([h for h in hosts_data if h["total_vulnerabilities"] > 0])
    hosts_with_enhanced = len([h for h in hosts_data if h["enhanced_analysis_completed"]])

    return {
        "summary": {
            "total_hosts": total_hosts,
            "active_hosts": active_hosts,
            "hosts_with_vulnerabilities": hosts_with_vulns,
            "hosts_with_enhanced_analysis": hosts_with_enhanced
        },
        "hosts": hosts_data
    }


@router.get("/vuls-config-info")
async def get_config_info(
    current_user: User = Depends(get_current_active_user)
):
    """Get information about the Vuls configuration file"""
    try:
        config_info = get_vuls_config_info()
        return config_info
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading Vuls config: {str(e)}"
        )


@router.post("/sync-from-vuls-config")
async def sync_hosts_from_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Synchronize hosts from Vuls configuration file"""
    try:
        stats = sync_hosts_from_vuls_config(db)
        return {
            "status": "success",
            "message": f"Synchronized {stats['total']} hosts from Vuls config",
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error synchronizing hosts: {str(e)}"
        )


@router.get("/{host_id}", response_model=HostResponse)
async def get_host(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific host"""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found"
        )
    return host


@router.put("/{host_id}", response_model=HostResponse)
async def update_host(
    host_id: int,
    host_data: HostUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update a host"""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found"
        )

    # Check if new name conflicts with existing host
    if host_data.name and host_data.name != host.name:
        if db.query(Host).filter(Host.name == host_data.name).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Host name already exists"
            )

    # Update host
    update_data = host_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(host, field, value)

    db.commit()
    db.refresh(host)

    return host


@router.delete("/{host_id}")
async def delete_host(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a host"""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found"
        )

    db.delete(host)
    db.commit()

    return {"message": "Host deleted successfully"}


@router.post("/{host_id}/test-connection")
async def test_host_connection(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Test connection to a host"""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found"
        )

    # TODO: Implement actual connection test
    # This would use the same logic as Vuls configtest

    return {"status": "success", "message": "Connection test not yet implemented"}


@router.get("/{host_id}/scan-history")
async def get_host_scan_history(
    host_id: int,
    request: Request,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_flexible)
):
    """Get scan history for a specific host"""
    from sqlalchemy import desc
    from ..models.scan import Scan

    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found"
        )

    scans = db.query(Scan).filter(
        Scan.host_id == host_id,
        Scan.status == "completed"
    ).order_by(desc(Scan.completed_at)).limit(limit).all()

    scan_history = []
    for scan in scans:
        scan_history.append({
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
        })

    return {
        "host": {
            "id": host.id,
            "name": host.name,
            "hostname": host.hostname
        },
        "scan_history": scan_history
    }
