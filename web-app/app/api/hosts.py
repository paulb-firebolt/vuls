"""Hosts API routes"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..models.base import get_db
from ..models.host import Host
from ..models.user import User
from ..auth import get_current_active_user

router = APIRouter()


class HostCreate(BaseModel):
    name: str
    hostname: str
    port: int = 22
    username: str
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
    username: str
    use_aws_proxy: bool
    aws_instance_id: Optional[str]
    aws_region: Optional[str]
    use_gcp_proxy: bool
    gcp_instance_name: Optional[str]
    gcp_zone: Optional[str]
    gcp_project: Optional[str]
    scan_schedule: Optional[str]
    scan_type: str
    scan_enabled: bool
    tags: Optional[dict]
    description: Optional[str]
    is_active: bool
    last_scan_at: Optional[str]
    last_scan_status: Optional[str]
    created_at: str
    updated_at: Optional[str]

    class Config:
        from_attributes = True


@router.get("/", response_model=List[HostResponse])
async def list_hosts(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
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
