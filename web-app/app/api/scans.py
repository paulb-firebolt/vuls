"""Scans API routes"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..models.base import get_db
from ..models.user import User
from ..auth import get_current_active_user

router = APIRouter()


@router.get("/")
async def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all scans"""
    return {"message": "Scans API - Coming soon"}


@router.post("/{host_id}/start")
async def start_scan(
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Start a scan for a host"""
    return {"message": f"Starting scan for host {host_id} - Coming soon"}
