"""Reports API routes"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..models.base import get_db
from ..models.user import User
from ..auth import get_current_active_user

router = APIRouter()


@router.get("/")
async def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all vulnerability reports"""
    return {"message": "Reports API - Coming soon"}


@router.get("/{scan_id}")
async def get_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability report for a specific scan"""
    return {"message": f"Report for scan {scan_id} - Coming soon"}
