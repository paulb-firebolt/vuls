"""Scheduled tasks API routes"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel
from croniter import croniter
from ..models.base import get_db
from ..models.user import User
from ..models.host import Host
from ..models.scheduled_task import ScheduledTask, TaskRun
from ..auth import get_current_active_user_from_cookie
from ..tasks.scheduler_tasks import get_next_run_time

router = APIRouter()


# Pydantic models for request/response
class ScheduledTaskCreate(BaseModel):
    name: str
    task_type: str  # scan, db_update
    description: Optional[str] = None
    cron_expression: str
    timezone: str = "UTC"
    config: dict = {}
    host_id: Optional[int] = None
    is_active: bool = True


class ScheduledTaskUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    cron_expression: Optional[str] = None
    timezone: Optional[str] = None
    config: Optional[dict] = None
    host_id: Optional[int] = None
    is_active: Optional[bool] = None


class ScheduledTaskResponse(BaseModel):
    id: int
    name: str
    task_type: str
    description: Optional[str]
    cron_expression: str
    timezone: str
    config: dict
    is_active: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    last_status: Optional[str]
    last_error: Optional[str]
    host_id: Optional[int]
    host_name: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class TaskRunResponse(BaseModel):
    id: int
    scheduled_task_id: int
    celery_task_id: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    result_data: Optional[dict]
    error_message: Optional[str]
    scan_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=List[ScheduledTaskResponse])
async def list_scheduled_tasks(
    request: Request,
    db: Session = Depends(get_db),
    task_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """List all scheduled tasks"""
    query = db.query(ScheduledTask)

    if task_type:
        query = query.filter(ScheduledTask.task_type == task_type)

    if is_active is not None:
        query = query.filter(ScheduledTask.is_active == is_active)

    tasks = query.all()

    # Add host name to response
    result = []
    for task in tasks:
        task_dict = {
            "id": task.id,
            "name": task.name,
            "task_type": task.task_type,
            "description": task.description,
            "cron_expression": task.cron_expression,
            "timezone": task.timezone,
            "config": task.config or {},
            "is_active": task.is_active,
            "last_run_at": task.last_run_at,
            "next_run_at": task.next_run_at,
            "last_status": task.last_status,
            "last_error": task.last_error,
            "host_id": task.host_id,
            "host_name": task.host.name if task.host else None,
            "created_at": task.created_at,
            "updated_at": task.updated_at
        }
        result.append(ScheduledTaskResponse(**task_dict))

    return result


@router.post("/", response_model=ScheduledTaskResponse)
async def create_scheduled_task(
    task_data: ScheduledTaskCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """Create a new scheduled task"""

    # Validate cron expression
    try:
        croniter(task_data.cron_expression)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid cron expression: {str(e)}"
        )

    # Validate task type
    if task_data.task_type not in ["scan", "db_update"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task type must be 'scan' or 'db_update'"
        )

    # For scan tasks, validate host exists
    if task_data.task_type == "scan":
        if not task_data.host_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Host ID is required for scan tasks"
            )

        host = db.query(Host).filter(Host.id == task_data.host_id).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )

    # Check if name is unique
    existing_task = db.query(ScheduledTask).filter(ScheduledTask.name == task_data.name).first()
    if existing_task:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task name must be unique"
        )

    # Calculate next run time
    now = datetime.now(timezone.utc)
    next_run_at = get_next_run_time(task_data.cron_expression, now)

    # Create the scheduled task
    scheduled_task = ScheduledTask(
        name=task_data.name,
        task_type=task_data.task_type,
        description=task_data.description,
        cron_expression=task_data.cron_expression,
        timezone=task_data.timezone,
        config=task_data.config,
        host_id=task_data.host_id,
        is_active=task_data.is_active,
        next_run_at=next_run_at
    )

    db.add(scheduled_task)
    db.commit()
    db.refresh(scheduled_task)

    # Prepare response
    task_dict = {
        "id": scheduled_task.id,
        "name": scheduled_task.name,
        "task_type": scheduled_task.task_type,
        "description": scheduled_task.description,
        "cron_expression": scheduled_task.cron_expression,
        "timezone": scheduled_task.timezone,
        "config": scheduled_task.config or {},
        "is_active": scheduled_task.is_active,
        "last_run_at": scheduled_task.last_run_at,
        "next_run_at": scheduled_task.next_run_at,
        "last_status": scheduled_task.last_status,
        "last_error": scheduled_task.last_error,
        "host_id": scheduled_task.host_id,
        "host_name": scheduled_task.host.name if scheduled_task.host else None,
        "created_at": scheduled_task.created_at,
        "updated_at": scheduled_task.updated_at
    }

    return ScheduledTaskResponse(**task_dict)


@router.get("/{task_id}", response_model=ScheduledTaskResponse)
async def get_scheduled_task(
    task_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """Get a specific scheduled task"""
    task = db.query(ScheduledTask).filter(ScheduledTask.id == task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled task not found"
        )

    task_dict = {
        "id": task.id,
        "name": task.name,
        "task_type": task.task_type,
        "description": task.description,
        "cron_expression": task.cron_expression,
        "timezone": task.timezone,
        "config": task.config or {},
        "is_active": task.is_active,
        "last_run_at": task.last_run_at,
        "next_run_at": task.next_run_at,
        "last_status": task.last_status,
        "last_error": task.last_error,
        "host_id": task.host_id,
        "host_name": task.host.name if task.host else None,
        "created_at": task.created_at,
        "updated_at": task.updated_at
    }

    return ScheduledTaskResponse(**task_dict)


@router.put("/{task_id}", response_model=ScheduledTaskResponse)
async def update_scheduled_task(
    task_id: int,
    task_data: ScheduledTaskUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """Update a scheduled task"""
    task = db.query(ScheduledTask).filter(ScheduledTask.id == task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled task not found"
        )

    # Validate cron expression if provided
    if task_data.cron_expression:
        try:
            croniter(task_data.cron_expression)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid cron expression: {str(e)}"
            )

    # Check if name is unique (if changing name)
    if task_data.name and task_data.name != task.name:
        existing_task = db.query(ScheduledTask).filter(ScheduledTask.name == task_data.name).first()
        if existing_task:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Task name must be unique"
            )

    # For scan tasks, validate host exists
    if task_data.host_id:
        host = db.query(Host).filter(Host.id == task_data.host_id).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Host not found"
            )

    # Update fields
    update_data = task_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(task, field, value)

    # Recalculate next run time if cron expression changed
    if task_data.cron_expression:
        now = datetime.now(timezone.utc)
        task.next_run_at = get_next_run_time(task_data.cron_expression, now)

    db.commit()
    db.refresh(task)

    task_dict = {
        "id": task.id,
        "name": task.name,
        "task_type": task.task_type,
        "description": task.description,
        "cron_expression": task.cron_expression,
        "timezone": task.timezone,
        "config": task.config or {},
        "is_active": task.is_active,
        "last_run_at": task.last_run_at,
        "next_run_at": task.next_run_at,
        "last_status": task.last_status,
        "last_error": task.last_error,
        "host_id": task.host_id,
        "host_name": task.host.name if task.host else None,
        "created_at": task.created_at,
        "updated_at": task.updated_at
    }

    return ScheduledTaskResponse(**task_dict)


@router.delete("/{task_id}")
async def delete_scheduled_task(
    task_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """Delete a scheduled task"""
    task = db.query(ScheduledTask).filter(ScheduledTask.id == task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled task not found"
        )

    db.delete(task)
    db.commit()

    return {"message": "Scheduled task deleted successfully"}


@router.get("/{task_id}/runs", response_model=List[TaskRunResponse])
async def get_task_runs(
    task_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie),
    limit: int = 50,
    status_filter: Optional[str] = None
):
    """Get task run history for a scheduled task"""
    task = db.query(ScheduledTask).filter(ScheduledTask.id == task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled task not found"
        )

    query = db.query(TaskRun).filter(TaskRun.scheduled_task_id == task_id)

    # Add status filter if provided
    if status_filter:
        query = query.filter(TaskRun.status == status_filter)

    task_runs = query.order_by(TaskRun.created_at.desc()).limit(limit).all()

    return [TaskRunResponse.from_orm(run) for run in task_runs]


@router.post("/{task_id}/run")
async def trigger_task_manually(
    task_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """Manually trigger a scheduled task"""
    from ..tasks.scan_tasks import run_vulnerability_scan
    from ..tasks.db_update_tasks import update_vulnerability_database

    task = db.query(ScheduledTask).filter(ScheduledTask.id == task_id).first()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled task not found"
        )

    # Create task run record
    task_run = TaskRun(
        scheduled_task_id=task.id,
        status="pending",
        started_at=datetime.now(timezone.utc)
    )
    db.add(task_run)
    db.commit()
    db.refresh(task_run)

    # Execute the appropriate task
    celery_task = None
    if task.task_type == "scan":
        celery_task = run_vulnerability_scan.delay(
            host_id=task.host_id,
            scan_type=task.config.get("scan_type", "fast"),
            task_run_id=task_run.id
        )
    elif task.task_type == "db_update":
        celery_task = update_vulnerability_database.delay(
            database_type=task.config.get("database_type", "all"),
            task_run_id=task_run.id
        )

    if celery_task:
        # Update task run with Celery task ID
        task_run.celery_task_id = celery_task.id
        task_run.status = "running"
        db.commit()

        return {
            "message": "Task triggered successfully",
            "task_run_id": task_run.id,
            "celery_task_id": celery_task.id
        }
    else:
        task_run.status = "failed"
        task_run.error_message = "Failed to start task"
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger task"
        )


@router.post("/cleanup-stale-jobs")
async def cleanup_stale_jobs(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user_from_cookie)
):
    """Clean up stale running jobs that are no longer actually running"""
    from celery import Celery
    from ..celery_app import celery_app

    # Get all task runs that are marked as running
    running_task_runs = db.query(TaskRun).filter(TaskRun.status == "running").all()

    cleaned_count = 0

    for task_run in running_task_runs:
        if task_run.celery_task_id:
            # Check if the Celery task is actually still running
            try:
                task_result = celery_app.AsyncResult(task_run.celery_task_id)

                # If task is not in active state, mark it as failed
                if task_result.state not in ['PENDING', 'RETRY', 'STARTED']:
                    task_run.status = "failed"
                    task_run.error_message = f"Task was orphaned (Celery state: {task_result.state})"
                    task_run.completed_at = datetime.now(timezone.utc)

                    # Update the scheduled task's last status
                    if task_run.scheduled_task:
                        task_run.scheduled_task.last_status = "failed"
                        task_run.scheduled_task.last_error = "Task was orphaned"

                    cleaned_count += 1

            except Exception as e:
                # If we can't check the task, assume it's stale
                task_run.status = "failed"
                task_run.error_message = f"Task was orphaned (Error checking status: {str(e)})"
                task_run.completed_at = datetime.now(timezone.utc)

                # Update the scheduled task's last status
                if task_run.scheduled_task:
                    task_run.scheduled_task.last_status = "failed"
                    task_run.scheduled_task.last_error = "Task was orphaned"

                cleaned_count += 1
        else:
            # No Celery task ID means it's definitely stale
            task_run.status = "failed"
            task_run.error_message = "Task was orphaned (No Celery task ID)"
            task_run.completed_at = datetime.now(timezone.utc)

            # Update the scheduled task's last status
            if task_run.scheduled_task:
                task_run.scheduled_task.last_status = "failed"
                task_run.scheduled_task.last_error = "Task was orphaned"

            cleaned_count += 1

    db.commit()

    return {
        "message": f"Cleaned up {cleaned_count} stale jobs",
        "cleaned_count": cleaned_count
    }
