"""Scheduled task model for managing recurring scans and database updates"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base


class ScheduledTask(Base):
    __tablename__ = "scheduled_tasks"

    id = Column(Integer, primary_key=True, index=True)

    # Task identification
    name = Column(String, nullable=False, unique=True)
    task_type = Column(String, nullable=False)  # scan, db_update
    description = Column(Text)

    # Scheduling
    cron_expression = Column(String, nullable=False)  # Cron format: "0 2 * * *"
    timezone = Column(String, default="UTC")

    # Task configuration
    config = Column(JSON)  # Task-specific configuration

    # Status
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime(timezone=True))
    next_run_at = Column(DateTime(timezone=True))
    last_status = Column(String)  # success, failed, running
    last_error = Column(Text)

    # For scan tasks - optional host association
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    host = relationship("Host", back_populates="scheduled_tasks")
    task_runs = relationship("TaskRun", back_populates="scheduled_task", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScheduledTask(id={self.id}, name='{self.name}', type='{self.task_type}')>"


class TaskRun(Base):
    __tablename__ = "task_runs"

    id = Column(Integer, primary_key=True, index=True)
    scheduled_task_id = Column(Integer, ForeignKey("scheduled_tasks.id"), nullable=False)

    # Execution details
    celery_task_id = Column(String, unique=True)  # Celery task ID for tracking
    status = Column(String, default="pending")  # pending, running, success, failed

    # Timing
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)

    # Results
    result_data = Column(JSON)  # Task-specific result data
    error_message = Column(Text)

    # For scan tasks - link to actual scan
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scheduled_task = relationship("ScheduledTask", back_populates="task_runs")
    scan = relationship("Scan")

    def __repr__(self):
        return f"<TaskRun(id={self.id}, task_id={self.scheduled_task_id}, status='{self.status}')>"
