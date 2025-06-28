"""Celery application configuration"""

from celery import Celery
from celery.schedules import crontab
from .config import settings

# Create Celery app
celery_app = Celery(
    "vuls-scheduler",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.scan_tasks", "app.tasks.db_update_tasks", "app.tasks.scheduler_tasks", "app.tasks.task_utils", "app.tasks.vulnerability_analysis_tasks"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    # Check for scheduled tasks every minute
    "check-scheduled-tasks": {
        "task": "app.tasks.scheduler_tasks.check_scheduled_tasks",
        "schedule": 60.0,  # Every minute
    },
    # Monthly database updates (1st of every month at 2 AM)
    "monthly-db-update": {
        "task": "app.tasks.db_update_tasks.update_all_databases",
        "schedule": crontab(hour=2, minute=0, day_of_month=1),  # At 02:00 on day-of-month 1
    },
}
