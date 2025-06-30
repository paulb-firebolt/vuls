"""Scheduler tasks for managing and executing scheduled tasks"""

import logging
from datetime import datetime, timezone
from croniter import croniter
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..models.base import get_db
from ..models.scheduled_task import ScheduledTask, TaskRun
from .scan_tasks import run_vulnerability_scan
from .db_update_tasks import update_vulnerability_database
from .security_data_tasks import update_all_ubuntu_security_data, check_security_data_freshness

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def check_scheduled_tasks(self):
    """Check for scheduled tasks that need to be executed"""
    try:
        db = next(get_db())
        now = datetime.now(timezone.utc)

        # Get all active scheduled tasks
        scheduled_tasks = db.query(ScheduledTask).filter(
            ScheduledTask.is_active == True
        ).all()

        executed_count = 0

        for task in scheduled_tasks:
            try:
                # Check if task should run now
                if should_run_task(task, now):
                    logger.info(f"Executing scheduled task: {task.name}")

                    # Create task run record
                    task_run = TaskRun(
                        scheduled_task_id=task.id,
                        status="pending",
                        started_at=now
                    )
                    db.add(task_run)
                    db.commit()

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
                    elif task.task_type == "security_data_update":
                        celery_task = update_all_ubuntu_security_data.delay(
                            force=task.config.get("force", False),
                            task_run_id=task_run.id
                        )
                    elif task.task_type == "security_data_check":
                        celery_task = check_security_data_freshness.delay(
                            task_run_id=task_run.id
                        )

                    if celery_task:
                        # Update task run with Celery task ID
                        task_run.celery_task_id = celery_task.id
                        task_run.status = "running"

                        # Update scheduled task
                        task.last_run_at = now
                        task.next_run_at = get_next_run_time(task.cron_expression, now)
                        task.last_status = "running"

                        db.commit()
                        executed_count += 1

            except Exception as e:
                logger.error(f"Error executing scheduled task {task.name}: {str(e)}")
                task.last_error = str(e)
                task.last_status = "failed"
                db.commit()

        db.close()

        return {
            "status": "success",
            "executed_tasks": executed_count,
            "checked_at": now.isoformat()
        }

    except Exception as e:
        logger.error(f"Error in check_scheduled_tasks: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }


def should_run_task(task: ScheduledTask, now: datetime) -> bool:
    """Check if a scheduled task should run now"""
    try:
        # If next_run_at is not set, calculate it
        if not task.next_run_at:
            task.next_run_at = get_next_run_time(task.cron_expression, now)
            return False

        # Check if it's time to run
        return now >= task.next_run_at

    except Exception as e:
        logger.error(f"Error checking if task should run: {str(e)}")
        return False


def get_next_run_time(cron_expression: str, base_time: datetime) -> datetime:
    """Calculate the next run time for a cron expression"""
    try:
        cron = croniter(cron_expression, base_time)
        return cron.get_next(datetime)
    except Exception as e:
        logger.error(f"Error calculating next run time: {str(e)}")
        # Default to 1 hour from now if cron parsing fails
        return base_time.replace(hour=base_time.hour + 1)


@celery_app.task(bind=True)
def cleanup_old_task_runs(self, days_to_keep: int = 30):
    """Clean up old task run records"""
    try:
        db = next(get_db())
        cutoff_date = datetime.now(timezone.utc).replace(day=datetime.now().day - days_to_keep)

        # Delete old task runs
        deleted_count = db.query(TaskRun).filter(
            TaskRun.created_at < cutoff_date
        ).delete()

        db.commit()
        db.close()

        logger.info(f"Cleaned up {deleted_count} old task runs")

        return {
            "status": "success",
            "deleted_count": deleted_count
        }

    except Exception as e:
        logger.error(f"Error cleaning up old task runs: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }
