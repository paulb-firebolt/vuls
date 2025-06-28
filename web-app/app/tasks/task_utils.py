"""Utility functions for task management"""

import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ..celery_app import celery_app
from ..models.base import get_db
from ..models.scheduled_task import TaskRun

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def update_task_status(self, task_run_id: int, status: str, result_data: dict = None, error_message: str = None):
    """Update the status of a task run"""
    try:
        db = next(get_db())
        task_run = db.query(TaskRun).filter(TaskRun.id == task_run_id).first()

        if task_run:
            task_run.status = status
            task_run.completed_at = datetime.now(timezone.utc)

            if task_run.started_at:
                duration = task_run.completed_at - task_run.started_at
                task_run.duration_seconds = int(duration.total_seconds())

            if result_data:
                task_run.result_data = result_data

            if error_message:
                task_run.error_message = error_message

            # Update the scheduled task status
            scheduled_task = task_run.scheduled_task
            scheduled_task.last_status = status
            scheduled_task.last_run_at = task_run.completed_at
            if error_message:
                scheduled_task.last_error = error_message

            db.commit()

            # Send WebSocket notification for task completion
            if status in ['success', 'failed']:
                try:
                    from ..utils.notification_service import publish_task_notification
                    publish_task_notification(
                        task_id=scheduled_task.id,
                        task_run_id=task_run_id,
                        status=status,
                        task_name=scheduled_task.name,
                        result_data=result_data
                    )
                    logger.info(f"Published WebSocket notification for task {scheduled_task.name} with status {status}")
                except Exception as e:
                    logger.error(f"Error sending WebSocket notification: {e}")

        db.close()

    except Exception as e:
        logger.error(f"Error updating task status: {str(e)}")
