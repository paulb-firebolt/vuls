"""Cleanup tasks for maintaining scheduler health"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..celery_app import celery_app
from ..models.base import get_db
from ..models.scheduled_task import ScheduledTask, TaskRun

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def clear_stuck_scheduler_jobs(self, max_age_hours: int = 2, dry_run: bool = False):
    """
    Clear stuck scheduler jobs

    Args:
        max_age_hours: Consider jobs stuck if running longer than this
        dry_run: If True, only report what would be done without making changes

    Returns:
        Dictionary with cleanup results
    """
    try:
        db = next(get_db())
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        results = {
            'stuck_task_runs': 0,
            'stuck_scheduled_tasks': 0,
            'revoked_celery_tasks': 0,
            'dry_run': dry_run,
            'cutoff_time': cutoff_time.isoformat(),
            'errors': []
        }

        logger.info(f"Starting stuck job cleanup (dry_run={dry_run}, max_age_hours={max_age_hours})")

        # 1. Clear stuck task runs
        stuck_runs = db.execute(text("""
            SELECT tr.id, tr.celery_task_id, tr.status, tr.started_at, st.name
            FROM task_runs tr
            LEFT JOIN scheduled_tasks st ON tr.scheduled_task_id = st.id
            WHERE tr.status IN ('pending', 'running')
            AND tr.started_at < :cutoff_time
        """), {'cutoff_time': cutoff_time}).fetchall()

        if stuck_runs:
            logger.info(f"Found {len(stuck_runs)} stuck task runs")

            for run in stuck_runs:
                run_id, celery_task_id, status, started_at, task_name = run
                logger.info(f"  - Task run {run_id} ({task_name}): {status} since {started_at}")

                if not dry_run:
                    # Update task run status
                    db.execute(text("""
                        UPDATE task_runs
                        SET status = 'failed',
                            completed_at = :now,
                            error_message = 'Task cleared due to being stuck',
                            duration_seconds = EXTRACT(EPOCH FROM (:now - started_at))::integer
                        WHERE id = :run_id
                    """), {
                        'run_id': run_id,
                        'now': datetime.now(timezone.utc)
                    })

                    # Revoke Celery task if it exists
                    if celery_task_id:
                        try:
                            celery_app.control.revoke(celery_task_id, terminate=True)
                            logger.info(f"    Revoked Celery task {celery_task_id}")
                            results['revoked_celery_tasks'] += 1
                        except Exception as e:
                            error_msg = f"Could not revoke Celery task {celery_task_id}: {e}"
                            logger.warning(f"    {error_msg}")
                            results['errors'].append(error_msg)

            results['stuck_task_runs'] = len(stuck_runs)
        else:
            logger.info("No stuck task runs found")

        # 2. Clear stuck scheduled tasks
        stuck_tasks = db.execute(text("""
            SELECT id, name, last_status, last_run_at
            FROM scheduled_tasks
            WHERE last_status = 'running'
            AND last_run_at < :cutoff_time
        """), {'cutoff_time': cutoff_time}).fetchall()

        if stuck_tasks:
            logger.info(f"Found {len(stuck_tasks)} stuck scheduled tasks")

            for task in stuck_tasks:
                task_id, name, last_status, last_run_at = task
                logger.info(f"  - Scheduled task {task_id} ({name}): {last_status} since {last_run_at}")

                if not dry_run:
                    # Reset scheduled task status
                    db.execute(text("""
                        UPDATE scheduled_tasks
                        SET last_status = 'failed',
                            last_error = 'Task cleared due to being stuck in running state'
                        WHERE id = :task_id
                    """), {'task_id': task_id})

            results['stuck_scheduled_tasks'] = len(stuck_tasks)
        else:
            logger.info("No stuck scheduled tasks found")

        # Commit changes if not dry run
        if not dry_run:
            db.commit()
            logger.info("Committed stuck job cleanup changes to database")
        else:
            logger.info("Dry run completed - no changes made to database")

        db.close()

        logger.info(f"Stuck job cleanup completed: {results}")
        return results

    except Exception as e:
        error_msg = f"Error in clear_stuck_scheduler_jobs: {str(e)}"
        logger.error(error_msg)
        return {
            'stuck_task_runs': 0,
            'stuck_scheduled_tasks': 0,
            'revoked_celery_tasks': 0,
            'dry_run': dry_run,
            'errors': [error_msg]
        }


@celery_app.task(bind=True)
def get_stuck_jobs_report(self, max_age_hours: int = 2):
    """
    Generate a report of stuck jobs without clearing them

    Args:
        max_age_hours: Consider jobs stuck if running longer than this

    Returns:
        Dictionary with stuck jobs report
    """
    try:
        db = next(get_db())
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        report = {
            'cutoff_time': cutoff_time.isoformat(),
            'max_age_hours': max_age_hours,
            'stuck_task_runs': [],
            'stuck_scheduled_tasks': [],
            'summary': {}
        }

        # Get stuck task runs
        stuck_runs = db.execute(text("""
            SELECT tr.id, tr.celery_task_id, tr.status, tr.started_at,
                   st.name, st.task_type
            FROM task_runs tr
            LEFT JOIN scheduled_tasks st ON tr.scheduled_task_id = st.id
            WHERE tr.status IN ('pending', 'running')
            AND tr.started_at < :cutoff_time
            ORDER BY tr.started_at
        """), {'cutoff_time': cutoff_time}).fetchall()

        for run in stuck_runs:
            report['stuck_task_runs'].append({
                'id': run[0],
                'celery_task_id': run[1],
                'status': run[2],
                'started_at': run[3].isoformat() if run[3] else None,
                'task_name': run[4],
                'task_type': run[5]
            })

        # Get stuck scheduled tasks
        stuck_tasks = db.execute(text("""
            SELECT id, name, task_type, last_status, last_run_at, last_error
            FROM scheduled_tasks
            WHERE last_status = 'running'
            AND last_run_at < :cutoff_time
            ORDER BY last_run_at
        """), {'cutoff_time': cutoff_time}).fetchall()

        for task in stuck_tasks:
            report['stuck_scheduled_tasks'].append({
                'id': task[0],
                'name': task[1],
                'task_type': task[2],
                'last_status': task[3],
                'last_run_at': task[4].isoformat() if task[4] else None,
                'last_error': task[5]
            })

        # Generate summary
        report['summary'] = {
            'stuck_task_runs_count': len(report['stuck_task_runs']),
            'stuck_scheduled_tasks_count': len(report['stuck_scheduled_tasks']),
            'total_stuck_jobs': len(report['stuck_task_runs']) + len(report['stuck_scheduled_tasks'])
        }

        db.close()

        logger.info(f"Generated stuck jobs report: {report['summary']}")
        return report

    except Exception as e:
        error_msg = f"Error generating stuck jobs report: {str(e)}"
        logger.error(error_msg)
        return {
            'cutoff_time': cutoff_time.isoformat() if 'cutoff_time' in locals() else None,
            'max_age_hours': max_age_hours,
            'stuck_task_runs': [],
            'stuck_scheduled_tasks': [],
            'summary': {'error': error_msg}
        }


@celery_app.task(bind=True)
def cleanup_old_task_runs_enhanced(self, days_to_keep: int = 30, batch_size: int = 1000):
    """
    Enhanced cleanup of old task run records with batching

    Args:
        days_to_keep: Keep task runs from the last N days
        batch_size: Number of records to delete in each batch

    Returns:
        Dictionary with cleanup results
    """
    try:
        db = next(get_db())
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)

        logger.info(f"Starting cleanup of task runs older than {cutoff_date}")

        total_deleted = 0
        batch_count = 0

        while True:
            # Delete in batches to avoid long-running transactions
            result = db.execute(text("""
                DELETE FROM task_runs
                WHERE id IN (
                    SELECT id FROM task_runs
                    WHERE created_at < :cutoff_date
                    ORDER BY created_at
                    LIMIT :batch_size
                )
            """), {
                'cutoff_date': cutoff_date,
                'batch_size': batch_size
            })

            deleted_count = result.rowcount
            total_deleted += deleted_count
            batch_count += 1

            db.commit()

            logger.info(f"Batch {batch_count}: Deleted {deleted_count} old task runs")

            # If we deleted fewer than batch_size, we're done
            if deleted_count < batch_size:
                break

        db.close()

        result = {
            'status': 'success',
            'total_deleted': total_deleted,
            'batch_count': batch_count,
            'cutoff_date': cutoff_date.isoformat(),
            'days_to_keep': days_to_keep
        }

        logger.info(f"Cleanup completed: {result}")
        return result

    except Exception as e:
        error_msg = f"Error cleaning up old task runs: {str(e)}"
        logger.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'total_deleted': total_deleted if 'total_deleted' in locals() else 0
        }


@celery_app.task(bind=True)
def reset_scheduler_state(self, force: bool = False):
    """
    Reset the entire scheduler state - use with caution

    Args:
        force: If True, reset all tasks regardless of status

    Returns:
        Dictionary with reset results
    """
    try:
        db = next(get_db())

        results = {
            'reset_scheduled_tasks': 0,
            'failed_task_runs': 0,
            'revoked_celery_tasks': 0,
            'force': force,
            'errors': []
        }

        logger.warning(f"Starting scheduler state reset (force={force})")

        # Get all scheduled tasks that need resetting
        if force:
            # Reset all scheduled tasks
            scheduled_tasks = db.execute(text("""
                SELECT id, name, last_status FROM scheduled_tasks
                WHERE last_status IN ('running', 'pending')
            """)).fetchall()
        else:
            # Only reset tasks that appear stuck
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
            scheduled_tasks = db.execute(text("""
                SELECT id, name, last_status FROM scheduled_tasks
                WHERE last_status = 'running'
                AND last_run_at < :cutoff_time
            """), {'cutoff_time': cutoff_time}).fetchall()

        # Reset scheduled tasks
        for task in scheduled_tasks:
            task_id, name, last_status = task
            logger.info(f"Resetting scheduled task {task_id} ({name}): {last_status}")

            db.execute(text("""
                UPDATE scheduled_tasks
                SET last_status = 'failed',
                    last_error = 'Task reset by scheduler state reset'
                WHERE id = :task_id
            """), {'task_id': task_id})

            results['reset_scheduled_tasks'] += 1

        # Get all running/pending task runs
        if force:
            task_runs = db.execute(text("""
                SELECT id, celery_task_id FROM task_runs
                WHERE status IN ('running', 'pending')
            """)).fetchall()
        else:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
            task_runs = db.execute(text("""
                SELECT id, celery_task_id FROM task_runs
                WHERE status IN ('running', 'pending')
                AND started_at < :cutoff_time
            """), {'cutoff_time': cutoff_time}).fetchall()

        # Fail all running/pending task runs
        for run in task_runs:
            run_id, celery_task_id = run
            logger.info(f"Failing task run {run_id}")

            db.execute(text("""
                UPDATE task_runs
                SET status = 'failed',
                    completed_at = :now,
                    error_message = 'Task failed by scheduler state reset'
                WHERE id = :run_id
            """), {
                'run_id': run_id,
                'now': datetime.now(timezone.utc)
            })

            # Revoke Celery task if it exists
            if celery_task_id:
                try:
                    celery_app.control.revoke(celery_task_id, terminate=True)
                    logger.info(f"Revoked Celery task {celery_task_id}")
                    results['revoked_celery_tasks'] += 1
                except Exception as e:
                    error_msg = f"Could not revoke Celery task {celery_task_id}: {e}"
                    logger.warning(error_msg)
                    results['errors'].append(error_msg)

            results['failed_task_runs'] += 1

        db.commit()
        db.close()

        logger.warning(f"Scheduler state reset completed: {results}")
        return results

    except Exception as e:
        error_msg = f"Error resetting scheduler state: {str(e)}"
        logger.error(error_msg)
        return {
            'reset_scheduled_tasks': 0,
            'failed_task_runs': 0,
            'revoked_celery_tasks': 0,
            'force': force,
            'errors': [error_msg]
        }
