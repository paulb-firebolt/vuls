#!/usr/bin/env python3
"""
Script to clear stuck scheduler jobs and reset the scheduler state.

This script handles various scenarios where jobs can get stuck:
1. Celery tasks that are hanging or timed out
2. Database records stuck in 'running' or 'pending' state
3. Orphaned Celery tasks not tracked in database
4. Scheduled tasks with inconsistent state
"""

import os
import sys
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from celery import Celery
from celery.result import AsyncResult

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+psycopg://vuls:password@localhost:5432/vuls')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Celery app for task management
celery_app = Celery(
    "vuls-scheduler",
    broker=REDIS_URL,
    backend=REDIS_URL
)

class StuckJobCleaner:
    """Handles clearing of stuck scheduler jobs"""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.engine = create_engine(DATABASE_URL)
        self.Session = sessionmaker(bind=self.engine)

    def clear_all_stuck_jobs(self, max_age_hours: int = 2) -> Dict[str, Any]:
        """
        Clear all types of stuck jobs

        Args:
            max_age_hours: Consider jobs stuck if running longer than this

        Returns:
            Dictionary with cleanup results
        """
        results = {
            'stuck_task_runs': 0,
            'stuck_scheduled_tasks': 0,
            'revoked_celery_tasks': 0,
            'orphaned_celery_tasks': 0,
            'errors': []
        }

        try:
            logger.info(f"Starting stuck job cleanup (dry_run={self.dry_run})")
            logger.info(f"Max age for stuck jobs: {max_age_hours} hours")

            # 1. Clear stuck task runs
            results['stuck_task_runs'] = self._clear_stuck_task_runs(max_age_hours)

            # 2. Clear stuck scheduled tasks
            results['stuck_scheduled_tasks'] = self._clear_stuck_scheduled_tasks(max_age_hours)

            # 3. Revoke hanging Celery tasks
            results['revoked_celery_tasks'] = self._revoke_hanging_celery_tasks(max_age_hours)

            # 4. Clean up orphaned Celery tasks
            results['orphaned_celery_tasks'] = self._clean_orphaned_celery_tasks()

            logger.info("Stuck job cleanup completed successfully")

        except Exception as e:
            error_msg = f"Error during cleanup: {str(e)}"
            logger.error(error_msg)
            results['errors'].append(error_msg)

        return results

    def _clear_stuck_task_runs(self, max_age_hours: int) -> int:
        """Clear task runs stuck in pending/running state"""
        session = self.Session()
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            # Find stuck task runs
            stuck_runs = session.execute(text("""
                SELECT tr.id, tr.celery_task_id, tr.status, tr.started_at, st.name
                FROM task_runs tr
                LEFT JOIN scheduled_tasks st ON tr.scheduled_task_id = st.id
                WHERE tr.status IN ('pending', 'running')
                AND tr.started_at < :cutoff_time
            """), {'cutoff_time': cutoff_time}).fetchall()

            if not stuck_runs:
                logger.info("No stuck task runs found")
                return 0

            logger.info(f"Found {len(stuck_runs)} stuck task runs")

            for run in stuck_runs:
                run_id, celery_task_id, status, started_at, task_name = run
                logger.info(f"  - Task run {run_id} ({task_name}): {status} since {started_at}")

                if not self.dry_run:
                    # Update task run status
                    session.execute(text("""
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
                        except Exception as e:
                            logger.warning(f"    Could not revoke Celery task {celery_task_id}: {e}")

            if not self.dry_run:
                session.commit()
                logger.info(f"Updated {len(stuck_runs)} stuck task runs")
            else:
                logger.info(f"Would update {len(stuck_runs)} stuck task runs (dry run)")

            return len(stuck_runs)

        finally:
            session.close()

    def _clear_stuck_scheduled_tasks(self, max_age_hours: int) -> int:
        """Clear scheduled tasks stuck in running state"""
        session = self.Session()
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            # Find scheduled tasks stuck in running state
            stuck_tasks = session.execute(text("""
                SELECT id, name, last_status, last_run_at
                FROM scheduled_tasks
                WHERE last_status = 'running'
                AND last_run_at < :cutoff_time
            """), {'cutoff_time': cutoff_time}).fetchall()

            if not stuck_tasks:
                logger.info("No stuck scheduled tasks found")
                return 0

            logger.info(f"Found {len(stuck_tasks)} stuck scheduled tasks")

            for task in stuck_tasks:
                task_id, name, last_status, last_run_at = task
                logger.info(f"  - Scheduled task {task_id} ({name}): {last_status} since {last_run_at}")

                if not self.dry_run:
                    # Reset scheduled task status
                    session.execute(text("""
                        UPDATE scheduled_tasks
                        SET last_status = 'failed',
                            last_error = 'Task cleared due to being stuck in running state'
                        WHERE id = :task_id
                    """), {'task_id': task_id})

            if not self.dry_run:
                session.commit()
                logger.info(f"Reset {len(stuck_tasks)} stuck scheduled tasks")
            else:
                logger.info(f"Would reset {len(stuck_tasks)} stuck scheduled tasks (dry run)")

            return len(stuck_tasks)

        finally:
            session.close()

    def _revoke_hanging_celery_tasks(self, max_age_hours: int) -> int:
        """Revoke Celery tasks that are hanging"""
        try:
            # Get active Celery tasks
            inspect = celery_app.control.inspect()
            active_tasks = inspect.active()

            if not active_tasks:
                logger.info("No active Celery tasks found")
                return 0

            revoked_count = 0
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            for worker, tasks in active_tasks.items():
                logger.info(f"Checking {len(tasks)} active tasks on worker {worker}")

                for task in tasks:
                    task_id = task.get('id')
                    task_name = task.get('name')
                    time_start = task.get('time_start')

                    if time_start:
                        start_time = datetime.fromtimestamp(time_start, tz=timezone.utc)
                        if start_time < cutoff_time:
                            logger.info(f"  - Found hanging task {task_id} ({task_name}): running since {start_time}")

                            if not self.dry_run:
                                celery_app.control.revoke(task_id, terminate=True)
                                logger.info(f"    Revoked hanging task {task_id}")
                                revoked_count += 1
                            else:
                                logger.info(f"    Would revoke hanging task {task_id} (dry run)")
                                revoked_count += 1

            if revoked_count > 0:
                logger.info(f"Revoked {revoked_count} hanging Celery tasks")
            else:
                logger.info("No hanging Celery tasks found")

            return revoked_count

        except Exception as e:
            logger.error(f"Error checking Celery tasks: {e}")
            return 0

    def _clean_orphaned_celery_tasks(self) -> int:
        """Clean up Celery tasks that are not tracked in database"""
        session = self.Session()
        try:
            # Get all Celery task IDs from database
            db_task_ids = session.execute(text("""
                SELECT DISTINCT celery_task_id
                FROM task_runs
                WHERE celery_task_id IS NOT NULL
                AND status IN ('pending', 'running')
            """)).fetchall()

            db_task_ids = {row[0] for row in db_task_ids}

            # Get active Celery tasks
            inspect = celery_app.control.inspect()
            active_tasks = inspect.active()

            if not active_tasks:
                return 0

            orphaned_count = 0

            for worker, tasks in active_tasks.items():
                for task in tasks:
                    task_id = task.get('id')
                    task_name = task.get('name')

                    # Check if this is a scheduler-related task not in database
                    if (task_name and 'scheduler' in task_name.lower() and
                        task_id not in db_task_ids):

                        logger.info(f"  - Found orphaned task {task_id} ({task_name})")

                        if not self.dry_run:
                            celery_app.control.revoke(task_id, terminate=True)
                            logger.info(f"    Revoked orphaned task {task_id}")
                            orphaned_count += 1
                        else:
                            logger.info(f"    Would revoke orphaned task {task_id} (dry run)")
                            orphaned_count += 1

            if orphaned_count > 0:
                logger.info(f"Cleaned up {orphaned_count} orphaned Celery tasks")
            else:
                logger.info("No orphaned Celery tasks found")

            return orphaned_count

        finally:
            session.close()

    def get_stuck_jobs_report(self, max_age_hours: int = 2) -> Dict[str, Any]:
        """Generate a report of stuck jobs without clearing them"""
        session = self.Session()
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            report = {
                'cutoff_time': cutoff_time.isoformat(),
                'stuck_task_runs': [],
                'stuck_scheduled_tasks': [],
                'active_celery_tasks': [],
                'summary': {}
            }

            # Get stuck task runs
            stuck_runs = session.execute(text("""
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
            stuck_tasks = session.execute(text("""
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

            # Get active Celery tasks
            try:
                inspect = celery_app.control.inspect()
                active_tasks = inspect.active()

                if active_tasks:
                    for worker, tasks in active_tasks.items():
                        for task in tasks:
                            time_start = task.get('time_start')
                            start_time = None
                            if time_start:
                                start_time = datetime.fromtimestamp(time_start, tz=timezone.utc)

                            report['active_celery_tasks'].append({
                                'worker': worker,
                                'task_id': task.get('id'),
                                'task_name': task.get('name'),
                                'started_at': start_time.isoformat() if start_time else None,
                                'is_hanging': start_time < cutoff_time if start_time else False
                            })
            except Exception as e:
                logger.warning(f"Could not get active Celery tasks: {e}")

            # Generate summary
            report['summary'] = {
                'stuck_task_runs_count': len(report['stuck_task_runs']),
                'stuck_scheduled_tasks_count': len(report['stuck_scheduled_tasks']),
                'active_celery_tasks_count': len(report['active_celery_tasks']),
                'hanging_celery_tasks_count': sum(1 for t in report['active_celery_tasks'] if t.get('is_hanging', False))
            }

            return report

        finally:
            session.close()


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Clear stuck scheduler jobs')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--max-age-hours', type=int, default=2,
                       help='Consider jobs stuck if running longer than this (default: 2)')
    parser.add_argument('--report-only', action='store_true',
                       help='Generate report only, do not clear anything')
    parser.add_argument('--force', action='store_true',
                       help='Force cleanup without confirmation')

    args = parser.parse_args()

    cleaner = StuckJobCleaner(dry_run=args.dry_run)

    if args.report_only:
        logger.info("Generating stuck jobs report...")
        report = cleaner.get_stuck_jobs_report(args.max_age_hours)

        print("\n=== STUCK JOBS REPORT ===")
        print(f"Cutoff time: {report['cutoff_time']}")
        print(f"Jobs older than {args.max_age_hours} hours are considered stuck")
        print()

        print("Summary:")
        for key, value in report['summary'].items():
            print(f"  {key}: {value}")
        print()

        if report['stuck_task_runs']:
            print("Stuck Task Runs:")
            for run in report['stuck_task_runs']:
                print(f"  - ID {run['id']}: {run['task_name']} ({run['status']}) since {run['started_at']}")

        if report['stuck_scheduled_tasks']:
            print("\nStuck Scheduled Tasks:")
            for task in report['stuck_scheduled_tasks']:
                print(f"  - ID {task['id']}: {task['name']} ({task['last_status']}) since {task['last_run_at']}")

        if report['active_celery_tasks']:
            hanging_tasks = [t for t in report['active_celery_tasks'] if t.get('is_hanging', False)]
            if hanging_tasks:
                print("\nHanging Celery Tasks:")
                for task in hanging_tasks:
                    print(f"  - {task['task_id']}: {task['task_name']} on {task['worker']} since {task['started_at']}")

        return

    # Confirmation for cleanup
    if not args.force and not args.dry_run:
        response = input(f"\nThis will clear all jobs stuck for more than {args.max_age_hours} hours. Continue? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return

    # Perform cleanup
    results = cleaner.clear_all_stuck_jobs(args.max_age_hours)

    print("\n=== CLEANUP RESULTS ===")
    print(f"Stuck task runs cleared: {results['stuck_task_runs']}")
    print(f"Stuck scheduled tasks reset: {results['stuck_scheduled_tasks']}")
    print(f"Hanging Celery tasks revoked: {results['revoked_celery_tasks']}")
    print(f"Orphaned Celery tasks cleaned: {results['orphaned_celery_tasks']}")

    if results['errors']:
        print("\nErrors encountered:")
        for error in results['errors']:
            print(f"  - {error}")

    if args.dry_run:
        print("\n(This was a dry run - no actual changes were made)")


if __name__ == "__main__":
    main()
