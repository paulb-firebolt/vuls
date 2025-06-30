#!/usr/bin/env python3
"""
Management script to clear stuck scheduler jobs from within the web-app container.

This script uses the Celery tasks to clear stuck jobs and can be run from within
the web-app container environment.
"""

import os
import sys
import asyncio
import logging
from celery.result import AsyncResult

# Add the app directory to the path so we can import from it
sys.path.insert(0, '/app')

from app.celery_app import celery_app
from app.tasks.cleanup_tasks import (
    clear_stuck_scheduler_jobs,
    get_stuck_jobs_report,
    cleanup_old_task_runs_enhanced,
    reset_scheduler_state
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def wait_for_task_result(task_result: AsyncResult, timeout: int = 300):
    """Wait for a Celery task to complete and return the result"""
    try:
        result = task_result.get(timeout=timeout)
        return result
    except Exception as e:
        logger.error(f"Task failed or timed out: {e}")
        return None


def clear_stuck_jobs(max_age_hours: int = 2, dry_run: bool = False, force: bool = False):
    """Clear stuck scheduler jobs"""
    if not force and not dry_run:
        response = input(f"\nThis will clear all jobs stuck for more than {max_age_hours} hours. Continue? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return

    print(f"Clearing stuck jobs (dry_run={dry_run}, max_age_hours={max_age_hours})...")

    # Execute the cleanup task
    task_result = clear_stuck_scheduler_jobs.delay(
        max_age_hours=max_age_hours,
        dry_run=dry_run
    )

    print(f"Task submitted: {task_result.id}")
    print("Waiting for completion...")

    result = wait_for_task_result(task_result)

    if result:
        print("\n=== CLEANUP RESULTS ===")
        print(f"Stuck task runs cleared: {result.get('stuck_task_runs', 0)}")
        print(f"Stuck scheduled tasks reset: {result.get('stuck_scheduled_tasks', 0)}")
        print(f"Celery tasks revoked: {result.get('revoked_celery_tasks', 0)}")

        if result.get('errors'):
            print("\nErrors encountered:")
            for error in result['errors']:
                print(f"  - {error}")

        if dry_run:
            print("\n(This was a dry run - no actual changes were made)")
    else:
        print("Failed to get task result")


def generate_report(max_age_hours: int = 2):
    """Generate a report of stuck jobs"""
    print(f"Generating stuck jobs report (max_age_hours={max_age_hours})...")

    task_result = get_stuck_jobs_report.delay(max_age_hours=max_age_hours)

    print(f"Task submitted: {task_result.id}")
    print("Waiting for completion...")

    result = wait_for_task_result(task_result)

    if result:
        print("\n=== STUCK JOBS REPORT ===")
        print(f"Cutoff time: {result.get('cutoff_time', 'N/A')}")
        print(f"Jobs older than {max_age_hours} hours are considered stuck")
        print()

        summary = result.get('summary', {})
        print("Summary:")
        for key, value in summary.items():
            print(f"  {key}: {value}")
        print()

        if result.get('stuck_task_runs'):
            print("Stuck Task Runs:")
            for run in result['stuck_task_runs']:
                print(f"  - ID {run['id']}: {run['task_name']} ({run['status']}) since {run['started_at']}")

        if result.get('stuck_scheduled_tasks'):
            print("\nStuck Scheduled Tasks:")
            for task in result['stuck_scheduled_tasks']:
                print(f"  - ID {task['id']}: {task['name']} ({task['last_status']}) since {task['last_run_at']}")

        if not result.get('stuck_task_runs') and not result.get('stuck_scheduled_tasks'):
            print("No stuck jobs found!")
    else:
        print("Failed to get task result")


def cleanup_old_runs(days_to_keep: int = 30, batch_size: int = 1000):
    """Clean up old task run records"""
    print(f"Cleaning up task runs older than {days_to_keep} days...")

    task_result = cleanup_old_task_runs_enhanced.delay(
        days_to_keep=days_to_keep,
        batch_size=batch_size
    )

    print(f"Task submitted: {task_result.id}")
    print("Waiting for completion...")

    result = wait_for_task_result(task_result)

    if result:
        print("\n=== CLEANUP RESULTS ===")
        if result.get('status') == 'success':
            print(f"Total deleted: {result.get('total_deleted', 0)}")
            print(f"Batches processed: {result.get('batch_count', 0)}")
            print(f"Cutoff date: {result.get('cutoff_date', 'N/A')}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
    else:
        print("Failed to get task result")


def reset_state(force: bool = False):
    """Reset scheduler state - use with caution"""
    if not force:
        print("\n⚠️  WARNING: This will reset the entire scheduler state!")
        print("This should only be used in emergency situations.")
        response = input("Are you sure you want to continue? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return

    print("Resetting scheduler state...")

    task_result = reset_scheduler_state.delay(force=force)

    print(f"Task submitted: {task_result.id}")
    print("Waiting for completion...")

    result = wait_for_task_result(task_result)

    if result:
        print("\n=== RESET RESULTS ===")
        print(f"Scheduled tasks reset: {result.get('reset_scheduled_tasks', 0)}")
        print(f"Task runs failed: {result.get('failed_task_runs', 0)}")
        print(f"Celery tasks revoked: {result.get('revoked_celery_tasks', 0)}")

        if result.get('errors'):
            print("\nErrors encountered:")
            for error in result['errors']:
                print(f"  - {error}")
    else:
        print("Failed to get task result")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Clear stuck scheduler jobs')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear stuck jobs')
    clear_parser.add_argument('--dry-run', action='store_true',
                             help='Show what would be done without making changes')
    clear_parser.add_argument('--max-age-hours', type=int, default=2,
                             help='Consider jobs stuck if running longer than this (default: 2)')
    clear_parser.add_argument('--force', action='store_true',
                             help='Force cleanup without confirmation')

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate stuck jobs report')
    report_parser.add_argument('--max-age-hours', type=int, default=2,
                              help='Consider jobs stuck if running longer than this (default: 2)')

    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old task runs')
    cleanup_parser.add_argument('--days-to-keep', type=int, default=30,
                               help='Keep task runs from the last N days (default: 30)')
    cleanup_parser.add_argument('--batch-size', type=int, default=1000,
                               help='Number of records to delete in each batch (default: 1000)')

    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Reset scheduler state (use with caution)')
    reset_parser.add_argument('--force', action='store_true',
                             help='Force reset without confirmation')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'clear':
            clear_stuck_jobs(
                max_age_hours=args.max_age_hours,
                dry_run=args.dry_run,
                force=args.force
            )
        elif args.command == 'report':
            generate_report(max_age_hours=args.max_age_hours)
        elif args.command == 'cleanup':
            cleanup_old_runs(
                days_to_keep=args.days_to_keep,
                batch_size=args.batch_size
            )
        elif args.command == 'reset':
            reset_state(force=args.force)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
