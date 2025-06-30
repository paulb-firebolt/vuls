#!/usr/bin/env python3
"""
Setup default scheduled tasks for security data updates
Creates scheduled tasks for USN and OVAL data updates in the database.
"""

import sys
import os
from datetime import datetime, timezone

# Add the web-app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web-app'))

from app.models.base import get_db
from app.models.scheduled_task import ScheduledTask


def create_security_data_schedules():
    """Create default scheduled tasks for security data updates."""

    db = next(get_db())

    try:
        # Check if security data tasks already exist
        existing_tasks = db.query(ScheduledTask).filter(
            ScheduledTask.task_type.in_(['security_data_update', 'security_data_check'])
        ).all()

        if existing_tasks:
            print(f"Found {len(existing_tasks)} existing security data tasks:")
            for task in existing_tasks:
                print(f"  - {task.name} ({task.task_type}): {task.cron_expression}")

            response = input("Do you want to recreate these tasks? (y/N): ")
            if not response.lower().startswith('y'):
                print("Keeping existing tasks.")
                return

            # Delete existing tasks
            for task in existing_tasks:
                db.delete(task)
            db.commit()
            print("Deleted existing security data tasks.")

        # Create new scheduled tasks
        tasks_to_create = [
            {
                'name': 'Daily USN Data Update',
                'description': 'Update Ubuntu Security Notices data daily at 2 AM',
                'task_type': 'security_data_update',
                'cron_expression': '0 2 * * *',  # Daily at 2 AM
                'config': {
                    'force': False
                },
                'is_active': True
            },
            {
                'name': 'Weekly OVAL Data Update',
                'description': 'Update Ubuntu OVAL data weekly on Sundays at 3 AM',
                'task_type': 'security_data_update',
                'cron_expression': '0 3 * * 0',  # Weekly on Sunday at 3 AM
                'config': {
                    'force': False
                },
                'is_active': True
            },
            {
                'name': 'Security Data Freshness Check',
                'description': 'Check security data freshness every 6 hours',
                'task_type': 'security_data_check',
                'cron_expression': '0 */6 * * *',  # Every 6 hours
                'config': {},
                'is_active': True
            }
        ]

        created_tasks = []
        for task_data in tasks_to_create:
            task = ScheduledTask(
                name=task_data['name'],
                description=task_data['description'],
                task_type=task_data['task_type'],
                cron_expression=task_data['cron_expression'],
                config=task_data['config'],
                is_active=task_data['is_active'],
                created_at=datetime.now(timezone.utc)
            )

            db.add(task)
            created_tasks.append(task)

        db.commit()

        print(f"\nCreated {len(created_tasks)} security data scheduled tasks:")
        for task in created_tasks:
            print(f"  ✅ {task.name}")
            print(f"     Type: {task.task_type}")
            print(f"     Schedule: {task.cron_expression}")
            print(f"     Description: {task.description}")
            print()

        print("Security data scheduled tasks have been set up successfully!")
        print("\nThese tasks will:")
        print("- Update USN data daily at 2 AM")
        print("- Update OVAL data weekly on Sundays at 3 AM")
        print("- Check data freshness every 6 hours")
        print("\nYou can modify these schedules through the web interface or database.")

    except Exception as e:
        print(f"Error creating scheduled tasks: {e}")
        db.rollback()
        return False
    finally:
        db.close()

    return True


def show_current_schedules():
    """Show current security data scheduled tasks."""

    db = next(get_db())

    try:
        tasks = db.query(ScheduledTask).filter(
            ScheduledTask.task_type.in_(['security_data_update', 'security_data_check'])
        ).all()

        if not tasks:
            print("No security data scheduled tasks found.")
            return

        print(f"Current security data scheduled tasks ({len(tasks)}):")
        print("=" * 60)

        for task in tasks:
            status = "✅ Active" if task.is_active else "❌ Inactive"
            print(f"Name: {task.name}")
            print(f"Type: {task.task_type}")
            print(f"Schedule: {task.cron_expression}")
            print(f"Status: {status}")
            print(f"Last Run: {task.last_run_at or 'Never'}")
            print(f"Next Run: {task.next_run_at or 'Not scheduled'}")
            print(f"Description: {task.description}")
            if task.config:
                print(f"Config: {task.config}")
            print("-" * 40)

    except Exception as e:
        print(f"Error retrieving scheduled tasks: {e}")
    finally:
        db.close()


def main():
    """Main function."""

    if len(sys.argv) > 1 and sys.argv[1] == 'show':
        show_current_schedules()
        return 0

    print("Ubuntu Security Data Scheduler Setup")
    print("=" * 40)
    print()

    try:
        success = create_security_data_schedules()
        return 0 if success else 1

    except Exception as e:
        print(f"Setup failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
