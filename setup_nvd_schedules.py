"""Setup NVD CVE update schedules."""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'web-app'))

from datetime import datetime, timezone
from app.models.base import get_db
from app.models.scheduled_task import ScheduledTask

def setup_nvd_schedules():
    """Set up NVD CVE update schedules."""

    db = next(get_db())

    try:
        # Weekly NVD CVE cache update (every Sunday at 2 AM)
        weekly_update = ScheduledTask(
            name="Weekly NVD CVE Update",
            description="Weekly update of NVD CVE cache with new CVEs from the last week",
            task_type="nvd_update",
            cron_expression="0 2 * * 0",  # Every Sunday at 2 AM
            is_active=True,
            config={
                "max_cves": 2000,
                "description": "Fetches new CVEs from NVD API weekly"
            },
            created_at=datetime.now(timezone.utc)
        )

        # Monthly NVD cache maintenance (first day of month at 3 AM)
        monthly_maintenance = ScheduledTask(
            name="Monthly NVD Cache Maintenance",
            description="Monthly maintenance and statistics for NVD CVE cache",
            task_type="nvd_maintenance",
            cron_expression="0 3 1 * *",  # First day of month at 3 AM
            is_active=True,
            config={
                "description": "Updates access counts and provides cache statistics"
            },
            created_at=datetime.now(timezone.utc)
        )

        # Check if tasks already exist
        existing_weekly = db.query(ScheduledTask).filter(
            ScheduledTask.name == "Weekly NVD CVE Update"
        ).first()

        existing_monthly = db.query(ScheduledTask).filter(
            ScheduledTask.name == "Monthly NVD Cache Maintenance"
        ).first()

        if not existing_weekly:
            db.add(weekly_update)
            print("✅ Added weekly NVD CVE update schedule")
        else:
            print("ℹ️  Weekly NVD CVE update schedule already exists")

        if not existing_monthly:
            db.add(monthly_maintenance)
            print("✅ Added monthly NVD cache maintenance schedule")
        else:
            print("ℹ️  Monthly NVD cache maintenance schedule already exists")

        db.commit()

        # Show all NVD-related scheduled tasks
        nvd_tasks = db.query(ScheduledTask).filter(
            ScheduledTask.task_type.in_(["nvd_update", "nvd_maintenance", "nvd_backfill"])
        ).all()

        print(f"\n📋 NVD Scheduled Tasks ({len(nvd_tasks)} total):")
        for task in nvd_tasks:
            status = "🟢 Active" if task.is_active else "🔴 Inactive"
            print(f"  {status} {task.name}")
            print(f"    Type: {task.task_type}")
            print(f"    Schedule: {task.cron_expression}")
            print(f"    Description: {task.description}")
            if task.next_run_at:
                print(f"    Next run: {task.next_run_at}")
            print()

        print("🎉 NVD schedules setup complete!")

    except Exception as e:
        print(f"❌ Error setting up NVD schedules: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    setup_nvd_schedules()
