#!/usr/bin/env python3
"""
Script to check what scheduled tasks are in the database
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Database connection
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+psycopg://vuls:password@localhost:5432/vuls')

def check_scheduled_tasks():
    """Check what scheduled tasks exist in the database"""
    try:
        engine = create_engine(DATABASE_URL)
        Session = sessionmaker(bind=engine)
        session = Session()

        print("=== SCHEDULED TASKS ===")

        # Check if scheduled_tasks table exists
        result = session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'scheduled_tasks'
            );
        """))

        table_exists = result.scalar()

        if not table_exists:
            print("❌ scheduled_tasks table does not exist")
            return

        print("✅ scheduled_tasks table exists")

        # Get all scheduled tasks
        result = session.execute(text("""
            SELECT id, name, task_type, cron_expression, is_active,
                   last_run_at, next_run_at, last_status, host_id, config
            FROM scheduled_tasks
            ORDER BY id;
        """))

        tasks = result.fetchall()

        if not tasks:
            print("📋 No scheduled tasks found in database")
        else:
            print(f"📋 Found {len(tasks)} scheduled task(s):")
            print()

            for task in tasks:
                print(f"Task ID: {task[0]}")
                print(f"  Name: {task[1]}")
                print(f"  Type: {task[2]}")
                print(f"  Cron: {task[3]}")
                print(f"  Active: {task[4]}")
                print(f"  Last Run: {task[5]}")
                print(f"  Next Run: {task[6]}")
                print(f"  Status: {task[7]}")
                print(f"  Host ID: {task[8]}")
                print(f"  Config: {task[9]}")
                print("-" * 50)

        print("\n=== TASK RUNS (Recent) ===")

        # Check if task_runs table exists
        result = session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'task_runs'
            );
        """))

        table_exists = result.scalar()

        if not table_exists:
            print("❌ task_runs table does not exist")
        else:
            # Get recent task runs
            result = session.execute(text("""
                SELECT tr.id, tr.scheduled_task_id, st.name, tr.status,
                       tr.started_at, tr.completed_at, tr.error_message
                FROM task_runs tr
                LEFT JOIN scheduled_tasks st ON tr.scheduled_task_id = st.id
                ORDER BY tr.started_at DESC
                LIMIT 10;
            """))

            runs = result.fetchall()

            if not runs:
                print("📋 No recent task runs found")
            else:
                print(f"📋 Found {len(runs)} recent task run(s):")
                print()

                for run in runs:
                    print(f"Run ID: {run[0]}")
                    print(f"  Task: {run[2]} (ID: {run[1]})")
                    print(f"  Status: {run[3]}")
                    print(f"  Started: {run[4]}")
                    print(f"  Completed: {run[5]}")
                    if run[6]:
                        print(f"  Error: {run[6]}")
                    print("-" * 30)

        print("\n=== HOSTS ===")

        # Check hosts table
        result = session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'hosts'
            );
        """))

        table_exists = result.scalar()

        if not table_exists:
            print("❌ hosts table does not exist")
        else:
            result = session.execute(text("""
                SELECT id, hostname, ip_address, is_active
                FROM hosts
                ORDER BY id;
            """))

            hosts = result.fetchall()

            if not hosts:
                print("📋 No hosts found in database")
            else:
                print(f"📋 Found {len(hosts)} host(s):")
                print()

                for host in hosts:
                    print(f"Host ID: {host[0]}")
                    print(f"  Hostname: {host[1]}")
                    print(f"  IP: {host[2]}")
                    print(f"  Active: {host[3]}")
                    print("-" * 30)

        session.close()

    except Exception as e:
        print(f"❌ Error checking database: {e}")
        return False

    return True

if __name__ == "__main__":
    print("Checking scheduled tasks in database...")
    print(f"Database URL: {DATABASE_URL}")
    print()

    success = check_scheduled_tasks()

    if not success:
        sys.exit(1)
