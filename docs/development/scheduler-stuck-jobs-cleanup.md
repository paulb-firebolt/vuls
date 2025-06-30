# Scheduler Stuck Jobs Cleanup

This document describes the comprehensive system for clearing stuck scheduler jobs in the vulnerability scanning application.

## Overview

The scheduler system can sometimes have jobs that get stuck in various states:

1. **Celery tasks that hang or timeout** - Tasks marked as "running" but never complete
2. **Database inconsistencies** - TaskRuns with "pending" or "running" status that never update
3. **Orphaned Celery tasks** - Tasks running in Celery but not tracked in the database
4. **Scheduled tasks stuck in "running" state** - When the last_status never gets updated

## Solution Components

### 1. Standalone Script (`clear_stuck_jobs.py`)

A comprehensive Python script that can be run independently to clear stuck jobs.

**Location**: `/clear_stuck_jobs.py` (root directory)

**Features**:
- Direct database and Celery access
- Comprehensive cleanup of all stuck job types
- Detailed reporting
- Dry-run mode for safe testing
- Batch processing for large cleanups

**Usage**:
```bash
# Generate report only
python clear_stuck_jobs.py --report-only

# Dry run (show what would be done)
python clear_stuck_jobs.py --dry-run

# Clear stuck jobs (with confirmation)
python clear_stuck_jobs.py

# Force clear without confirmation
python clear_stuck_jobs.py --force

# Custom age threshold (default: 2 hours)
python clear_stuck_jobs.py --max-age-hours 4
```

### 2. Celery Tasks (`web-app/app/tasks/cleanup_tasks.py`)

Celery tasks that can be called programmatically or from the web interface.

**Available Tasks**:

#### `clear_stuck_scheduler_jobs`
Clears stuck scheduler jobs with configurable parameters.

```python
from app.tasks.cleanup_tasks import clear_stuck_scheduler_jobs

# Clear stuck jobs
result = clear_stuck_scheduler_jobs.delay(max_age_hours=2, dry_run=False)
```

#### `get_stuck_jobs_report`
Generates a detailed report of stuck jobs without clearing them.

```python
from app.tasks.cleanup_tasks import get_stuck_jobs_report

# Generate report
result = get_stuck_jobs_report.delay(max_age_hours=2)
```

#### `cleanup_old_task_runs_enhanced`
Enhanced cleanup of old task run records with batching.

```python
from app.tasks.cleanup_tasks import cleanup_old_task_runs_enhanced

# Clean up old records
result = cleanup_old_task_runs_enhanced.delay(days_to_keep=30, batch_size=1000)
```

#### `reset_scheduler_state`
Emergency reset of the entire scheduler state (use with caution).

```python
from app.tasks.cleanup_tasks import reset_scheduler_state

# Reset scheduler state
result = reset_scheduler_state.delay(force=False)
```

### 3. Web App Management Script (`web-app/clear_stuck_jobs.py`)

A management script that runs within the web-app container environment.

**Location**: `/web-app/clear_stuck_jobs.py`

**Usage**:
```bash
# From within the web-app container
cd /app

# Generate report
python clear_stuck_jobs.py report

# Clear stuck jobs with dry run
python clear_stuck_jobs.py clear --dry-run

# Clear stuck jobs
python clear_stuck_jobs.py clear

# Clean up old task runs
python clear_stuck_jobs.py cleanup --days-to-keep 30

# Emergency reset (use with caution)
python clear_stuck_jobs.py reset
```

## Docker Container Usage

### Running from Host System

```bash
# Generate report
docker exec vuls-web-app python clear_stuck_jobs.py report

# Clear stuck jobs (dry run)
docker exec vuls-web-app python clear_stuck_jobs.py clear --dry-run

# Clear stuck jobs
docker exec vuls-web-app python clear_stuck_jobs.py clear --force
```

### Running the Standalone Script

```bash
# From the host system (requires environment variables)
export DATABASE_URL="postgresql+psycopg://vuls:password@localhost:5432/vuls"
export REDIS_URL="redis://localhost:6379/0"

python clear_stuck_jobs.py --report-only
```

## Monitoring and Prevention

### Automatic Cleanup Schedule

The system now includes automatic cleanup tasks in the Celery beat schedule:

```python
# In web-app/app/celery_app.py
celery_app.conf.beat_schedule = {
    # Auto-clear stuck jobs every 2 hours
    "auto-clear-stuck-jobs": {
        "task": "app.tasks.cleanup_tasks.clear_stuck_scheduler_jobs",
        "schedule": 7200.0,  # Every 2 hours (7200 seconds)
        "kwargs": {"max_age_hours": 2, "dry_run": False}
    },
    # Clean up old task runs weekly (Sunday at 3 AM)
    "weekly-cleanup-old-task-runs": {
        "task": "app.tasks.cleanup_tasks.cleanup_old_task_runs_enhanced",
        "schedule": crontab(hour=3, minute=0, day_of_week=0),  # Sunday at 03:00
        "kwargs": {"days_to_keep": 30, "batch_size": 1000}
    },
}
```

**Benefits of Automatic Cleanup:**
- **Proactive Maintenance**: Prevents stuck jobs from accumulating
- **Reduced Manual Intervention**: Less need for manual cleanup
- **System Reliability**: Keeps the scheduler running smoothly
- **Early Problem Detection**: Regular cleanup can reveal patterns

**Monitoring Automatic Cleanup:**
```bash
# Check Celery beat scheduler logs
docker logs vuls-scheduler

# Check if automatic tasks are scheduled
docker exec vuls-worker celery -A app.celery_app inspect scheduled

# View recent cleanup activity in application logs
docker logs vuls-worker | grep "clear_stuck_scheduler_jobs"
```

### Health Checks

Create a health check endpoint that reports stuck jobs:

```python
# In your web application
@app.route('/health/scheduler')
def scheduler_health():
    from app.tasks.cleanup_tasks import get_stuck_jobs_report

    result = get_stuck_jobs_report.delay(max_age_hours=1)
    report = result.get(timeout=30)

    if report['summary']['total_stuck_jobs'] > 0:
        return jsonify({
            'status': 'warning',
            'stuck_jobs': report['summary']['total_stuck_jobs'],
            'details': report
        }), 200

    return jsonify({'status': 'healthy'}), 200
```

## Troubleshooting

### Common Issues

1. **Celery Workers Not Responding**
   ```bash
   # Check worker status
   docker exec vuls-web-app celery -A app.celery_app inspect active

   # Restart workers if needed
   docker restart vuls-web-app
   ```

2. **Database Connection Issues**
   ```bash
   # Check database connectivity
   docker exec vuls-web-app python -c "from app.models.base import get_db; next(get_db())"
   ```

3. **Redis Connection Issues**
   ```bash
   # Check Redis connectivity
   docker exec vuls-web-app python -c "from app.celery_app import celery_app; celery_app.control.inspect().stats()"
   ```

### Emergency Procedures

If the scheduler is completely stuck:

1. **Stop all Celery workers**:
   ```bash
   docker exec vuls-web-app pkill -f celery
   ```

2. **Clear all active tasks**:
   ```bash
   docker exec vuls-web-app python clear_stuck_jobs.py reset --force
   ```

3. **Restart the web application**:
   ```bash
   docker restart vuls-web-app
   ```

## Best Practices

1. **Regular Monitoring**: Check for stuck jobs regularly using the report functionality
2. **Gradual Cleanup**: Use dry-run mode first to understand what will be cleaned
3. **Backup Before Reset**: Always backup the database before using the reset functionality
4. **Monitor Logs**: Watch application logs for patterns that might indicate why jobs get stuck
5. **Resource Monitoring**: Ensure adequate CPU and memory for Celery workers

## Configuration

### Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string for Celery broker/backend

### Celery Configuration

Key settings that affect job stability:

```python
# In web-app/app/celery_app.py
celery_app.conf.update(
    task_time_limit=30 * 60,  # 30 minutes hard limit
    task_soft_time_limit=25 * 60,  # 25 minutes soft limit
    worker_prefetch_multiplier=1,  # Prevent worker overload
    worker_max_tasks_per_child=1000,  # Restart workers periodically
)
```

## API Integration

The cleanup tasks can be integrated into web APIs:

```python
from flask import jsonify
from app.tasks.cleanup_tasks import clear_stuck_scheduler_jobs

@app.route('/api/admin/clear-stuck-jobs', methods=['POST'])
def api_clear_stuck_jobs():
    max_age_hours = request.json.get('max_age_hours', 2)
    dry_run = request.json.get('dry_run', False)

    task = clear_stuck_scheduler_jobs.delay(
        max_age_hours=max_age_hours,
        dry_run=dry_run
    )

    return jsonify({
        'task_id': task.id,
        'status': 'submitted'
    })
```

This comprehensive system ensures that stuck scheduler jobs can be identified, reported, and cleared effectively, maintaining the health and reliability of the vulnerability scanning scheduler.
