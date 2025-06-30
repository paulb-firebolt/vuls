# Quick Reference: Stuck Jobs Cleanup

This document provides quick commands for clearing stuck scheduler jobs.

## Container Names

- **Production**: `vuls-web`, `vuls-worker`, `vuls-scheduler`
- **Development**: `vuls-web-dev`, `vuls-worker-dev`, `vuls-scheduler-dev`

## Script Location

The cleanup script is located at: `web-app/app/scripts/clear_stuck_jobs.py`

## Quick Commands

### Check for Stuck Jobs
```bash
# From host system (production)
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py report

# From host system (development)
docker exec vuls-web-dev uv run /app/app/scripts/clear_stuck_jobs.py report

# From within container
uv run /app/app/scripts/clear_stuck_jobs.py report
```

### Clear Stuck Jobs (Safe)
```bash
# Dry run first (recommended) - production
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py clear --dry-run

# Actually clear them - production (requires -ti for interactive prompt)
docker exec -ti vuls-web uv run /app/app/scripts/clear_stuck_jobs.py clear

# Development containers
docker exec vuls-web-dev uv run /app/app/scripts/clear_stuck_jobs.py clear --dry-run
docker exec -ti vuls-web-dev uv run /app/app/scripts/clear_stuck_jobs.py clear
```

### Emergency Clear (No Confirmation)
```bash
# Production (no -ti needed as --force skips prompts)
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py clear --force

# Development (no -ti needed as --force skips prompts)
docker exec vuls-web-dev uv run /app/app/scripts/clear_stuck_jobs.py clear --force
```

### Clean Up Old Records
```bash
# Clean up task runs older than 30 days - production
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py cleanup

# Development
docker exec vuls-web-dev uv run /app/app/scripts/clear_stuck_jobs.py cleanup
```

### Emergency Reset (Use with Caution!)
```bash
# This resets the entire scheduler state - production
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py reset

# Development
docker exec vuls-web-dev uv run /app/app/scripts/clear_stuck_jobs.py reset
```

## Alternative: Standalone Script

If the web-app container is not working, use the standalone script:

```bash
# Set environment variables
export DATABASE_URL="postgresql+psycopg://vuls:password@localhost:5432/vuls"
export REDIS_URL="redis://localhost:6379/0"

# Run cleanup
./clear_stuck_jobs.py --report-only
./clear_stuck_jobs.py --dry-run
./clear_stuck_jobs.py --force
```

## Common Scenarios

### Scenario 1: Jobs Running Too Long
```bash
# Check what's stuck
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py report

# Clear jobs older than 1 hour (requires -ti for interactive prompt)
docker exec -ti vuls-web uv run /app/app/scripts/clear_stuck_jobs.py clear --max-age-hours 1
```

### Scenario 2: Scheduler Completely Stuck
```bash
# 1. Check status
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py report

# 2. Try normal clear first (--force skips prompts, no -ti needed)
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py clear --force

# 3. If still stuck, emergency reset (--force skips prompts, no -ti needed)
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py reset --force

# 4. Restart container
docker restart vuls-web
```

### Scenario 3: Database Full of Old Records
```bash
# Clean up old task runs (keeps last 7 days)
docker exec vuls-web uv run /app/app/scripts/clear_stuck_jobs.py cleanup --days-to-keep 7
```

## Monitoring

### Check Scheduler Health
```bash
# Quick health check (production)
docker exec vuls-web python -c "
from app.tasks.cleanup_tasks import get_stuck_jobs_report
result = get_stuck_jobs_report.delay(max_age_hours=1).get(timeout=30)
print(f'Stuck jobs: {result[\"summary\"][\"total_stuck_jobs\"]}')
"

# Development
docker exec vuls-web-dev python -c "
from app.tasks.cleanup_tasks import get_stuck_jobs_report
result = get_stuck_jobs_report.delay(max_age_hours=1).get(timeout=30)
print(f'Stuck jobs: {result[\"summary\"][\"total_stuck_jobs\"]}')
"
```

### Check Celery Workers
```bash
# Check if workers are responding (production)
docker exec vuls-worker celery -A app.celery_app inspect active

# Check worker stats (production)
docker exec vuls-worker celery -A app.celery_app inspect stats

# Development
docker exec vuls-worker-dev celery -A app.celery_app inspect active
docker exec vuls-worker-dev celery -A app.celery_app inspect stats
```

## Files Created

- `clear_stuck_jobs.py` - Standalone cleanup script
- `web-app/app/scripts/clear_stuck_jobs.py` - Container-based management script
- `web-app/app/tasks/cleanup_tasks.py` - Celery tasks for cleanup
- `docs/development/scheduler-stuck-jobs-cleanup.md` - Full documentation

## Automatic Cleanup

The system now includes automatic cleanup tasks that run periodically:

### Auto-Clear Stuck Jobs
- **Frequency**: Every 2 hours
- **Threshold**: Jobs stuck for more than 2 hours
- **Task**: `auto-clear-stuck-jobs`
- **Action**: Automatically clears stuck jobs without manual intervention

### Weekly Old Task Cleanup
- **Frequency**: Every Sunday at 3 AM
- **Retention**: Keeps last 30 days of task runs
- **Task**: `weekly-cleanup-old-task-runs`
- **Action**: Removes old task run records to prevent database bloat

### Monitoring Automatic Cleanup
```bash
# Check Celery beat scheduler logs
docker logs vuls-scheduler

# Check if automatic tasks are scheduled
docker exec vuls-worker celery -A app.celery_app inspect scheduled
```

## Safety Notes

1. **Always use `--dry-run` first** to see what will be affected (for manual cleanup)
2. **Generate a report** before clearing to understand the scope
3. **Backup the database** before using reset functionality
4. **Monitor logs** after cleanup to ensure normal operation resumes
5. **Automatic cleanup** runs every 2 hours to keep the system healthy

## Troubleshooting

If commands fail:

1. **Check container is running**: `docker ps | grep vuls-web`
2. **Check database connection**: `docker exec vuls-web python -c "from app.models.base import get_db; next(get_db())"`
3. **Check Redis connection**: `docker exec vuls-web python -c "from app.celery_app import celery_app; print('OK')"`
4. **Check logs**: `docker logs vuls-web`

For detailed documentation, see: `docs/development/scheduler-stuck-jobs-cleanup.md`
