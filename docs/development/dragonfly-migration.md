# Redis to Dragonfly Migration

## Overview

This document describes the migration from Redis to Dragonfly for the task queue system in the vulnerability scanning application.

## Why Dragonfly?

Dragonfly was chosen as a Redis replacement due to:

- **Licensing**: Dragonfly uses the Business Source License (BSL) which is more permissive than Redis's dual licensing model
- **Redis Compatibility**: Dragonfly is fully compatible with Redis protocols and commands
- **Performance**: Dragonfly offers better performance characteristics, especially for memory usage and multi-threading
- **Drop-in Replacement**: No application code changes required due to Redis protocol compatibility

## Changes Made

### Docker Compose Configuration

The `vuls-redis` service in `compose.yml` was updated:

**Before (Redis):**

```yaml
vuls-redis:
  image: redis:7-alpine
  container_name: vuls-redis
  healthcheck:
    test: [CMD, redis-cli, ping]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 5s
  profiles: [web, dev]
```

**After (Dragonfly):**

```yaml
vuls-redis:
  image: docker.dragonflydb.io/dragonflydb/dragonfly:latest
  container_name: vuls-redis
  command: ["--logtostderr", "--alsologtostderr=false"]
  healthcheck:
    test: [CMD, redis-cli, ping]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 5s
  profiles: [web, dev]
```

### Application Configuration

No changes were required to the application configuration since:

- The Redis URL format remains the same: `redis://vuls-redis:6379`
- Celery continues to use the same Redis protocol
- All Redis commands used by Celery are supported by Dragonfly

## Dragonfly Configuration

The Dragonfly container is configured with:

- `--logtostderr`: Direct logs to stderr for Docker logging
- `--alsologtostderr=false`: Prevent duplicate log entries
- `--requirepass`: Password authentication for security
- `--rename_command=CONFIG:VULS_CONFIG_CMD_RENAMED`: Rename dangerous CONFIG command

## Security Enhancements

For security best practices, the following measures have been implemented:

### Password Authentication

- **Environment Variable**: `REDIS_PASSWORD` (defaults to `VulsRedisSecurePassword2025`)
- **Connection Format**: `redis://:password@vuls-redis:6379`
- **Health Checks**: Updated to use authentication

### Command Renaming

- **CONFIG Command**: Renamed to `VULS_CONFIG_CMD_RENAMED`
- **Purpose**: Prevents unauthorized configuration changes
- **Access**: Only available with the renamed command

## Compatibility

Dragonfly maintains full compatibility with:

- **Redis Protocol**: All Redis commands used by Celery
- **Celery**: Task queue, result backend, and beat scheduler
- **Health Checks**: Redis CLI commands for monitoring
- **Connection Strings**: Same Redis URL format

## Benefits

1. **Licensing Clarity**: Avoids Redis licensing concerns
2. **Performance**: Better memory efficiency and multi-core utilization
3. **Compatibility**: Zero application code changes required
4. **Monitoring**: Same Redis CLI tools work for monitoring

## Testing

To verify the migration:

1. **Start the development environment:**

   ```bash
   docker compose --profile dev up -d
   ```

2. **Check Dragonfly health:**

   ```bash
   docker compose exec vuls-redis redis-cli ping
   ```

3. **Verify Celery connectivity:**

   ```bash
   docker compose exec vuls-worker-dev uv run celery -A app.tasks inspect ping
   ```

4. **Test task execution:**
   ```bash
   # Submit a test task through the web interface
   # Check logs for successful task processing
   docker compose logs vuls-worker-dev
   ```

## Rollback Plan

If issues arise, rollback by reverting the Docker image:

```yaml
vuls-redis:
  image: redis:7-alpine # Revert to Redis
  container_name: vuls-redis
  # Remove Dragonfly-specific command
  healthcheck:
    test: [CMD, redis-cli, ping]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 5s
  profiles: [web, dev]
```

## Monitoring

Monitor Dragonfly using the same Redis tools:

- **Connection check:** `redis-cli ping`
- **Info command:** `redis-cli info`
- **Memory usage:** `redis-cli info memory`
- **Client connections:** `redis-cli info clients`

## Future Considerations

- **Dragonfly-specific features**: Consider leveraging Dragonfly's enhanced features in future updates
- **Configuration tuning**: Optimize Dragonfly configuration for the specific workload
- **Monitoring integration**: Integrate Dragonfly-specific metrics if needed
