# Development Containers

This document explains the development container setup that provides hot reload functionality for faster development cycles.

## Overview

The project uses a single Dockerfile per service with build arguments to create both production and development versions of containers. Development containers are designed to reload automatically when code changes are detected, eliminating the need for manual rebuilds and restarts during development.

## Container Types

### Production Containers (Profile: `web`)

- `vuls-web`: Main web application
- `vuls-worker`: Celery background task worker
- `vuls-scheduler`: Celery beat scheduler
- `vuls-executor`: Docker executor service

### Development Containers (Profile: `dev`)

- `vuls-web-dev`: Web application with hot reload
- `vuls-worker-dev`: Celery worker with hot reload
- `vuls-scheduler-dev`: Celery scheduler with hot reload
- `vuls-executor-dev`: Docker executor with hot reload

## Key Differences

### Development Features

1. **Hot Reload**: Code changes trigger automatic restarts
2. **Source Code Mounting**: Local source code is mounted into containers
3. **Development Dependencies**: Additional tools like watchdog for file monitoring
4. **Solo Pool**: Celery worker uses solo pool for better debugging

### Volume Mounts

Development containers mount source code directories:

- `./web-app/app:/app/app:rw` - Python application code
- `./docker-executor:/app:rw` - Executor service code
- `./web-app/static:/app/static:rw` - Static files

## Usage

### Start Development Environment

```bash
# Start all development containers
docker compose --profile dev up -d

# Start specific development services
docker compose --profile dev up vuls-web-dev vuls-worker-dev -d

# Alternative: Set default profile for session
export COMPOSE_PROFILES=dev
docker compose up -d  # Will use dev profile by default
```

### Start Production Environment

```bash
# Start all production containers
docker compose --profile web up -d

# Alternative: Set default profile for session
export COMPOSE_PROFILES=web
docker compose up -d  # Will use web profile by default
```

### Switch Between Environments

```bash
# Stop development environment
docker compose --profile dev down

# Start production environment
docker compose --profile web up -d

# Or using environment variable
export COMPOSE_PROFILES=web
docker compose down && docker compose up -d
```

## Development Workflow

1. **Code Changes**: Edit files in your local development environment
2. **Automatic Reload**: Development containers detect changes and restart automatically
3. **No Rebuild Required**: Changes are reflected immediately without rebuilding images
4. **Database Persistence**: Database and Redis data persist across container restarts

## Container-Specific Notes

### Web Application (`vuls-web-dev`)

- Uses single Dockerfile with `BUILD_TYPE=development` argument
- Enables `--reload` flag for uvicorn hot reload
- Mounts source code for hot reload
- Includes alembic files for database migrations

### Celery Worker (`vuls-worker-dev`)

- Uses solo pool for better debugging
- Connects to development executor service
- Automatically reloads when task code changes
- Built with `BUILD_TYPE=development` argument

### Celery Scheduler (`vuls-scheduler-dev`)

- Monitors scheduled task definitions
- Reloads when scheduler configuration changes
- Built with `BUILD_TYPE=development` argument

### Docker Executor (`vuls-executor-dev`)

- Uses watchdog for Python file monitoring
- Automatically restarts on code changes
- Maintains same Docker socket access as production
- Built with `BUILD_TYPE=development` argument

## Best Practices

### When to Use Development Containers

- ✅ Active development and debugging
- ✅ Testing new features
- ✅ Rapid iteration cycles
- ✅ Local development environment

### When to Use Production Containers

- ✅ Performance testing
- ✅ Production-like testing
- ✅ Final integration testing
- ✅ Deployment preparation

### Development Tips

1. **Monitor Logs**: Use `docker compose logs -f <service>` to watch for reload events
2. **Database Migrations**: Run migrations in development containers for testing
3. **Port Conflicts**: Ensure no conflicts between dev and prod containers on same ports
4. **Resource Usage**: Development containers may use more resources due to file watching
5. **Profile Environment Variable**: Set `export COMPOSE_PROFILES=dev` to avoid typing `--profile dev` repeatedly

### Profile Environment Variable

For convenience during development, you can set the default profile:

```bash
# Set development as default profile for your session
export COMPOSE_PROFILES=dev

# Now you can use shorter commands
docker compose up -d
docker compose down
docker compose logs -f vuls-web-dev

# To switch to production temporarily
docker compose --profile web up -d

# Or change the default
export COMPOSE_PROFILES=web
```

## Troubleshooting

### Container Won't Start

```bash
# Check container logs
docker compose logs vuls-web-dev

# Rebuild development image
docker compose build vuls-web-dev
```

### Hot Reload Not Working

1. Verify source code is properly mounted
2. Check file permissions on mounted volumes
3. Ensure watchdog is running in container logs

### Performance Issues

- Development containers use more CPU due to file watching
- Consider excluding large directories from file monitoring
- Use production containers for performance testing

## Architecture

### Single Dockerfile Approach

The project uses a consolidated approach with a single Dockerfile per service that supports both production and development builds through build arguments:

```dockerfile
# Build argument to determine if this is a dev build
ARG BUILD_TYPE=production

# Install development dependencies only if BUILD_TYPE=development
RUN if [ "$BUILD_TYPE" = "development" ]; then \
    pip install --no-cache-dir watchdog; \
    fi

# Run with conditional reload based on build type
CMD if [ "$BUILD_TYPE" = "development" ]; then \
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload; \
    else \
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000; \
    fi
```

### Build Arguments in Compose

Services specify their build type through compose configuration:

```yaml
# Production build
vuls-web:
  build:
    context: ./web-app
    args:
      BUILD_TYPE: production

# Development build
vuls-web-dev:
  build:
    context: ./web-app
    args:
      BUILD_TYPE: development
```

### Benefits of This Approach

1. **DRY Principle**: Single source of truth for each service
2. **Easier Maintenance**: Changes only need to be made in one place
3. **Consistency**: Ensures dev and prod environments stay in sync
4. **Reduced Complexity**: Fewer files to manage
5. **Better CI/CD**: Single Dockerfile can build both variants

## Configuration

### Environment Variables

Development containers inherit the same environment variables as production containers, ensuring consistency between environments.

### Networking

Development containers use the same network configuration as production, allowing seamless switching between environments.

### Data Persistence

Database and Redis data volumes are shared between development and production containers, maintaining data consistency.
