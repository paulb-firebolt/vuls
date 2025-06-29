# Development Containers Setup

This document describes the development container setup for the vulnerability scanning system, including hot reload functionality for improved developer experience.

## Overview

The development environment uses Docker containers with the following features:

- **Hot Reload**: Automatic restart of services when code changes are detected
- **Supervisord**: Process management for running multiple services in containers
- **Volume Mounts**: Live code synchronization between host and containers
- **Development Dependencies**: Additional tools and packages for development

## Container Architecture

### Web Application Container (`vuls-web-dev`)

- **Base Image**: Python 3.11 with UV package manager
- **Purpose**: Runs the FastAPI web application
- **Hot Reload**: Uses `uvicorn --reload` for automatic restart on code changes
- **Port**: 8000 (mapped to host)
- **Volume Mounts**:
  - `./web-app/app:/app/app` - Application code
  - `./web-app/static:/app/static` - Static files

### Worker Container (`vuls-worker-dev`)

- **Base Image**: Python 3.11 with UV package manager
- **Purpose**: Runs Celery workers for background tasks
- **Hot Reload**: Uses supervisord + entr for automatic restart on code changes
- **Services Managed**:
  - `celery-worker`: Main Celery worker process
  - `hot-reload-watcher`: File watcher for automatic restarts

### Executor Container (`vuls-executor-dev`)

- **Base Image**: Python 3.11 with UV package manager
- **Purpose**: Executes vulnerability scans and remote operations
- **Hot Reload**: Uses `uvicorn --reload` for automatic restart
- **Port**: 8001 (mapped to host)

## Hot Reload Implementation

### Web Application Hot Reload

The web application uses uvicorn's built-in reload functionality:

```yaml
command: uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

This automatically detects changes to Python files and restarts the server.

### Worker Hot Reload

The worker container uses a more sophisticated approach with supervisord:

#### Supervisord Configuration (`supervisord-celery.conf`)

```ini
[supervisord]
nodaemon=true
logfile=/dev/stdout
logfile_maxbytes=0
pidfile=/tmp/supervisord.pid

[unix_http_server]
file=/tmp/supervisor.sock
chmod=0777

[supervisorctl]
serverurl=unix:///tmp/supervisor.sock

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[program:celery-worker]
command=uv run celery -A app.tasks worker --loglevel=info --pool=solo
directory=/app
user=appuser
autostart=true
autorestart=false
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
environment=PATH="/app/.venv/bin:%(ENV_PATH)s",UV_CACHE_DIR="/home/appuser/.cache/uv",HOME="/home/appuser"

[program:hot-reload-watcher]
command=bash -c 'find /app/app -name "*.py" | entr -n -r supervisorctl -s unix:///tmp/supervisor.sock restart celery-worker'
directory=/app
user=root
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
environment=PATH="/usr/bin:%(ENV_PATH)s"
```

#### How It Works

1. **File Watcher**: The `hot-reload-watcher` process uses `entr` to monitor Python files
2. **Change Detection**: When a `.py` file changes, `entr` triggers a restart command
3. **Service Restart**: `supervisorctl` restarts the `celery-worker` process
4. **Code Reload**: The new worker process loads the updated code

#### Key Components

- **entr**: File watcher utility that monitors file changes
- **supervisord**: Process supervisor that manages multiple processes
- **supervisorctl**: Command-line client for controlling supervisord

## Development Workflow

### Starting Development Environment

```bash
# Start all development containers
docker compose up -d

# View logs for all services
docker compose logs -f

# View logs for specific service
docker compose logs -f vuls-web-dev
docker compose logs -f vuls-worker-dev
docker compose logs -f vuls-executor-dev
```

### Making Code Changes

1. **Edit Code**: Make changes to any Python file in the mounted directories
2. **Automatic Reload**: Services will automatically restart and load new code
3. **Verify Changes**: Check logs to confirm restart and test functionality

### Monitoring Hot Reload

Watch the logs to see hot reload in action:

```bash
# Monitor worker restarts
docker compose logs -f vuls-worker-dev

# Look for these messages indicating successful reload:
# celery-worker: stopped
# celery-worker: started
```

### Testing Hot Reload

You can test the hot reload functionality by:

1. Making a small change to a task file (e.g., `web-app/app/tasks/lynis_tasks.py`)
2. Watching the logs for restart messages
3. Verifying the change takes effect without manual restart

## Troubleshooting

### Common Issues

#### Worker Not Restarting

**Symptoms**: Code changes don't trigger worker restart

**Solutions**:
1. Check if supervisord is running: `docker exec vuls-worker-dev supervisorctl status`
2. Verify file watcher is active in logs
3. Ensure file changes are in mounted volume paths

#### Permission Issues

**Symptoms**: Cache directory permission errors

**Solutions**:
1. Verify environment variables in supervisord config
2. Check user permissions in container
3. Ensure cache directories are properly created and owned

#### Socket Connection Errors

**Symptoms**: `unix:///var/run/supervisor.sock no such file`

**Solutions**:
1. Verify supervisord socket path configuration
2. Check if supervisord is running as expected
3. Ensure socket file permissions are correct

### Debugging Commands

```bash
# Check supervisord status
docker exec vuls-worker-dev supervisorctl status

# View supervisord logs
docker exec vuls-worker-dev supervisorctl tail -f celery-worker

# Restart specific service
docker exec vuls-worker-dev supervisorctl restart celery-worker

# Check file watcher process
docker exec vuls-worker-dev ps aux | grep entr
```

## Performance Considerations

### Development vs Production

- **Development**: Hot reload enabled, debug logging, development dependencies
- **Production**: Hot reload disabled, optimized for performance and security

### Resource Usage

- File watchers consume minimal CPU but monitor file system events
- Automatic restarts may cause brief service interruptions
- Volume mounts have slight performance overhead compared to copied files

## Security Notes

### Development Only

The hot reload functionality should **never** be enabled in production environments:

- File watchers can be security risks
- Automatic restarts can cause service disruptions
- Development configurations may expose sensitive information

### Container Security

- Development containers run with elevated privileges for debugging
- Production containers should use minimal privileges and security hardening
- Sensitive data should never be included in development images

## Future Improvements

### Planned Enhancements

1. **Selective Restart**: Only restart affected services based on changed files
2. **Faster Reload**: Optimize restart times for better developer experience
3. **IDE Integration**: Better integration with development environments
4. **Test Automation**: Automatic test execution on code changes

### Configuration Options

Consider adding environment variables to control hot reload behavior:

- `ENABLE_HOT_RELOAD`: Toggle hot reload functionality
- `RELOAD_PATTERNS`: Customize which files trigger restarts
- `RELOAD_DELAY`: Add delay before restart to batch changes
