# Task Scheduling

The Vuls Web application includes a comprehensive task scheduling system that allows you to automate vulnerability scans and database updates. This system is built on Celery and Redis, providing reliable and scalable task execution.

## Overview

The scheduler supports two main types of tasks:

1. **Vulnerability Scans** - Automated scans of your configured hosts
2. **Database Updates** - Regular updates of vulnerability databases (NVD, OVAL, GOST)

## Architecture

The scheduling system uses a secure, multi-component architecture:

### Core Components

- **Web Application** - User interface and API endpoints
- **Celery Worker** - Background task processing
- **Celery Beat Scheduler** - Cron-based task scheduling
- **Redis** - Message broker and result backend
- **PostgreSQL** - Task metadata and history storage
- **Docker Executor Sidecar** - Secure Docker operations

### Security Architecture

The system implements a **sidecar pattern** for enhanced security:

- **Isolated Execution** - All Docker operations run in a separate, dedicated container
- **API-Based Communication** - Secure API communication between components using API keys
- **Function-Based Endpoints** - Only predefined operations are allowed (no arbitrary command execution)
- **Non-Root Execution** - All containers run with minimal privileges
- **Async Operations** - Non-blocking task execution with real-time monitoring

### Data Flow

1. **Task Creation** - Users create scheduled tasks via web interface or API
2. **Task Scheduling** - Celery Beat checks for due tasks every minute
3. **Task Execution** - Celery Worker processes tasks asynchronously
4. **Secure Operations** - Worker communicates with Docker Executor Sidecar via secure API
5. **Container Execution** - Sidecar manages Docker containers for scans and database updates
6. **Result Processing** - Results are collected and stored in PostgreSQL
7. **Status Updates** - Real-time status updates available via web interface and API

## Features

- **Cron-based Scheduling** - Use standard cron expressions for flexible scheduling
- **Manual Execution** - Trigger any scheduled task manually
- **Task History** - View execution history and results for each task
- **Real-time Status** - Monitor task execution status in real-time
- **Error Handling** - Comprehensive error logging and notification
- **Web Interface** - Easy-to-use web interface for managing tasks
- **Automatic Host Sync** - Hosts are automatically synchronized from Vuls configuration when SSH config is updated

## Automatic Host Synchronization

The scheduler automatically synchronizes hosts from your Vuls configuration whenever you update the SSH configuration. This ensures that your scheduled tasks always use the most current host definitions.

### How It Works

1. **SSH Config Update** - When you save changes to the SSH configuration via the web interface
2. **Vuls Config Update** - The system automatically updates the `config/config.toml` file with the new host definitions
3. **Host Sync Trigger** - A background Celery task is automatically triggered to synchronize the hosts
4. **Database Update** - The hosts table is updated with the latest host information from the Vuls config

### Benefits

- **Single Source of Truth** - Hosts are defined once in the SSH/Vuls config and automatically synchronized
- **No Manual Entry** - No need to manually add hosts to the scheduler interface
- **Consistency** - Scan modes and settings match the Vuls configuration exactly
- **Real-time Updates** - Changes are synchronized immediately when SSH config is saved

### Synchronized Data

The following host information is automatically synchronized:

- **Host Name** - Unique identifier from SSH config
- **Hostname/IP** - Target address for scanning
- **Scan Mode** - Automatically determined based on connection type:
  - **AWS SSM** → Fast scan mode
  - **GCP IAP** → Fast scan mode
  - **Cloudflare Access** → Offline scan mode
  - **Direct SSH** → Fast and offline scan modes
- **Vuls Configuration** - Complete Vuls config section for the host

### Manual Synchronization

You can also manually trigger host synchronization using the API:

```bash
POST /api/hosts/sync-from-vuls-config
```

This is useful for:

- Troubleshooting synchronization issues
- Forcing a sync after manual config file changes
- Initial setup and testing

## Accessing the Scheduler

Navigate to the **Scheduler** section in the main navigation menu. This will take you to the task management interface where you can:

- View all scheduled tasks
- Create new tasks
- Edit existing tasks
- Monitor task execution
- View task history

## Creating Scheduled Tasks

### Vulnerability Scan Tasks

To create a scheduled vulnerability scan:

1. Click **Create New Task**
2. Enter a descriptive **Task Name**
3. Select **Vulnerability Scan** as the task type
4. Choose the **Target Host** from your configured hosts
5. Select the **Scan Type**:
   - **Fast Scan** - Quick vulnerability assessment
   - **Full Scan** - Comprehensive deep scan
6. Set the **Schedule** using cron expression
7. Add an optional **Description**
8. Ensure the task is **Active**

### Database Update Tasks

To create a scheduled database update:

1. Click **Create New Task**
2. Enter a descriptive **Task Name**
3. Select **Database Update** as the task type
4. Choose the **Database Type**:
   - **All Databases** - Update all vulnerability databases
   - **NVD Database** - National Vulnerability Database
   - **Ubuntu OVAL** - Ubuntu vulnerability data
   - **Debian OVAL** - Debian vulnerability data
   - **Red Hat OVAL** - Red Hat/CentOS vulnerability data
   - **Amazon Linux OVAL** - Amazon Linux vulnerability data
   - **Alpine OVAL** - Alpine Linux vulnerability data
   - **GOST Ubuntu** - Ubuntu security tracker data
   - **GOST Debian** - Debian security tracker data
   - **GOST Red Hat** - Red Hat security tracker data
5. Set the **Schedule** using cron expression
6. Add an optional **Description**
7. Ensure the task is **Active**

## Cron Expressions

The scheduler uses standard cron expressions with five fields:

```
* * * * *
│ │ │ │ │
│ │ │ │ └─── Day of week (0-7, Sunday = 0 or 7)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

### Common Examples

| Schedule                   | Cron Expression | Description                |
| -------------------------- | --------------- | -------------------------- |
| Every day at 2 AM          | `0 2 * * *`     | Daily maintenance scans    |
| Every Sunday at midnight   | `0 0 * * 0`     | Weekly comprehensive scans |
| Every hour                 | `0 * * * *`     | Frequent monitoring        |
| Every 15 minutes           | `*/15 * * * *`  | High-frequency checks      |
| First day of month at 3 AM | `0 3 1 * *`     | Monthly database updates   |
| Weekdays at 6 AM           | `0 6 * * 1-5`   | Business day scans         |

## Default Scheduled Tasks

The system comes with some pre-configured scheduled tasks:

### Monthly Database Updates

- **Schedule**: `0 2 1 * *` (1st of every month at 2 AM)
- **Type**: Database Update (All Databases)
- **Purpose**: Keep vulnerability databases current

### Task Scheduler Monitoring

- **Schedule**: Every minute
- **Type**: Internal system task
- **Purpose**: Check for and execute scheduled tasks

## Task Management

### Viewing Tasks

The main scheduler interface shows:

- **Task Statistics** - Overview of total, active, scan, and database update tasks
- **Task List** - Detailed view of all scheduled tasks with:
  - Task name and description
  - Task type and target (for scans)
  - Cron schedule
  - Next scheduled run time
  - Last execution status and time
  - Active/inactive status

### Filtering and Search

Use the filter options to find specific tasks:

- **Task Type Filter** - Show only scan tasks or database updates
- **Status Filter** - Show only active or inactive tasks
- **Search** - Search by task name, description, or host name

### Manual Execution

You can manually trigger any scheduled task by clicking the **Run Now** button. This will:

- Create a new task run record
- Execute the task immediately
- Update the task status
- Show the execution results

### Task History

Click on any task to view its execution history, including:

- Execution start and end times
- Duration
- Status (success, failed, running)
- Result data (vulnerabilities found, databases updated)
- Error messages (if any)

## Monitoring and Troubleshooting

### Task Status Indicators

- **Green (Success)** - Task completed successfully
- **Red (Failed)** - Task encountered an error
- **Blue (Running)** - Task is currently executing
- **Gray (Never run)** - Task has not been executed yet

### Common Issues

#### Task Not Running

- Check if the task is **Active**
- Verify the cron expression is valid
- Ensure the Celery worker and scheduler services are running

#### Scan Failures

- Verify host connectivity and SSH configuration
- Check if the target host is accessible
- Review error messages in the task history

#### Database Update Failures

- Check internet connectivity
- Verify Docker is running and has access to pull images
- Review disk space for database storage

### Logs and Debugging

Task execution logs are available in:

- Web interface task history
- Application logs (`/app/logs/`)
- Celery worker logs

## Best Practices

### Scheduling Guidelines

1. **Avoid Peak Hours** - Schedule intensive tasks during off-peak hours
2. **Stagger Tasks** - Don't schedule multiple heavy tasks at the same time
3. **Regular Updates** - Keep vulnerability databases updated monthly
4. **Monitor Resources** - Ensure adequate system resources for scheduled tasks

### Security Considerations

1. **SSH Keys** - Use SSH keys instead of passwords for host access
2. **Network Access** - Ensure proper network security for scan targets
3. **User Permissions** - Limit scheduler access to authorized users
4. **Audit Trail** - Regularly review task execution history

### Performance Optimization

1. **Fast Scans** - Use fast scans for frequent monitoring
2. **Full Scans** - Reserve full scans for comprehensive assessments
3. **Database Updates** - Update only necessary databases if storage is limited
4. **Cleanup** - Old task run records are automatically cleaned up after 30 days

## API Integration

The scheduler provides REST API endpoints for programmatic access:

- `GET /api/scheduled-tasks/` - List all scheduled tasks
- `POST /api/scheduled-tasks/` - Create a new scheduled task
- `GET /api/scheduled-tasks/{id}` - Get specific task details
- `PUT /api/scheduled-tasks/{id}` - Update a scheduled task
- `DELETE /api/scheduled-tasks/{id}` - Delete a scheduled task
- `POST /api/scheduled-tasks/{id}/run` - Manually trigger a task
- `GET /api/scheduled-tasks/{id}/runs` - Get task execution history

See the API documentation for detailed request/response formats.

## Docker Executor Sidecar

The Docker Executor Sidecar is a critical security component that handles all Docker operations in an isolated environment.

### Security Features

- **Isolated Container** - Runs in a separate container with minimal privileges
- **API Key Authentication** - All communication secured with API keys
- **Function-Based Operations** - Only predefined operations allowed (no shell access)
- **Non-Root Execution** - Runs as non-root user with Docker group permissions
- **Async Processing** - Non-blocking operations with real-time status monitoring

### Supported Operations

The sidecar provides secure endpoints for:

- **Database Updates** - NVD, OVAL, and GOST database fetching
- **Vulnerability Scans** - Host scanning operations
- **Job Monitoring** - Real-time status tracking and result collection

### API Endpoints

The sidecar exposes the following internal API endpoints:

- `GET /health` - Health check endpoint
- `POST /database/update` - Start database update job
- `POST /scan` - Start vulnerability scan job
- `GET /jobs/{job_id}` - Get job status and results
- `GET /jobs/{job_id}/logs` - Get job execution logs

### Configuration

The sidecar is configured via environment variables:

- `EXECUTOR_API_KEY` - API key for secure communication
- Docker socket access for container management
- Compose project directory mount for accessing configuration

### Monitoring

You can monitor sidecar operations through:

- **Web Interface** - Task status and history in the scheduler
- **API Responses** - Real-time job status via REST API
- **Container Logs** - Docker logs for the executor container
- **Health Checks** - Built-in health monitoring endpoint

## Troubleshooting

If you encounter issues with the scheduler:

1. Check the system status in the dashboard
2. Verify Celery worker and Redis services are running
3. Review task execution logs
4. Ensure proper network connectivity for scans and database updates
5. Check system resources (CPU, memory, disk space)
6. Verify Docker Executor Sidecar is running and accessible
7. Check API key configuration in environment variables

### Common Sidecar Issues

#### Sidecar Not Responding

- Check if the `vuls-executor` container is running
- Verify API key configuration matches between services
- Ensure Docker socket permissions are correct

#### Database Update Failures

- Check internet connectivity for downloading vulnerability data
- Verify sufficient disk space for database storage
- Review Docker container logs for specific error messages

#### Permission Errors

- Ensure the executor user has proper Docker group membership
- Verify Docker socket group ID matches container configuration
- Check file system permissions for mounted volumes

For additional support, consult the system logs or contact your administrator.
