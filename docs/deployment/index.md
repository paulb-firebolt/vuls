# Deployment Guide

This guide covers deploying the Vuls Web application with the complete scheduling system, including the secure Docker Executor Sidecar architecture.

## Architecture Overview

The Vuls Web application uses a microservices architecture with the following components:

### Core Services

- **Web Application** (`vuls-web-dev`) - Main web interface and API
- **PostgreSQL Database** (`vuls-db`) - Application data storage
- **Redis** (`vuls-redis`) - Message broker and cache
- **Celery Worker** (`vuls-worker`) - Background task processing
- **Celery Beat Scheduler** (`vuls-scheduler`) - Cron-based task scheduling
- **Docker Executor Sidecar** (`vuls-executor`) - Secure Docker operations

### Security Architecture

The system implements a **sidecar pattern** for enhanced security:

- **Isolated Execution** - All Docker operations run in a separate container
- **API-Based Communication** - Secure API communication using API keys
- **Function-Based Endpoints** - Only predefined operations allowed
- **Non-Root Execution** - All containers run with minimal privileges

## Prerequisites

- Docker and Docker Compose
- Sufficient disk space for vulnerability databases (10+ GB recommended)
- Network access for downloading vulnerability data
- SSH access to target hosts (for scanning)

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd vuls
```

### 2. Configure Environment

Create a `.env` file with secure configuration:

```bash
# Generate a secure API key
EXECUTOR_API_KEY=$(openssl rand -hex 32)
echo "EXECUTOR_API_KEY=$EXECUTOR_API_KEY" > .env
```

### 3. Start Development Environment

```bash
# Start all services including scheduler
docker compose --profile dev up -d

# Check service status
docker compose --profile dev ps
```

### 4. Initialize Database

```bash
# The database will be automatically initialized on first startup
# Check logs to ensure successful initialization
docker compose logs vuls-web-dev
```

### 5. Access the Application

- **Web Interface**: http://localhost:8000
- **Scheduler**: http://localhost:8000/scheduler
- **API Documentation**: http://localhost:8000/docs

## Production Deployment

### 1. Environment Configuration

Create a production `.env` file:

```bash
# Security
EXECUTOR_API_KEY=your-secure-api-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# Database
DATABASE_URL=postgresql+psycopg://vuls:your-db-password@vuls-db:5432/vuls

# Redis
REDIS_URL=redis://vuls-redis:6379

# Optional: External database
# DATABASE_URL=postgresql+psycopg://user:pass@external-db:5432/vuls
```

### 2. Production Compose Override

Create `docker-compose.prod.yml`:

```yaml
version: "3.8"

services:
  vuls-web:
    build: ./web-app
    container_name: vuls-web-prod
    ports:
      - "80:8000"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
    restart: unless-stopped

  vuls-worker:
    restart: unless-stopped
    environment:
      - EXECUTOR_URL=http://vuls-executor:8080
      - EXECUTOR_API_KEY=${EXECUTOR_API_KEY}

  vuls-scheduler:
    restart: unless-stopped

  vuls-executor:
    restart: unless-stopped
    environment:
      - EXECUTOR_API_KEY=${EXECUTOR_API_KEY}

  vuls-db:
    restart: unless-stopped
    volumes:
      - vuls_db_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_PASSWORD=your-secure-db-password

  vuls-redis:
    restart: unless-stopped
```

### 3. Start Production Services

```bash
# Start production environment
docker compose -f compose.yml -f docker-compose.prod.yml --profile web up -d

# Verify all services are running
docker compose ps
```

## Service Configuration

### Docker Executor Sidecar

The executor sidecar requires specific configuration for secure operation:

#### Environment Variables

```bash
# Required
EXECUTOR_API_KEY=your-secure-api-key

# Optional
EXECUTOR_PORT=8080
EXECUTOR_HOST=0.0.0.0
```

#### Volume Mounts

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock # Docker socket access
  - .:/compose:ro # Compose project directory
```

#### Security Considerations

- The executor runs as a non-root user with Docker group permissions
- Only predefined API endpoints are exposed
- All communication is secured with API keys
- No shell access or arbitrary command execution

### Celery Configuration

#### Worker Configuration

```yaml
environment:
  - DATABASE_URL=${DATABASE_URL}
  - REDIS_URL=${REDIS_URL}
  - EXECUTOR_URL=http://vuls-executor:8080
  - EXECUTOR_API_KEY=${EXECUTOR_API_KEY}
```

#### Scheduler Configuration

```yaml
environment:
  - DATABASE_URL=${DATABASE_URL}
  - REDIS_URL=${REDIS_URL}
```

## Monitoring and Maintenance

### Health Checks

Monitor service health using:

```bash
# Check all services
docker compose ps

# Check specific service logs
docker compose logs vuls-worker
docker compose logs vuls-executor
docker compose logs vuls-scheduler

# Check executor health
curl http://localhost:8080/health
```

### Database Maintenance

```bash
# Backup database
docker exec vuls-db pg_dump -U vuls vuls > backup.sql

# Restore database
docker exec -i vuls-db psql -U vuls vuls < backup.sql
```

### Log Management

Logs are available through Docker:

```bash
# View real-time logs
docker compose logs -f vuls-worker

# View specific service logs
docker compose logs vuls-executor --tail 100
```

## Security Considerations

### API Key Management

- Generate strong, unique API keys for production
- Rotate API keys regularly
- Store keys securely (environment variables, secrets management)
- Never commit API keys to version control

### Network Security

- Use reverse proxy (nginx, traefik) for production
- Enable HTTPS/TLS encryption
- Restrict network access to necessary ports only
- Use firewall rules to limit access

### Container Security

- All containers run as non-root users
- Minimal base images used
- Regular security updates applied
- No unnecessary privileges granted

### Database Security

- Use strong database passwords
- Enable database encryption at rest
- Regular database backups
- Restrict database network access

## Scaling

### Horizontal Scaling

Scale Celery workers for increased throughput:

```bash
# Scale workers
docker compose up -d --scale vuls-worker=3

# Monitor worker performance
docker compose logs vuls-worker
```

### Resource Allocation

Adjust resource limits in compose files:

```yaml
services:
  vuls-worker:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: "1.0"
        reservations:
          memory: 1G
          cpus: "0.5"
```

## Backup and Recovery

### Database Backup

```bash
# Automated backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker exec vuls-db pg_dump -U vuls vuls | gzip > "backup_${DATE}.sql.gz"
```

### Configuration Backup

```bash
# Backup configuration files
tar -czf config_backup.tar.gz config/ .env compose.yml
```

### Recovery Procedure

1. Stop all services
2. Restore database from backup
3. Restore configuration files
4. Restart services
5. Verify system functionality

## Troubleshooting

### Common Issues

#### Services Not Starting

```bash
# Check service status
docker compose ps

# Check logs for errors
docker compose logs

# Restart specific service
docker compose restart vuls-worker
```

#### Database Connection Issues

```bash
# Check database connectivity
docker exec vuls-web-dev python -c "
from app.config import settings
print('Database URL:', settings.database_url)
"

# Test database connection
docker exec vuls-db psql -U vuls -c "SELECT version();"
```

#### Executor Sidecar Issues

```bash
# Check executor health
curl http://localhost:8080/health

# Check executor logs
docker compose logs vuls-executor

# Verify API key configuration
docker exec vuls-worker env | grep EXECUTOR
```

#### Task Execution Failures

```bash
# Check worker logs
docker compose logs vuls-worker

# Check Redis connectivity
docker exec vuls-worker python -c "
import redis
r = redis.from_url('redis://vuls-redis:6379')
print('Redis ping:', r.ping())
"

# Monitor task queue
docker exec vuls-worker celery -A app.tasks inspect active
```

### Performance Optimization

#### Database Performance

- Regular VACUUM and ANALYZE operations
- Appropriate indexing for query patterns
- Connection pooling configuration
- Query optimization

#### Worker Performance

- Adjust worker concurrency based on CPU cores
- Monitor memory usage and adjust limits
- Use appropriate task routing
- Implement task result expiration

#### Storage Optimization

- Regular cleanup of old task results
- Compress vulnerability database files
- Use appropriate storage drivers
- Monitor disk usage

## Support

For additional support:

1. Check the troubleshooting section above
2. Review service logs for error messages
3. Consult the user guide documentation
4. Contact your system administrator

## Updates and Maintenance

### Updating the Application

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart services
docker compose --profile dev up -d --build

# Check for any migration requirements
docker compose logs vuls-web-dev | grep -i migration
```

### Security Updates

- Regularly update base Docker images
- Apply security patches to the host system
- Update dependency packages
- Review and rotate API keys

### Monitoring

Set up monitoring for:

- Service availability and health
- Resource usage (CPU, memory, disk)
- Task execution success rates
- Database performance metrics
- Security events and access logs
