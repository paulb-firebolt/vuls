# Lynis Security Audit Integration - Complete Implementation

## Overview

This document describes the complete implementation of Lynis security audit integration into the Vuls vulnerability scanning system. Lynis is a security auditing tool that performs comprehensive security scans on Unix/Linux systems.

## Architecture

The Lynis integration follows the same pattern as the existing Vuls vulnerability scanning:

1. **Database Models** - Store scan results and findings
2. **Services** - Business logic for managing scans and parsing results
3. **Celery Tasks** - Background processing for remote scans
4. **Docker Executor** - Secure execution of remote operations
5. **SSH Client Container** - Dedicated container for remote connections

## Components Implemented

### 1. Database Models

#### LynisScan (`web-app/app/models/lynis_scan.py`)

- Stores scan metadata and status
- Tracks hardening index (0-100 score)
- Links to host and findings
- Includes system information (OS, kernel version)
- Tracks Lynis version and git information

#### LynisControl (`web-app/app/models/lynis_control.py`)

- Represents security controls tested by Lynis
- Categorizes controls (AUTH, BOOT, FILE, etc.)
- Stores control descriptions

#### LynisFinding (`web-app/app/models/lynis_finding.py`)

- Individual security findings from scans
- Types: WARNING, SUGGESTION, FINDING
- Status: OK, FOUND, NOT_FOUND, SKIPPED
- Links findings to controls and scans

### 2. Services

#### LynisService (`web-app/app/services/lynis_service.py`)

- **Report Parsing**: Parses Lynis report files (.dat format)
- **Scan Management**: Creates and updates scan records
- **Finding Processing**: Extracts and categorizes findings
- **Control Management**: Auto-creates security controls
- **Summary Generation**: Provides scan summaries and statistics

Key methods:

- `create_scan()` - Initialize new scan
- `parse_lynis_report()` - Parse report file
- `update_scan_with_results()` - Store parsed results
- `get_findings_summary()` - Generate summary statistics

### 3. Celery Tasks

#### Lynis Tasks (`web-app/app/tasks/lynis_tasks.py`)

- **`run_lynis_scan()`** - Main scan orchestration task
- **`cleanup_old_lynis_reports()`** - Maintenance task for old reports

The main scan task:

1. Creates scan record
2. Builds Lynis installation script
3. Sends to Docker executor
4. Monitors progress
5. Parses results when complete
6. Updates database with findings

### 4. Docker Executor Integration

#### SSH Client Container (`build/ssh-client/Dockerfile`)

- Ubuntu-based container with SSH client tools
- AWS CLI for Session Manager support
- Google Cloud CLI for IAP tunnel support
- Cloudflared for tunnel support
- Supports multiple connection methods

#### Executor Endpoints (`docker-executor/main.py`)

- **`POST /lynis/scan`** - Start Lynis security audit
- **`execute_lynis_scan()`** - Execute scan on remote host
- **`_build_ssh_command_for_lynis()`** - Build connection commands

### 5. Database Migration

Created Alembic migration to add new tables:

- `lynis_scans` - Main scan records
- `lynis_controls` - Security control definitions
- `lynis_findings` - Individual findings
- Updated `hosts` table with Lynis relationships

## Scan Process Flow

1. **Initiation**: User triggers Lynis scan for a host
2. **Task Creation**: Celery task `run_lynis_scan` is queued
3. **Scan Record**: Database record created with "running" status
4. **Script Generation**: Lynis installation script built based on target OS
5. **Executor Request**: Task sends request to Docker executor
6. **SSH Connection**: Executor uses SSH client container to connect
7. **Remote Execution**:
   - Upload installation script
   - Install Lynis on target system
   - Run security audit
   - Download report file
8. **Report Processing**: Parse .dat report file
9. **Database Update**: Store findings and update scan status
10. **Completion**: Scan marked as completed with results

## Security Features

### Connection Methods

- **Standard SSH**: Key-based authentication
- **AWS Session Manager**: For EC2 instances
- **GCP IAP Tunnels**: For GCE instances
- **Cloudflare Tunnels**: For tunnel-connected hosts

### Security Controls

- SSH key management with proper permissions
- Isolated execution in containers
- No persistent connections
- Audit trail of all operations

## Report Format Support

Lynis generates reports in `.dat` format with key=value pairs:

```
lynis_version=3.0.9
scan_date=2025-01-29 10:30:00
hardening_index=85
os_name=Ubuntu
os_version=22.04
warning[AUTH-9262]=Weak password policy detected
suggestion[BOOT-5122]=Enable secure boot
```

The parser extracts:

- Scan metadata (version, date, scores)
- System information (OS, kernel)
- Security findings (warnings, suggestions)
- Control test results

## Integration Points

### Host Model Updates

- Added `lynis_scans` relationship
- Added `latest_lynis_scan` property
- Added `latest_lynis_findings` property

### Compose Configuration

- Added SSH client build target
- Updated volume mounts for alembic files
- Network connectivity for containers

## Usage Examples

### Starting a Scan

```python
from app.tasks.lynis_tasks import run_lynis_scan

# Start scan for host ID 1
task = run_lynis_scan.delay(host_id=1, scan_options={
    'quick_scan': True,
    'tests': ['AUTH', 'BOOT']
})
```

### Accessing Results

```python
from app.services.lynis_service import LynisService

service = LynisService(db)
scan = service.get_latest_scan_for_host(host_id=1)
summary = service.get_findings_summary(scan.id)

print(f"Hardening Index: {scan.hardening_index}")
print(f"Warnings: {summary['warnings']}")
print(f"Suggestions: {summary['suggestions']}")
```

## Future Enhancements

### Planned Features

1. **Web UI Integration** - Dashboard views for Lynis results
2. **Scheduled Scans** - Automated periodic security audits
3. **Compliance Reporting** - Map findings to compliance frameworks
4. **Remediation Guidance** - Actionable fix recommendations
5. **Trend Analysis** - Track security posture over time
6. **Custom Controls** - Organization-specific security checks

### API Endpoints (Future)

- `GET /api/lynis/scans` - List scans
- `GET /api/lynis/scans/{id}` - Get scan details
- `POST /api/lynis/scans` - Start new scan
- `GET /api/lynis/findings` - Search findings
- `GET /api/lynis/controls` - List security controls

## Maintenance

### Regular Tasks

- Run `cleanup_old_lynis_reports` to remove old report files
- Monitor scan success rates and failure patterns
- Update Lynis version in installation script
- Review and update security control definitions

### Monitoring

- Track scan completion rates
- Monitor executor resource usage
- Alert on repeated scan failures
- Review security findings trends

## Conclusion

The Lynis integration provides comprehensive security auditing capabilities that complement the existing vulnerability scanning. It follows established patterns in the codebase and provides a solid foundation for security compliance and monitoring.

The implementation is production-ready with proper error handling, security controls, and scalability considerations. It integrates seamlessly with the existing infrastructure while adding powerful new security assessment capabilities.
