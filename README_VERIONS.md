# Monthly Vulnerability Scanning Guide with Vuls

## Overview

This guide outlines the process for conducting regular monthly vulnerability scans using Vuls in a containerized environment. The process ensures consistent, automated vulnerability assessments across your infrastructure.

## Prerequisites

- Docker and Docker Compose installed
- Vuls container with AWS CLI and GCP CLI
- SSH access to target systems (direct or via AWS Session Manager)
- Vulnerability databases configured

## Monthly Scanning Workflow

### Phase 1: Database Updates (1st of each month)

#### 1.1 Update Vulnerability Databases

**Frequency**: Monthly (or weekly for high-security environments)

**IMPORTANT - OS Version Limitations**: 
- **Ubuntu OVAL**: Only covers currently supported LTS versions (20.04, 22.04, 24.04)
- **Debian OVAL**: Only covers currently supported versions (10, 11, 12)
- **End-of-Life (EOL) systems**: Cannot be properly scanned due to missing OVAL data
- **Recently released versions**: May show 0 vulnerabilities if well-patched

**Supported OS Versions for Vulnerability Scanning**:
- ✅ **Ubuntu**: 20.04 LTS (Focal), 22.04 LTS (Jammy), 24.04 LTS (Noble)
- ✅ **Debian**: 10 (Buster), 11 (Bullseye), 12 (Bookworm)  
- ✅ **RHEL/CentOS**: 7, 8, 9
- ✅ **Amazon Linux**: 1, 2, 2023
- ❌ **Ubuntu 16.04/18.04**: EOL - Limited or no OVAL data available
- ❌ **Debian 8/9**: EOL - Limited or no OVAL data available

```bash
# Navigate to your Vuls directory
cd ~/docker/vuls

# Update NVD (CVE) database - most critical
docker compose --profile fetch up vuls-nvd

# Update OS-specific databases (only supported versions)
docker compose --profile fetch up vuls-ubuntu    # Ubuntu 20.04, 22.04, 24.04
docker compose --profile fetch up vuls-debian    # Debian 10, 11, 12
docker compose --profile fetch up vuls-redhat    # RHEL/CentOS 7, 8, 9
docker compose --profile fetch up vuls-amazon    # Amazon Linux 1, 2, 2023

# Verify database updates
ls -la ./db/
du -sh ./db/*
```

**Expected Database Sizes**:
- `cve.sqlite3`: 1-2GB (NVD database - ~280K CVEs)
- `oval.sqlite3`: 200-400MB (OS-specific vulnerabilities - ~200K definitions)

**Database Coverage Verification**:
```bash
# Check which OS versions are covered
docker compose run --rm --entrypoint sqlite3 vuls /vuls/db/oval.sqlite3 "SELECT DISTINCT substr(title, instr(title, 'Ubuntu'), 20) FROM definitions WHERE title LIKE '%Ubuntu%' LIMIT 5;"

# Check total definitions count
docker compose run --rm --entrypoint sqlite3 vuls /vuls/db/oval.sqlite3 "SELECT COUNT(*) FROM definitions;"
```

#### 1.2 Validate Database Updates

```bash
# Check database timestamps
stat ./db/*.sqlite3

# Test database connectivity
docker-compose run --rm vuls configtest -config=/vuls/config.toml
```

### Phase 2: System Discovery and Inventory

#### 2.1 Update Target Systems Inventory

**Review and update your `config/config.toml`**:

```toml
[servers]

# On-premise systems
[servers.production-web]
host = "192.168.1.100"
port = "22"
user = "admin"
keyPath = "/root/.ssh/id_ed25519"
osFamily = "ubuntu"
scanMode = ["fast"]

# AWS EC2 instances (via Session Manager)
[servers.aws-web-prod]
host = "i-0a1347a614cf7cea5"
port = "22"
user = "admin"
keyPath = "/root/.ssh/id_aws"
osFamily = "ubuntu"
scanMode = ["fast"]

# Add new systems discovered during the month
[servers.new-system]
host = "10.0.1.50"
port = "22"
user = "ubuntu"
keyPath = "/root/.ssh/id_ed25519"
osFamily = "ubuntu"
scanMode = ["fast"]
```

#### 2.2 Validate System Access

```bash
# Test configuration for all systems
docker compose run --rm vuls configtest -config=/vuls/config.toml

# Test SSH connectivity to each system
docker compose run --rm --entrypoint ssh vuls admin@target-system

# Enter container for manual testing if needed
docker compose run --rm --entrypoint /bin/sh vuls
# Inside container:
# ssh -vvv admin@target-system
# aws sts get-caller-identity
# gcloud auth list
# exit
```

### Phase 3: Vulnerability Scanning

#### 3.1 Pre-Scan Checklist

- [ ] Vulnerability databases updated
- [ ] All target systems accessible
- [ ] SSH keys properly mounted
- [ ] AWS/GCP credentials configured
- [ ] Previous scan results backed up

#### 3.2 Execute Monthly Scan

```bash
# Create monthly results directory
SCAN_DATE=$(date +%Y-%m)
mkdir -p ./results/monthly-scans/$SCAN_DATE

# Run comprehensive scan
docker compose run --rm vuls scan -config=/vuls/config.toml

# Generate detailed reports
docker compose run --rm vuls report -config=/vuls/config.toml -format-json
docker compose run --rm vuls report -config=/vuls/config.toml -format-full-text
docker compose run --rm vuls report -config=/vuls/config.toml -format-csv
```

#### 3.3 Scan Verification

```bash
# Check scan completed successfully
ls -la ./results/$(date +%Y-%m-%d)*

# Verify all systems were scanned
docker-compose run --rm vuls report -config=/vuls/config.toml -format-one-line-text
```

### Phase 4: Results Analysis and Reporting

#### 4.1 Generate Management Reports

```bash
# Create executive summary
docker compose run --rm vuls report -config=/vuls/config.toml -format-short-text > ./results/monthly-scans/$SCAN_DATE/executive-summary.txt

# Generate detailed CSV for tracking
docker compose run --rm vuls report -config=/vuls/config.toml -format-csv > ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv

# Create system-by-system breakdown
docker compose run --rm vuls report -config=/vuls/config.toml -format-full-text > ./results/monthly-scans/$SCAN_DATE/full-report.txt
```

#### 4.2 Vulnerability Prioritization and Interpretation

**Critical Actions Required**:
1. **Critical/High vulnerabilities**: Immediate action required
2. **Medium vulnerabilities**: Plan remediation within 30 days
3. **Low vulnerabilities**: Include in next maintenance window  
4. **0 vulnerabilities**: Verify interpretation (see below)

**Understanding Zero Vulnerability Results**:

**✅ Legitimate Zero Vulnerabilities (Good)**:
- **Recent LTS systems**: Ubuntu 24.04, Debian 12 (well-patched)
- **Actively maintained systems**: Regular security updates applied
- **Container images**: Recent base images with security patches

**⚠️ False Zero Vulnerabilities (Concerning)**:
- **EOL systems**: Ubuntu 16.04/18.04, Debian 8/9 showing 0 CVEs
- **Scan errors**: "Skip OVAL" messages in logs
- **Database issues**: Missing OVAL data for target OS version

**Validation Steps for Zero Vulnerability Results**:
```bash
# Check if OVAL database covers your OS version
docker compose run --rm --entrypoint sqlite3 vuls /vuls/db/oval.sqlite3 "SELECT COUNT(*) FROM definitions WHERE title LIKE '%Ubuntu 18.04%';"

# Look for OVAL skip messages in scan logs
docker compose run --rm vuls scan -debug 2>&1 | grep -i "skip.*oval"

# Verify system is actually supported
docker compose run --rm vuls configtest -debug | grep -i "detected"
```

**Priority Matrix**:
- CVSS 9.0-10.0 (Critical) → Patch within 72 hours
- CVSS 7.0-8.9 (High) → Patch within 7 days
- CVSS 4.0-6.9 (Medium) → Patch within 30 days
- CVSS 0.1-3.9 (Low) → Next maintenance cycle
- **0 CVEs on EOL systems** → Urgent OS upgrade required

#### 4.3 Trend Analysis

```bash
# Compare with previous month
diff ./results/monthly-scans/$(date -d "last month" +%Y-%m)/executive-summary.txt \
     ./results/monthly-scans/$SCAN_DATE/executive-summary.txt

# Track vulnerability counts over time
echo "$(date +%Y-%m): $(grep -c 'CVE-' ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)" >> vulnerability-trends.log
```

### Phase 5: Remediation Tracking

#### 5.1 Create Remediation Plan

```bash
# Extract high-priority vulnerabilities
grep -E "(Critical|High)" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv > high-priority-vulns.csv

# Create remediation tickets/tasks
# (Integrate with your ticketing system)
```

#### 5.2 Track Remediation Progress

Create a tracking spreadsheet with:
- CVE ID
- Affected System
- Severity
- Discovery Date
- Assigned Owner
- Target Remediation Date
- Status
- Verification Date

### Phase 6: Compliance and Documentation

#### 6.1 Compliance Reporting

```bash
# Generate compliance report
cat > ./results/monthly-scans/$SCAN_DATE/compliance-report.md << EOF
# Monthly Vulnerability Assessment Report - $SCAN_DATE

## Executive Summary
- Systems Scanned: $(grep -c "\[servers\." config/config.toml)
- Total Vulnerabilities: $(grep -c "CVE-" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)
- Critical: $(grep -c "Critical" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)
- High: $(grep -c "High" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)
- Medium: $(grep -c "Medium" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)
- Low: $(grep -c "Low" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)

## Remediation Status
- Patched This Month: [To be filled]
- In Progress: [To be filled]
- Scheduled: [To be filled]

## Next Month Actions
- [List planned remediation activities]
EOF
```

#### 6.2 Archive Results

```bash
# Compress monthly results
tar -czf ./archive/vulnerability-scan-$SCAN_DATE.tar.gz ./results/monthly-scans/$SCAN_DATE/

# Clean up old detailed results (keep last 6 months)
find ./results/ -type d -name "20*" -mtime +180 -exec rm -rf {} \;
```

## Automation Scripts

### Monthly Scan Script

```bash
#!/bin/bash
# monthly-vuln-scan.sh

set -e

SCAN_DATE=$(date +%Y-%m)
LOG_FILE="./logs/monthly-scan-$SCAN_DATE.log"

echo "Starting monthly vulnerability scan for $SCAN_DATE" | tee -a $LOG_FILE

# Update databases
echo "Updating vulnerability databases..." | tee -a $LOG_FILE
docker compose --profile fetch up vuls-nvd vuls-ubuntu vuls-debian

# Validate configuration
echo "Validating configuration..." | tee -a $LOG_FILE
docker compose run --rm vuls configtest -config=/vuls/config.toml

# Run scan
echo "Executing vulnerability scan..." | tee -a $LOG_FILE
docker compose run --rm vuls scan -config=/vuls/config.toml

# Generate reports
echo "Generating reports..." | tee -a $LOG_FILE
mkdir -p ./results/monthly-scans/$SCAN_DATE
docker compose run --rm vuls report -config=/vuls/config.toml -format-csv > ./results/monthly-scans/$SCAN_DATE/vulnerabilities.csv
docker compose run --rm vuls report -config=/vuls/config.toml -format-short-text > ./results/monthly-scans/$SCAN_DATE/summary.txt

echo "Monthly scan completed successfully" | tee -a $LOG_FILE
```

### Database Update Script

```bash
#!/bin/bash
# update-vuln-databases.sh

echo "Updating Vuls vulnerability databases..."

# Update all databases
docker compose --profile fetch up vuls-nvd
docker compose --profile fetch up vuls-ubuntu
docker compose --profile fetch up vuls-debian
docker compose --profile fetch up vuls-redhat

# Log update completion
echo "$(date): Database update completed" >> ./logs/database-updates.log

# Check database sizes
du -sh ./db/* >> ./logs/database-sizes.log
```

## Container Management

### Entering the Vuls Container

For troubleshooting, manual testing, or detailed inspection:

```bash
# Enter container with shell access
docker compose run --rm --entrypoint /bin/sh vuls

# Alternative: Enter with bash if available
docker compose run --rm --entrypoint /bin/bash vuls
```

### Common Container Commands

Once inside the container, you can:

```bash
# Check Vuls version and help
vuls --version
vuls help

# Inspect configuration
cat /vuls/config.toml

# Check database files
ls -la /vuls/db/
du -sh /vuls/db/*

# Test connectivity
ping target-system
ssh -T admin@target-system

# AWS/GCP commands
aws sts get-caller-identity
aws ssm describe-instance-information
gcloud auth list
gcloud config list

# Manual scan commands
vuls configtest -config=/vuls/config.toml
vuls scan -config=/vuls/config.toml -debug
vuls report -config=/vuls/config.toml -format-short-text

# Check logs
tail -f /vuls/logs/vuls.log
cat /var/log/vuls/vuls.log

# Exit container
exit
```

### Interactive Debugging Session

```bash
# Start an interactive session for debugging
docker compose run --rm --entrypoint /bin/sh vuls

# Inside container - comprehensive system check:
echo "=== Vuls Environment Check ==="
echo "Vuls version: $(vuls --version)"
echo "Config file: $(ls -la /vuls/config.toml)"
echo "Databases: $(ls -la /vuls/db/)"
echo "SSH keys: $(ls -la /root/.ssh/)"
echo "AWS CLI: $(aws --version 2>/dev/null || echo 'Not available')"
echo "GCloud CLI: $(gcloud --version 2>/dev/null || echo 'Not available')"
echo "Session Manager: $(session-manager-plugin --version 2>/dev/null || echo 'Not available')"

# Test database connectivity
sqlite3 /vuls/db/cve.sqlite3 "SELECT COUNT(*) AS cve_count FROM cves;" 2>/dev/null || echo "CVE database not accessible"

# Test configuration
vuls configtest -config=/vuls/config.toml

exit
```

### Security
- Rotate SSH keys regularly
- Use dedicated service accounts for scanning
- Implement least-privilege access
- Encrypt scan results at rest
- Secure database files

### Performance
- Schedule scans during off-peak hours
- Use fast scan mode for regular scans
- Implement parallel scanning for large environments
- Monitor resource usage

### Accuracy
- Keep vulnerability databases current
- Validate scan results manually
- Maintain accurate asset inventory
- Regular false positive analysis

### Integration
- Integrate with ticketing systems
- Automate report distribution
- Connect to SIEM/logging systems
- Link with patch management tools

## Troubleshooting Common Issues

### OS Version Compatibility Issues

**Problem**: Systems showing 0 vulnerabilities unexpectedly

**Diagnosis**:
```bash
# Check which OS versions have OVAL data
docker compose run --rm --entrypoint sqlite3 vuls /vuls/db/oval.sqlite3 "SELECT DISTINCT substr(title, instr(title, 'Ubuntu'), 20) FROM definitions WHERE title LIKE '%Ubuntu%';"

# Check for OVAL skip messages
docker compose run --rm vuls report -debug 2>&1 | grep -i "skip.*oval"

# Verify OS detection
docker compose run --rm vuls configtest -debug | grep -i "detected"
```

**Solutions**:
- **EOL systems**: Upgrade to supported OS versions or accept limited scanning
- **Missing OVAL data**: Verify OS version is in supported list
- **Recent systems**: May legitimately have 0 vulnerabilities

### SSH Connection Failures
```bash
# Test SSH connectivity
docker compose run --rm --entrypoint ssh vuls -vvv target-system

# Check SSH key permissions
ls -la ./.ssh/

# Enter container for manual debugging
docker compose run --rm --entrypoint /bin/sh vuls
# Inside container:
# ls -la /root/.ssh/
# cat /root/.ssh/config
# ssh -T git@github.com  # test key loading
# ssh -vvv admin@target-system
# exit
```

### AWS Session Manager Issues
```bash
# Verify AWS credentials
docker compose run --rm --entrypoint aws vuls sts get-caller-identity

# Test Session Manager
docker compose run --rm --entrypoint aws vuls ssm describe-instance-information

# Enter container for AWS debugging
docker compose run --rm --entrypoint /bin/sh vuls
# Inside container:
# aws configure list
# aws sts get-caller-identity
# aws ssm describe-instance-information
# which session-manager-plugin
# session-manager-plugin --version
# exit
```

### Database Issues
```bash
# Verify database integrity
sqlite3 ./db/cve.sqlite3 "PRAGMA integrity_check;"

# Check database sizes
du -sh ./db/*

# Enter container for database inspection
docker compose run --rm --entrypoint /bin/sh vuls
# Inside container:
# ls -la /vuls/db/
# sqlite3 /vuls/db/cve.sqlite3 "SELECT COUNT(*) FROM cves;"
# sqlite3 /vuls/db/oval.sqlite3 "SELECT name FROM sqlite_master WHERE type='table';"
# exit
```

## Compliance Considerations

### Standards Alignment
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **ISO 27001**: Risk assessment and treatment
- **PCI DSS**: Regular vulnerability assessments
- **SOC 2**: System monitoring and vulnerability management

### Documentation Requirements
- Scan frequency and coverage
- Vulnerability assessment procedures  
- Remediation timelines and tracking
- Risk acceptance documentation
- Evidence of continuous monitoring
- **OS version limitations and coverage gaps**

### Compliance Reporting Considerations

**Important Compliance Notes**:
- **EOL System Risk**: Document that EOL systems (Ubuntu 16.04/18.04, Debian 8/9) cannot be properly scanned
- **Coverage Gaps**: Explicitly note OS versions not covered by vulnerability databases
- **False Negatives**: Acknowledge potential for missed vulnerabilities on unsupported systems
- **Compensating Controls**: Implement additional security measures for EOL systems

**Sample Compliance Language**:
```
"Vulnerability scanning covers all systems running supported operating system versions 
(Ubuntu 20.04+, Debian 10+, RHEL 7+). End-of-life systems require additional manual 
security review and compensating controls due to limited vulnerability database coverage."
```

## Conclusion

Regular monthly vulnerability scanning with Vuls provides continuous visibility into your security posture. This systematic approach ensures vulnerabilities are identified, prioritized, and remediated in a timely manner, supporting your overall cybersecurity strategy and compliance requirements.

**Key Takeaways**:
- **OS Version Awareness**: Ensure target systems run supported OS versions for accurate scanning
- **Zero Vulnerability Validation**: Always verify whether 0 CVEs indicates good security or scanning limitations
- **EOL System Management**: Plan upgrades for end-of-life systems that cannot be properly scanned
- **Database Coverage**: Regularly verify vulnerability database coverage matches your environment

**Critical Success Factors**:
1. **Maintain supported OS versions** across your infrastructure
2. **Validate scan results** don't just accept zero vulnerability counts
3. **Document coverage limitations** for compliance and risk management
4. **Plan EOL system transitions** before vulnerability database support ends

Remember to adapt this process to your organization's specific needs, risk tolerance, compliance requirements, and the reality of OS version limitations in vulnerability scanning tools.

