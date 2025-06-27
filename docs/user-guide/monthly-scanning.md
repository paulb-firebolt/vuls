# Monthly Vulnerability Scanning Workflow

This guide outlines the process for conducting regular monthly vulnerability scans using Vuls in a containerized environment. The process ensures consistent, automated vulnerability assessments across your infrastructure.

## Prerequisites

- Docker and Docker Compose installed
- Vuls container with AWS CLI and GCP CLI
- SSH access to target systems (direct or via AWS Session Manager)
- Vulnerability databases configured

## Phase 1: Database Updates (1st of each month)

### 1.1 Update Vulnerability Databases

**Frequency**: Monthly (or weekly for high-security environments)

!!! warning "OS Version Limitations" - **Ubuntu OVAL**: Only covers currently supported LTS versions (20.04, 22.04, 24.04) - **Debian OVAL**: Only covers currently supported versions (10, 11, 12) - **End-of-Life (EOL) systems**: Cannot be properly scanned due to missing OVAL data - **Recently released versions**: May show 0 vulnerabilities if well-patched

**Supported OS Versions for Vulnerability Scanning**:

| OS                     | Supported Versions                                      | Status                     |
| ---------------------- | ------------------------------------------------------- | -------------------------- |
| **Ubuntu**             | 20.04 LTS (Focal), 22.04 LTS (Jammy), 24.04 LTS (Noble) | ✅ Fully Supported         |
| **Debian**             | 10 (Buster), 11 (Bullseye), 12 (Bookworm)               | ✅ Fully Supported         |
| **RHEL/CentOS**        | 7, 8, 9                                                 | ✅ Fully Supported         |
| **Amazon Linux**       | 1, 2, 2023                                              | ✅ Fully Supported         |
| **Ubuntu 16.04/18.04** | EOL versions                                            | ❌ Limited or no OVAL data |
| **Debian 8/9**         | EOL versions                                            | ❌ Limited or no OVAL data |

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

### 1.2 Validate Database Updates

```bash
# Check database timestamps
stat ./db/*.sqlite3

# Test database connectivity
docker-compose run --rm vuls configtest
```

## Phase 2: System Discovery and Inventory

### 2.1 Update Target Systems Inventory

**Review and update your `config/config.toml`**:

```toml
[cveDict]
type = "sqlite3"
SQLite3Path = "/vuls/db/cve.sqlite3"

[ovalDict]
type = "sqlite3"
SQLite3Path = "/vuls/db/oval.sqlite3"

[gost]
type = "sqlite3"
SQLite3Path = "/vuls/db/gost.sqlite3"

[exploit]
type = "sqlite3"
SQLite3Path = "/vuls/db/go-exploitdb.sqlite3"

[metasploit]
type = "sqlite3"
SQLite3Path = "/vuls/db/go-msfdb.sqlite3"

[kevuln]
type = "sqlite3"
SQLite3Path = "/vuls/db/go-kev.sqlite3"

[cti]
type = "sqlite3"
SQLite3Path = "/vuls/db/go-cti.sqlite3"

[servers]

[servers.icinga2]
host = "icinga2"
port = "22"
user = "admin"
keypath = "/root/.ssh/id_aws"

[servers.anisette-v3]
host = "anisette-v3"
port = "22"
user = "ubuntu"
keypath = "/root/.ssh/id_aws"

[servers.retailaware-u16tbpe]
host = "retailaware-u16tbpe"
```

### 2.2 Validate System Access

```bash
# Test configuration for all systems
docker compose run --rm vuls configtest

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

### 2.3 SSH Agent Configuration for Multiple Keys

When scanning multiple systems with different SSH keys, use SSH agent for seamless key management:

**On Host System (before scanning)**:

```bash
# Start SSH agent
eval $(ssh-agent)

# Add specific keys for different systems
ssh-add ~/.ssh/id_aws          # AWS EC2 instances
ssh-add ~/.ssh/id_gcp          # GCP instances
ssh-add ~/.ssh/id_ed25519      # On-premise systems
ssh-add ~/.ssh/id_rsa          # Legacy systems

# Verify keys are loaded
ssh-add -l

# Test connectivity with agent
ssh your-target-system         # Should work without specifying key
```

**Configure SSH agent forwarding in your SSH config**:

```bash
cat >> ~/.ssh/config << 'EOF'
host *
  IdentityFile ~/.ssh/id_aws
  IdentitiesOnly yes

host icinga2
  User admin
  Hostname i-0a1347a614cf7cea5
  ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"
  ControlPersist 72h

host anisette-v3
  User ubuntu
  HostName i-022d1ec1b8c62660b
  ProxyCommand sh -c "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"

Host retailaware-u16tbpe
  User paulb
  IdentityFile ~/.ssh/id_gcp
  IdentitiesOnly yes
  ProxyCommand gcloud compute ssh %h --tunnel-through-iap --zone=us-east1-b --project=thingsboard-210800 -- -W %h:%p
EOF
```

## Phase 3: Vulnerability Scanning

### 3.1 Pre-Scan Checklist

- [ ] Vulnerability databases updated
- [ ] All target systems accessible
- [ ] SSH keys properly mounted
- [ ] AWS/GCP credentials configured
- [ ] Previous scan results backed up

### 3.2 Execute Monthly Scan

```bash
# Create monthly results directory
SCAN_DATE=$(date +%Y-%m)
mkdir -p ./results/monthly-scans/$SCAN_DATE

# Run comprehensive scan
docker compose run --rm vuls scan

# Generate detailed reports
docker compose run --rm vuls report -format-json
docker compose run --rm vuls report -format-full-text
docker compose run --rm vuls report -format-csv
```

### 3.3 Scan Verification

```bash
# Check scan completed successfully
ls -la ./results/$(date +%Y-%m-%d)*

# Verify all systems were scanned
docker-compose run --rm vuls report -format-one-line-text
```

## Phase 4: Results Analysis and Reporting

### 4.1 Generate Management Reports

```bash
# Create executive summary
docker compose run --rm vuls report -format-list > ./results/monthly-scans/$SCAN_DATE/executive-summary.txt

# Generate detailed CSV for tracking
docker compose run --rm vuls report -format-csv > ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv

# Create system-by-system breakdown
docker compose run --rm vuls report -format-full-text > ./results/monthly-scans/$SCAN_DATE/full-report.txt
```

### 4.2 Vulnerability Prioritization and Interpretation

**Critical Actions Required**:

1. **Critical/High vulnerabilities**: Immediate action required
2. **Medium vulnerabilities**: Plan remediation within 30 days
3. **Low vulnerabilities**: Include in next maintenance window
4. **0 vulnerabilities**: Verify interpretation (see below)

!!! info "Understanding Zero Vulnerability Results"

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

### 4.3 Trend Analysis

```bash
# Compare with previous month
diff ./results/monthly-scans/$(date -d "last month" +%Y-%m)/executive-summary.txt \
     ./results/monthly-scans/$SCAN_DATE/executive-summary.txt

# Track vulnerability counts over time
echo "$(date +%Y-%m): $(grep -c 'CVE-' ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv)" >> vulnerability-trends.log
```

## Phase 5: Remediation Tracking

### 5.1 Create Remediation Plan

```bash
# Extract high-priority vulnerabilities
grep -E "(Critical|High)" ./results/monthly-scans/$SCAN_DATE/detailed-vulnerabilities.csv > high-priority-vulns.csv

# Create remediation tickets/tasks
# (Integrate with your ticketing system)
```

### 5.2 Track Remediation Progress

Create a tracking spreadsheet with:

- CVE ID
- Affected System
- Severity
- Discovery Date
- Assigned Owner
- Target Remediation Date
- Status
- Verification Date

## Phase 6: Compliance and Documentation

### 6.1 Compliance Reporting

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

### 6.2 Archive Results

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
docker compose run --rm vuls configtest

# Run scan
echo "Executing vulnerability scan..." | tee -a $LOG_FILE
docker compose run --rm vuls scan

# Generate reports
echo "Generating reports..." | tee -a $LOG_FILE
mkdir -p ./results/monthly-scans/$SCAN_DATE
docker compose run --rm vuls report -format-csv > ./results/monthly-scans/$SCAN_DATE/vulnerabilities.csv
docker compose run --rm vuls report -format-list > ./results/monthly-scans/$SCAN_DATE/summary.txt

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

## Troubleshooting Common Issues

### Why OVAL Scanning May Be Skipped

If you see "Skip OVAL and Scan with gost alone" message, it indicates that OVAL scanning has been programmatically disabled for End-of-Life (EOL) operating systems.

**Root Cause**: Vuls automatically skips OVAL scanning for EOL systems, even when the OVAL database contains vulnerability definitions.

**Affected Systems**:

- ❌ **Ubuntu 16.04 (Xenial)**: EOL April 2021 - OVAL scanning skipped
- ❌ **Ubuntu 18.04 (Bionic)**: EOL May 2023 - OVAL scanning skipped
- ❌ **Debian 8 (Jessie)**: EOL June 2020 - OVAL scanning skipped
- ❌ **Debian 9 (Stretch)**: EOL July 2022 - OVAL scanning skipped

**What This Means**:

1. **Database is OK**: Your OVAL database may contain 30,000+ vulnerability definitions for the EOL system
2. **Configuration is OK**: Vuls correctly detects the target OS version
3. **Intentional Behavior**: Vuls skips OVAL scanning by design for EOL systems
4. **Limited Detection**: Only GOST, CPE, and other detection methods are used

**Solutions**:

1. **Recommended**: Upgrade EOL systems to supported versions (Ubuntu 20.04+, Debian 10+)
2. **Temporary**: Accept limited vulnerability detection and implement compensating controls
3. **Documentation**: Note the limitation in security assessments and compliance reports

### SSH Connection Failures

```bash
# Test SSH connectivity
docker compose run --rm --entrypoint ssh vuls -vvv target-system

# Check SSH key permissions
ls -la ./.ssh/

# Enter container for manual debugging
docker compose run --rm --entrypoint /bin/sh vuls
```

### AWS Session Manager Issues

```bash
# Verify AWS credentials
docker compose run --rm --entrypoint aws vuls sts get-caller-identity

# Test Session Manager
docker compose run --rm --entrypoint aws vuls ssm describe-instance-information
```

### Database Issues

```bash
# Verify database integrity
sqlite3 ./db/cve.sqlite3 "PRAGMA integrity_check;"

# Check database sizes
du -sh ./db/*
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

!!! warning "Compliance Reporting Considerations"
**Important Compliance Notes**: - **EOL System Risk**: Document that EOL systems (Ubuntu 16.04/18.04, Debian 8/9) cannot be properly scanned - **Coverage Gaps**: Explicitly note OS versions not covered by vulnerability databases - **False Negatives**: Acknowledge potential for missed vulnerabilities on unsupported systems - **Compensating Controls**: Implement additional security measures for EOL systems

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
