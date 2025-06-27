# Installation

This guide will walk you through installing and setting up the Vuls Vulnerability Management System.

## Prerequisites

Before installing Vuls, ensure your system meets these requirements:

### System Requirements

- **Operating System**: Linux, macOS, or Windows with WSL2
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 10GB minimum for databases and results
- **Network**: Internet connectivity for database updates

### Required Software

- **Docker**: Version 20.10 or later
- **Docker Compose**: Version 2.0 or later
- **Git**: For cloning the repository

## Installation Steps

### 1. Install Docker and Docker Compose

#### Ubuntu/Debian

```bash
# Update package index
sudo apt update

# Install Docker
sudo apt install -y docker.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker
```

#### CentOS/RHEL

```bash
# Install Docker
sudo yum install -y docker docker-compose-plugin

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
```

#### macOS

```bash
# Install Docker Desktop from https://docker.com/products/docker-desktop
# Or use Homebrew:
brew install --cask docker
```

### 2. Clone the Vuls Repository

```bash
# Clone the repository
git clone https://github.com/your-org/vuls-vulnerability-scanner.git
cd vuls-vulnerability-scanner

# Verify the structure
ls -la
```

### 3. Initial Setup

```bash
# Create necessary directories
mkdir -p {db,logs,results,config/backups}

# Set proper permissions
chmod 755 db logs results config
```

### 4. Configure Environment

```bash
# Copy example configuration
cp config/config.toml.example config/config.toml

# Edit configuration for your environment
nano config/config.toml
```

### 5. Download Vulnerability Databases

```bash
# Update all vulnerability databases (this may take 30-60 minutes)
docker compose --profile fetch up vuls-nvd
docker compose --profile fetch up vuls-ubuntu
docker compose --profile fetch up vuls-debian
docker compose --profile fetch up vuls-redhat

# Verify database downloads
ls -lh db/
```

Expected output:

```
-rw-r--r-- 1 user user 1.2G cve.sqlite3
-rw-r--r-- 1 user user 350M oval.sqlite3
-rw-r--r-- 1 user user  45M gost.sqlite3
```

### 6. Test Installation

```bash
# Test configuration
docker compose run --rm vuls configtest

# Test database connectivity
docker compose run --rm vuls version
```

## Web Interface Setup (Optional)

To enable the web management interface:

```bash
# Start the web application stack
docker compose --profile web up -d

# Access the web interface
open http://localhost:8000
```

### Create Initial Admin User

1. Navigate to http://localhost:8000
2. Click "Create Admin"
3. Use default credentials: `admin` / `admin123`
4. Change the password after first login

## Verification

### Test Basic Functionality

```bash
# Test SSH connectivity (replace with your target)
docker compose run --rm --entrypoint ssh vuls user@target-system

# Run a test scan (if you have a configured target)
docker compose run --rm vuls scan

# Generate a test report
docker compose run --rm vuls report -format-list
```

### Check Service Status

```bash
# View running containers
docker compose ps

# Check logs
docker compose logs vuls
```

## Troubleshooting

### Common Issues

#### Docker Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo (not recommended for production)
sudo docker compose up
```

#### Database Download Failures

```bash
# Check internet connectivity
ping google.com

# Retry specific database
docker compose --profile fetch up vuls-nvd --force-recreate

# Check disk space
df -h
```

#### Port Conflicts

```bash
# Check what's using port 8000
sudo lsof -i :8000

# Change port in docker-compose.yml
# ports:
#   - "8001:8000"  # Change external port
```

#### SSH Connection Issues

```bash
# Test SSH manually
ssh -vvv user@target-system

# Check SSH key permissions
ls -la ~/.ssh/
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/*.pub
```

### Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](../reference/troubleshooting.md)
2. Review Docker and system logs
3. Verify all prerequisites are met
4. Consult the community forums

## Next Steps

Once installation is complete:

1. **[Configure your system](configuration.md)** - Set up target hosts and scanning parameters
2. **[Run your first scan](first-scan.md)** - Execute a vulnerability assessment
3. **[Explore the web interface](../user-guide/web-interface.md)** - Use the management dashboard

## Security Considerations

### File Permissions

```bash
# Secure configuration files
chmod 600 config/config.toml
chmod 600 .ssh/id_*

# Secure database files
chmod 600 db/*.sqlite3
```

### Network Security

- Ensure Docker daemon is properly secured
- Use SSH keys instead of passwords
- Consider VPN for remote scanning
- Implement proper firewall rules

### Data Protection

- Encrypt sensitive configuration data
- Regularly backup scan results
- Implement log rotation
- Monitor system access

---

**Installation complete!** Continue to [Configuration](configuration.md) to set up your scanning targets.
