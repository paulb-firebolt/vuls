FROM python:3.11-slim

# Build argument to determine if this is a dev build
ARG BUILD_TYPE=production

WORKDIR /app

# Set shell options for better error handling
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install Docker CLI and SSH client (needed for docker compose commands and SSH config validation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    openssh-client && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install development dependencies for hot reload if this is a dev build
RUN if [ "$BUILD_TYPE" = "development" ]; then \
    pip install --no-cache-dir watchdog; \
    fi

# Copy application code
# For development, source code will be mounted as a volume
COPY . .

# Create non-root user for security and add to docker group
RUN groupadd -g 956 docker || true && \
    useradd -l -m -u 1000 -G docker executor && \
    chown -R executor:executor /app

# Note: Running as root for SSH file management privileges
# This container is designed for privileged operations and runs in a controlled environment
USER root

EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run with conditional hot reload based on build type
CMD if [ "$BUILD_TYPE" = "development" ]; then \
    exec python -m watchdog.auto_restart --directory=/app --pattern=*.py --recursive main.py; \
    else \
    exec python main.py; \
    fi
