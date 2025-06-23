# Simple working approach - no RPM extraction
FROM vuls/vuls:latest

# Switch to root
USER root

# Install basic dependencies + glibc compatibility for Session Manager
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    bash \
    ca-certificates \
    jq \
    git \
    vim \
    curl \
    wget \
    binutils \
    gcompat \
    libc6-compat \
    sqlite

# Install AWS CLI via pip
RUN pip3 install --break-system-packages awscli

# Install Session Manager Plugin from DEB package (working method)
RUN cd /tmp && \
    curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o session-manager-plugin.deb && \
    ar x session-manager-plugin.deb && \
    tar -xf data.tar.gz && \
    cp usr/local/sessionmanagerplugin/bin/session-manager-plugin /usr/local/bin/ && \
    chmod +x /usr/local/bin/session-manager-plugin && \
    rm -rf /tmp/*

# Install Google Cloud SDK
RUN cd /tmp && \
    curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-458.0.1-linux-x86_64.tar.gz && \
    tar -xf google-cloud-cli-458.0.1-linux-x86_64.tar.gz -C /opt/ && \
    /opt/google-cloud-sdk/install.sh --quiet --path-update=false && \
    ln -sf /opt/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud && \
    ln -sf /opt/google-cloud-sdk/bin/gsutil /usr/local/bin/gsutil && \
    rm -f google-cloud-cli-458.0.1-linux-x86_64.tar.gz

# Install cloudflared
RUN cd /tmp && \
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && \
    chmod +x cloudflared && \
    mv cloudflared /usr/local/bin/ && \
    rm -rf /tmp/*

# Test installations
RUN echo "=== Testing AWS CLI ===" && aws --version
RUN echo "=== Testing Session Manager Plugin ===" && session-manager-plugin --version
RUN echo "=== Testing GCloud CLI ===" && gcloud version
RUN echo "=== Testing cloudflared ===" && cloudflared --version

# Create directories for cloud credentials
RUN mkdir -p /root/.aws /root/.config/gcloud

# Update PATH
ENV PATH="/usr/local/bin:/opt/google-cloud-sdk/bin:${PATH}"

# Set working directory
WORKDIR /vuls

# Set default entrypoint back to vuls
ENTRYPOINT ["vuls"]
