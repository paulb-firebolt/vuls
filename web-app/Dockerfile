FROM python:3.11-slim

# Build argument to determine if this is a dev build
ARG BUILD_TYPE=production

# Set working directory
WORKDIR /app

# Install system dependencies including curl for health check and supervisor for hot reload
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    supervisor \
    entr \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
# For development, we only copy pyproject.toml first for better caching
# since the source code will be mounted as a volume
COPY pyproject.toml ./
RUN if [ "$BUILD_TYPE" = "production" ]; then \
    echo "Production build - copying source code"; \
    else \
    echo "Development build - source code will be mounted"; \
    fi

# Copy source code only for production builds
COPY app/ ./app/
COPY static/ ./static/

# Copy supervisord configuration for development
COPY supervisord-celery.conf /etc/supervisor/supervisord-celery.conf

# Install dependencies
RUN uv sync

# Install development dependencies for hot reload if this is a dev build
RUN if [ "$BUILD_TYPE" = "development" ]; then \
    uv add watchdog; \
    fi

# Create non-root user with home directory and matching host UID/GID
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN groupadd -g $GROUP_ID appuser && useradd -l -u $USER_ID -g appuser -m appuser
RUN chown -R appuser:appuser /app
# Create and set permissions for UV cache directory
RUN mkdir -p /home/appuser/.cache && chown -R appuser:appuser /home/appuser/.cache
# Create volume directories with proper permissions
RUN mkdir -p /app/results /app/logs /app/config && chown -R appuser:appuser /app/results /app/logs /app/config

# For development builds, stay as root to run supervisord, otherwise switch to appuser
RUN if [ "$BUILD_TYPE" = "development" ]; then \
    echo "Development build - staying as root for supervisord"; \
    else \
    echo "Production build - switching to appuser"; \
    fi

# Switch to appuser for production builds only
RUN if [ "$BUILD_TYPE" != "development" ]; then \
    echo "Switching to appuser for production"; \
    else \
    echo "Staying as root for development"; \
    fi

USER root

# Expose port
EXPOSE 8000

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application with conditional reload based on build type
CMD if [ "$BUILD_TYPE" = "development" ]; then \
    exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload; \
    else \
    exec uv run uvicorn app.main:app --host 0.0.0.0 --port 8000; \
    fi
