FROM python:3.10-slim AS runtime

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure instance dir exists and is writable (for SQLite DB and secret key)
RUN mkdir -p /app/instance && chmod 775 /app/instance

# Copy entrypoint script and set permissions
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create non-root user with dynamic UID
RUN useradd -m sylla && \
    chown -R sylla:sylla /app && \
    chown sylla:sylla /entrypoint.sh

# Expose Gunicorn port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:8000/ || exit 1

# Switch to non-root user
USER sylla

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]