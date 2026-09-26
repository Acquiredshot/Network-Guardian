FROM python:3.14-slim

LABEL maintainer="Acquiredshot"
LABEL description="Network Guardian — Autonomous network auditing, IDS/IPS, and remote access"

# Install system dependencies for network scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml requirements.txt ./
COPY network_guardian/ ./network_guardian/

# Install the package with all dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Copy the rest of the project
COPY . .

EXPOSE 8080

# Health check via dashboard health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')"

# Default environment (secrets passed at runtime, never baked in)
ENV HOST="0.0.0.0"
ENV PORT="8080"
ENV NG_MODE="standalone"

# Use the entrypoint script for flexible startup modes
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["cli"]
