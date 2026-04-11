FROM python:3.13-slim

LABEL maintainer="Acquiredshot"
LABEL description="Network Guardian — Autonomous network auditing, IDS/IPS, and remote access"

# Install system dependencies for network scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml ./

# Install the package dependencies
RUN pip install --no-cache-dir pyyaml>=6.0 pytest>=7.0 pytest-asyncio>=0.23

# Copy the full project
COPY network_guardian/ ./network_guardian/
COPY tests/ ./tests/
COPY whatsapp_server.py ./
COPY config.example.yaml ./
COPY README.md ./

# Install the package
RUN pip install --no-cache-dir -e .

# Verify installation and run tests
RUN python -m pytest tests/ -q --tb=short

# Expose ports: dashboard (8080) and WhatsApp webhook (8765)
EXPOSE 8080 8765

# Health check via WhatsApp server health endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/health')" || exit 1

# Default environment (secrets passed at runtime, never baked in)
ENV ALLOWED_NUMBERS=""
ENV HOST="0.0.0.0"
ENV PORT="8765"

# Use the WhatsApp server as default entrypoint for demos
# Can be overridden to run CLI: docker run -it network-guardian cli
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["server"]
