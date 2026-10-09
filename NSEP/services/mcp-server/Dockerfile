FROM python:3.14-slim

WORKDIR /app

COPY pyproject.toml .

RUN pip install --no-cache-dir "mcp>=2.2,<3" httpx pydantic-settings

COPY services /app/services

ENV PYTHONPATH=/app/services/mcp-server:/app/services

CMD ["python", "-m", "app.server"]
