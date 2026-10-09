FROM python:3.14-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn pika pydantic-settings "psycopg[binary]" "celery[redis]" redis
COPY services /app/services
ENV PYTHONPATH=/app/services/ingestion-api:/app/services
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
