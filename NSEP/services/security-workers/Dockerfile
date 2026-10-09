FROM python:3.14-slim

WORKDIR /app

COPY pyproject.toml .

RUN pip install --no-cache-dir "celery[redis]" pydantic-settings "psycopg[binary]" "requests>=2.32,<3"

COPY services /app/services

ENV PYTHONPATH=/app/services/security-workers:/app/services

CMD ["celery", "-A", "app.celery_app.celery", "worker", "--loglevel=INFO"]
