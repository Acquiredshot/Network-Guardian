# Infrastructure

The local stack is defined in `docker-compose.yml`. Production deployment targets Azure Container Apps for the ingestion API and Celery worker, PostgreSQL Flexible Server for persistence, Azure Cache for Redis, and Azure OpenAI as an optional enhancement. Infrastructure provisioning is deferred to the deployment workflow.
