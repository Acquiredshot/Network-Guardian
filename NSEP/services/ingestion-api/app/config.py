from pydantic import HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@localhost:5432/security_events"
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672//"
    redis_url: str = "redis://localhost:6379/0"

    # Config-only flags for the read-only integrations status endpoint.
    # Never holds secrets (API tokens stay in security-workers only).
    zammad_enabled: bool = False
    zammad_url: str = "http://localhost:8080"
    network_guardian_enabled: bool = False
    network_guardian_intake_url: str = "http://localhost:8080/api/event-fabric/intake"
    network_guardian_dashboard_url: HttpUrl = HttpUrl("http://localhost:8080/")
    mcp_server_url: str = "http://localhost:8100/mcp"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
