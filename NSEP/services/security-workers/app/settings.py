from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:postgres@localhost:5432/security_events"
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672//"
    redis_url: str = "redis://localhost:6379/0"

    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None

    zammad_url: str = "http://localhost:8080"
    zammad_api_token: str | None = None
    zammad_enabled: bool = True
    zammad_group_id: int = 1
    zammad_customer_id: int = 2

    network_guardian_enabled: bool = False
    network_guardian_intake_url: str = "http://localhost:8080/api/event-fabric/intake"
    network_guardian_asset_id: str = "nsep-pipeline"
    network_guardian_tenant_id: str = "nsep-tenant"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
