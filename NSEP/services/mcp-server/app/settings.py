from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    nsep_api_base_url: str = "http://localhost:8000"
    request_timeout: float = 10.0

    mcp_transport: str = "stdio"  # stdio | sse | streamable-http
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8100

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
