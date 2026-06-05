import pytest

from network_guardian.config import Config
from network_guardian.saas import (
    TenantContext,
    TenancyError,
    TokenError,
    create_access_token,
    generate_api_key,
    require_org_access,
    require_role,
    verify_access_token,
    verify_api_key,
)


class TestSaaSConfig:
    def test_defaults(self):
        cfg = Config()
        assert cfg.saas.mode == "standalone"
        assert cfg.saas.database_url == ""
        assert cfg.saas.jwt_issuer == "network-guardian"
        assert cfg.saas.jwt_audience == "network-guardian-api"

    def test_load_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            """
saas:
  mode: saas
  database_url: postgresql://localhost/ng
  jwt_secret: test-secret
  jwt_issuer: issuer-x
  jwt_audience: audience-x
  access_token_ttl: 7200
  stripe_secret_key: sk_test_123
  stripe_webhook_secret: whsec_123
""".strip()
        )

        cfg = Config.load(str(cfg_file))
        assert cfg.saas.mode == "saas"
        assert cfg.saas.database_url == "postgresql://localhost/ng"
        assert cfg.saas.jwt_secret == "test-secret"
        assert cfg.saas.jwt_issuer == "issuer-x"
        assert cfg.saas.jwt_audience == "audience-x"
        assert cfg.saas.access_token_ttl == 7200
        assert cfg.saas.stripe_secret_key == "sk_test_123"
        assert cfg.saas.stripe_webhook_secret == "whsec_123"

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("NG_MODE", "saas")
        monkeypatch.setenv("DATABASE_URL", "sqlite:///tmp/ng.db")
        monkeypatch.setenv("JWT_SECRET", "env-secret")
        monkeypatch.setenv("JWT_ISSUER", "env-issuer")
        monkeypatch.setenv("JWT_AUDIENCE", "env-audience")
        monkeypatch.setenv("ACCESS_TOKEN_TTL", "1800")
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live")
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_live")

        cfg = Config.load(None)
        assert cfg.saas.mode == "saas"
        assert cfg.saas.database_url == "sqlite:///tmp/ng.db"
        assert cfg.saas.jwt_secret == "env-secret"
        assert cfg.saas.jwt_issuer == "env-issuer"
        assert cfg.saas.jwt_audience == "env-audience"
        assert cfg.saas.access_token_ttl == 1800
        assert cfg.saas.stripe_secret_key == "sk_live"
        assert cfg.saas.stripe_webhook_secret == "whsec_live"


class TestSaaSAuth:
    def test_access_token_round_trip(self):
        token = create_access_token(
            subject="user-123",
            org_id="org-456",
            role="admin",
            secret="super-secret",
            issuer="network-guardian",
            audience="network-guardian-api",
            ttl_seconds=300,
            now=100,
        )

        claims = verify_access_token(
            token,
            secret="super-secret",
            issuer="network-guardian",
            audience="network-guardian-api",
            now=200,
        )
        assert claims.sub == "user-123"
        assert claims.org_id == "org-456"
        assert claims.role == "admin"

    def test_rejects_invalid_audience(self):
        token = create_access_token(
            subject="user-123",
            org_id="org-456",
            role="viewer",
            secret="super-secret",
            issuer="network-guardian",
            audience="network-guardian-api",
            ttl_seconds=300,
            now=100,
        )

        with pytest.raises(TokenError, match="audience"):
            verify_access_token(
                token,
                secret="super-secret",
                issuer="network-guardian",
                audience="different-audience",
                now=150,
            )

    def test_generate_and_verify_api_key(self):
        api_key, key_hash = generate_api_key()
        assert api_key.startswith("ng_")
        assert verify_api_key(api_key, key_hash)
        assert not verify_api_key("ng_invalid.bad", key_hash)


class TestTenancy:
    def test_same_org_access_allowed(self):
        context = TenantContext(user_id="user-1", organization_id="org-1", role="admin")
        require_org_access(context, "org-1")

    def test_cross_org_access_denied(self):
        context = TenantContext(user_id="user-1", organization_id="org-1", role="admin")
        with pytest.raises(TenancyError, match="Cross-tenant"):
            require_org_access(context, "org-2")

    def test_role_enforcement(self):
        context = TenantContext(user_id="user-1", organization_id="org-1", role="analyst")
        require_role(context, "viewer")
        require_role(context, "analyst")
        with pytest.raises(TenancyError, match="Insufficient"):
            require_role(context, "admin")
