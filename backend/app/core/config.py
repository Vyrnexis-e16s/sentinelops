"""Application settings, loaded from the environment."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration.

    All values match the names used by `.env.example` at the repo root.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core ---
    app_name: str = Field("SentinelOps", alias="APP_NAME")
    app_env: Literal["development", "staging", "production", "test"] = Field(
        "development", alias="APP_ENV"
    )
    secret_key: str = Field(..., alias="SECRET_KEY")
    log_level: str = Field("INFO", alias="LOG_LEVEL")

    # --- Database ---
    postgres_user: str = Field("sentinel", alias="POSTGRES_USER")
    postgres_password: str = Field("devpassword", alias="POSTGRES_PASSWORD")
    postgres_db: str = Field("sentinelops", alias="POSTGRES_DB")
    postgres_host: str = Field("db", alias="POSTGRES_HOST")
    postgres_port: int = Field(5432, alias="POSTGRES_PORT")
    database_url: str = Field(
        "postgresql+asyncpg://sentinel:devpassword@db:5432/sentinelops",
        alias="DATABASE_URL",
    )

    # --- Redis / Celery ---
    redis_url: str = Field("redis://redis:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field("redis://redis:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field("redis://redis:6379/2", alias="CELERY_RESULT_BACKEND")

    # --- Auth ---
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(60, alias="JWT_EXPIRE_MINUTES")
    webauthn_rp_id: str = Field("localhost", alias="WEBAUTHN_RP_ID")
    webauthn_rp_name: str = Field("SentinelOps", alias="WEBAUTHN_RP_NAME")
    webauthn_origin: str = Field("http://localhost:3000", alias="WEBAUTHN_ORIGIN")

    # --- Vault ---
    vault_master_key: str = Field(..., alias="VAULT_MASTER_KEY")
    vault_storage_path: str = Field("/var/lib/sentinelops/vault", alias="VAULT_STORAGE_PATH")

    # --- Recon ---
    recon_max_concurrency: int = Field(50, alias="RECON_MAX_CONCURRENCY")
    recon_timeout_seconds: int = Field(5, alias="RECON_TIMEOUT_SECONDS")
    # Comma/space-separated. Empty = any target (dev). Example: "scanme.nmap.org,10.0.0.0/8,192.168.1.0/24"
    recon_target_allowlist: str = Field("", alias="RECON_TARGET_ALLOWLIST")
    nvd_api_base: str = Field(
        "https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_API_BASE"
    )

    # --- IDS ---
    ids_model_path: str = Field("/app/ml/artifacts/ids_rf.joblib", alias="IDS_MODEL_PATH")

    # --- Ops / optional integrations reserved for roadmap features ---
    expose_prometheus: bool = Field(True, alias="EXPOSE_PROMETHEUS")
    kafka_bootstrap: str = Field("", alias="KAFKA_BOOTSTRAP")
    oidc_issuer: str = Field("", alias="OIDC_ISSUER")
    s3_vault_endpoint: str = Field("", alias="S3_VAULT_ENDPOINT")
    pqc_kyber_hybrid: bool = Field(False, alias="PQC_KYBER_HYBRID")
    hsm_pkcs11_lib: str = Field("", alias="HSM_PKCS11_LIB")
    neograph_uri: str = Field("", alias="NEO4J_URI")

    # --- Optional LLM (VAPT triage / OpenAI-compatible) ---
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    sentinelops_llm_model: str = Field("gpt-4o-mini", alias="SENTINELOPS_LLM_MODEL")
    sentinelops_llm_base_url: str = Field("https://api.openai.com/v1", alias="SENTINELOPS_LLM_BASE_URL")

    # --- CORS ---
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"]
    )

    @field_validator("secret_key")
    @classmethod
    def _secret_key_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("vault_master_key")
    @classmethod
    def _vault_master_key_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("VAULT_MASTER_KEY must be at least 32 characters")
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_test(self) -> bool:
        return self.app_env == "test"


@lru_cache
def get_settings() -> Settings:
    """Cached accessor so tests can override via ``get_settings.cache_clear()``."""
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
