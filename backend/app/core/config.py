from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import EmailStr, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Security Gate Bypass Manager"
    environment: str = "production"
    database_url: str = ""
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "bypass"
    postgres_user: str = "bypass"
    postgres_password: SecretStr | None = None
    postgres_password_file: str | None = None
    jwt_secret: SecretStr | None = None
    jwt_secret_file: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    admin_session_cookie_name: str = "sgbm_admin_session"
    session_cookie_secure: bool = False
    api_key_pepper: SecretStr | None = None
    api_key_pepper_file: str | None = None
    cors_origins: str = "http://localhost:3000"
    expiring_soon_days: int = 7
    evaluate_rate_limit_per_minute: int = 120
    initial_admin_username: str | None = Field(default=None, min_length=2, max_length=64)
    initial_admin_password: SecretStr | None = None
    initial_admin_email: EmailStr | None = None
    initial_admin_display_name: str = "Initial Administrator"

    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore", env_ignore_empty=True, hide_input_in_errors=True
    )

    @staticmethod
    def read_secret_file(path: str | None, label: str) -> SecretStr | None:
        if not path:
            return None
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"could not read {label} file") from exc
        if not value:
            raise ValueError(f"{label} file is empty")
        return SecretStr(value)

    @model_validator(mode="after")
    def resolve_runtime_secrets(self):
        if self.jwt_secret is None:
            self.jwt_secret = self.read_secret_file(self.jwt_secret_file, "JWT secret")
        if self.api_key_pepper is None:
            self.api_key_pepper = self.read_secret_file(self.api_key_pepper_file, "API key pepper")
        if self.jwt_secret is None or self.api_key_pepper is None:
            raise ValueError("JWT secret and API key pepper must be provided directly or through secret files")
        self.reject_insecure_secret(self.jwt_secret)
        self.reject_insecure_secret(self.api_key_pepper)
        if not self.database_url:
            password = self.postgres_password or self.read_secret_file(
                self.postgres_password_file, "PostgreSQL password"
            )
            if password is None:
                raise ValueError("database URL or PostgreSQL password must be provided")
            self.database_url = (
                f"postgresql+psycopg://{quote_plus(self.postgres_user)}:"
                f"{quote_plus(password.get_secret_value())}@{self.postgres_host}:"
                f"{self.postgres_port}/{quote_plus(self.postgres_db)}"
            )
        return self

    @classmethod
    def reject_insecure_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        weak = {"change-me", "changeme", "secret", "development-only-secret"}
        if len(secret) < 32:
            raise ValueError("secret must contain at least 32 characters")
        if secret.lower() in weak:
            raise ValueError("insecure default secret is not allowed")
        return value

    @field_validator("jwt_secret", "api_key_pepper")
    @classmethod
    def reject_insecure_secrets(cls, value: SecretStr | None) -> SecretStr | None:
        return cls.reject_insecure_secret(value) if value is not None else None

    @field_validator("initial_admin_password")
    @classmethod
    def validate_initial_admin_password(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        length = len(value.get_secret_value())
        if length < 8 or length > 256:
            raise ValueError("initial administrator password must contain between 8 and 256 characters")
        return value

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
