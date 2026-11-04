"""Validated configuration. Database credentials stay in the environment, never in code."""
from functools import cached_property
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url


class Settings(BaseSettings):
    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = Field(default=5432, ge=1, le=65535)
    DB_NAME: str = ""
    DB_USER: str = ""
    DB_PASSWORD: str = ""
    HISN_DATABASE_URL: str | None = None  # testing or deployment override
    hisn_cookie_secure: bool = True
    hisn_session_hours: int = Field(default=12, ge=1, le=168)
    hisn_allowed_origins: str = ""
    hisn_trusted_hosts: str = "localhost,127.0.0.1,testserver"
    hisn_e2guardian_log: str = "/var/log/e2guardian/access.log"
    hisn_squid_log: str = "/var/log/squid/access.log"
    hisn_log_timezone: str = "UTC"
    hisn_log_level: str = "INFO"
    hisn_managed_blocklist: str = ""  # explicitly configured, no default system path
    hisn_enforcement_enabled: bool = False
    hisn_auto_enforce: bool = False
    hisn_service_control_enabled: bool = False
    hisn_detection_window_minutes: int = Field(default=15, ge=1, le=1440)
    hisn_detection_threshold: int = Field(default=3, ge=2, le=100)
    jwt_secret_key: str = ""  # deprecated JWT implementation retained for migration only
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def validate_database(self):
        if not self.HISN_DATABASE_URL and not all([self.DB_NAME, self.DB_USER, self.DB_PASSWORD]):
            raise ValueError("Configure DB_NAME, DB_USER, DB_PASSWORD or HISN_DATABASE_URL")
        return self

    @property
    def database_url(self) -> URL:
        if self.HISN_DATABASE_URL:
            return make_url(self.HISN_DATABASE_URL)
        return URL.create("postgresql+psycopg", username=self.DB_USER, password=self.DB_PASSWORD, host=self.DB_HOST, port=self.DB_PORT, database=self.DB_NAME)


settings = Settings()
