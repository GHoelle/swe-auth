"""Application settings, loaded from environment variables.

Security notes:
- DATABASE_URL and REDIS_URL have no defaults. If they're missing, the app refuses
  to start (fail closed) instead of falling back to some insecure default.
- They're typed as SecretStr, so printing or logging the settings object shows
  '**********' instead of the passwords embedded in the URLs.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Required, no default. A production deploy that forgot to set it used to silently run
    # as "development" (docs on, insecure cookies allowed). Fail closed instead.
    # (Found by the security review. The production Docker image also sets it.)
    environment: Literal["development", "test", "production"]

    database_url: SecretStr
    redis_url: SecretStr

    # OWASP Session Management Cheat Sheet: 15-30 minutes idle for low-risk apps, and 4-8
    # hours absolute for full-day use. The absolute limit caps how long a stolen session
    # token can be used, even if the attacker keeps it active.
    session_idle_timeout_seconds: int = Field(default=30 * 60, gt=0)
    session_absolute_timeout_seconds: int = Field(default=8 * 60 * 60, gt=0)

    # Secure + __Host- cookie by default. Only for unusual local setups; refused in production.
    session_cookie_secure: bool = True

    # Each Argon2 hash holds 64 MiB of RAM for ~100 ms. Capping how many run at once caps
    # memory use (4 x 64 MiB = 256 MiB), so a login flood can't exhaust the server.
    # Requests that can't get a slot within the timeout get a 503 instead of piling up.
    password_hash_max_concurrency: int = Field(default=4, gt=0)
    password_hash_queue_timeout_seconds: float = Field(default=1.0, gt=0)

    @model_validator(mode="after")
    def _check_security_settings(self) -> "Settings":
        if self.session_absolute_timeout_seconds < self.session_idle_timeout_seconds:
            raise ValueError("SESSION_ABSOLUTE_TIMEOUT_SECONDS must be >= the idle timeout")
        if self.is_production and not self.session_cookie_secure:
            raise ValueError("SESSION_COOKIE_SECURE cannot be false in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment
