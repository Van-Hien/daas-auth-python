from typing import Annotated

from pydantic import StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

# A setting that is missing, empty or only spaces is refused (R-2).
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class Settings(BaseSettings):
    """Every setting of the service. Read once, at startup."""

    # DAAS_AUTH_DATABASE_URL, or a line in the file .env
    model_config = SettingsConfigDict(
        env_prefix="DAAS_AUTH_",
        env_file=".env",
        hide_input_in_errors=True,  # an error never prints a secret value
    )

    # Used from M3 on. Required already, so the start-up check has something to check.
    database_url: NonEmptyStr


def load_settings() -> Settings:
    # mypy sees database_url as a missing argument, but pydantic-settings fills it
    # from the environment.
    return Settings()  # type: ignore[call-arg]
