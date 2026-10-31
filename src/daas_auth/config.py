from typing import Annotated

from pydantic import StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Every setting of the service. Read once, at startup.

    Settings() fills each field from an environment variable named
    DAAS_AUTH_ + the field name in capitals, or from a line in the file .env.
    A setting that is missing or invalid stops the start (R-2).
    """

    # Where the values come from
    model_config = SettingsConfigDict(
        env_prefix="DAAS_AUTH_",  # database_url is read from DAAS_AUTH_DATABASE_URL
        env_file=".env",  # a line in .env works too
        hide_input_in_errors=True,  # an error never prints a secret value
    )

    # The settings. A field without a default is required.
    # Spaces at both ends are removed first, then at least 1 character must be left.
    database_url: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def load_settings() -> Settings:
    # mypy sees database_url as a missing argument,
    # but pydantic-settings fills it from the environment.
    return Settings()  # type: ignore[call-arg]


class MigrationSettings(BaseSettings):
    """The account that may change the schema. Read by Alembic only, never by the service."""

    model_config = SettingsConfigDict(
        env_prefix="DAAS_MIGRATE_",  # database_url is read from DAAS_MIGRATE_DATABASE_URL
        env_file=".env.migrate",  # its own file, so the service's .env holds no schema rights
        hide_input_in_errors=True,
    )

    database_url: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def load_migration_settings() -> MigrationSettings:
    return MigrationSettings()  # type: ignore[call-arg]
