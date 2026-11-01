from typing import Annotated

from pydantic import SecretStr, StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL


class Settings(BaseSettings):
    """
    Every setting of the service. Read once, at startup.

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
    # The browser calls the service from the frontend's page, another origin (CORS).
    # PHP answers every origin; this service only these. Set as a JSON list:
    # DAAS_AUTH_CORS_ORIGINS='["https://front1.cluster.local:8443"]'
    cors_origins: list[str] = ["https://front1.cluster.local:8443"]


def load_settings() -> Settings:
    # mypy sees database_url as a missing argument,
    # but pydantic-settings fills it from the environment.
    return Settings()  # type: ignore[call-arg]


class MigrationSettings(BaseSettings):
    """
    The account that may change the schema. Read by Alembic only, never by the service.
    """

    model_config = SettingsConfigDict(
        env_prefix="DAAS_MIGRATE_",  # database_url is read from DAAS_MIGRATE_DATABASE_URL
        env_file=".env.migrate",  # its own file, so the service's .env holds no schema rights
        hide_input_in_errors=True,
    )

    database_url: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def load_migration_settings() -> MigrationSettings:
    return MigrationSettings()  # type: ignore[call-arg]


class ImportSettings(BaseSettings):
    """
    PHP's database, read by `daas-auth import-php`. Not needed after the transfer.
    """

    model_config = SettingsConfigDict(
        env_prefix="DAAS_IMPORT_",  # user is read from DAAS_IMPORT_USER, and so on
        env_file=".env.import",
        hide_input_in_errors=True,
    )

    host: str = "127.0.0.1"
    port: int = 3316  # PHP's mariadb-dev (compose file of the PHP repo)
    user: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    password: SecretStr  # SecretStr prints as ********** if it ever ends up in a log
    database: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

    def url(self) -> URL:
        # URL.create escapes special characters in the password; a hand-built string would not
        return URL.create(
            "mysql+pymysql",
            username=self.user,
            password=self.password.get_secret_value(),
            host=self.host,
            port=self.port,
            database=self.database,
        )


def load_import_settings() -> ImportSettings:
    return ImportSettings()  # type: ignore[call-arg]
