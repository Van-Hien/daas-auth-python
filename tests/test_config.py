from pathlib import Path

import pytest
from pydantic import ValidationError

from daas_auth.config import load_settings


@pytest.fixture(autouse=True)
def no_env_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # ".env" is looked up in the current directory. An empty one has none, so
    # a test sees only the environment it sets itself.
    monkeypatch.chdir(tmp_path)


def test_missing_database_url_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DAAS_AUTH_DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        load_settings()


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_database_url_is_refused(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("DAAS_AUTH_DATABASE_URL", value)
    with pytest.raises(ValidationError):
        load_settings()


def test_database_url_is_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DAAS_AUTH_DATABASE_URL", "sqlite://")
    assert load_settings().database_url == "sqlite://"
