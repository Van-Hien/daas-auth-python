import hashlib
from collections.abc import Callable
from urllib.error import URLError

import bcrypt
import pytest
from fastapi.testclient import TestClient

from daas_auth.domain import passwords
from daas_auth.domain.errors import Refused
from daas_auth.domain.passwords import (
    breach_count,
    hash_password,
    refuse_weak_password,
    verify_password,
)

# Made by PHP 8.2.35 in daas-auth-php-apache-dev-1 on 2026-10-30:
# php -r 'echo password_hash("spike-password", PASSWORD_DEFAULT);'
PHP_HASH = b"$2y$10$Ulr40X9IAWfcs1IckyTs.eWAXZWEjmAiztkcaZR6thzW7BPTSWnkC"


def test_bcrypt_verifies_a_php_2y_hash() -> None:
    assert bcrypt.checkpw(b"spike-password", PHP_HASH)


def test_bcrypt_refuses_a_wrong_password_for_a_php_hash() -> None:
    assert not bcrypt.checkpw(b"spike-passworD", PHP_HASH)


def test_new_hashes_are_argon2id_and_verify() -> None:
    stored = hash_password("new-password")
    assert stored.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert verify_password("new-password", stored)
    assert not verify_password("new-passworD", stored)


def test_php_hashes_verify_through_the_same_function() -> None:
    assert verify_password("spike-password", PHP_HASH.decode())
    assert not verify_password("spike-passworD", PHP_HASH.decode())


STRONG = "Bärenstark und müde 7"
# SHA-1 of "password" starts with 5BAA6; the other 35 characters stay here.
PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def leaked(password: str, count: int) -> Callable[[str], str]:
    """A range answer that holds this password with this count."""
    suffix = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest()
    return lambda prefix: f"{suffix[5:].upper()}:{count}\r\n"


def check(password: str, check_breaches: bool = True) -> None:
    refuse_weak_password(
        password, name="Anna Smith", email="anna.s@x.de", check_breaches=check_breaches
    )


def test_composed_and_decomposed_umlauts_are_one_password() -> None:
    stored = hash_password("B\u00e4renstark und m\u00fcde 7")  # ä as one character
    assert verify_password("Ba\u0308renstark und mu\u0308de 7", stored)  # a + dots


def test_a_strong_password_passes() -> None:
    check(STRONG)


def test_too_few_different_characters_are_refused() -> None:
    with pytest.raises(Refused, match="at least 5 different characters"):
        check("abababababababab")


@pytest.mark.parametrize(
    "password", ["ANNA-has-a-long-pw", "smith-and-sons-ltd", "my-daas-password"]
)
def test_name_email_and_service_name_are_refused(password: str) -> None:
    with pytest.raises(Refused, match="must not contain"):
        check(password)


def test_a_leaked_password_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(passwords, "_fetch_range", leaked(STRONG, 3))
    with pytest.raises(Refused, match="Have I Been Pwned"):
        check(STRONG)


def test_only_the_first_five_hex_characters_are_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[str] = []

    def answer(prefix: str) -> str:
        sent.append(prefix)
        return f"{PASSWORD_SUFFIX}:52372427\r\n"

    monkeypatch.setattr(passwords, "_fetch_range", answer)
    assert breach_count("password") == 52372427
    assert sent == ["5BAA6"]


def test_a_padding_line_is_not_a_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(passwords, "_fetch_range", leaked(STRONG, 0))
    check(STRONG)


def test_unreachable_accepts_and_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def down(prefix: str) -> str:
        raise URLError("no route to host")

    monkeypatch.setattr(passwords, "_fetch_range", down)
    check(STRONG)
    assert "Pwned Passwords unreachable" in caplog.text


def test_switched_off_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_run(prefix: str) -> str:
        raise AssertionError("Pwned Passwords was called")

    monkeypatch.setattr(passwords, "_fetch_range", must_not_run)
    check(STRONG, check_breaches=False)


def test_post_user_answers_a_leaked_password_with_400(
    client: TestClient, admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(passwords, "_fetch_range", leaked(STRONG, 3))
    body = {"name": "Anna", "email": "anna@x.de", "password": STRONG}
    response = client.post("/user", json=body, headers=admin)
    assert response.status_code == 400
    assert "Have I Been Pwned" in response.json()["detail"]
