import bcrypt

from daas_auth.domain.passwords import hash_password, verify_password

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
