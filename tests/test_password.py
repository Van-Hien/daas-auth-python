import bcrypt

# Made by PHP 8.2.35 in daas-auth-php-apache-dev-1 on 2026-10-30:
# php -r 'echo password_hash("spike-password", PASSWORD_DEFAULT);'
PHP_HASH = b"$2y$10$Ulr40X9IAWfcs1IckyTs.eWAXZWEjmAiztkcaZR6thzW7BPTSWnkC"


def test_bcrypt_verifies_a_php_2y_hash() -> None:
    assert bcrypt.checkpw(b"spike-password", PHP_HASH)


def test_bcrypt_refuses_a_wrong_password_for_a_php_hash() -> None:
    assert not bcrypt.checkpw(b"spike-passworD", PHP_HASH)
