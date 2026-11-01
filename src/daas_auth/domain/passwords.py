"""
Password hashes.
For this Python BE Argon2id is used;
PHP's bcrypt hashes still verify.
"""

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# OWASP's minimum profile: 19 MiB, 2 passes, 1 lane.
_argon2 = PasswordHasher(memory_cost=19 * 1024, time_cost=2, parallelism=1)


def hash_password(password: str) -> str:
    # 97 characters, users.password is varchar(255)
    return _argon2.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$2"):
        # bcrypt from PHP (starts with '$2y$'). PHP uses only the first 72 bytes.
        return bcrypt.checkpw(password.encode()[:72], stored_hash.encode())
    try:
        return _argon2.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False
