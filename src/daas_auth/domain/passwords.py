"""
Password hashes, and the checks a new password must pass.
For this Python BE Argon2id is used;
PHP's bcrypt hashes still verify.
Using normalization on password input.
Apply extra rules, and checked against HIPB (haveibeenpwned.com)
"""

import hashlib
import logging
import re
import unicodedata
from http.client import HTTPException
from urllib.request import Request, urlopen

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from daas_auth.domain.errors import Refused

log = logging.getLogger(__name__)

# OWASP's minimum profile: 19 MiB, 2 passes, 1 lane.
_argon2 = PasswordHasher(memory_cost=19 * 1024, time_cost=2, parallelism=1)

# "aaaaaaaaaaaaaaa" and "abababababababab" are long, but guessed at once.
MIN_DISTINCT_CHARACTERS = 5
# Shorter words of the name and the email are not looked for: "Li", "x@x.de".
MIN_CONTEXT_WORD = 3
# Pwned Passwords answers in about 0.2 s; after this the check is skipped.
PWNED_TIMEOUT_SECONDS = 3


def hash_password(password: str) -> str:
    # 97 characters, users.password is varchar(255)
    return _argon2.hash(_prepare(password))


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$2"):
        # bcrypt from PHP (starts with '$2y$'). PHP uses only the first 72 bytes.
        return bcrypt.checkpw(password.encode()[:72], stored_hash.encode())
    try:
        return _argon2.verify(stored_hash, _prepare(password))
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """
    True for PHP's bcrypt, or an Argon2id hash made with other parameters
    """
    return stored_hash.startswith("$2") or _argon2.check_needs_rehash(stored_hash)


def refuse_weak_password(
    password: str, *, name: str, email: str, check_breaches: bool
) -> None:
    """
    Where a password is set, before it is hashed. Login never runs this.
    """
    prepared = _prepare(password).casefold()
    if len(set(prepared)) < MIN_DISTINCT_CHARACTERS:
        raise Refused(
            400,
            f"The password needs at least {MIN_DISTINCT_CHARACTERS} different characters.",
        )
    for word in sorted(_context_words(name, email)):
        if word in prepared:
            raise Refused(400, f"The password must not contain {word!r}.")
    if check_breaches and breach_count(password):
        raise Refused(
            400, "This password is in a list of leaked passwords (Have I Been Pwned)."
        )


def breach_count(password: str) -> int | None:
    """
    How often Pwned Passwords has seen the password; None if it can't be reached.
    Only the first 5 of the SHA-1's 40 hex characters leave this host.
    """
    sha1 = hashlib.sha1(_prepare(password).encode(), usedforsecurity=False)
    digest = sha1.hexdigest().upper()
    try:
        return _count_in_range(_fetch_range(digest[:5]), digest[5:])
    except (OSError, HTTPException, ValueError):
        # Fail open: a network problem must not stop an admin from creating a user.
        log.warning("Pwned Passwords unreachable: password accepted without the check")
        return None


def _fetch_range(prefix: str) -> str:
    # Add-Padding: the answer gets a random number of fake lines with the count 0,
    # so its size says less about the prefix.
    with urlopen(
        Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
        ),
        timeout=PWNED_TIMEOUT_SECONDS,
    ) as response:
        body: bytes = response.read()
    return body.decode()


def _count_in_range(lines: str, suffix: str) -> int:
    # Each line is SUFFIX:COUNT. A padding line has the count 0, so it never refuses.
    for line in lines.splitlines():
        found, _, count = line.partition(":")
        if found == suffix:
            return int(count)
    return 0


def _context_words(name: str, email: str) -> set[str]:
    # "Anna Smith", "anna.s@x.de" -> {"anna", "smith", "daas"}
    local_part = email.rpartition("@")[0]
    words = re.split(r"\W+", _prepare(f"{name} {local_part}").casefold())
    return {word for word in words if len(word) >= MIN_CONTEXT_WORD} | {"daas"}


def _prepare(password: str) -> str:
    # "ä" from macOS (a + combining dot) and from Windows (one character) become the same.
    return unicodedata.normalize("NFKC", password)
