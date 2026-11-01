def normalise_email(email: str) -> str:
    """
    One spelling per email: no spaces at the ends, lower case.
    Used before every store and every lookup. Migration 0005 has its own copy too.
    """
    return email.strip().lower()
