import hashlib
import secrets

from pwdlib import PasswordHash


_password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty")

    return _password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return _password_hasher.verify(password, stored_hash)


def generate_secure_token() -> str:
    return secrets.token_urlsafe(32)


def hash_secure_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()
