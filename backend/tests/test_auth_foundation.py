import app.models

from app.core.model_base import Base
from app.core.security import (
    generate_secure_token,
    hash_password,
    hash_secure_token,
    verify_password,
)


def test_password_hashing_uses_argon2id():
    password = "Local-Test-Password-Only-2026!"
    stored_hash = hash_password(password)

    assert stored_hash.startswith("$argon2id$")
    assert password not in stored_hash
    assert verify_password(password, stored_hash)
    assert not verify_password("IncorrectPassword", stored_hash)


def test_password_hashes_use_unique_salts():
    password = "Another-Local-Test-Password!"

    first = hash_password(password)
    second = hash_password(password)

    assert first != second


def test_secure_tokens_are_random_and_hashed():
    first = generate_secure_token()
    second = generate_secure_token()

    assert first != second
    assert len(first) >= 32

    digest = hash_secure_token(first)

    assert len(digest) == 64
    assert digest != first
    assert hash_secure_token(first) == digest
    assert hash_secure_token(second) != digest


def test_authentication_tables_are_registered():
    assert "payflow.user_sessions" in Base.metadata.tables
    assert "payflow.auth_tokens" in Base.metadata.tables


def test_email_verification_is_nullable():
    table = Base.metadata.tables["payflow.users"]
    assert table.c.email_verified_at.nullable is True


def test_raw_session_tokens_are_not_model_columns():
    table = Base.metadata.tables["payflow.user_sessions"]

    assert "token_hash" in table.c
    assert "token" not in table.c
    assert "plaintext_token" not in table.c
