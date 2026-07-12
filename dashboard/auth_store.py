from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from pqc.kyber_mlkem import generate_keys


PBKDF2_ITERATIONS = 200_000
PASSWORD_SALT_BYTES = 16

SUPABASE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    mlkem_public_key_hex TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
"""


@dataclass
class UserRecord:
    id: str
    email: str
    full_name: str
    password_salt: str
    password_hash: str
    mlkem_public_key_hex: str
    created_at: float
    is_active: bool = True


class AuthError(Exception):
    pass


class _BaseAuthRepository:
    def create_user(self, email: str, full_name: str, password: str) -> tuple[UserRecord, str]:
        raise NotImplementedError

    def authenticate(self, email: str, password: str) -> UserRecord:
        raise NotImplementedError

    def get_user_by_email(self, email: str) -> UserRecord:
        raise NotImplementedError

    def rotate_mlkem_keys(self, email: str, password: str) -> tuple[UserRecord, str]:
        raise NotImplementedError


class InMemoryAuthRepository(_BaseAuthRepository):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users_by_id: dict[str, UserRecord] = {}
        self._users_by_email: dict[str, str] = {}

    def create_user(self, email: str, full_name: str, password: str) -> tuple[UserRecord, str]:
        normalized_email = email.strip().lower()
        with self._lock:
            if normalized_email in self._users_by_email:
                raise AuthError("Email already registered")

            salt = secrets.token_hex(PASSWORD_SALT_BYTES)
            password_hash = _hash_password(password, salt)
            public_key, secret_key = generate_keys()
            user = UserRecord(
                id=secrets.token_urlsafe(16),
                email=normalized_email,
                full_name=full_name.strip(),
                password_salt=salt,
                password_hash=password_hash,
                mlkem_public_key_hex=public_key.hex(),
                created_at=time.time(),
            )
            self._users_by_id[user.id] = user
            self._users_by_email[normalized_email] = user.id
            return user, secret_key.hex()

    def authenticate(self, email: str, password: str) -> UserRecord:
        normalized_email = email.strip().lower()
        with self._lock:
            user_id = self._users_by_email.get(normalized_email)
            if user_id is None:
                raise AuthError("Invalid credentials")
            user = self._users_by_id[user_id]
            if not _verify_password(password, user.password_salt, user.password_hash):
                raise AuthError("Invalid credentials")
            return user

    def get_user_by_email(self, email: str) -> UserRecord:
        normalized_email = email.strip().lower()
        with self._lock:
            user_id = self._users_by_email.get(normalized_email)
            if user_id is None:
                raise AuthError("User not found")
            return self._users_by_id[user_id]

    def rotate_mlkem_keys(self, email: str, password: str) -> tuple[UserRecord, str]:
        normalized_email = email.strip().lower()
        with self._lock:
            user_id = self._users_by_email.get(normalized_email)
            if user_id is None:
                raise AuthError("User not found")
            user = self._users_by_id[user_id]
            if not _verify_password(password, user.password_salt, user.password_hash):
                raise AuthError("Invalid credentials")
            public_key, secret_key = generate_keys()
            user.mlkem_public_key_hex = public_key.hex()
            return user, secret_key.hex()


class SQLAlchemyAuthRepository(_BaseAuthRepository):
    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url, poolclass=NullPool)
        self._bootstrap_schema()

    def _bootstrap_schema(self) -> None:
        with self.engine.begin() as conn:
            conn.execute(text(SUPABASE_SCHEMA_SQL))

    def create_user(self, email: str, full_name: str, password: str) -> tuple[UserRecord, str]:
        normalized_email = email.strip().lower()
        with self.engine.begin() as conn:
            result = conn.execute(
                text("SELECT id FROM users WHERE email = :email"),
                {"email": normalized_email}
            ).fetchone()
            if result is not None:
                raise AuthError("Email already registered")

            salt = secrets.token_hex(PASSWORD_SALT_BYTES)
            password_hash = _hash_password(password, salt)
            public_key, secret_key = generate_keys()
            user_id = secrets.token_urlsafe(16)
            created_at = time.time()

            conn.execute(
                text("""
                    INSERT INTO users (id, email, full_name, password_salt, password_hash, mlkem_public_key_hex, created_at, is_active)
                    VALUES (:id, :email, :full_name, :password_salt, :password_hash, :mlkem_public_key_hex, :created_at, :is_active)
                """),
                {
                    "id": user_id,
                    "email": normalized_email,
                    "full_name": full_name.strip(),
                    "password_salt": salt,
                    "password_hash": password_hash,
                    "mlkem_public_key_hex": public_key.hex(),
                    "created_at": created_at,
                    "is_active": True
                }
            )

            user = UserRecord(
                id=user_id,
                email=normalized_email,
                full_name=full_name.strip(),
                password_salt=salt,
                password_hash=password_hash,
                mlkem_public_key_hex=public_key.hex(),
                created_at=created_at,
                is_active=True
            )
            return user, secret_key.hex()

    def authenticate(self, email: str, password: str) -> UserRecord:
        normalized_email = email.strip().lower()
        with self.engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM users WHERE email = :email"),
                {"email": normalized_email}
            ).fetchone()
            if row is None:
                raise AuthError("Invalid credentials")

            user = UserRecord(
                id=row.id,
                email=row.email,
                full_name=row.full_name,
                password_salt=row.password_salt,
                password_hash=row.password_hash,
                mlkem_public_key_hex=row.mlkem_public_key_hex,
                created_at=float(row.created_at),
                is_active=bool(row.is_active)
            )

            if not _verify_password(password, user.password_salt, user.password_hash):
                raise AuthError("Invalid credentials")

            return user

    def get_user_by_email(self, email: str) -> UserRecord:
        normalized_email = email.strip().lower()
        with self.engine.connect() as conn:
            u_row = conn.execute(
                text("SELECT * FROM users WHERE email = :email"),
                {"email": normalized_email}
            ).fetchone()
            if u_row is None:
                raise AuthError("User not found")
            return UserRecord(
                id=u_row.id,
                email=u_row.email,
                full_name=u_row.full_name,
                password_salt=u_row.password_salt,
                password_hash=u_row.password_hash,
                mlkem_public_key_hex=u_row.mlkem_public_key_hex,
                created_at=float(u_row.created_at),
                is_active=bool(u_row.is_active)
            )

    def rotate_mlkem_keys(self, email: str, password: str) -> tuple[UserRecord, str]:
        normalized_email = email.strip().lower()
        with self.engine.begin() as conn:
            u_row = conn.execute(
                text("SELECT * FROM users WHERE email = :email"),
                {"email": normalized_email}
            ).fetchone()
            if u_row is None:
                raise AuthError("User not found")

            # Check credentials
            user = UserRecord(
                id=u_row.id,
                email=u_row.email,
                full_name=u_row.full_name,
                password_salt=u_row.password_salt,
                password_hash=u_row.password_hash,
                mlkem_public_key_hex=u_row.mlkem_public_key_hex,
                created_at=float(u_row.created_at),
                is_active=bool(u_row.is_active)
            )
            if not _verify_password(password, user.password_salt, user.password_hash):
                raise AuthError("Invalid credentials")

            public_key, secret_key = generate_keys()
            conn.execute(
                text("""
                    UPDATE users 
                    SET mlkem_public_key_hex = :pk
                    WHERE id = :id
                """),
                {"pk": public_key.hex(), "id": u_row.id}
            )

            user.mlkem_public_key_hex = public_key.hex()
            return user, secret_key.hex()


_repo: _BaseAuthRepository | None = None
_repo_lock = threading.RLock()


def get_auth_repository() -> _BaseAuthRepository:
    global _repo
    if _repo is not None:
        return _repo

    with _repo_lock:
        if _repo is not None:
            return _repo
        user = os.getenv("user", "").strip()
        password = os.getenv("password", "").strip()
        host = os.getenv("host", "").strip()
        port = os.getenv("port", "").strip() or "6543"
        dbname = os.getenv("dbname", "").strip() or "postgres"

        if user and password and host:
            import urllib.parse
            safe_user = urllib.parse.quote_plus(user)
            safe_password = urllib.parse.quote_plus(password)
            database_url = f"postgresql+psycopg2://{safe_user}:{safe_password}@{host}:{port}/{dbname}?sslmode=require"
            _repo = SQLAlchemyAuthRepository(database_url)
        else:
            _repo = InMemoryAuthRepository()
        return _repo


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS).hex()


def _verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    computed = _hash_password(password, salt_hex)
    return hmac.compare_digest(computed, expected_hash)
