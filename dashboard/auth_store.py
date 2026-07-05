from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests

from pqc.kyber_mlkem import generate_keys


PBKDF2_ITERATIONS = 200_000
PASSWORD_SALT_BYTES = 16
API_KEY_BYTES = 32
DEFAULT_API_KEY_TTL_SECONDS = 30 * 24 * 60 * 60

SUPABASE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    mlkem_public_key_hex TEXT NOT NULL,
    mlkem_private_key_hex TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT 'default',
    created_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION,
    revoked_at DOUBLE PRECISION,
    last_used_at DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
"""


@dataclass
class UserRecord:
    id: str
    email: str
    full_name: str
    password_salt: str
    password_hash: str
    mlkem_public_key_hex: str
    mlkem_private_key_hex: str
    created_at: float
    is_active: bool = True


@dataclass
class ApiKeyRecord:
    id: str
    user_id: str
    key_hash: str
    key_prefix: str
    label: str
    created_at: float
    expires_at: float | None = None
    revoked_at: float | None = None
    last_used_at: float | None = None


@dataclass
class AuthSession:
    user: UserRecord
    api_key: ApiKeyRecord
    plain_api_key: str


class AuthError(Exception):
    pass


class _BaseAuthRepository:
    def create_user(self, email: str, full_name: str, password: str) -> AuthSession:
        raise NotImplementedError

    def authenticate(self, email: str, password: str) -> AuthSession:
        raise NotImplementedError

    def issue_api_key(self, user_id: str, label: str = "default", ttl_seconds: int = DEFAULT_API_KEY_TTL_SECONDS) -> tuple[ApiKeyRecord, str]:
        raise NotImplementedError

    def verify_api_key(self, api_key: str) -> tuple[UserRecord, ApiKeyRecord]:
        raise NotImplementedError

    def list_api_keys(self, user_id: str) -> list[ApiKeyRecord]:
        raise NotImplementedError

    def revoke_api_key(self, user_id: str, api_key_id: str) -> None:
        raise NotImplementedError

    def get_user_by_id(self, user_id: str) -> UserRecord:
        raise NotImplementedError

    def rotate_mlkem_keys(self, user_id: str) -> UserRecord:
        raise NotImplementedError


class InMemoryAuthRepository(_BaseAuthRepository):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users_by_id: dict[str, UserRecord] = {}
        self._users_by_email: dict[str, str] = {}
        self._keys_by_id: dict[str, ApiKeyRecord] = {}
        self._keys_by_hash: dict[str, str] = {}

    def create_user(self, email: str, full_name: str, password: str) -> AuthSession:
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
                mlkem_private_key_hex=secret_key.hex(),
                created_at=time.time(),
            )
            self._users_by_id[user.id] = user
            self._users_by_email[normalized_email] = user.id
            api_key_record, plain_api_key = self._insert_key(user.id, label="default", ttl_seconds=DEFAULT_API_KEY_TTL_SECONDS)
            return AuthSession(user=user, api_key=api_key_record, plain_api_key=plain_api_key)

    def authenticate(self, email: str, password: str) -> AuthSession:
        normalized_email = email.strip().lower()
        with self._lock:
            user_id = self._users_by_email.get(normalized_email)
            if user_id is None:
                raise AuthError("Invalid credentials")
            user = self._users_by_id[user_id]
            if not _verify_password(password, user.password_salt, user.password_hash):
                raise AuthError("Invalid credentials")
            api_key_record, plain_api_key = self._insert_key(user.id, label="login", ttl_seconds=DEFAULT_API_KEY_TTL_SECONDS)
            return AuthSession(user=user, api_key=api_key_record, plain_api_key=plain_api_key)

    def issue_api_key(self, user_id: str, label: str = "default", ttl_seconds: int = DEFAULT_API_KEY_TTL_SECONDS) -> tuple[ApiKeyRecord, str]:
        with self._lock:
            return self._insert_key(user_id, label=label, ttl_seconds=ttl_seconds)

    def verify_api_key(self, api_key: str) -> tuple[UserRecord, ApiKeyRecord]:
        key_hash = _hash_api_key(api_key)
        with self._lock:
            key_id = self._keys_by_hash.get(key_hash)
            if key_id is None:
                raise AuthError("Unauthorized")
            key = self._keys_by_id[key_id]
            if key.revoked_at is not None:
                raise AuthError("Unauthorized")
            if key.expires_at is not None and key.expires_at < time.time():
                raise AuthError("Unauthorized")
            user = self._users_by_id.get(key.user_id)
            if user is None or not user.is_active:
                raise AuthError("Unauthorized")
            key.last_used_at = time.time()
            return user, key

    def list_api_keys(self, user_id: str) -> list[ApiKeyRecord]:
        with self._lock:
            return [key for key in self._keys_by_id.values() if key.user_id == user_id]

    def revoke_api_key(self, user_id: str, api_key_id: str) -> None:
        with self._lock:
            key = self._keys_by_id.get(api_key_id)
            if key is None or key.user_id != user_id:
                raise AuthError("API key not found")
            key.revoked_at = time.time()

    def get_user_by_id(self, user_id: str) -> UserRecord:
        with self._lock:
            user = self._users_by_id.get(user_id)
            if user is None:
                raise AuthError("User not found")
            return user

    def rotate_mlkem_keys(self, user_id: str) -> UserRecord:
        with self._lock:
            user = self._users_by_id.get(user_id)
            if user is None:
                raise AuthError("User not found")
            public_key, secret_key = generate_keys()
            user.mlkem_public_key_hex = public_key.hex()
            user.mlkem_private_key_hex = secret_key.hex()
            return user

    def _insert_key(self, user_id: str, label: str, ttl_seconds: int) -> tuple[ApiKeyRecord, str]:
        plain_api_key = _issue_plain_api_key()
        key_hash = _hash_api_key(plain_api_key)
        record = ApiKeyRecord(
            id=secrets.token_urlsafe(16),
            user_id=user_id,
            key_hash=key_hash,
            key_prefix=plain_api_key[:8],
            label=label,
            created_at=time.time(),
            expires_at=time.time() + ttl_seconds if ttl_seconds else None,
        )
        self._keys_by_id[record.id] = record
        self._keys_by_hash[key_hash] = record.id
        return record, plain_api_key


class SupabaseAuthRepository(_BaseAuthRepository):
    def __init__(
        self,
        supabase_url: str,
        service_role_key: str,
        database_url: str | None = None,
        users_table: str = "users",
        api_keys_table: str = "api_keys",
    ) -> None:
        self.supabase_url = supabase_url.rstrip("/") + "/"
        self.headers = {
            "apikey": service_role_key,
            "Authorization": f"Bearer {service_role_key}",
            "Content-Type": "application/json",
        }
        self.users_table = users_table
        self.api_keys_table = api_keys_table
        if database_url:
            self._bootstrap_schema(database_url)

    def create_user(self, email: str, full_name: str, password: str) -> AuthSession:
        normalized_email = email.strip().lower()
        existing = self._select_one(self.users_table, {"email": f"eq.{normalized_email}"})
        if existing is not None:
            raise AuthError("Email already registered")

        salt = secrets.token_hex(PASSWORD_SALT_BYTES)
        password_hash = _hash_password(password, salt)
        public_key, secret_key = generate_keys()
        user_payload = {
            "email": normalized_email,
            "full_name": full_name.strip(),
            "password_salt": salt,
            "password_hash": password_hash,
            "mlkem_public_key_hex": public_key.hex(),
            "mlkem_private_key_hex": secret_key.hex(),
            "is_active": True,
        }
        user = self._insert(self.users_table, user_payload)
        api_key_record, plain_api_key = self.issue_api_key(user["id"], label="default", ttl_seconds=DEFAULT_API_KEY_TTL_SECONDS)
        return AuthSession(user=_user_from_row(user), api_key=api_key_record, plain_api_key=plain_api_key)

    def authenticate(self, email: str, password: str) -> AuthSession:
        normalized_email = email.strip().lower()
        user_row = self._select_one(self.users_table, {"email": f"eq.{normalized_email}"})
        if user_row is None:
            raise AuthError("Invalid credentials")
        user = _user_from_row(user_row)
        if not _verify_password(password, user.password_salt, user.password_hash):
            raise AuthError("Invalid credentials")
        api_key_record, plain_api_key = self.issue_api_key(user.id, label="login", ttl_seconds=DEFAULT_API_KEY_TTL_SECONDS)
        return AuthSession(user=user, api_key=api_key_record, plain_api_key=plain_api_key)

    def issue_api_key(self, user_id: str, label: str = "default", ttl_seconds: int = DEFAULT_API_KEY_TTL_SECONDS) -> tuple[ApiKeyRecord, str]:
        plain_api_key = _issue_plain_api_key()
        created_at = time.time()
        record = self._insert(
            self.api_keys_table,
            {
                "user_id": user_id,
                "key_hash": _hash_api_key(plain_api_key),
                "key_prefix": plain_api_key[:8],
                "label": label,
                "created_at": created_at,
                "expires_at": created_at + ttl_seconds if ttl_seconds else None,
                "revoked_at": None,
                "last_used_at": None,
            },
        )
        return _api_key_from_row(record), plain_api_key

    def verify_api_key(self, api_key: str) -> tuple[UserRecord, ApiKeyRecord]:
        key_hash = _hash_api_key(api_key)
        key_row = self._select_one(self.api_keys_table, {"key_hash": f"eq.{key_hash}", "revoked_at": "is.null"})
        if key_row is None:
            raise AuthError("Unauthorized")
        api_key_record = _api_key_from_row(key_row)
        if api_key_record.expires_at is not None and api_key_record.expires_at < time.time():
            raise AuthError("Unauthorized")
        user_row = self._select_one(self.users_table, {"id": f"eq.{api_key_record.user_id}"})
        if user_row is None or not user_row.get("is_active", True):
            raise AuthError("Unauthorized")
        self._patch(self.api_keys_table, api_key_record.id, {"last_used_at": time.time()})
        return _user_from_row(user_row), api_key_record

    def list_api_keys(self, user_id: str) -> list[ApiKeyRecord]:
        return [_api_key_from_row(row) for row in self._select(self.api_keys_table, {"user_id": f"eq.{user_id}"})]

    def revoke_api_key(self, user_id: str, api_key_id: str) -> None:
        key = self._select_one(self.api_keys_table, {"id": f"eq.{api_key_id}", "user_id": f"eq.{user_id}"})
        if key is None:
            raise AuthError("API key not found")
        self._patch(self.api_keys_table, api_key_id, {"revoked_at": time.time()})

    def get_user_by_id(self, user_id: str) -> UserRecord:
        user_row = self._select_one(self.users_table, {"id": f"eq.{user_id}"})
        if user_row is None:
            raise AuthError("User not found")
        return _user_from_row(user_row)

    def rotate_mlkem_keys(self, user_id: str) -> UserRecord:
        user_row = self._select_one(self.users_table, {"id": f"eq.{user_id}"})
        if user_row is None:
            raise AuthError("User not found")
        public_key, secret_key = generate_keys()
        updates = {
            "mlkem_public_key_hex": public_key.hex(),
            "mlkem_private_key_hex": secret_key.hex(),
        }
        self._patch(self.users_table, user_id, updates)
        user_row.update(updates)
        return _user_from_row(user_row)

    def _select(self, table: str, filters: dict[str, str]) -> list[dict[str, Any]]:
        params = {"select": "*", **filters}
        response = requests.get(
            urljoin(self.supabase_url, f"rest/v1/{table}"),
            headers=self.headers,
            params=params,
            timeout=20,
        )
        response.raise_for_status()
        return response.json()

    def _select_one(self, table: str, filters: dict[str, str]) -> dict[str, Any] | None:
        rows = self._select(table, filters)
        if not rows:
            return None
        return rows[0]

    def _insert(self, table: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {**self.headers, "Prefer": "return=representation"}
        response = requests.post(
            urljoin(self.supabase_url, f"rest/v1/{table}"),
            headers=headers,
            params={"select": "*"},
            json=payload,
            timeout=20,
        )
        response.raise_for_status()
        rows = response.json()
        if isinstance(rows, list):
            return rows[0]
        return rows

    def _patch(self, table: str, row_id: str, payload: dict[str, Any]) -> None:
        response = requests.patch(
            urljoin(self.supabase_url, f"rest/v1/{table}"),
            headers=self.headers,
            params={"id": f"eq.{row_id}"},
            json=payload,
            timeout=20,
        )
        response.raise_for_status()

    def _bootstrap_schema(self, database_url: str) -> None:
        try:
            import psycopg2
        except ImportError as exc:
            raise AuthError("psycopg2 is required for Supabase schema bootstrap") from exc

        with psycopg2.connect(database_url) as connection:
            connection.autocommit = True
            with connection.cursor() as cursor:
                cursor.execute(SUPABASE_SCHEMA_SQL)


_repo: _BaseAuthRepository | None = None
_repo_lock = threading.RLock()


def get_auth_repository() -> _BaseAuthRepository:
    global _repo
    if _repo is not None:
        return _repo

    with _repo_lock:
        if _repo is not None:
            return _repo
        supabase_url = os.getenv("SUPABASE_URL", "").strip()
        supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        if supabase_url and supabase_key:
            database_url = os.getenv("SUPABASE_DB_URL", os.getenv("DATABASE_URL", "")).strip() or None
            _repo = SupabaseAuthRepository(supabase_url, supabase_key, database_url=database_url)
        else:
            _repo = InMemoryAuthRepository()
        return _repo


def hash_api_key_for_storage(api_key: str) -> str:
    return _hash_api_key(api_key)


def _issue_plain_api_key(prefix: str | None = None) -> str:
    token = secrets.token_urlsafe(API_KEY_BYTES)
    if prefix:
        return prefix + token[len(prefix):]
    return token


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS).hex()


def _verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    computed = _hash_password(password, salt_hex)
    return hmac.compare_digest(computed, expected_hash)


def _user_from_row(row: dict[str, Any]) -> UserRecord:
    return UserRecord(
        id=row["id"],
        email=row["email"],
        full_name=row.get("full_name", ""),
        password_salt=row["password_salt"],
        password_hash=row["password_hash"],
        mlkem_public_key_hex=row.get("mlkem_public_key_hex", ""),
        mlkem_private_key_hex=row.get("mlkem_private_key_hex", ""),
        created_at=float(row.get("created_at", time.time())),
        is_active=bool(row.get("is_active", True)),
    )


def _api_key_from_row(row: dict[str, Any]) -> ApiKeyRecord:
    return ApiKeyRecord(
        id=row["id"],
        user_id=row["user_id"],
        key_hash=row["key_hash"],
        key_prefix=row.get("key_prefix", ""),
        label=row.get("label", "default"),
        created_at=float(row.get("created_at", time.time())),
        expires_at=row.get("expires_at"),
        revoked_at=row.get("revoked_at"),
        last_used_at=row.get("last_used_at"),
    )
