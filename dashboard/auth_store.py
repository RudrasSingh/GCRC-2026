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
SESSION_TOKEN_BYTES = 32
DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60

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

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT UNIQUE NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    revoked_at DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
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


@dataclass
class SessionRecord:
    id: str
    user_id: str
    session_token: str
    created_at: float
    expires_at: float
    revoked_at: float | None = None


@dataclass
class AuthSession:
    user: UserRecord
    session_token: str
    session: SessionRecord
    mlkem_private_key: str | None = None


class AuthError(Exception):
    pass


class _BaseAuthRepository:
    def create_user(self, email: str, full_name: str, password: str) -> AuthSession:
        raise NotImplementedError

    def authenticate(self, email: str, password: str) -> AuthSession:
        raise NotImplementedError

    def logout(self, session_token: str) -> None:
        raise NotImplementedError

    def verify_session(self, session_token: str) -> tuple[UserRecord, SessionRecord]:
        raise NotImplementedError

    def get_user_by_id(self, user_id: str) -> UserRecord:
        raise NotImplementedError

    def rotate_mlkem_keys(self, user_id: str) -> tuple[UserRecord, str]:
        raise NotImplementedError


class InMemoryAuthRepository(_BaseAuthRepository):
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users_by_id: dict[str, UserRecord] = {}
        self._users_by_email: dict[str, str] = {}
        self._sessions_by_id: dict[str, SessionRecord] = {}
        self._sessions_by_token: dict[str, str] = {}

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
                created_at=time.time(),
            )
            self._users_by_id[user.id] = user
            self._users_by_email[normalized_email] = user.id
            session_record, plain_token = self._insert_session(user.id)
            return AuthSession(
                user=user,
                session_token=plain_token,
                session=session_record,
                mlkem_private_key=secret_key.hex()
            )

    def authenticate(self, email: str, password: str) -> AuthSession:
        normalized_email = email.strip().lower()
        with self._lock:
            user_id = self._users_by_email.get(normalized_email)
            if user_id is None:
                raise AuthError("Invalid credentials")
            user = self._users_by_id[user_id]
            if not _verify_password(password, user.password_salt, user.password_hash):
                raise AuthError("Invalid credentials")
            session_record, plain_token = self._insert_session(user.id)
            return AuthSession(user=user, session_token=plain_token, session=session_record)

    def logout(self, session_token: str) -> None:
        with self._lock:
            session_id = self._sessions_by_token.get(session_token)
            if session_id is not None:
                session = self._sessions_by_id[session_id]
                session.revoked_at = time.time()

    def verify_session(self, session_token: str) -> tuple[UserRecord, SessionRecord]:
        with self._lock:
            session_id = self._sessions_by_token.get(session_token)
            if session_id is None:
                raise AuthError("Unauthorized")
            session = self._sessions_by_id[session_id]
            if session.revoked_at is not None:
                raise AuthError("Unauthorized")
            if session.expires_at < time.time():
                raise AuthError("Unauthorized")
            user = self._users_by_id.get(session.user_id)
            if user is None or not user.is_active:
                raise AuthError("Unauthorized")
            return user, session

    def get_user_by_id(self, user_id: str) -> UserRecord:
        with self._lock:
            user = self._users_by_id.get(user_id)
            if user is None:
                raise AuthError("User not found")
            return user

    def rotate_mlkem_keys(self, user_id: str) -> tuple[UserRecord, str]:
        with self._lock:
            user = self._users_by_id.get(user_id)
            if user is None:
                raise AuthError("User not found")
            public_key, secret_key = generate_keys()
            user.mlkem_public_key_hex = public_key.hex()
            return user, secret_key.hex()

    def _insert_session(self, user_id: str, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> tuple[SessionRecord, str]:
        plain_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        record = SessionRecord(
            id=secrets.token_urlsafe(16),
            user_id=user_id,
            session_token=plain_token,
            created_at=time.time(),
            expires_at=time.time() + ttl_seconds,
        )
        self._sessions_by_id[record.id] = record
        self._sessions_by_token[plain_token] = record.id
        return record, plain_token


class SupabaseAuthRepository(_BaseAuthRepository):
    def __init__(
        self,
        supabase_url: str,
        service_role_key: str,
        database_url: str | None = None,
        users_table: str = "users",
        sessions_table: str = "sessions",
    ) -> None:
        self.supabase_url = supabase_url.rstrip("/") + "/"
        self.headers = {
            "apikey": service_role_key,
            "Authorization": f"Bearer {service_role_key}",
            "Content-Type": "application/json",
        }
        self.users_table = users_table
        self.sessions_table = sessions_table
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
            "is_active": True,
        }
        user = self._insert(self.users_table, user_payload)
        session_record, plain_token = self._insert_session(user["id"])
        return AuthSession(
            user=_user_from_row(user),
            session_token=plain_token,
            session=session_record,
            mlkem_private_key=secret_key.hex()
        )

    def authenticate(self, email: str, password: str) -> AuthSession:
        normalized_email = email.strip().lower()
        user_row = self._select_one(self.users_table, {"email": f"eq.{normalized_email}"})
        if user_row is None:
            raise AuthError("Invalid credentials")
        user = _user_from_row(user_row)
        if not _verify_password(password, user.password_salt, user.password_hash):
            raise AuthError("Invalid credentials")
        session_record, plain_token = self._insert_session(user.id)
        return AuthSession(user=user, session_token=plain_token, session=session_record)

    def logout(self, session_token: str) -> None:
        session = self._select_one(self.sessions_table, {"session_token": f"eq.{session_token}"})
        if session is not None:
            self._patch(self.sessions_table, session["id"], {"revoked_at": time.time()})

    def verify_session(self, session_token: str) -> tuple[UserRecord, SessionRecord]:
        session_row = self._select_one(self.sessions_table, {"session_token": f"eq.{session_token}", "revoked_at": "is.null"})
        if session_row is None:
            raise AuthError("Unauthorized")
        session_record = _session_from_row(session_row)
        if session_record.expires_at < time.time():
            raise AuthError("Unauthorized")
        user_row = self._select_one(self.users_table, {"id": f"eq.{session_record.user_id}"})
        if user_row is None or not user_row.get("is_active", True):
            raise AuthError("Unauthorized")
        return _user_from_row(user_row), session_record

    def get_user_by_id(self, user_id: str) -> UserRecord:
        user_row = self._select_one(self.users_table, {"id": f"eq.{user_id}"})
        if user_row is None:
            raise AuthError("User not found")
        return _user_from_row(user_row)

    def rotate_mlkem_keys(self, user_id: str) -> tuple[UserRecord, str]:
        user_row = self._select_one(self.users_table, {"id": f"eq.{user_id}"})
        if user_row is None:
            raise AuthError("User not found")
        public_key, secret_key = generate_keys()
        updates = {
            "mlkem_public_key_hex": public_key.hex(),
        }
        self._patch(self.users_table, user_id, updates)
        user_row.update(updates)
        return _user_from_row(user_row), secret_key.hex()

    def _insert_session(self, user_id: str, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> tuple[SessionRecord, str]:
        plain_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        created_at = time.time()
        record = self._insert(
            self.sessions_table,
            {
                "user_id": user_id,
                "session_token": plain_token,
                "created_at": created_at,
                "expires_at": created_at + ttl_seconds,
                "revoked_at": None,
            },
        )
        return _session_from_row(record), plain_token

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


class SQLAlchemyAuthRepository(_BaseAuthRepository):
    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url, poolclass=NullPool)
        self._bootstrap_schema()

    def _bootstrap_schema(self) -> None:
        with self.engine.connect() as conn:
            with conn.begin():
                conn.execute(text(SUPABASE_SCHEMA_SQL))

    def create_user(self, email: str, full_name: str, password: str) -> AuthSession:
        normalized_email = email.strip().lower()
        with self.engine.connect() as conn:
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

            with conn.begin():
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

            session_record, plain_token = self._insert_session(conn, user_id)
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
            return AuthSession(
                user=user,
                session_token=plain_token,
                session=session_record,
                mlkem_private_key=secret_key.hex()
            )

    def authenticate(self, email: str, password: str) -> AuthSession:
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

            session_record, plain_token = self._insert_session(conn, user.id)
            return AuthSession(user=user, session_token=plain_token, session=session_record)

    def logout(self, session_token: str) -> None:
        with self.engine.connect() as conn:
            with conn.begin():
                conn.execute(
                    text("UPDATE sessions SET revoked_at = :revoked_at WHERE session_token = :token"),
                    {"revoked_at": time.time(), "token": session_token}
                )

    def verify_session(self, session_token: str) -> tuple[UserRecord, SessionRecord]:
        with self.engine.connect() as conn:
            s_row = conn.execute(
                text("SELECT * FROM sessions WHERE session_token = :token AND revoked_at IS NULL"),
                {"token": session_token}
            ).fetchone()
            if s_row is None:
                raise AuthError("Unauthorized")

            session_record = SessionRecord(
                id=s_row.id,
                user_id=s_row.user_id,
                session_token=s_row.session_token,
                created_at=float(s_row.created_at),
                expires_at=float(s_row.expires_at),
                revoked_at=None
            )

            if session_record.expires_at < time.time():
                raise AuthError("Unauthorized")

            u_row = conn.execute(
                text("SELECT * FROM users WHERE id = :id"),
                {"id": session_record.user_id}
            ).fetchone()

            if u_row is None or not bool(u_row.is_active):
                raise AuthError("Unauthorized")

            user_record = UserRecord(
                id=u_row.id,
                email=u_row.email,
                full_name=u_row.full_name,
                password_salt=u_row.password_salt,
                password_hash=u_row.password_hash,
                mlkem_public_key_hex=u_row.mlkem_public_key_hex,
                created_at=float(u_row.created_at),
                is_active=bool(u_row.is_active)
            )
            return user_record, session_record

    def get_user_by_id(self, user_id: str) -> UserRecord:
        with self.engine.connect() as conn:
            u_row = conn.execute(
                text("SELECT * FROM users WHERE id = :id"),
                {"id": user_id}
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

    def rotate_mlkem_keys(self, user_id: str) -> tuple[UserRecord, str]:
        with self.engine.connect() as conn:
            u_row = conn.execute(
                text("SELECT * FROM users WHERE id = :id"),
                {"id": user_id}
            ).fetchone()
            if u_row is None:
                raise AuthError("User not found")

            public_key, secret_key = generate_keys()
            with conn.begin():
                conn.execute(
                    text("""
                        UPDATE users 
                        SET mlkem_public_key_hex = :pk
                        WHERE id = :id
                    """),
                    {"pk": public_key.hex(), "id": user_id}
                )

            user_record = UserRecord(
                id=u_row.id,
                email=u_row.email,
                full_name=u_row.full_name,
                password_salt=u_row.password_salt,
                password_hash=u_row.password_hash,
                mlkem_public_key_hex=public_key.hex(),
                created_at=float(u_row.created_at),
                is_active=bool(u_row.is_active)
            )
            return user_record, secret_key.hex()

    def _insert_session(self, conn, user_id: str, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> tuple[SessionRecord, str]:
        plain_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        session_id = secrets.token_urlsafe(16)
        created_at = time.time()
        expires_at = created_at + ttl_seconds

        with conn.begin():
            conn.execute(
                text("""
                    INSERT INTO sessions (id, user_id, session_token, created_at, expires_at, revoked_at)
                    VALUES (:id, :user_id, :session_token, :created_at, :expires_at, NULL)
                """),
                {
                    "id": session_id,
                    "user_id": user_id,
                    "session_token": plain_token,
                    "created_at": created_at,
                    "expires_at": expires_at
                }
            )

        record = SessionRecord(
            id=session_id,
            user_id=user_id,
            session_token=plain_token,
            created_at=created_at,
            expires_at=expires_at,
            revoked_at=None
        )
        return record, plain_token


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
        port = os.getenv("port", "6543").strip()
        dbname = os.getenv("dbname", "postgres").strip()

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


def _user_from_row(row: dict[str, Any]) -> UserRecord:
    return UserRecord(
        id=row["id"],
        email=row["email"],
        full_name=row.get("full_name", ""),
        password_salt=row["password_salt"],
        password_hash=row["password_hash"],
        mlkem_public_key_hex=row.get("mlkem_public_key_hex", ""),
        created_at=float(row.get("created_at", time.time())),
        is_active=bool(row.get("is_active", True)),
    )


def _session_from_row(row: dict[str, Any]) -> SessionRecord:
    return SessionRecord(
        id=row["id"],
        user_id=row["user_id"],
        session_token=row["session_token"],
        created_at=float(row.get("created_at", time.time())),
        expires_at=float(row.get("expires_at", time.time())),
        revoked_at=row.get("revoked_at"),
    )
