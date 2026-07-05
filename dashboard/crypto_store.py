from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class StoredSecret:
    value: bytes
    kind: str
    expires_at: float


class EphemeralSecretStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._secrets: dict[str, StoredSecret] = {}

    def put(self, value: bytes, kind: str, ttl_seconds: int) -> str:
        handle = secrets.token_urlsafe(32)
        expires_at = time.time() + ttl_seconds

        with self._lock:
            self._cleanup_locked()
            self._secrets[handle] = StoredSecret(value=value, kind=kind, expires_at=expires_at)

        return handle

    def resolve(self, handle: str, expected_kind: str | None = None) -> bytes:
        with self._lock:
            self._cleanup_locked()
            secret = self._secrets.get(handle)
            if secret is None:
                raise KeyError(handle)
            if expected_kind is not None and secret.kind != expected_kind:
                raise KeyError(handle)
            return secret.value

    def _cleanup_locked(self) -> None:
        now = time.time()
        expired = [handle for handle, secret in self._secrets.items() if secret.expires_at <= now]
        for handle in expired:
            self._secrets.pop(handle, None)


secret_store = EphemeralSecretStore()