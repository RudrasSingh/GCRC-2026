from __future__ import annotations

from fastapi import Header, HTTPException, status as http_status

from dashboard.auth_store import AuthError, get_auth_repository


def require_user_from_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    if not x_api_key:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    try:
        return get_auth_repository().verify_api_key(x_api_key)
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Unauthorized") from exc