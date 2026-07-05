from __future__ import annotations

from pydantic import BaseModel, Field


EMAIL_PATTERN = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(..., min_length=10, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=120)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(..., min_length=1, max_length=128)


class ApiKeyIssueRequest(BaseModel):
    label: str = Field(default="default", min_length=1, max_length=64)


class MlkemKeyRotateRequest(BaseModel):
    confirm: bool = Field(default=True)


class RevokeApiKeyRequest(BaseModel):
    api_key_id: str = Field(..., min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    mlkem_public_key: str
    created_at: float


class ApiKeyResponse(BaseModel):
    id: str
    label: str
    key_prefix: str
    created_at: float
    expires_at: float | None
    revoked_at: float | None
    last_used_at: float | None


class AuthSessionResponse(BaseModel):
    user: UserResponse
    api_key: str
    api_key_id: str
    api_key_prefix: str


class AuthenticatedUserResponse(BaseModel):
    user: UserResponse
    api_key: ApiKeyResponse
