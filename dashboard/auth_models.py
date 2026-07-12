from __future__ import annotations

from pydantic import BaseModel, Field

EMAIL_PATTERN = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(..., min_length=6, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=120)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(..., min_length=1, max_length=128)


class MlkemKeyRotateRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, pattern=EMAIL_PATTERN)
    password: str = Field(..., min_length=1, max_length=128)


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    mlkem_public_key: str
    mlkem_private_key: str | None = None
    created_at: float
