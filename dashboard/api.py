import hashlib
import hmac
import os
import threading
import time

from fastapi import Depends, FastAPI, HTTPException, status as http_status
from pydantic import BaseModel, Field

from analysis.metrics import run_metrics
from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import dna_to_text, text_to_dna
from pqc.kyber_mlkem import decapsulate, encapsulate, generate_keys

from dashboard.auth_models import (
    ApiKeyIssueRequest,
    ApiKeyResponse,
    AuthSessionResponse,
    AuthenticatedUserResponse,
    LoginRequest,
    RegisterRequest,
    RevokeApiKeyRequest,
    UserResponse,
    MlkemKeyRotateRequest,
)
from dashboard.auth_store import AuthError, get_auth_repository
from dashboard.crypto_store import secret_store
from dashboard.security import require_user_from_api_key


MAX_MESSAGE_LENGTH = 32768
MAX_HEX_LENGTH = 16384
MAX_HANDLE_LENGTH = 128
DEFAULT_SECRET_TTL_SECONDS = 24 * 60 * 60


class CryptoError(Exception):
    pass


class EncryptedPackage(BaseModel):
    cipher_dna: str = Field(..., min_length=1, max_length=MAX_MESSAGE_LENGTH * 4)
    kyber_ciphertext: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)
    hmac: str = Field(..., min_length=64, max_length=64)
    length: int = Field(..., ge=0, le=MAX_MESSAGE_LENGTH)


class EncryptRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_MESSAGE_LENGTH)
    public_key: str | None = Field(default=None, min_length=1, max_length=MAX_HEX_LENGTH)


class DecryptRequest(BaseModel):
    package: EncryptedPackage
    secret_key_handle: str | None = Field(default=None, min_length=1, max_length=MAX_HANDLE_LENGTH)


class PublicKeyRequest(BaseModel):
    public_key: str | None = Field(default=None, min_length=1, max_length=MAX_HEX_LENGTH)


class KeygenResponse(BaseModel):
    public_key: str
    secret_key_handle: str
    secret_key_expires_in: int


class EncapsulateResponse(BaseModel):
    ciphertext: str
    shared_secret_handle: str
    shared_secret_fingerprint: str


class DecapsulateRequest(BaseModel):
    ciphertext: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)
    secret_key_handle: str | None = Field(default=None, min_length=1, max_length=MAX_HANDLE_LENGTH)


class DecapsulateResponse(BaseModel):
    shared_secret_handle: str
    shared_secret_fingerprint: str


class EncryptResponse(EncryptedPackage):
    pass


class DecryptResponse(BaseModel):
    plaintext: str


def _decode_hex(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise CryptoError(f"Invalid {label}") from exc


def _fingerprint(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _encrypt_message(message: str, public_key: bytes) -> EncryptResponse:
    kem_ciphertext, shared_key = encapsulate(public_key)
    dna_key = hashlib.sha256(shared_key).hexdigest()[:32]

    cipher = GCRC(dna_key)
    dna = text_to_dna(message)
    encrypted_dna = cipher.encrypt(dna)
    hmac_tag = hmac.new(shared_key, encrypted_dna.encode(), hashlib.sha256).hexdigest()

    return EncryptResponse(
        cipher_dna=encrypted_dna,
        kyber_ciphertext=kem_ciphertext.hex(),
        hmac=hmac_tag,
        length=len(dna),
    )


def _decrypt_package(package: EncryptedPackage, secret_key: bytes) -> str:
    kem_cipher = _decode_hex(package.kyber_ciphertext, "Kyber ciphertext")
    shared_key = decapsulate(kem_cipher, secret_key)

    computed_hmac = hmac.new(
        shared_key,
        package.cipher_dna.encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(package.hmac, computed_hmac):
        raise CryptoError("Ciphertext integrity check failed")

    dna_key = hashlib.sha256(shared_key).hexdigest()[:32]
    cipher = GCRC(dna_key)
    decrypted_dna = cipher.decrypt(package.cipher_dna)

    if package.length > len(decrypted_dna):
        raise CryptoError("Invalid package length")

    decrypted_dna = decrypted_dna[:package.length]
    return dna_to_text(decrypted_dna)


def _user_response(user) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        mlkem_public_key=user.mlkem_public_key_hex,
        created_at=user.created_at,
    )


def _api_key_response(api_key) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=api_key.id,
        label=api_key.label,
        key_prefix=api_key.key_prefix,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
        last_used_at=api_key.last_used_at,
    )

app = FastAPI()

analysis_running = False
current_metrics = {}


def run_analysis():

    global analysis_running, current_metrics

    analysis_running = True

    for i in range(50):

        current_metrics = run_metrics(200)

        time.sleep(1)

    analysis_running = False


@app.post("/start-analysis")
def start_analysis():

    global analysis_running

    if analysis_running:
        return {"status": "already running"}

    thread = threading.Thread(target=run_analysis)
    thread.start()

    return {"status": "started"}


@app.get("/status")
def status():

    return {
        "running": analysis_running,
        "metrics": current_metrics
    }


@app.post("/auth/register", response_model=AuthSessionResponse)
def register_endpoint(request: RegisterRequest):
    try:
        session = get_auth_repository().create_user(request.email, request.full_name, request.password)
        return AuthSessionResponse(
            user=_user_response(session.user),
            api_key=session.plain_api_key,
            api_key_id=session.api_key.id,
            api_key_prefix=session.api_key.key_prefix,
        )
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/auth/login", response_model=AuthSessionResponse)
def login_endpoint(request: LoginRequest):
    try:
        session = get_auth_repository().authenticate(request.email, request.password)
        return AuthSessionResponse(
            user=_user_response(session.user),
            api_key=session.plain_api_key,
            api_key_id=session.api_key.id,
            api_key_prefix=session.api_key.key_prefix,
        )
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials") from exc


@app.get("/auth/me", response_model=AuthenticatedUserResponse)
def me_endpoint(auth_context=Depends(require_user_from_api_key)):
    user, api_key = auth_context
    return AuthenticatedUserResponse(user=_user_response(user), api_key=_api_key_response(api_key))


@app.get("/auth/api-keys", response_model=list[ApiKeyResponse])
def list_api_keys_endpoint(auth_context=Depends(require_user_from_api_key)):
    user, _ = auth_context
    return [_api_key_response(api_key) for api_key in get_auth_repository().list_api_keys(user.id)]


@app.post("/auth/api-keys", response_model=AuthSessionResponse)
def issue_api_key_endpoint(request: ApiKeyIssueRequest, auth_context=Depends(require_user_from_api_key)):
    user, _ = auth_context
    api_key, plain_api_key = get_auth_repository().issue_api_key(user.id, label=request.label)
    return AuthSessionResponse(
        user=_user_response(user),
        api_key=plain_api_key,
        api_key_id=api_key.id,
        api_key_prefix=api_key.key_prefix,
    )


@app.delete("/auth/api-keys/{api_key_id}")
def revoke_api_key_endpoint(api_key_id: str, auth_context=Depends(require_user_from_api_key)):
    user, _ = auth_context
    try:
        get_auth_repository().revoke_api_key(user.id, api_key_id)
        return {"status": "revoked"}
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@app.post("/auth/mlkem-keys/rotate", response_model=UserResponse)
def rotate_mlkem_keys_endpoint(request: MlkemKeyRotateRequest, auth_context=Depends(require_user_from_api_key)):
    user, _ = auth_context
    if not request.confirm:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Rotation not confirmed")

    try:
        updated_user = get_auth_repository().rotate_mlkem_keys(user.id)
        return _user_response(updated_user)
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@app.post("/crypto/encrypt", response_model=EncryptResponse)
def encrypt_endpoint(request: EncryptRequest, auth_context=Depends(require_user_from_api_key)):

    try:
        user, _ = auth_context
        public_key_hex = request.public_key or user.mlkem_public_key_hex
        public_key = _decode_hex(public_key_hex, "public key")
        return _encrypt_message(request.message, public_key)
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption failed")


@app.post("/crypto/decrypt", response_model=DecryptResponse)
def decrypt_endpoint(request: DecryptRequest, auth_context=Depends(require_user_from_api_key)):

    try:
        user, _ = auth_context
        secret_key_hex = request.secret_key_handle or user.mlkem_private_key_hex
        secret_key = _decode_hex(secret_key_hex, "private key")
        plaintext = _decrypt_package(request.package, secret_key)
        return DecryptResponse(plaintext=plaintext)
    except KeyError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Secret key handle not found") from exc
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decryption failed")


@app.post("/kem/keygen", response_model=KeygenResponse)
def kem_keygen_endpoint(auth_context=Depends(require_user_from_api_key)):

    user, _ = auth_context
    updated_user = get_auth_repository().rotate_mlkem_keys(user.id)

    return KeygenResponse(
        public_key=updated_user.mlkem_public_key_hex,
        secret_key_handle="managed-server-side",
        secret_key_expires_in=DEFAULT_SECRET_TTL_SECONDS,
    )


@app.post("/kem/encapsulate", response_model=EncapsulateResponse)
def kem_encapsulate_endpoint(request: PublicKeyRequest, auth_context=Depends(require_user_from_api_key)):

    try:
        user, _ = auth_context
        public_key_hex = request.public_key or user.mlkem_public_key_hex
        public_key = _decode_hex(public_key_hex, "public key")
        ciphertext, shared_key = encapsulate(public_key)
        shared_secret_handle = secret_store.put(shared_key, kind="shared_secret", ttl_seconds=DEFAULT_SECRET_TTL_SECONDS)

        return EncapsulateResponse(
            ciphertext=ciphertext.hex(),
            shared_secret_handle=shared_secret_handle,
            shared_secret_fingerprint=_fingerprint(shared_key),
        )
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encapsulation failed")


@app.post("/kem/decapsulate", response_model=DecapsulateResponse)
def kem_decapsulate_endpoint(request: DecapsulateRequest, auth_context=Depends(require_user_from_api_key)):

    try:
        user, _ = auth_context
        secret_key_hex = request.secret_key_handle or user.mlkem_private_key_hex
        secret_key = _decode_hex(secret_key_hex, "private key")
        ciphertext = _decode_hex(request.ciphertext, "Kyber ciphertext")
        shared_key = decapsulate(ciphertext, secret_key)
        shared_secret_handle = secret_store.put(shared_key, kind="shared_secret", ttl_seconds=DEFAULT_SECRET_TTL_SECONDS)

        return DecapsulateResponse(
            shared_secret_handle=shared_secret_handle,
            shared_secret_fingerprint=_fingerprint(shared_key),
        )
    except KeyError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Secret key handle not found") from exc
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decapsulation failed")