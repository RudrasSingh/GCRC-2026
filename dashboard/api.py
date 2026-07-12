import hashlib
import hmac
import os
import threading
import time

from fastapi import Depends, FastAPI, HTTPException, status as http_status
from pydantic import BaseModel, Field

from dashboard.metrics import run_metrics
from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import dna_to_text, text_to_dna
from pqc.kyber_mlkem import decapsulate, encapsulate, generate_keys

from dashboard.auth_models import (
    AuthSessionResponse,
    AuthenticatedUserResponse,
    LoginRequest,
    RegisterRequest,
    UserResponse,
    MlkemKeyRotateRequest,
)
from dashboard.auth_store import AuthError, get_auth_repository
from dashboard.crypto_store import secret_store
from dashboard.security import require_user_from_session


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
    secret_key_handle: str | None = Field(default=None, min_length=1, max_length=MAX_HEX_LENGTH)


class PublicKeyRequest(BaseModel):
    public_key: str | None = Field(default=None, min_length=1, max_length=MAX_HEX_LENGTH)


class KeygenResponse(BaseModel):
    public_key: str
    secret_key_handle: str
    secret_key_expires_in: int
    secret_key: str | None = None


class EncapsulateResponse(BaseModel):
    ciphertext: str
    shared_secret_handle: str
    shared_secret_fingerprint: str


class DecapsulateRequest(BaseModel):
    ciphertext: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)
    secret_key_handle: str | None = Field(default=None, min_length=1, max_length=MAX_HEX_LENGTH)


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
        mlkem_private_key=None,
        created_at=user.created_at,
    )


app = FastAPI()

analysis_running = False
current_metrics = {}


def run_analysis():
    global analysis_running, current_metrics
    analysis_running = True
    for _ in range(50):
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
        user_res = _user_response(session.user)
        user_res.mlkem_private_key = session.mlkem_private_key
        return AuthSessionResponse(
            user=user_res,
            session_token=session.session_token,
        )
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/auth/login", response_model=AuthSessionResponse)
def login_endpoint(request: LoginRequest):
    try:
        session = get_auth_repository().authenticate(request.email, request.password)
        return AuthSessionResponse(
            user=_user_response(session.user),
            session_token=session.session_token,
        )
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials") from exc


@app.post("/auth/logout")
def logout_endpoint(auth_context=Depends(require_user_from_session)):
    _, session = auth_context
    get_auth_repository().logout(session.session_token)
    return {"status": "logged out"}


@app.get("/auth/me", response_model=AuthenticatedUserResponse)
def me_endpoint(auth_context=Depends(require_user_from_session)):
    user, _ = auth_context
    return AuthenticatedUserResponse(user=_user_response(user))


@app.post("/auth/mlkem-keys/rotate", response_model=UserResponse)
def rotate_mlkem_keys_endpoint(request: MlkemKeyRotateRequest, auth_context=Depends(require_user_from_session)):
    user, _ = auth_context
    if not request.confirm:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Rotation not confirmed")

    try:
        updated_user, private_key_hex = get_auth_repository().rotate_mlkem_keys(user.id)
        user_res = _user_response(updated_user)
        user_res.mlkem_private_key = private_key_hex
        return user_res
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@app.post("/crypto/encrypt", response_model=EncryptResponse)
def encrypt_endpoint(request: EncryptRequest, auth_context=Depends(require_user_from_session)):
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
def decrypt_endpoint(request: DecryptRequest, auth_context=Depends(require_user_from_session)):
    try:
        secret_key_handle = request.secret_key_handle
        if secret_key_handle is None or secret_key_handle == "managed-server-side":
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail="Direct server-managed decryption is disabled. You must provide a valid secret_key_handle (ephemeral handle) or the raw secret_key hex string directly."
            )

        try:
            secret_key_bytes = secret_store.resolve(secret_key_handle, "mlkem_private_key")
            secret_key_hex = secret_key_bytes.hex()
        except KeyError:
            secret_key_hex = secret_key_handle

        secret_key = _decode_hex(secret_key_hex, "private key")
        plaintext = _decrypt_package(request.package, secret_key)
        return DecryptResponse(plaintext=plaintext)
    except HTTPException:
        raise
    except KeyError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Secret key handle not found") from exc
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decryption failed")


@app.post("/kem/keygen", response_model=KeygenResponse)
def kem_keygen_endpoint(auth_context=Depends(require_user_from_session)):
    user, _ = auth_context
    updated_user, private_key_hex = get_auth_repository().rotate_mlkem_keys(user.id)
    
    # Store in ephemeral secret_store to allow resolution via returned handle
    secret_key_handle = secret_store.put(
        bytes.fromhex(private_key_hex),
        kind="mlkem_private_key",
        ttl_seconds=DEFAULT_SECRET_TTL_SECONDS
    )

    return KeygenResponse(
        public_key=updated_user.mlkem_public_key_hex,
        secret_key_handle=secret_key_handle,
        secret_key_expires_in=DEFAULT_SECRET_TTL_SECONDS,
        secret_key=private_key_hex,
    )


@app.post("/kem/encapsulate", response_model=EncapsulateResponse)
def kem_encapsulate_endpoint(request: PublicKeyRequest, auth_context=Depends(require_user_from_session)):
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
def kem_decapsulate_endpoint(request: DecapsulateRequest, auth_context=Depends(require_user_from_session)):
    try:
        secret_key_handle = request.secret_key_handle
        if secret_key_handle is None or secret_key_handle == "managed-server-side":
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail="Direct server-managed decapsulation is disabled. You must provide a valid secret_key_handle (ephemeral handle) or the raw secret_key hex string directly."
            )

        try:
            secret_key_bytes = secret_store.resolve(secret_key_handle, "mlkem_private_key")
            secret_key_hex = secret_key_bytes.hex()
        except KeyError:
            secret_key_hex = secret_key_handle

        secret_key = _decode_hex(secret_key_hex, "private key")
        ciphertext = _decode_hex(request.ciphertext, "Kyber ciphertext")
        shared_key = decapsulate(ciphertext, secret_key)
        shared_secret_handle = secret_store.put(shared_key, kind="shared_secret", ttl_seconds=DEFAULT_SECRET_TTL_SECONDS)

        return DecapsulateResponse(
            shared_secret_handle=shared_secret_handle,
            shared_secret_fingerprint=_fingerprint(shared_key),
        )
    except HTTPException:
        raise
    except KeyError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Secret key handle not found") from exc
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decapsulation failed")