import hashlib
import hmac
import os
import threading
import time

from fastapi import FastAPI, HTTPException, status as http_status
from pydantic import BaseModel, Field

from dashboard.metrics import run_metrics
from cipher.gcrc_cipher import GCRC
from encoding.dna_codec import dna_to_text, text_to_dna
from pqc.kyber_mlkem import decapsulate, encapsulate, generate_keys

from dashboard.auth_models import (
    LoginRequest,
    RegisterRequest,
    UserResponse,
    MlkemKeyRotateRequest,
)
from dashboard.auth_store import AuthError, get_auth_repository


MAX_MESSAGE_LENGTH = 32768
MAX_HEX_LENGTH = 16384


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
    email: str | None = Field(default=None, min_length=3, max_length=254)


class DecryptRequest(BaseModel):
    package: EncryptedPackage
    secret_key: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)


class KeygenResponse(BaseModel):
    public_key: str
    secret_key: str


class EncapsulateRequest(BaseModel):
    public_key: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)


class EncapsulateResponse(BaseModel):
    ciphertext: str
    shared_secret: str
    shared_secret_fingerprint: str


class DecapsulateRequest(BaseModel):
    ciphertext: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)
    secret_key: str = Field(..., min_length=1, max_length=MAX_HEX_LENGTH)


class DecapsulateResponse(BaseModel):
    shared_secret: str
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


@app.post("/auth/register", response_model=UserResponse)
def register_endpoint(request: RegisterRequest):
    try:
        user, private_key_hex = get_auth_repository().create_user(request.email, request.full_name, request.password)
        user_res = _user_response(user)
        user_res.mlkem_private_key = private_key_hex
        return user_res
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/auth/login", response_model=UserResponse)
def login_endpoint(request: LoginRequest):
    try:
        user = get_auth_repository().authenticate(request.email, request.password)
        return _user_response(user)
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials") from exc


@app.post("/auth/mlkem-keys/rotate", response_model=UserResponse)
def rotate_mlkem_keys_endpoint(request: MlkemKeyRotateRequest):
    try:
        user, private_key_hex = get_auth_repository().rotate_mlkem_keys(request.email, request.password)
        user_res = _user_response(user)
        user_res.mlkem_private_key = private_key_hex
        return user_res
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@app.post("/crypto/encrypt", response_model=EncryptResponse)
def encrypt_endpoint(request: EncryptRequest):
    try:
        if request.public_key:
            public_key_hex = request.public_key
        elif request.email:
            user = get_auth_repository().get_user_by_email(request.email)
            public_key_hex = user.mlkem_public_key_hex
        else:
            raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Must provide either public_key or email")
        
        public_key = _decode_hex(public_key_hex, "public key")
        return _encrypt_message(request.message, public_key)
    except AuthError as exc:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption failed")


@app.post("/crypto/decrypt", response_model=DecryptResponse)
def decrypt_endpoint(request: DecryptRequest):
    try:
        secret_key = _decode_hex(request.secret_key, "private key")
        plaintext = _decrypt_package(request.package, secret_key)
        return DecryptResponse(plaintext=plaintext)
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decryption failed")


@app.post("/kem/keygen", response_model=KeygenResponse)
def kem_keygen_endpoint():
    try:
        public_key, secret_key = generate_keys()
        return KeygenResponse(
            public_key=public_key.hex(),
            secret_key=secret_key.hex(),
        )
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Keygen failed")


@app.post("/kem/encapsulate", response_model=EncapsulateResponse)
def kem_encapsulate_endpoint(request: EncapsulateRequest):
    try:
        public_key = _decode_hex(request.public_key, "public key")
        ciphertext, shared_key = encapsulate(public_key)
        return EncapsulateResponse(
            ciphertext=ciphertext.hex(),
            shared_secret=shared_key.hex(),
            shared_secret_fingerprint=_fingerprint(shared_key),
        )
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encapsulation failed")


@app.post("/kem/decapsulate", response_model=DecapsulateResponse)
def kem_decapsulate_endpoint(request: DecapsulateRequest):
    try:
        secret_key = _decode_hex(request.secret_key, "private key")
        ciphertext = _decode_hex(request.ciphertext, "Kyber ciphertext")
        shared_key = decapsulate(ciphertext, secret_key)
        return DecapsulateResponse(
            shared_secret=shared_key.hex(),
            shared_secret_fingerprint=_fingerprint(shared_key),
        )
    except CryptoError as exc:
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decapsulation failed")