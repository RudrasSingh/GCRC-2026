# GCRC Cryptographic API Server Documentation

This document describes the Zero-Knowledge Client-Managed key flow and provides a complete reference for all API endpoints, including input schemas, authentication requirements, and output payloads.

---

## Zero-Knowledge Key Management Flow

To maximize privacy and security, the server enforces a **Zero-Knowledge client-managed private key model**:
1.  **Public Key Storage:** The database only stores the user's ML-KEM public key (`mlkem_public_key_hex`). The database **never** stores or records the corresponding private key (`mlkem_private_key_hex`).
2.  **Immediate Return:** When a user is registered (`/auth/register`), rotates their keys (`/auth/mlkem-keys/rotate`), or generates fresh KEM keys (`/kem/keygen`), the private key is returned **immediately** in the JSON response payload. The client **must** save this key locally (e.g. to a file or client vault).
3.  **Authentication:** Auth endpoints return a `session_token`. All subsequent calls must present this token in the header:
    ```http
    Authorization: Bearer YOUR_SESSION_TOKEN
    ```
4.  **Decryption & Decapsulation:** Since the server does not store the private key, direct server-managed decryption/decapsulation is disabled (attempting to use `"managed-server-side"` returns `400 Bad Request`). The client must supply the private key in one of two ways:
    *   **Ephemeral Handle:** Pass a valid `secret_key_handle` (the private key is temporarily registered in the server's memory cache for 24 hours during keygen).
    *   **Raw Hex Key:** Pass the raw private key hex string directly as the `secret_key_handle`.

---

## Auth & Session Endpoints

### 1. `POST /auth/register`
Creates a user account, generates the initial ML-KEM key pair, registers the public key, and returns the session token along with the private key.

- **Authentication:** Public
- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword123",
    "full_name": "John Doe"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "user": {
      "id": "user_id_string",
      "email": "user@example.com",
      "full_name": "John Doe",
      "mlkem_public_key": "HEX_ENCODED_PUBLIC_KEY",
      "mlkem_private_key": "HEX_ENCODED_PRIVATE_KEY_HERE",
      "created_at": 1690000000.0
    },
    "session_token": "session_token_string"
  }
  ```

---

### 2. `POST /auth/login`
Authenticates user credentials and issues a session token.

- **Authentication:** Public
- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword123"
  }
  ```
- **Response Payload (200 OK):**
  *(Note: `mlkem_private_key` is null as it is not stored in the database)*
  ```json
  {
    "user": {
      "id": "user_id_string",
      "email": "user@example.com",
      "full_name": "John Doe",
      "mlkem_public_key": "HEX_ENCODED_PUBLIC_KEY",
      "mlkem_private_key": null,
      "created_at": 1690000000.0
    },
    "session_token": "session_token_string"
  }
  ```

---

### 3. `POST /auth/logout`
Revokes the current session token.

- **Authentication:** Bearer Session Token
- **Response Payload (200 OK):**
  ```json
  {
    "status": "logged out"
  }
  ```

---

### 4. `GET /auth/me`
Retrieves details of the currently authenticated user session.

- **Authentication:** Bearer Session Token
- **Response Payload (200 OK):**
  ```json
  {
    "user": {
      "id": "user_id_string",
      "email": "user@example.com",
      "full_name": "John Doe",
      "mlkem_public_key": "HEX_ENCODED_PUBLIC_KEY",
      "mlkem_private_key": null,
      "created_at": 1690000000.0
    }
  }
  ```

---

### 5. `POST /auth/mlkem-keys/rotate`
Rotates the user's permanent ML-KEM key pair, updating the public key in the database and returning the private key.

- **Authentication:** Bearer Session Token
- **Request Body:**
  ```json
  {
    "confirm": true
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "id": "user_id_string",
    "email": "user@example.com",
    "full_name": "John Doe",
    "mlkem_public_key": "NEW_HEX_ENCODED_PUBLIC_KEY",
    "mlkem_private_key": "NEW_HEX_ENCODED_PRIVATE_KEY",
    "created_at": 1690000000.0
  }
  ```

---

## Cryptographic Endpoints

### 6. `POST /kem/keygen`
Generates a fresh ML-KEM key pair, registers the private key temporarily in the ephemeral `secret_store` (valid for 24 hours), updates the user's public key in the database, and returns the new keys and handle.

- **Authentication:** Bearer Session Token
- **Response Payload (200 OK):**
  ```json
  {
    "public_key": "HEX_ENCODED_PUBLIC_KEY",
    "secret_key_handle": "ephemeral_secret_key_handle",
    "secret_key_expires_in": 86400,
    "secret_key": "HEX_ENCODED_PRIVATE_KEY"
  }
  ```

---

### 7. `POST /kem/encapsulate`
Encapsulates a shared secret using either the user's public key (default) or a specified public key, returning the ciphertext and an ephemeral shared secret handle.

- **Authentication:** Bearer Session Token
- **Request Body:**
  ```json
  {
    "public_key": "HEX_ENCODED_PUBLIC_KEY_OR_NULL"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "ciphertext": "HEX_ENCODED_CIPHERTEXT",
    "shared_secret_handle": "ephemeral_shared_secret_handle",
    "shared_secret_fingerprint": "SHA256_FINGERPRINT"
  }
  ```

---

### 8. `POST /kem/decapsulate`
Decapsulates Kyber ciphertext to derive the shared secret.

- **Authentication:** Bearer Session Token
- **Request Body:**
  ```json
  {
    "ciphertext": "HEX_ENCODED_CIPHERTEXT",
    "secret_key_handle": "HEX_ENCODED_PRIVATE_KEY_OR_EPHEMERAL_HANDLE"
  }
  ```
  *(Note: Must be either the ephemeral key handle from keygen or the raw private key hex string. If left blank or set to `"managed-server-side"`, returns `400 Bad Request`)*

- **Response Payload (200 OK):**
  ```json
  {
    "shared_secret_handle": "ephemeral_shared_secret_handle",
    "shared_secret_fingerprint": "SHA256_FINGERPRINT"
  }
  ```

---

### 9. `POST /crypto/encrypt`
Encrypts a message using post-quantum Kyber KEM coupled with GCRC DNA-based symmetric encryption.

- **Authentication:** Bearer Session Token
- **Request Body:**
  ```json
  {
    "message": "Secret plaintext message",
    "public_key": "HEX_ENCODED_PUBLIC_KEY_OR_NULL"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "cipher_dna": "DNA_BASES_REPRESENTATION",
    "kyber_ciphertext": "HEX_ENCODED_KYBER_CIPHERTEXT",
    "hmac": "HEX_ENCODED_HMAC_SHA256",
    "length": 128
  }
  ```

---

### 10. `POST /crypto/decrypt`
Decrypts a DNA-GCRC encrypted package.

- **Authentication:** Bearer Session Token
- **Request Body:**
  ```json
  {
    "package": {
      "cipher_dna": "DNA_BASES_REPRESENTATION",
      "kyber_ciphertext": "HEX_ENCODED_KYBER_CIPHERTEXT",
      "hmac": "HEX_ENCODED_HMAC_SHA256",
      "length": 128
    },
    "secret_key_handle": "HEX_ENCODED_PRIVATE_KEY_OR_EPHEMERAL_HANDLE"
  }
  ```
  *(Note: Must be either the ephemeral key handle from keygen or the raw private key hex string. If left blank or set to `"managed-server-side"`, returns `400 Bad Request`)*

- **Response Payload (200 OK):**
  ```json
  {
    "plaintext": "Secret plaintext message"
  }
  ```

---

## Live Monitoring & Status Endpoints

### 11. `POST /start-analysis`
Starts the background GCRC cryptanalysis simulation.

- **Authentication:** Public
- **Response Payload (200 OK):**
  ```json
  {
    "status": "started"
  }
  ```

---

### 12. `GET /status`
Fetches active cryptanalysis status and metrics.

- **Authentication:** Public
- **Response Payload (200 OK):**
  ```json
  {
    "running": true,
    "metrics": {
      "avalanche": 0.5012,
      "entropy": 7.9942,
      "chi_square": 182.4,
      "serial_corr": 0.0015
    }
  }
  ```
