# GCRC Cryptographic API Server Documentation (Stateless Version)

This document describes the simplified, stateless API server configuration. There are **no session tokens**, **no authorization headers**, and **no session database tables**. Cryptographic endpoints are stateless utilities that take key inputs directly.

Password validation is relaxed, requiring a minimum of **6** characters (supporting passwords such as `"hello@123"`).

---

## Auth & Account Endpoints

### 1. `POST /auth/register`
Registers a new user, generates their initial ML-KEM key pair, stores the public key in the database, and returns the registration details and the **private key** immediately. The database does not store the private key.

- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "hello@123",
    "full_name": "Atul"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "id": "user_id_string",
    "email": "user@example.com",
    "full_name": "Atul",
    "mlkem_public_key": "HEX_ENCODED_PUBLIC_KEY",
    "mlkem_private_key": "HEX_ENCODED_PRIVATE_KEY",
    "created_at": 1690000000.0
  }
  ```

---

### 2. `POST /auth/login`
Checks database credentials. Returns user details with the private key set to `null` (since the server does not store it).

- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "hello@123"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "id": "user_id_string",
    "email": "user@example.com",
    "full_name": "Atul",
    "mlkem_public_key": "HEX_ENCODED_PUBLIC_KEY",
    "mlkem_private_key": null,
    "created_at": 1690000000.0
  }
  ```

---

### 3. `POST /auth/mlkem-keys/rotate`
Authenticates credentials and rotates the user's permanent key pair. The new public key is stored in the database, and the new private key is returned in the response.

- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "hello@123"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "id": "user_id_string",
    "email": "user@example.com",
    "full_name": "Atul",
    "mlkem_public_key": "NEW_HEX_ENCODED_PUBLIC_KEY",
    "mlkem_private_key": "NEW_HEX_ENCODED_PRIVATE_KEY",
    "created_at": 1690000000.0
  }
  ```

---

## Cryptographic Utility Endpoints

These endpoints are stateless and do not require any session headers or logins.

### 4. `POST /kem/keygen`
Utility to generate a random post-quantum ML-KEM key pair.

- **Response Payload (200 OK):**
  ```json
  {
    "public_key": "HEX_ENCODED_PUBLIC_KEY",
    "secret_key": "HEX_ENCODED_PRIVATE_KEY"
  }
  ```

---

### 5. `POST /kem/encapsulate`
Encapsulates a shared secret using the provided public key.

- **Request Body:**
  ```json
  {
    "public_key": "HEX_ENCODED_PUBLIC_KEY"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "ciphertext": "HEX_ENCODED_CIPHERTEXT",
    "shared_secret": "HEX_ENCODED_SHARED_SECRET",
    "shared_secret_fingerprint": "SHA256_FINGERPRINT_OF_SECRET"
  }
  ```

---

### 6. `POST /kem/decapsulate`
Decapsulates a ciphertext using the provided raw private key to derive the shared secret.

- **Request Body:**
  ```json
  {
    "ciphertext": "HEX_ENCODED_CIPHERTEXT",
    "secret_key": "HEX_ENCODED_PRIVATE_KEY"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "shared_secret": "HEX_ENCODED_SHARED_SECRET",
    "shared_secret_fingerprint": "SHA256_FINGERPRINT_OF_SECRET"
  }
  ```

---

### 7. `POST /crypto/encrypt`
Encrypts a message using post-quantum Kyber KEM coupled with GCRC DNA-based symmetric encryption.
*Note: You can pass a `public_key` directly, or specify an `email` to let the server look up the user's public key in the database.*

- **Request Body:**
  ```json
  {
    "message": "Secret message to encrypt",
    "public_key": "HEX_ENCODED_PUBLIC_KEY_OR_NULL",
    "email": "user@example.com"
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

### 8. `POST /crypto/decrypt`
Decrypts a GCRC encrypted package using the provided raw private key.

- **Request Body:**
  ```json
  {
    "package": {
      "cipher_dna": "DNA_BASES_REPRESENTATION",
      "kyber_ciphertext": "HEX_ENCODED_KYBER_CIPHERTEXT",
      "hmac": "HEX_ENCODED_HMAC_SHA256",
      "length": 128
    },
    "secret_key": "HEX_ENCODED_PRIVATE_KEY"
  }
  ```
- **Response Payload (200 OK):**
  ```json
  {
    "plaintext": "Secret message to encrypt"
  }
  ```

---

## Live Monitoring & Status Endpoints

### 9. `POST /start-analysis`
Starts the background GCRC cryptanalysis simulation.

- **Response Payload (200 OK):**
  ```json
  {
    "status": "started"
  }
  ```

---

### 10. `GET /status`
Fetches active cryptanalysis status and metrics.

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
