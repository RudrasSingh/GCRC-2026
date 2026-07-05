# API Reference

This server exposes application registration, API-key management, and crypto endpoints.

## Authentication

Most endpoints require `X-API-Key` in the request headers. The key is issued by the registration or login flows.

Example:

```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:8000/auth/me
```

## Environment Variables

- `GCRC_API_KEY`: legacy global key gate. If set, crypto endpoints require it; if empty, the application auth layer handles access through issued API keys.
- `SUPABASE_URL`: optional Supabase project URL.
- `SUPABASE_SERVICE_ROLE_KEY`: optional Supabase service-role secret used for user and API-key persistence.
- `SUPABASE_DB_URL` or `DATABASE_URL`: optional Postgres connection string used to bootstrap tables automatically on startup.

If `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `SUPABASE_DB_URL` are provided, the server connects to Supabase Postgres and creates the required `users` and `api_keys` tables automatically if they do not already exist.

## Auth Endpoints

### `POST /auth/register`

Creates a new user and issues the first API key.

Request body:

```json
{
  "email": "alice@example.com",
  "password": "very-secure-password",
  "full_name": "Alice Example"
}
```

Response fields:

- `user`
- `api_key`
- `api_key_id`
- `api_key_prefix`

The returned `user` object includes the user’s MLKEM public key. The matching private key stays on the server and is never sent to the client.

The MLKEM keypair is generated once at registration time, stored with the user record, and reused by the crypto endpoints. It is not regenerated on each encrypt/decrypt call.

### `POST /auth/login`

Authenticates an existing user and issues a new API key.

The response also includes the current MLKEM public key.

### `GET /auth/me`

Returns the current user and the API key metadata associated with the request.

The user object includes the MLKEM public key.

### `GET /auth/api-keys`

Lists the authenticated user’s API keys.

### `POST /auth/api-keys`

Issues another API key for the authenticated user.

Request body:

```json
{ "label": "mobile-app" }
```

### `DELETE /auth/api-keys/{api_key_id}`

Revokes a specific API key that belongs to the authenticated user.

### `POST /auth/mlkem-keys/rotate`

Rotates the authenticated user’s MLKEM keypair. The new private key remains server-side and the response returns the new public key.

Use this when you want to reissue the user’s keypair without recreating the account.

## Crypto Endpoints

### `POST /kem/keygen`

Rotates the authenticated user’s stored Kyber/ML-KEM keypair and returns the new public key.

### `POST /kem/encapsulate`

Encapsulates to the authenticated user’s stored public key by default. You can still provide an explicit recipient public key if needed.

Request body:

```json
{
  "public_key": "HEX_ENCODED_PUBLIC_KEY"
}
```

### `POST /kem/decapsulate`

Decapsulates a ciphertext using the authenticated user’s stored private key by default.

Request body:

```json
{
  "ciphertext": "HEX_ENCODED_CIPHERTEXT",
  "secret_key_handle": "HANDLE"
}
```

### `POST /crypto/encrypt`

Encrypts a plaintext message using the Kyber-backed DNA-GCRC pipeline and the authenticated user’s stored public key by default.

Request body:

```json
{
  "message": "HELLO WORLD",
  "public_key": "HEX_ENCODED_PUBLIC_KEY"
}
```

### `POST /crypto/decrypt`

Decrypts a package using the authenticated user’s stored private key by default.

Request body:

```json
{
  "package": {
    "cipher_dna": "...",
    "kyber_ciphertext": "...",
    "hmac": "...",
    "length": 0
  },
  "secret_key_handle": "HANDLE"
}
```

## Status Endpoints

- `GET /status` for analysis state
- `POST /start-analysis` to trigger the existing analysis worker

## Quick Local Test

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"very-secure-password","full_name":"Alice Example"}'

curl -X POST http://localhost:8000/kem/keygen \
  -H "X-API-Key: <api_key_from_register>"
```
