# Docker Deployment

This repository includes a container image for the FastAPI server.

## Files

- `Dockerfile` builds the API server image.
- `docker-compose.yml` runs the server locally on port `8000`.
- `.env` can be used to pass Supabase credentials and the optional legacy API key.

## Start the server

```bash
docker compose up --build
```

The API will be available at `http://localhost:8000`.

## Test the endpoints

1. Register a user.
2. Copy the returned `api_key`.
3. Use `/auth/me` to view the stored MLKEM public key for the account.
4. Call the crypto and KEM endpoints with `X-API-Key`; the server uses the stored private key automatically unless you override the public key for a recipient.
5. Use `/auth/api-keys` and `/auth/mlkem-keys/rotate` to manage the account state.

## Supabase mode

Set these environment variables when you want persistence:

```bash
SUPABASE_URL=...
SUPABASE_SERVICE_ROLE_KEY=...
SUPABASE_DB_URL=...
```

`SUPABASE_DB_URL` should be the Postgres connection string from your Supabase project. When all three variables are present, the server will create the required tables automatically on startup if they do not exist yet.

If they are omitted, the server uses in-memory storage for local testing.

For a travel-friendly setup, place the values in a local `.env` file and start the stack with:

```bash
docker compose up --build
```

The container will boot, bootstrap the database schema if Supabase credentials are present, and expose the API on `http://localhost:8000`.
