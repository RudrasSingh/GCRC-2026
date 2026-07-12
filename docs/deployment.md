# Docker & Cloud Deployment

This repository containerizes the FastAPI API server, making it ready for local running or production cloud platforms (like Render, AWS, Heroku, etc.).

---

## Deployment Configuration

Production platforms like Render build the application using the [`Dockerfile`](file:///d:/Developer/analysis/Dockerfile).
Since your local [`.env`](file:///d:/Developer/analysis/.env) contains private database credentials, it is included in [`.gitignore`](file:///d:/Developer/analysis/.gitignore) and is not pushed to GitHub.

As a result:
*   The `Dockerfile` does **not** copy the `.env` file during the build stage.
*   Instead, environment variables are injected at runtime by the host environment (Render Dashboard settings or Docker Compose).

---

## How to Deploy on Render

1.  **Create a Web Service:** Link your GitHub repository to a new Web Service on Render.
2.  **Select Environment:** Choose **Docker** as the runtime.
3.  **Configure Environment Variables:**
    In the Render Web Service settings, add the following environment variables (using lowercase names as required by the backend config):
    *   `user` (e.g. `postgres.bdentnuxdbeoafcpiqhh`)
    *   `password` (your database password)
    *   `host` (e.g. `aws-1-ap-south-1.pooler.supabase.com`)
    *   `port` (e.g. `6543`)
    *   `dbname` (e.g. `postgres`)

Render will build the Docker container and automatically run the FastAPI server, exposing it publicly.

---

## Running Locally

### 1. Build and Start the Stack
To boot the FastAPI server locally inside a Docker container:
```bash
docker compose up --build
```
This loads your local `.env` variables and starts the API listening on `http://localhost:8000`.

### 2. Database Bootstrapping
Make sure your database tables are created before making requests. Run the local bootstrapper:
```bash
python create_tables.py
```
This script connects using the credentials in your `.env` file and executes the SQL schema queries. If credentials are not supplied, the backend repository defaults to a volatile in-memory fallback.
