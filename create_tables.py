import os
import urllib.parse
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv
from dashboard.auth_store import SUPABASE_SCHEMA_SQL

load_dotenv()

def create_tables():
    user = os.getenv("user", "").strip()
    password = os.getenv("password", "").strip()
    host = os.getenv("host", "").strip()
    port = os.getenv("port", "").strip() or "6543"
    dbname = os.getenv("dbname", "").strip() or "postgres"

    if not (user and password and host):
        print("Error: Database environment variables (user, password, host) are not fully set in .env.")
        return

    safe_user = urllib.parse.quote_plus(user)
    safe_password = urllib.parse.quote_plus(password)
    db_url = f"postgresql+psycopg2://{safe_user}:{safe_password}@{host}:{port}/{dbname}?sslmode=require"
    
    print("Connecting to database using SQLAlchemy...")
    try:
        engine = create_engine(db_url, poolclass=NullPool)
        with engine.begin() as connection:
            print("Executing schema script...")
            connection.execute(text(SUPABASE_SCHEMA_SQL))
            print("Tables created/verified successfully.")
    except Exception as e:
        print(f"Error creating tables: {e}")

if __name__ == "__main__":
    create_tables()
