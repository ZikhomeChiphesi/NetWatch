from __future__ import annotations

import os
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = BASE_DIR / "migrations"
load_dotenv(BASE_DIR / ".env")


def get_connection():
    url = os.getenv("DATABASE_URL")

    if url:
        return psycopg2.connect(url)

    password = os.getenv("DB_PASSWORD")
    if not password:
        raise RuntimeError(
            "DATABASE_URL or DB_PASSWORD must be configured"
        )

    return psycopg2.connect(
        dbname=os.getenv("DB_NAME", "netwatch"),
        user=os.getenv("DB_USER", "postgres"),
        password=password,
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
    )


def run_migrations() -> None:
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        raise RuntimeError(f"No migrations found in {MIGRATIONS_DIR}")

    conn = get_connection()
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.commit()

        for path in files:
            version = path.name

            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = %s",
                    (version,),
                )
                if cur.fetchone():
                    print(f"[migration] already applied: {version}")
                    continue

            sql = path.read_text(encoding="utf-8")

            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    cur.execute(
                        "INSERT INTO schema_migrations(version) VALUES (%s)",
                        (version,),
                    )
                conn.commit()
                print(f"[migration] applied: {version}")
            except Exception:
                conn.rollback()
                raise
    finally:
        conn.close()


if __name__ == "__main__":
    run_migrations()
