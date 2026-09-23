import logging
import os

import psycopg

logger = logging.getLogger(__name__)

_REQUIRED_VARS = (
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_DB",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
)


def check_database() -> None:
    missing = [name for name in _REQUIRED_VARS if not os.environ.get(name)]
    if missing:
        logger.error(
            "PostgreSQL connectivity check failed: missing environment variables: %s",
            ", ".join(missing),
        )
        raise RuntimeError("database configuration incomplete")

    host = os.environ["POSTGRES_HOST"]
    port = os.environ["POSTGRES_PORT"]
    dbname = os.environ["POSTGRES_DB"]
    user = os.environ["POSTGRES_USER"]
    password = os.environ["POSTGRES_PASSWORD"]

    try:
        with psycopg.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            connect_timeout=5,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                row = cur.fetchone()
        if row is None or row[0] != 1:
            raise RuntimeError("unexpected result from SELECT 1")
    except Exception as exc:
        logger.error(
            "PostgreSQL connectivity check failed (%s): %s host=%s port=%s dbname=%s user=%s",
            type(exc).__name__,
            str(exc).replace(password, "***"),
            host,
            port,
            dbname,
            user,
        )
        raise
