import logging
import os
from collections.abc import Generator

from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)

_REQUIRED_VARS = (
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_DB",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
)


def get_database_url() -> URL:
    missing = [name for name in _REQUIRED_VARS if not os.environ.get(name)]
    if missing:
        logger.error(
            "Database configuration incomplete: missing environment variables: %s",
            ", ".join(missing),
        )
        raise RuntimeError(f"Database configuration incomplete: missing {', '.join(missing)}")

    return URL.create(
        drivername="postgresql+psycopg",
        username=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        host=os.environ["POSTGRES_HOST"],
        port=int(os.environ.get("POSTGRES_PORT", 5432)),
        database=os.environ["POSTGRES_DB"],
    )


def create_db_engine(url: URL | str | None = None) -> Engine:
    target_url = url or get_database_url()
    return create_engine(
        target_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )


def _get_or_create_engine() -> Engine:
    global engine, SessionLocal
    if engine is None:
        engine = create_db_engine()
        SessionLocal.configure(bind=engine)
    return engine


try:
    engine: Engine | None = create_db_engine()
except Exception:
    engine = None

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    _get_or_create_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database() -> None:
    host = os.environ.get("POSTGRES_HOST", "")
    port = os.environ.get("POSTGRES_PORT", "")
    dbname = os.environ.get("POSTGRES_DB", "")
    user = os.environ.get("POSTGRES_USER", "")
    password = os.environ.get("POSTGRES_PASSWORD", "")

    missing = [name for name in _REQUIRED_VARS if not os.environ.get(name)]
    if missing:
        logger.error(
            "PostgreSQL connectivity check failed: missing environment variables: %s",
            ", ".join(missing),
        )
        raise RuntimeError("database configuration incomplete")

    active_engine = _get_or_create_engine()

    try:
        with active_engine.connect() as conn:
            row = conn.execute(text("SELECT 1")).scalar()
        if row != 1:
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
