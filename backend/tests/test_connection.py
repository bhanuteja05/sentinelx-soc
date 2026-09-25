import os
import pytest
from sqlalchemy import text

from app.db.session import check_database, create_db_engine, get_database_url


def test_database_url_from_env():
    url = get_database_url()
    assert url.drivername == "postgresql+psycopg"
    assert url.username == os.environ["POSTGRES_USER"]
    assert url.database == os.environ["POSTGRES_DB"]
    assert url.host == os.environ["POSTGRES_HOST"]


def test_database_url_missing_env_raises(monkeypatch):
    monkeypatch.delenv("POSTGRES_DB", raising=False)
    with pytest.raises(RuntimeError, match="missing POSTGRES_DB"):
        get_database_url()


def test_database_connection(engine):
    with engine.connect() as conn:
        val = conn.execute(text("SELECT 1")).scalar()
        assert val == 1


def test_check_database_helper():
    # Should run without error on healthy database
    check_database()
