import os
from collections.abc import Generator

# Disable background Wazuh ingestion polling during test execution to prevent
# asynchronous polling cycles from polluting database test fixtures.
os.environ["WAZUH_INGEST_ENABLED"] = "false"

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, _get_or_create_engine
from app.wazuh.config import get_wazuh_settings
from app.wazuh.scheduler import wazuh_scheduler

wazuh_scheduler.settings = get_wazuh_settings()


@pytest.fixture(scope="session")
def engine():
    return _get_or_create_engine()


@pytest.fixture
def db_session(engine) -> Generator[Session, None, None]:
    connection = engine.connect()
    session = Session(bind=connection)

    yield session

    session.close()
    connection.close()


@pytest.fixture
def clean_db(db_session: Session) -> Session:
    db_session.execute(text("TRUNCATE TABLE users, alerts, cases, case_alerts, case_notes, triage_rules RESTART IDENTITY CASCADE"))
    db_session.commit()
    return db_session
