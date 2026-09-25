from collections.abc import Generator

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, _get_or_create_engine


@pytest.fixture(scope="session")
def engine():
    return _get_or_create_engine()


@pytest.fixture
def db_session(engine) -> Generator[Session, None, None]:
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)

    yield session

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


@pytest.fixture
def clean_db(db_session: Session) -> Session:
    db_session.execute(text("TRUNCATE TABLE alerts, cases RESTART IDENTITY CASCADE"))
    db_session.commit()
    return db_session
