import os
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from app.db.session import engine


def test_alembic_migration_lifecycle():
    # Load alembic configuration
    ini_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    alembic_cfg = Config(ini_path)

    # 1. Downgrade to base
    command.downgrade(alembic_cfg, "base")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "alerts" not in tables
    assert "cases" not in tables
    assert "users" not in tables
    assert "case_notes" not in tables
    assert "triage_rules" not in tables
    assert "case_evidence" not in tables

    # 2. Upgrade to head
    command.upgrade(alembic_cfg, "head")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "alerts" in tables
    assert "cases" in tables
    assert "users" in tables
    assert "case_notes" in tables
    assert "triage_rules" in tables
    assert "case_evidence" in tables
    assert "alembic_version" in tables

    case_cols = [c["name"] for c in inspector.get_columns("cases")]
    assert "assignee_id" in case_cols
    assert "disposition" in case_cols
    assert "root_cause" in case_cols
    assert "resolution_summary" in case_cols
    assert "resolved_at" in case_cols
    assert "resolved_by_id" in case_cols
