from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

VALID_ACTION_TYPES: set[str] = {"correlate_or_create", "create_case"}
VALID_CASE_SEVERITIES: set[str] = {"critical", "high", "medium", "low"}


class TriageRule(Base):
    __tablename__ = "triage_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)

    # Matching criteria
    min_rule_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    # Action configuration
    action_type: Mapped[str] = mapped_column(
        String(32), default="correlate_or_create", nullable=False
    )
    case_severity: Mapped[str] = mapped_column(String(32), default="high", nullable=False)
    case_title_template: Mapped[str] = mapped_column(
        String(255),
        default="[Auto-Triage] {rule_name}: {alert_description}",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<TriageRule(id={self.id}, name='{self.name}', is_active={self.is_active})>"
