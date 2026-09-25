from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.case_alert import CaseAlert
    from app.models.case_evidence import CaseEvidence
    from app.models.case_note import CaseNote
    from app.models.user import User

VALID_DISPOSITIONS: set[str] = {
    "true_positive_incident",
    "false_positive_benign",
    "benign_authorized_activity",
}

VALID_ROOT_CAUSES: set[str] = {
    "malware_execution",
    "credential_compromise",
    "privilege_escalation",
    "unauthorized_access",
    "misconfiguration",
    "policy_violation",
    "security_testing",
}


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True, nullable=False)

    assignee_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    disposition: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    root_cause: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    resolution_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assignee: Mapped["User | None"] = relationship(
        "User",
        foreign_keys=[assignee_id],
        lazy="joined",
    )
    resolved_by: Mapped["User | None"] = relationship(
        "User",
        foreign_keys=[resolved_by_id],
        lazy="joined",
    )
    case_alerts: Mapped[list["CaseAlert"]] = relationship(
        "CaseAlert",
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        secondary="case_alerts",
        viewonly=True,
    )
    notes: Mapped[list["CaseNote"]] = relationship(
        "CaseNote",
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CaseNote.created_at.asc()",
    )
    evidence: Mapped[list["CaseEvidence"]] = relationship(
        "CaseEvidence",
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CaseEvidence.created_at.asc()",
    )

    def __repr__(self) -> str:
        return f"<Case(id={self.id}, title='{self.title}', status='{self.status}', severity='{self.severity}')>"
