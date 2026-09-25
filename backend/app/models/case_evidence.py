from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.case import Case
    from app.models.user import User

VALID_EVIDENCE_TYPES: set[str] = {
    "ip",
    "domain",
    "hash_sha256",
    "hash_md5",
    "url",
    "file_path",
    "user_account",
    "host",
}

VALID_VERDICTS: set[str] = {
    "malicious",
    "suspicious",
    "benign",
    "informational",
}


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("cases.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    alert_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("alerts.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    evidence_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    verdict: Mapped[str] = mapped_column(
        String(32), index=True, server_default="suspicious", nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
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

    case: Mapped["Case"] = relationship("Case", back_populates="evidence")
    alert: Mapped["Alert | None"] = relationship("Alert", lazy="joined")
    added_by: Mapped["User | None"] = relationship("User", lazy="joined")

    def __repr__(self) -> str:
        return (
            f"<CaseEvidence(id={self.id}, case_id={self.case_id}, "
            f"type='{self.evidence_type}', verdict='{self.verdict}')>"
        )
