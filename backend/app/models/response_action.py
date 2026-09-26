from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.case import Case
    from app.models.user import User

VALID_ACTION_STATUSES: set[str] = {
    "pending",
    "executing",
    "succeeded",
    "failed",
    "cancelled",
}

VALID_TARGET_TYPES: set[str] = {
    "ip",
    "agent",
}


class ResponseAction(Base):
    """Auditable defensive containment and active response execution record."""

    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("cases.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    alert_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("alerts.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    command: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_value: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), index=True, server_default="pending", nullable=False
    )
    execution_output: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_by_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    case: Mapped["Case | None"] = relationship("Case", backref="response_actions")
    alert: Mapped["Alert | None"] = relationship("Alert", backref="response_actions")
    executed_by: Mapped["User | None"] = relationship("User", foreign_keys=[executed_by_id])

    def __repr__(self) -> str:
        return (
            f"<ResponseAction(id={self.id}, command={self.command!r}, "
            f"target={self.target_value!r}, status={self.status!r})>"
        )
