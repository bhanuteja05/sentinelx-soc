from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    wazuh_alert_id: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    agent_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    agent_name: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    rule_level: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decoder: Mapped[str | None] = mapped_column(String(64), nullable=True)

    mitre_tactics: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    raw_alert: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<Alert(id={self.id}, wazuh_alert_id='{self.wazuh_alert_id}', "
            f"rule_id='{self.rule_id}', level={self.rule_level})>"
        )
