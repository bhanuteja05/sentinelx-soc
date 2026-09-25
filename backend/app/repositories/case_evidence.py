from typing import Any

from sqlalchemy.orm import Session

from app.models.case_evidence import CaseEvidence


def create_evidence(db: Session, evidence: CaseEvidence) -> CaseEvidence:
    """Persist a new CaseEvidence item."""
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def get_evidence_by_id(db: Session, evidence_id: int) -> CaseEvidence | None:
    """Retrieve an evidence item by its primary key."""
    return db.query(CaseEvidence).filter(CaseEvidence.id == evidence_id).first()


def list_case_evidence(db: Session, case_id: int) -> list[CaseEvidence]:
    """Retrieve all evidence cataloged for a specific case, ordered chronologically."""
    return (
        db.query(CaseEvidence)
        .filter(CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.created_at.asc())
        .all()
    )


def get_evidence_by_case_type_value(
    db: Session, case_id: int, evidence_type: str, value: str
) -> CaseEvidence | None:
    """Look up an evidence item by case_id, evidence_type, and value for deduplication."""
    return (
        db.query(CaseEvidence)
        .filter(
            CaseEvidence.case_id == case_id,
            CaseEvidence.evidence_type == evidence_type,
            CaseEvidence.value == value,
        )
        .first()
    )


def update_evidence(
    db: Session, evidence: CaseEvidence, updates: dict[str, Any]
) -> CaseEvidence:
    """Update fields on an existing evidence item."""
    for key, value in updates.items():
        setattr(evidence, key, value)
    db.commit()
    db.refresh(evidence)
    return evidence


def delete_evidence(db: Session, evidence: CaseEvidence) -> None:
    """Delete an evidence item."""
    db.delete(evidence)
    db.commit()
