"""
backend/app/api/enrichment.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Alert enrichment endpoints — IOC extraction and MITRE ATT&CK mapping.

These endpoints are read-only and operate on alerts that are already
persisted in PostgreSQL. They do NOT modify the alert row; enrichment
is computed on-demand and returned in the response.

Endpoints
---------
GET /api/v1/alerts/{alert_id}/iocs
    Extract IOCs from a persisted alert's structured fields and raw_alert JSONB.

GET /api/v1/alerts/{alert_id}/mitre
    Normalize MITRE ATT&CK techniques and tactics for a persisted alert.

GET /api/v1/alerts/{alert_id}/enrich
    Combined endpoint returning both IOC and MITRE enrichment in one call.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.analysis.ioc import extract_alert_iocs
from app.analysis.mitre import extract_mitre_from_alert
from app.db import get_db
from app.services.alert import get_alert

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Enrichment"],
)

# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class IOCOut(BaseModel):
    """IOC indicator returned by the extraction endpoint."""

    ioc_type: str
    value: str
    source_field: str | None = None


class IOCResponse(BaseModel):
    """IOC extraction result for a single alert."""

    alert_id: int
    wazuh_alert_id: str
    indicators: list[IOCOut]
    summary: dict[str, list[str]]   # ioc_type → sorted unique values


class MITRETechniqueOut(BaseModel):
    """Normalized MITRE ATT&CK technique."""

    technique_id: str
    is_subtechnique: bool
    parent_id: str | None = None
    source_field: str | None = None


class MITRETacticOut(BaseModel):
    """Normalized MITRE ATT&CK tactic."""

    slug: str
    is_known: bool
    source_field: str | None = None


class MITREResponse(BaseModel):
    """MITRE ATT&CK mapping result for a single alert."""

    alert_id: int
    wazuh_alert_id: str
    techniques: list[MITRETechniqueOut]
    tactics: list[MITRETacticOut]
    has_mappings: bool


class EnrichmentResponse(BaseModel):
    """Combined IOC and MITRE enrichment for a single alert."""

    alert_id: int
    wazuh_alert_id: str
    iocs: dict[str, list[str]]          # compact summary of extracted IOCs
    indicators: list[IOCOut]             # full indicator list with source fields
    mitre: dict[str, Any]               # MITREMapping.to_dict() output


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/{alert_id}/iocs", response_model=IOCResponse)
def get_alert_iocs(
    alert_id: int,
    include_private_ips: bool = Query(
        default=False,
        description="Include RFC-1918 / loopback IPv4 addresses in results",
    ),
    db: Session = Depends(get_db),
) -> IOCResponse:
    """Extract IOC indicators from a persisted alert.

    Scans structured network fields (src_ip, dst_ip) and the raw_alert JSONB
    payload for IPv4, IPv6, domains, URLs, email addresses, and file hashes.
    Private IP ranges are excluded by default.
    """
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    alert_dict = {
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "description": alert.description,
        "location": alert.location,
        "agent_name": alert.agent_name,
        "raw_alert": alert.raw_alert or {},
    }

    result = extract_alert_iocs(alert_dict, include_private_ips=include_private_ips)

    return IOCResponse(
        alert_id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        indicators=[
            IOCOut(ioc_type=i.ioc_type, value=i.value, source_field=i.source_field)
            for i in result.all_unique()
        ],
        summary=result.to_dict(),
    )


@router.get("/{alert_id}/mitre", response_model=MITREResponse)
def get_alert_mitre(
    alert_id: int,
    db: Session = Depends(get_db),
) -> MITREResponse:
    """Normalize MITRE ATT&CK techniques and tactics for a persisted alert.

    Extracts from existing ``mitre_tactics`` / ``mitre_techniques`` columns
    and from the ``raw_alert.rule.mitre`` subtree. Does not invent mappings.
    """
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    alert_dict = {
        "mitre_techniques": alert.mitre_techniques or [],
        "mitre_tactics": alert.mitre_tactics or [],
        "raw_alert": alert.raw_alert or {},
        "description": alert.description,
    }

    mapping = extract_mitre_from_alert(alert_dict)

    return MITREResponse(
        alert_id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        techniques=[
            MITRETechniqueOut(
                technique_id=t.technique_id,
                is_subtechnique=t.is_subtechnique,
                parent_id=t.parent_id,
                source_field=t.source_field,
            )
            for t in mapping.techniques
        ],
        tactics=[
            MITRETacticOut(
                slug=t.slug,
                is_known=t.is_known,
                source_field=t.source_field,
            )
            for t in mapping.tactics
        ],
        has_mappings=mapping.has_mappings(),
    )


@router.get("/{alert_id}/enrich", response_model=EnrichmentResponse)
def get_alert_enrichment(
    alert_id: int,
    include_private_ips: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> EnrichmentResponse:
    """Return combined IOC extraction and MITRE mapping for a single alert."""
    alert = get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    alert_dict = {
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "description": alert.description,
        "location": alert.location,
        "agent_name": alert.agent_name,
        "mitre_techniques": alert.mitre_techniques or [],
        "mitre_tactics": alert.mitre_tactics or [],
        "raw_alert": alert.raw_alert or {},
    }

    ioc_result = extract_alert_iocs(alert_dict, include_private_ips=include_private_ips)
    mitre_mapping = extract_mitre_from_alert(alert_dict)

    return EnrichmentResponse(
        alert_id=alert.id,
        wazuh_alert_id=alert.wazuh_alert_id,
        iocs=ioc_result.to_dict(),
        indicators=[
            IOCOut(ioc_type=i.ioc_type, value=i.value, source_field=i.source_field)
            for i in ioc_result.all_unique()
        ],
        mitre=mitre_mapping.to_dict(),
    )
