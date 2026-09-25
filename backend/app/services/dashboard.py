"""
backend/app/services/dashboard.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dedicated service layer for SOC Dashboard and Investigation Analytics.

Provides real-time SQL-aggregated telemetry:
  - Alert metrics (total, 24h, 7d, severity, association status)
  - Case metrics (total, open, severity, status)
  - Time-series analytics (24h hourly, 7d daily, with zero-filling)
  - MITRE ATT&CK technique and tactic distributions
  - IOC aggregation derived from stored alert telemetry
  - Recent activity feeds (alerts, cases, case investigation notes)
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.analysis.ioc import extract_alert_iocs
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_alert import CaseAlert
from app.models.case_note import CaseNote
from app.models.user import User
from app.repositories.case import count_case_alerts


def get_dashboard_summary(db: Session) -> dict[str, Any]:
    """Compile comprehensive SOC analytics and metrics from PostgreSQL."""
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

    # 1. Alert Aggregations (Single SQL query for efficiency)
    alert_agg_stmt = text("""
        SELECT
            count(*) AS total,
            count(*) FILTER (WHERE timestamp >= :c24) AS count_24h,
            count(*) FILTER (WHERE timestamp >= :c7d) AS count_7d,
            count(*) FILTER (WHERE rule_level >= 12) AS critical,
            count(*) FILTER (WHERE rule_level >= 8 AND rule_level < 12) AS high,
            count(*) FILTER (WHERE rule_level >= 5 AND rule_level < 8) AS medium,
            count(*) FILTER (WHERE rule_level < 5 OR rule_level IS NULL) AS low
        FROM alerts
    """)
    alert_row = db.execute(alert_agg_stmt, {"c24": cutoff_24h, "c7d": cutoff_7d}).mappings().one()

    # Alert Association Status (associated with at least one case vs unassigned)
    status_agg_stmt = text("""
        SELECT
            count(DISTINCT a.id) FILTER (WHERE ca.case_id IS NOT NULL) AS associated,
            count(DISTINCT a.id) FILTER (WHERE ca.case_id IS NULL) AS unassociated
        FROM alerts a
        LEFT JOIN case_alerts ca ON a.id = ca.alert_id
    """)
    status_row = db.execute(status_agg_stmt).mappings().one()

    alert_metrics = {
        "total": alert_row["total"] or 0,
        "last_24h": alert_row["count_24h"] or 0,
        "last_7d": alert_row["count_7d"] or 0,
        "by_severity": {
            "critical": alert_row["critical"] or 0,
            "high": alert_row["high"] or 0,
            "medium": alert_row["medium"] or 0,
            "low": alert_row["low"] or 0,
        },
        "by_status": {
            "associated": status_row["associated"] or 0,
            "unassociated": status_row["unassociated"] or 0,
        },
    }

    # 2. Case Aggregations
    case_agg_stmt = text("""
        SELECT
            count(*) AS total,
            count(*) FILTER (WHERE status != 'closed') AS open_cases,
            count(*) FILTER (WHERE status = 'open') AS status_open,
            count(*) FILTER (WHERE status = 'in_progress') AS status_in_progress,
            count(*) FILTER (WHERE status = 'escalated') AS status_escalated,
            count(*) FILTER (WHERE status = 'resolved') AS status_resolved,
            count(*) FILTER (WHERE status = 'closed') AS status_closed,
            count(*) FILTER (WHERE severity = 'critical') AS sev_critical,
            count(*) FILTER (WHERE severity = 'high') AS sev_high,
            count(*) FILTER (WHERE severity = 'medium') AS sev_medium,
            count(*) FILTER (WHERE severity = 'low') AS sev_low
        FROM cases
    """)
    case_row = db.execute(case_agg_stmt).mappings().one()

    case_metrics = {
        "total": case_row["total"] or 0,
        "open": case_row["open_cases"] or 0,
        "by_severity": {
            "critical": case_row["sev_critical"] or 0,
            "high": case_row["sev_high"] or 0,
            "medium": case_row["sev_medium"] or 0,
            "low": case_row["sev_low"] or 0,
        },
        "by_status": {
            "open": case_row["status_open"] or 0,
            "in_progress": case_row["status_in_progress"] or 0,
            "escalated": case_row["status_escalated"] or 0,
            "resolved": case_row["status_resolved"] or 0,
            "closed": case_row["status_closed"] or 0,
        },
    }

    # 3. 24-Hour Time-Series (Hourly buckets with zero-filling)
    hourly_stmt = text("""
        SELECT
            date_trunc('hour', timestamp) AS bucket,
            count(*) AS count
        FROM alerts
        WHERE timestamp >= :c24
        GROUP BY bucket
        ORDER BY bucket
    """)
    hourly_rows = db.execute(hourly_stmt, {"c24": cutoff_24h}).fetchall()
    hourly_map: dict[datetime, int] = {
        row[0]: row[1] for row in hourly_rows if row[0] is not None
    }

    current_hour = now.replace(minute=0, second=0, microsecond=0)
    time_series_24h = []
    for i in range(23, -1, -1):
        bucket_time = current_hour - timedelta(hours=i)
        # Match timezone or match by timestamp ISO prefix
        found_count = 0
        for b_time, count in hourly_map.items():
            if b_time.year == bucket_time.year and b_time.month == bucket_time.month and \
               b_time.day == bucket_time.day and b_time.hour == bucket_time.hour:
                found_count = count
                break
        time_series_24h.append({
            "timestamp": bucket_time.isoformat(),
            "label": bucket_time.strftime("%H:00"),
            "count": found_count,
        })

    # 4. 7-Day Time-Series (Daily buckets with zero-filling)
    daily_stmt = text("""
        SELECT
            date_trunc('day', timestamp) AS bucket,
            count(*) AS count
        FROM alerts
        WHERE timestamp >= :c7d
        GROUP BY bucket
        ORDER BY bucket
    """)
    daily_rows = db.execute(daily_stmt, {"c7d": cutoff_7d}).fetchall()
    daily_map: dict[datetime, int] = {
        row[0]: row[1] for row in daily_rows if row[0] is not None
    }

    current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    time_series_7d = []
    for i in range(6, -1, -1):
        bucket_day = current_day - timedelta(days=i)
        found_count = 0
        for b_day, count in daily_map.items():
            if b_day.year == bucket_day.year and b_day.month == bucket_day.month and \
               b_day.day == bucket_day.day:
                found_count = count
                break
        time_series_7d.append({
            "date": bucket_day.strftime("%Y-%m-%d"),
            "label": bucket_day.strftime("%b %d"),
            "count": found_count,
        })

    # 5. MITRE ATT&CK Analytics (Aggregated from stored alert data)
    mitre_tech_stmt = text("""
        SELECT tech, count(*) AS count
        FROM alerts, jsonb_array_elements_text(mitre_techniques) AS tech
        WHERE mitre_techniques IS NOT NULL AND jsonb_typeof(mitre_techniques) = 'array'
        GROUP BY tech
        ORDER BY count DESC
        LIMIT 10
    """)
    mitre_tech_rows = db.execute(mitre_tech_stmt).fetchall()
    top_techniques = [{"technique_id": row[0], "count": row[1]} for row in mitre_tech_rows]

    mitre_tactic_stmt = text("""
        SELECT tactic, count(*) AS count
        FROM alerts, jsonb_array_elements_text(mitre_tactics) AS tactic
        WHERE mitre_tactics IS NOT NULL AND jsonb_typeof(mitre_tactics) = 'array'
        GROUP BY tactic
        ORDER BY count DESC
        LIMIT 10
    """)
    mitre_tactic_rows = db.execute(mitre_tactic_stmt).fetchall()
    top_tactics = [{"tactic": row[0], "count": row[1]} for row in mitre_tactic_rows]

    # 6. IOC Analytics (Derived from recent stored alerts using existing analysis engine)
    recent_alerts_for_iocs = db.scalars(
        select(Alert).order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(100)
    ).all()

    ioc_type_counts: dict[str, int] = {}
    ioc_samples: dict[str, list[str]] = {}
    total_iocs_found = 0

    for a in recent_alerts_for_iocs:
        alert_dict = {
            "id": a.id,
            "description": a.description,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "location": a.location,
            "raw_alert": a.raw_alert or {},
        }
        res = extract_alert_iocs(alert_dict)
        for ind in res.indicators:
            total_iocs_found += 1
            ioc_type_counts[ind.ioc_type] = ioc_type_counts.get(ind.ioc_type, 0) + 1
            if ind.ioc_type not in ioc_samples:
                ioc_samples[ind.ioc_type] = []
            if ind.value not in ioc_samples[ind.ioc_type] and len(ioc_samples[ind.ioc_type]) < 5:
                ioc_samples[ind.ioc_type].append(ind.value)

    ioc_summary = {
        "source": "derived_from_alerts",
        "analyzed_alert_count": len(recent_alerts_for_iocs),
        "total_indicators": total_iocs_found,
        "by_type": ioc_type_counts,
        "samples": ioc_samples,
    }

    # 7. Recent Alerts (Top 5)
    recent_alerts_query = (
        select(Alert)
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .limit(5)
    )
    recent_alerts_items = db.scalars(recent_alerts_query).all()
    recent_alerts = [
        {
            "id": a.id,
            "wazuh_alert_id": a.wazuh_alert_id,
            "timestamp": a.timestamp.isoformat(),
            "agent_id": a.agent_id,
            "agent_name": a.agent_name,
            "rule_id": a.rule_id,
            "rule_level": a.rule_level,
            "description": a.description,
            "mitre_tactics": a.mitre_tactics or [],
            "mitre_techniques": a.mitre_techniques or [],
        }
        for a in recent_alerts_items
    ]

    # 8. Recent Cases (Top 5)
    recent_cases_query = (
        select(Case)
        .order_by(Case.created_at.desc(), Case.id.desc())
        .limit(5)
    )
    recent_cases_items = db.scalars(recent_cases_query).all()
    recent_cases = [
        {
            "id": c.id,
            "title": c.title,
            "status": c.status,
            "severity": c.severity,
            "alert_count": count_case_alerts(db, c.id),
            "created_at": c.created_at.isoformat(),
        }
        for c in recent_cases_items
    ]

    # 9. Recent Investigation Activity (Top 5 Case Notes)
    recent_notes_stmt = (
        select(
            CaseNote.id,
            CaseNote.case_id,
            Case.title.label("case_title"),
            User.username.label("author_username"),
            CaseNote.content,
            CaseNote.created_at,
        )
        .join(Case, Case.id == CaseNote.case_id)
        .join(User, User.id == CaseNote.author_id)
        .order_by(CaseNote.created_at.desc(), CaseNote.id.desc())
        .limit(5)
    )
    recent_notes_rows = db.execute(recent_notes_stmt).all()
    recent_activity = [
        {
            "id": row.id,
            "case_id": row.case_id,
            "case_title": row.case_title,
            "author_username": row.author_username,
            "content": row.content[:200] + ("…" if len(row.content) > 200 else ""),
            "created_at": row.created_at.isoformat(),
        }
        for row in recent_notes_rows
    ]

    return {
        "generated_at": now.isoformat(),
        "alerts": alert_metrics,
        "cases": case_metrics,
        "time_series_24h": time_series_24h,
        "time_series_7d": time_series_7d,
        "mitre": {
            "top_techniques": top_techniques,
            "top_tactics": top_tactics,
        },
        "iocs": ioc_summary,
        "recent_alerts": recent_alerts,
        "recent_cases": recent_cases,
        "recent_activity": recent_activity,
    }
