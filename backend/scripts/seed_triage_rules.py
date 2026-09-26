"""
backend/scripts/seed_triage_rules.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Idempotent development seed script for default SOC triage and escalation rules.
"""

import os
import sys

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import SessionLocal
from app.models.triage_rule import TriageRule


BASELINE_RULES = [
    {
        "name": "Critical Alert Auto-Escalation",
        "description": "Automatically escalates critical severity Wazuh alerts (rule level 12+) into an incident case or correlates into an active investigation.",
        "is_active": True,
        "min_rule_level": 12,
        "rule_ids": [],
        "mitre_techniques": [],
        "mitre_tactics": [],
        "action_type": "correlate_or_create",
        "case_severity": "critical",
        "case_title_template": "[Auto-Triage] Critical Severity Alert on {agent}",
    },
    {
        "name": "Credential Access Threat Detection",
        "description": "Detects MITRE Credential Access tactics and escalates to a high-severity investigation.",
        "is_active": True,
        "min_rule_level": None,
        "rule_ids": [],
        "mitre_techniques": [],
        "mitre_tactics": ["credential-access"],
        "action_type": "correlate_or_create",
        "case_severity": "high",
        "case_title_template": "[Auto-Triage] Credential Access Detected on {agent}",
    },
]


def seed_triage_rules() -> int:
    db = SessionLocal()
    try:
        for rule_data in BASELINE_RULES:
            existing = db.query(TriageRule).filter(TriageRule.name == rule_data["name"]).first()
            if existing:
                print(f"Triage rule '{existing.name}' already exists (ID: {existing.id}). Skipping.")
            else:
                new_rule = TriageRule(**rule_data)
                db.add(new_rule)
                db.commit()
                db.refresh(new_rule)
                print(f"Created triage rule '{new_rule.name}' (ID: {new_rule.id}).")
        return 0
    except Exception as exc:
        print(f"ERROR: Failed to seed triage rules ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(seed_triage_rules())
