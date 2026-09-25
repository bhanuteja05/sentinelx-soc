"""
backend/app/analysis/mitre.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
MITRE ATT&CK normalization helpers.

Design principles
-----------------
* Works entirely from data already present in the Wazuh alert.
* Does NOT invent techniques — only normalizes what Wazuh provides.
* Traceable: every normalized technique/tactic includes its source.
* No external API calls; no network access.

Wazuh stores ATT&CK data in ``rule.mitre`` with fields:
  - ``technique``:  list of technique IDs, e.g. ["T1059", "T1059.001"]
  - ``tactic``:     list of tactic names, e.g. ["execution"]
  - ``id``:         alias for technique (some Wazuh versions)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Technique ID normalization
# ---------------------------------------------------------------------------

# Valid ATT&CK technique format: T followed by 4 digits, optional .NNN subtechnique
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

# Known ATT&CK tactic slugs (Enterprise ATT&CK v14)
KNOWN_TACTICS: frozenset[str] = frozenset(
    {
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
        "reconnaissance",
        "resource-development",
    }
)

# Tactic display-name to slug map (Wazuh sometimes uses display names)
_TACTIC_ALIASES: dict[str, str] = {
    "initial access": "initial-access",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "lateral movement": "lateral-movement",
    "command and control": "command-and-control",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MITRETechnique:
    """A normalized ATT&CK technique reference."""

    technique_id: str           # e.g. "T1059" or "T1059.001"
    is_subtechnique: bool       # True if contains a dot (T1059.001)
    parent_id: str | None       # "T1059" for subtechniques, None otherwise
    source_field: str | None = None


@dataclass(frozen=True)
class MITRETactic:
    """A normalized ATT&CK tactic reference."""

    slug: str                   # e.g. "execution"
    is_known: bool              # True if slug is in KNOWN_TACTICS
    source_field: str | None = None


@dataclass
class MITREMapping:
    """Complete MITRE ATT&CK mapping derived from a single alert."""

    techniques: list[MITRETechnique] = field(default_factory=list)
    tactics: list[MITRETactic] = field(default_factory=list)

    def technique_ids(self) -> list[str]:
        return [t.technique_id for t in self.techniques]

    def tactic_slugs(self) -> list[str]:
        return [t.slug for t in self.tactics]

    def has_mappings(self) -> bool:
        return bool(self.techniques or self.tactics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": [
                {
                    "id": t.technique_id,
                    "is_subtechnique": t.is_subtechnique,
                    "parent_id": t.parent_id,
                }
                for t in self.techniques
            ],
            "tactics": [
                {
                    "slug": t.slug,
                    "is_known": t.is_known,
                }
                for t in self.tactics
            ],
        }


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def normalize_technique_id(raw: str) -> str | None:
    """Normalize a raw technique string to uppercase 'T1234' or 'T1234.001'.

    Returns None if the input does not match the expected format.
    """
    if not raw or not isinstance(raw, str):
        return None
    m = _TECHNIQUE_RE.search(raw.strip())
    if m:
        return m.group(1).upper()
    return None


def normalize_tactic_slug(raw: str) -> str | None:
    """Normalize a tactic name/slug to a known ATT&CK tactic slug.

    Handles:
    - Already-correct slugs: "execution" → "execution"
    - Display names: "Privilege Escalation" → "privilege-escalation"
    - Spaces → hyphens: "lateral movement" → "lateral-movement"
    """
    if not raw or not isinstance(raw, str):
        return None
    normalized = raw.strip().lower()
    # Try alias map first
    if normalized in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[normalized]
    # Try replacing spaces with hyphens
    slug = normalized.replace(" ", "-")
    return slug if slug else None


def parse_mitre_technique(raw: str, source_field: str | None = None) -> MITRETechnique | None:
    """Parse a raw technique string into a MITRETechnique."""
    tid = normalize_technique_id(raw)
    if not tid:
        return None
    is_sub = "." in tid
    parent = tid.split(".")[0] if is_sub else None
    return MITRETechnique(
        technique_id=tid,
        is_subtechnique=is_sub,
        parent_id=parent,
        source_field=source_field,
    )


def parse_mitre_tactic(raw: str, source_field: str | None = None) -> MITRETactic | None:
    """Parse a raw tactic name into a MITRETactic."""
    slug = normalize_tactic_slug(raw)
    if not slug:
        return None
    return MITRETactic(
        slug=slug,
        is_known=slug in KNOWN_TACTICS,
        source_field=source_field,
    )


# ---------------------------------------------------------------------------
# Alert-level mapping extraction
# ---------------------------------------------------------------------------

def _as_str_list(value: Any) -> list[str]:
    """Coerce a value to a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


def extract_mitre_from_alert(
    alert_dict: dict[str, Any],
) -> MITREMapping:
    """Extract MITRE ATT&CK mappings from a persisted Alert dict or WazuhAlert snapshot.

    Sources inspected (in priority order):
    1. ``mitre_techniques`` (already-normalized list on the persisted Alert)
    2. ``mitre_tactics``   (already-normalized list on the persisted Alert)
    3. ``raw_alert.rule.mitre.technique``  (from Wazuh Indexer hit)
    4. ``raw_alert.rule.mitre.tactic``     (from Wazuh Indexer hit)
    5. ``raw_alert.rule.mitre.id``         (alias used by some Wazuh versions)
    6. Description text scanning (last resort — high false-positive risk, conservative)
    """
    mapping = MITREMapping()
    seen_tech: set[str] = set()
    seen_tac: set[str] = set()

    def _add_technique(raw: str, source: str) -> None:
        t = parse_mitre_technique(raw, source_field=source)
        if t and t.technique_id not in seen_tech:
            seen_tech.add(t.technique_id)
            mapping.techniques.append(t)

    def _add_tactic(raw: str, source: str) -> None:
        t = parse_mitre_tactic(raw, source_field=source)
        if t and t.slug not in seen_tac:
            seen_tac.add(t.slug)
            mapping.tactics.append(t)

    # 1 & 2. Top-level normalized fields (already extracted by Wazuh ingestion)
    for tech in _as_str_list(alert_dict.get("mitre_techniques")):
        _add_technique(tech, "mitre_techniques")
    for tac in _as_str_list(alert_dict.get("mitre_tactics")):
        _add_tactic(tac, "mitre_tactics")

    # 3-5. Raw alert Wazuh rule.mitre subtree
    raw = alert_dict.get("raw_alert")
    if isinstance(raw, dict):
        rule = raw.get("rule")
        if not isinstance(rule, dict):
            rule = {}
        mitre = rule.get("mitre")
        if isinstance(mitre, dict):
            for tech in _as_str_list(mitre.get("technique") or mitre.get("id")):
                _add_technique(tech, "raw_alert.rule.mitre.technique")
            for tac in _as_str_list(mitre.get("tactic")):
                _add_tactic(tac, "raw_alert.rule.mitre.tactic")

    # 6. Description text scanning (fallback) — only for technique IDs, not tactics.
    description = alert_dict.get("description") or alert_dict.get("rule_description") or ""
    if description and not mapping.has_mappings():
        for m in _TECHNIQUE_RE.finditer(description):
            _add_technique(m.group(1), "description")

    return mapping
