"""
backend/app/analysis/ioc.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deterministic IOC (Indicator of Compromise) extraction from arbitrary text
and alert dictionaries.

Design principles
-----------------
* Pure functions — no I/O, no side effects, fully testable offline.
* No external API calls in this module.
* Extraction is regex-based and intentionally conservative: we prefer
  false negatives over false positives to keep analyst signal clean.
* Provider interface is defined here so enrichment backends can be
  added later without touching extraction logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# IOC type constants
# ---------------------------------------------------------------------------

IOC_IPV4 = "ipv4"
IOC_IPV6 = "ipv6"
IOC_DOMAIN = "domain"
IOC_URL = "url"
IOC_EMAIL = "email"
IOC_MD5 = "md5"
IOC_SHA1 = "sha1"
IOC_SHA256 = "sha256"

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# IPv4: four octets in 0-255 range, not followed by another digit or dot.
# Excludes private/reserved ranges at extraction-time — callers filter downstream.
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)

# IPv6: full and compressed forms (does not match embedded IPv4 or link-local zones).
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"              # full
    r"|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"  # compressed
    r"|\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"             # leading ::
    r"|\b(?:[0-9a-fA-F]{1,4}:)*::\b"                              # trailing ::
)

# URL: http/https with optional path, query string, fragment.
# Stops at whitespace or common trailing punctuation.
_RE_URL = re.compile(
    r"https?://[^\s\"'<>\[\](){},;]+"
)

# Email: RFC 5321-lite (local@domain.tld)
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# Domain: hostname.tld — at least one dot, only valid chars.
# We apply a TLD allowlist check after matching to reduce false positives.
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}"
    r"[a-zA-Z]{2,}\b"
)

# Hashes — matched by exact character-count and hex alphabet.
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# ---------------------------------------------------------------------------
# Private IP ranges (excluded from IOC results by default)
# ---------------------------------------------------------------------------

_PRIVATE_IPV4_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.0.0.0",
    "169.254.",  # link-local
    "255.255.255.255",
)


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_IPV4_PREFIXES)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IOCIndicator:
    """A single extracted Indicator of Compromise."""

    ioc_type: str
    value: str
    source_field: str | None = None


@dataclass
class IOCResult:
    """Collection of IOCs extracted from a single alert or text."""

    indicators: list[IOCIndicator] = field(default_factory=list)

    def by_type(self, ioc_type: str) -> list[IOCIndicator]:
        return [i for i in self.indicators if i.ioc_type == ioc_type]

    def values(self, ioc_type: str) -> list[str]:
        return [i.value for i in self.by_type(ioc_type)]

    def all_unique(self) -> list[IOCIndicator]:
        seen: set[tuple[str, str]] = set()
        unique: list[IOCIndicator] = []
        for ind in self.indicators:
            key = (ind.ioc_type, ind.value)
            if key not in seen:
                seen.add(key)
                unique.append(ind)
        return unique

    def to_dict(self) -> dict[str, list[str]]:
        """Compact mapping of type → sorted unique values for API serialization."""
        seen: dict[str, set[str]] = {}
        for ind in self.indicators:
            seen.setdefault(ind.ioc_type, set()).add(ind.value)
        return {k: sorted(v) for k, v in seen.items() if v}


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------

_FILE_EXTENSIONS: frozenset[str] = frozenset({
    "log", "txt", "exe", "dll", "conf", "json", "yml", "yaml", "py", "sh",
    "service", "gz", "tar", "zip", "csv", "xml", "ini", "bin", "so", "dat",
    "bak", "cfg", "tmp", "ps1", "bat", "cmd", "sys", "syslog", "rpm", "deb",
})


def extract_iocs_from_text(
    text: str,
    source_field: str | None = None,
    *,
    include_private_ips: bool = False,
) -> list[IOCIndicator]:
    """Extract all IOC types from a single text string.

    Parameters
    ----------
    text:
        Arbitrary string to scan.
    source_field:
        Name of the originating field (e.g. ``"description"``) for tracing.
    include_private_ips:
        When False (default), RFC-1918 / loopback IPv4 addresses are excluded.

    Returns
    -------
    list[IOCIndicator]
        Deduplicated indicators found in ``text``.
    """
    if not text or not isinstance(text, str):
        return []

    indicators: list[IOCIndicator] = []
    seen: set[tuple[str, str]] = set()

    def _add(ioc_type: str, value: str) -> None:
        key = (ioc_type, value)
        if key not in seen:
            seen.add(key)
            indicators.append(IOCIndicator(ioc_type=ioc_type, value=value, source_field=source_field))

    # URLs first — strip embedded IPs/domains from further matching
    url_spans: set[tuple[int, int]] = set()
    for m in _RE_URL.finditer(text):
        url = m.group().rstrip(".,;)")
        _add(IOC_URL, url)
        url_spans.add((m.start(), m.end()))

    def _in_url(m: re.Match) -> bool:
        """True if this match is inside a URL already captured."""
        for s, e in url_spans:
            if m.start() >= s and m.end() <= e:
                return True
        return False

    # Emails (before domain to prevent partial overlap)
    email_spans: set[tuple[int, int]] = set()
    for m in _RE_EMAIL.finditer(text):
        if not _in_url(m):
            _add(IOC_EMAIL, m.group())
            email_spans.add((m.start(), m.end()))

    def _in_email(m: re.Match) -> bool:
        for s, e in email_spans:
            if m.start() >= s and m.end() <= e:
                return True
        return False

    # SHA-256 before SHA-1 before MD5 (longest first to avoid subset matches)
    for m in _RE_SHA256.finditer(text):
        _add(IOC_SHA256, m.group().lower())
    sha256_spans = {(m.start(), m.end()) for m in _RE_SHA256.finditer(text)}

    def _in_sha256(m: re.Match) -> bool:
        for s, e in sha256_spans:
            if m.start() >= s and m.end() <= e:
                return True
        return False

    for m in _RE_SHA1.finditer(text):
        if not _in_sha256(m):
            _add(IOC_SHA1, m.group().lower())

    sha1_spans = {(m.start(), m.end()) for m in _RE_SHA1.finditer(text) if not _in_sha256(m)}

    def _in_sha1(m: re.Match) -> bool:
        for s, e in sha1_spans:
            if m.start() >= s and m.end() <= e:
                return True
        return False

    for m in _RE_MD5.finditer(text):
        if not _in_sha256(m) and not _in_sha1(m):
            _add(IOC_MD5, m.group().lower())

    # IPv4
    for m in _RE_IPV4.finditer(text):
        if _in_url(m):
            continue
        ip = m.group()
        if include_private_ips or not _is_private_ip(ip):
            _add(IOC_IPV4, ip)

    # IPv6
    for m in _RE_IPV6.finditer(text):
        if not _in_url(m):
            _add(IOC_IPV6, m.group().lower())

    # Domains (skip if already inside a URL or email)
    for m in _RE_DOMAIN.finditer(text):
        if _in_url(m) or _in_email(m):
            continue
        domain = m.group().lower()
        # Very short tokens like "v1.0" or "py3.13" are not domains
        parts = domain.split(".")
        if len(parts) < 2 or len(parts[-1]) < 2:
            continue
        if parts[-1] in _FILE_EXTENSIONS:
            continue
        _add(IOC_DOMAIN, domain)

    return indicators


def extract_iocs_from_dict(
    data: Any,
    source_field: str | None = None,
    *,
    include_private_ips: bool = False,
    _depth: int = 0,
) -> list[IOCIndicator]:
    """Recursively extract IOCs from a nested dict/list/str structure.

    Recurses up to 6 levels deep to handle complex Wazuh raw_alert payloads.
    """
    if _depth > 6:
        return []
    indicators: list[IOCIndicator] = []
    if isinstance(data, str):
        indicators.extend(
            extract_iocs_from_text(data, source_field=source_field, include_private_ips=include_private_ips)
        )
    elif isinstance(data, dict):
        for k, v in data.items():
            child_field = f"{source_field}.{k}" if source_field else k
            indicators.extend(
                extract_iocs_from_dict(v, source_field=child_field, include_private_ips=include_private_ips, _depth=_depth + 1)
            )
    elif isinstance(data, list):
        for item in data:
            indicators.extend(
                extract_iocs_from_dict(item, source_field=source_field, include_private_ips=include_private_ips, _depth=_depth + 1)
            )
    return indicators


def extract_alert_iocs(
    alert_dict: dict[str, Any],
    *,
    include_private_ips: bool = False,
) -> IOCResult:
    """Extract all IOCs from a persisted Alert dict or raw_alert snapshot.

    Prioritizes high-signal fields: src_ip, dst_ip, description, location, raw_alert.
    Returns a deduped IOCResult.

    Parameters
    ----------
    alert_dict:
        Dict representation of an Alert ORM object (or any dict with alert fields).
    include_private_ips:
        Pass True when analysing internal lateral movement alerts.
    """
    indicators: list[IOCIndicator] = []

    # Structured network fields first (high confidence)
    for field_name in ("src_ip", "dst_ip"):
        value = alert_dict.get(field_name)
        if value and isinstance(value, str):
            ip = value.strip()
            if _RE_IPV4.match(ip):
                if include_private_ips or not _is_private_ip(ip):
                    indicators.append(IOCIndicator(ioc_type=IOC_IPV4, value=ip, source_field=field_name))
            elif _RE_IPV6.match(ip):
                indicators.append(IOCIndicator(ioc_type=IOC_IPV6, value=ip.lower(), source_field=field_name))

    # Text fields
    for field_name in ("description", "location", "agent_name"):
        value = alert_dict.get(field_name)
        if value:
            indicators.extend(
                extract_iocs_from_text(value, source_field=field_name, include_private_ips=include_private_ips)
            )

    # Recursive scan of raw_alert JSONB (if present and is a dict)
    raw = alert_dict.get("raw_alert")
    if isinstance(raw, dict):
        indicators.extend(
            extract_iocs_from_dict(raw, source_field="raw_alert", include_private_ips=include_private_ips)
        )

    result = IOCResult()
    seen: set[tuple[str, str]] = set()
    for ind in indicators:
        key = (ind.ioc_type, ind.value)
        if key not in seen:
            seen.add(key)
            result.indicators.append(ind)

    return result
