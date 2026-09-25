"""
backend/tests/test_analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for IOC extraction and MITRE ATT&CK normalization.

All tests are pure unit tests — no database, no HTTP, no external APIs.
"""

import pytest

from app.analysis.ioc import (
    IOC_DOMAIN,
    IOC_EMAIL,
    IOC_IPV4,
    IOC_IPV6,
    IOC_MD5,
    IOC_SHA1,
    IOC_SHA256,
    IOC_URL,
    IOCResult,
    extract_alert_iocs,
    extract_iocs_from_dict,
    extract_iocs_from_text,
)
from app.analysis.mitre import (
    MITREMapping,
    extract_mitre_from_alert,
    normalize_tactic_slug,
    normalize_technique_id,
    parse_mitre_tactic,
    parse_mitre_technique,
)


# ===========================================================================
# IOC extraction — extract_iocs_from_text
# ===========================================================================


class TestExtractIPv4:
    def test_plain_ipv4(self):
        iocs = extract_iocs_from_text("Attacker from 203.0.113.5 detected")
        assert any(i.ioc_type == IOC_IPV4 and i.value == "203.0.113.5" for i in iocs)

    def test_multiple_ipv4(self):
        text = "src=198.51.100.1 dst=203.0.113.99"
        iocs = extract_iocs_from_text(text)
        values = [i.value for i in iocs if i.ioc_type == IOC_IPV4]
        assert "198.51.100.1" in values
        assert "203.0.113.99" in values

    def test_private_ipv4_excluded_by_default(self):
        iocs = extract_iocs_from_text("Traffic from 192.168.1.100")
        assert not any(i.ioc_type == IOC_IPV4 for i in iocs)

    def test_private_ipv4_included_when_requested(self):
        iocs = extract_iocs_from_text("Traffic from 192.168.1.100", include_private_ips=True)
        assert any(i.ioc_type == IOC_IPV4 and i.value == "192.168.1.100" for i in iocs)

    def test_loopback_excluded(self):
        iocs = extract_iocs_from_text("Localhost 127.0.0.1 access")
        assert not any(i.ioc_type == IOC_IPV4 for i in iocs)

    def test_invalid_octet_not_matched(self):
        iocs = extract_iocs_from_text("Not an IP: 999.1.2.3")
        assert not any(i.value == "999.1.2.3" for i in iocs)

    def test_source_field_tracked(self):
        iocs = extract_iocs_from_text("203.0.113.1", source_field="description")
        ip_iocs = [i for i in iocs if i.ioc_type == IOC_IPV4]
        assert ip_iocs[0].source_field == "description"


class TestExtractURL:
    def test_http_url(self):
        iocs = extract_iocs_from_text("Visited http://malware.example.com/payload.exe")
        urls = [i.value for i in iocs if i.ioc_type == IOC_URL]
        assert any("malware.example.com" in u for u in urls)

    def test_https_url(self):
        iocs = extract_iocs_from_text("Download from https://evil.io/stage2.ps1")
        urls = [i.value for i in iocs if i.ioc_type == IOC_URL]
        assert any("evil.io" in u for u in urls)

    def test_url_not_extracted_as_domain(self):
        iocs = extract_iocs_from_text("https://example.com/path")
        domains = [i.value for i in iocs if i.ioc_type == IOC_DOMAIN]
        # example.com should NOT appear separately when it's inside the URL
        assert "example.com" not in domains


class TestExtractDomain:
    def test_plain_domain(self):
        iocs = extract_iocs_from_text("C2 host at evil-c2.net connected")
        domains = [i.value for i in iocs if i.ioc_type == IOC_DOMAIN]
        assert "evil-c2.net" in domains

    def test_file_extensions_not_extracted_as_domain(self):
        iocs = extract_iocs_from_text("Examining auth.log and service.conf and script.py")
        domains = [i.value for i in iocs if i.ioc_type == IOC_DOMAIN]
        assert "auth.log" not in domains
        assert "service.conf" not in domains
        assert "script.py" not in domains


class TestExtractEmail:
    def test_plain_email(self):
        iocs = extract_iocs_from_text("Sent from phish@evil.tld to victim@corp.local")
        emails = [i.value for i in iocs if i.ioc_type == IOC_EMAIL]
        assert "phish@evil.tld" in emails
        assert "victim@corp.local" in emails

    def test_email_not_duplicated_as_domain(self):
        iocs = extract_iocs_from_text("admin@corp.example")
        domains = [i.value for i in iocs if i.ioc_type == IOC_DOMAIN]
        assert "corp.example" not in domains


class TestExtractHashes:
    def test_md5(self):
        iocs = extract_iocs_from_text("Hash: d41d8cd98f00b204e9800998ecf8427e")
        hashes = [i for i in iocs if i.ioc_type == IOC_MD5]
        assert any(h.value == "d41d8cd98f00b204e9800998ecf8427e" for h in hashes)

    def test_sha1(self):
        iocs = extract_iocs_from_text("SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
        hashes = [i for i in iocs if i.ioc_type == IOC_SHA1]
        assert any(h.value == "da39a3ee5e6b4b0d3255bfef95601890afd80709" for h in hashes)

    def test_sha256(self):
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs_from_text(f"SHA256: {sha}")
        hashes = [i for i in iocs if i.ioc_type == IOC_SHA256]
        assert any(h.value == sha for h in hashes)

    def test_sha256_not_also_md5(self):
        """A 64-char hex string must not also produce MD5/SHA1 matches."""
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        iocs = extract_iocs_from_text(sha)
        types = {i.ioc_type for i in iocs}
        assert IOC_SHA256 in types
        assert IOC_MD5 not in types
        assert IOC_SHA1 not in types

    def test_hash_case_normalized(self):
        iocs = extract_iocs_from_text("MD5: D41D8CD98F00B204E9800998ECF8427E")
        hashes = [i for i in iocs if i.ioc_type == IOC_MD5]
        assert any(h.value == "d41d8cd98f00b204e9800998ecf8427e" for h in hashes)


class TestExtractMalformed:
    def test_empty_string(self):
        assert extract_iocs_from_text("") == []

    def test_none_text(self):
        assert extract_iocs_from_text(None) == []  # type: ignore[arg-type]

    def test_non_string(self):
        assert extract_iocs_from_text(12345) == []  # type: ignore[arg-type]

    def test_whitespace_only(self):
        assert extract_iocs_from_text("   ") == []


class TestExtractDedup:
    def test_no_duplicate_indicators(self):
        text = "203.0.113.1 and 203.0.113.1 again"
        iocs = extract_iocs_from_text(text)
        ipv4_values = [i.value for i in iocs if i.ioc_type == IOC_IPV4]
        assert ipv4_values.count("203.0.113.1") == 1


class TestExtractFromDict:
    def test_flat_dict(self):
        data = {"src": "203.0.113.5", "desc": "malware from 198.51.100.1"}
        iocs = extract_iocs_from_dict(data)
        values = [i.value for i in iocs if i.ioc_type == IOC_IPV4]
        assert "203.0.113.5" in values
        assert "198.51.100.1" in values

    def test_nested_dict(self):
        data = {"rule": {"data": {"srcip": "203.0.113.2"}}}
        iocs = extract_iocs_from_dict(data)
        values = [i.value for i in iocs if i.ioc_type == IOC_IPV4]
        assert "203.0.113.2" in values

    def test_list_of_dicts(self):
        data = [{"ip": "203.0.113.3"}, {"ip": "203.0.113.4"}]
        iocs = extract_iocs_from_dict(data)
        values = [i.value for i in iocs if i.ioc_type == IOC_IPV4]
        assert "203.0.113.3" in values
        assert "203.0.113.4" in values

    def test_max_depth_respected(self):
        # Build 10-deep nesting — should not crash
        data: dict = {"a": {}}
        current = data["a"]
        for _ in range(10):
            current["x"] = {}
            current = current["x"]
        current["ip"] = "203.0.113.99"  # too deep to be extracted
        iocs = extract_iocs_from_dict(data)
        # Should not raise — result may or may not include the deep IP
        assert isinstance(iocs, list)


class TestExtractAlertIOCs:
    def test_network_fields_extracted(self):
        alert = {
            "src_ip": "203.0.113.1",
            "dst_ip": "203.0.113.2",
            "description": "Port scan",
            "raw_alert": {},
        }
        result = extract_alert_iocs(alert)
        values = result.values(IOC_IPV4)
        assert "203.0.113.1" in values
        assert "203.0.113.2" in values

    def test_private_ips_excluded(self):
        alert = {"src_ip": "10.0.0.1", "dst_ip": "192.168.0.1", "raw_alert": {}}
        result = extract_alert_iocs(alert)
        assert result.values(IOC_IPV4) == []

    def test_raw_alert_scanned(self):
        alert = {
            "raw_alert": {
                "data": {"srcip": "198.51.100.5"}
            }
        }
        result = extract_alert_iocs(alert)
        assert "198.51.100.5" in result.values(IOC_IPV4)

    def test_empty_alert(self):
        result = extract_alert_iocs({})
        assert isinstance(result, IOCResult)
        assert result.indicators == []

    def test_to_dict(self):
        alert = {"src_ip": "203.0.113.99", "raw_alert": {}}
        result = extract_alert_iocs(alert)
        d = result.to_dict()
        assert IOC_IPV4 in d
        assert "203.0.113.99" in d[IOC_IPV4]


# ===========================================================================
# MITRE ATT&CK — normalization
# ===========================================================================


class TestNormalizeTechniqueId:
    def test_standard_technique(self):
        assert normalize_technique_id("T1059") == "T1059"

    def test_subtechnique(self):
        assert normalize_technique_id("T1059.001") == "T1059.001"

    def test_lowercase_normalized(self):
        assert normalize_technique_id("t1059") == "T1059"

    def test_embedded_in_text(self):
        assert normalize_technique_id("uses T1059.003 for execution") == "T1059.003"

    def test_invalid_returns_none(self):
        assert normalize_technique_id("not-a-technique") is None

    def test_empty_returns_none(self):
        assert normalize_technique_id("") is None

    def test_none_returns_none(self):
        assert normalize_technique_id(None) is None  # type: ignore[arg-type]


class TestNormalizeTacticSlug:
    def test_known_slug(self):
        assert normalize_tactic_slug("execution") == "execution"

    def test_display_name_privilege_escalation(self):
        assert normalize_tactic_slug("Privilege Escalation") == "privilege-escalation"

    def test_space_to_hyphen(self):
        assert normalize_tactic_slug("lateral movement") == "lateral-movement"

    def test_empty_returns_none(self):
        assert normalize_tactic_slug("") is None

    def test_none_returns_none(self):
        assert normalize_tactic_slug(None) is None  # type: ignore[arg-type]


class TestParseMitreTechnique:
    def test_valid_technique(self):
        t = parse_mitre_technique("T1059")
        assert t is not None
        assert t.technique_id == "T1059"
        assert not t.is_subtechnique
        assert t.parent_id is None

    def test_subtechnique(self):
        t = parse_mitre_technique("T1059.001")
        assert t is not None
        assert t.is_subtechnique
        assert t.parent_id == "T1059"

    def test_invalid_returns_none(self):
        assert parse_mitre_technique("bad") is None

    def test_source_field_preserved(self):
        t = parse_mitre_technique("T1059", source_field="rule.mitre")
        assert t is not None
        assert t.source_field == "rule.mitre"


class TestParseMitreTactic:
    def test_known_tactic(self):
        t = parse_mitre_tactic("execution")
        assert t is not None
        assert t.slug == "execution"
        assert t.is_known

    def test_unknown_tactic(self):
        t = parse_mitre_tactic("unknown-phase")
        assert t is not None
        assert t.slug == "unknown-phase"
        assert not t.is_known

    def test_none_returns_none(self):
        assert parse_mitre_tactic(None) is None  # type: ignore[arg-type]


class TestExtractMitreFromAlert:
    def test_from_mitre_techniques_field(self):
        alert = {
            "mitre_techniques": ["T1059", "T1059.001"],
            "mitre_tactics": ["execution"],
            "raw_alert": {},
        }
        mapping = extract_mitre_from_alert(alert)
        assert mapping.has_mappings()
        tech_ids = mapping.technique_ids()
        assert "T1059" in tech_ids
        assert "T1059.001" in tech_ids
        assert "execution" in mapping.tactic_slugs()

    def test_from_raw_alert_rule_mitre(self):
        alert = {
            "mitre_techniques": [],
            "mitre_tactics": [],
            "raw_alert": {
                "rule": {
                    "mitre": {
                        "technique": ["T1078"],
                        "tactic": ["persistence"],
                    }
                }
            },
        }
        mapping = extract_mitre_from_alert(alert)
        assert "T1078" in mapping.technique_ids()
        assert "persistence" in mapping.tactic_slugs()

    def test_no_mappings(self):
        alert = {"raw_alert": {}}
        mapping = extract_mitre_from_alert(alert)
        assert not mapping.has_mappings()

    def test_deduplication(self):
        # T1059 appears in both mitre_techniques and raw_alert
        alert = {
            "mitre_techniques": ["T1059"],
            "mitre_tactics": [],
            "raw_alert": {
                "rule": {
                    "mitre": {
                        "technique": ["T1059"],
                    }
                }
            },
        }
        mapping = extract_mitre_from_alert(alert)
        assert mapping.technique_ids().count("T1059") == 1

    def test_to_dict(self):
        alert = {
            "mitre_techniques": ["T1059"],
            "mitre_tactics": ["execution"],
            "raw_alert": {},
        }
        mapping = extract_mitre_from_alert(alert)
        d = mapping.to_dict()
        assert "techniques" in d
        assert "tactics" in d
        assert any(t["id"] == "T1059" for t in d["techniques"])
        assert any(t["slug"] == "execution" for t in d["tactics"])

    def test_malformed_raw_alert_does_not_raise(self):
        alert = {"raw_alert": {"rule": "not-a-dict"}}
        mapping = extract_mitre_from_alert(alert)
        assert isinstance(mapping, MITREMapping)

    def test_empty_alert_dict(self):
        mapping = extract_mitre_from_alert({})
        assert not mapping.has_mappings()


# ===========================================================================
# Enrichment API integration (TestClient, no DB)
# ===========================================================================


def _make_alert_dict(
    *,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    description: str | None = None,
    mitre_techniques: list[str] | None = None,
    mitre_tactics: list[str] | None = None,
    raw_alert: dict | None = None,
) -> dict:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "description": description,
        "location": None,
        "agent_name": None,
        "mitre_techniques": mitre_techniques or [],
        "mitre_tactics": mitre_tactics or [],
        "raw_alert": raw_alert or {},
    }


class TestEnrichmentCombined:
    """Integration smoke tests for the combined extract_alert_iocs + extract_mitre_from_alert flow."""

    def test_full_enrichment(self):
        alert = _make_alert_dict(
            src_ip="203.0.113.10",
            description="PowerShell download from https://malware.io/stage2.exe",
            mitre_techniques=["T1059.001"],
            mitre_tactics=["execution"],
            raw_alert={"rule": {"mitre": {"technique": ["T1059.001"], "tactic": ["execution"]}}},
        )
        iocs = extract_alert_iocs(alert)
        mitre = extract_mitre_from_alert(alert)

        assert "203.0.113.10" in iocs.values(IOC_IPV4)
        assert any("malware.io" in u for u in iocs.values(IOC_URL))
        assert "T1059.001" in mitre.technique_ids()
        assert "execution" in mitre.tactic_slugs()

    def test_enrichment_empty_alert(self):
        alert = _make_alert_dict()
        iocs = extract_alert_iocs(alert)
        mitre = extract_mitre_from_alert(alert)
        assert iocs.indicators == []
        assert not mitre.has_mappings()
