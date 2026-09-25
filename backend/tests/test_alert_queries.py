"""
tests/test_alert_queries.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for the Alert Investigation & Query Layer.

Covers:
  - Pagination (default, custom page/page_size, page navigation, empty DB, out-of-bounds)
  - Sorting (timestamp, rule_level, id, rule_id, created_at, asc/desc, deterministic tie-breaking)
  - Filtering (exact rule_level, min/max rule_level, agent_id, agent_name, rule_id, time ranges)
  - MITRE JSONB filtering (exact tactic containment, technique containment)
  - Combined filters
  - Single alert lookups (by DB id, by Wazuh alert id, 404s, raw_alert present in detail, excluded in list)
  - Query parameter validation & error handling (400, 422)
"""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest

from app.api.deps import get_current_active_user
from app.db import get_db
from app.main import app
from app.models.user import User
from app.repositories.alert import create_alert


@pytest.fixture
def client(clean_db):
    """TestClient with get_db and get_current_active_user overridden to use clean test database session."""
    def override_get_db():
        yield clean_db

    mock_admin = User(
        id=1,
        username="testadmin",
        email="testadmin@sentinelx.local",
        password_hash="dummy",
        role="admin",
        is_active=True,
    )
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_active_user] = lambda: mock_admin
    yield TestClient(app)
    app.dependency_overrides.clear()



def _seed_alert(db, **overrides):
    """Helper to seed an alert in the database with defaults."""
    now = datetime.now(timezone.utc)
    defaults = {
        "wazuh_alert_id": f"wazuh-{now.timestamp()}-{id(overrides)}",
        "timestamp": now,
        "agent_id": "001",
        "agent_name": "host-alpha",
        "rule_id": "1001",
        "rule_level": 5,
        "description": "Test alert description",
        "location": "/var/log/syslog",
        "decoder": "syslog",
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["Command and Scripting Interpreter"],
        "raw_alert": {"original": "data", "event_id": 4624},
    }
    defaults.update(overrides)
    return create_alert(db, defaults)


# ---------------------------------------------------------------------------
# 1 · Pagination Tests
# ---------------------------------------------------------------------------


def test_pagination_empty_database(client, clean_db):
    """Empty database returns 200 with total=0, pages=0, items=[]."""
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["page"] == 1
    assert data["page_size"] == 25
    assert data["pages"] == 0


def test_pagination_default_and_custom_page_size(client, clean_db):
    """Test default page size and custom page_size."""
    base_time = datetime(2026, 9, 25, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(30):
        _seed_alert(
            clean_db,
            wazuh_alert_id=f"alert-{i:02d}",
            timestamp=base_time + timedelta(minutes=i),
        )

    # Default: page=1, page_size=25 -> 25 items returned, total 30, pages 2
    resp1 = client.get("/api/v1/alerts")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert len(data1["items"]) == 25
    assert data1["total"] == 30
    assert data1["page"] == 1
    assert data1["page_size"] == 25
    assert data1["pages"] == 2

    # Custom: page=2, page_size=25 -> 5 items returned
    resp2 = client.get("/api/v1/alerts?page=2&page_size=25")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) == 5
    assert data2["page"] == 2

    # Custom size: page=1, page_size=10 -> 10 items, pages 3
    resp3 = client.get("/api/v1/alerts?page=1&page_size=10")
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert len(data3["items"]) == 10
    assert data3["pages"] == 3


def test_pagination_out_of_bounds_page(client, clean_db):
    """Requesting a page beyond total pages returns 200 with empty items."""
    _seed_alert(clean_db, wazuh_alert_id="single-alert")

    resp = client.get("/api/v1/alerts?page=999&page_size=25")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 1
    assert data["page"] == 999
    assert data["pages"] == 1


# ---------------------------------------------------------------------------
# 2 · Sorting Tests
# ---------------------------------------------------------------------------


def test_sorting_by_timestamp(client, clean_db):
    """Test timestamp ascending and descending sort."""
    t1 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 25, 9, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 25, 10, 0, 0, tzinfo=timezone.utc)

    _seed_alert(clean_db, wazuh_alert_id="a1", timestamp=t1)
    _seed_alert(clean_db, wazuh_alert_id="a2", timestamp=t2)
    _seed_alert(clean_db, wazuh_alert_id="a3", timestamp=t3)

    # Descending (default)
    resp_desc = client.get("/api/v1/alerts?sort_by=timestamp&sort_order=desc")
    assert resp_desc.status_code == 200
    ids_desc = [item["wazuh_alert_id"] for item in resp_desc.json()["items"]]
    assert ids_desc == ["a3", "a2", "a1"]

    # Ascending
    resp_asc = client.get("/api/v1/alerts?sort_by=timestamp&sort_order=asc")
    assert resp_asc.status_code == 200
    ids_asc = [item["wazuh_alert_id"] for item in resp_asc.json()["items"]]
    assert ids_asc == ["a1", "a2", "a3"]


def test_sorting_by_rule_level(client, clean_db):
    """Test rule_level sorting."""
    _seed_alert(clean_db, wazuh_alert_id="lvl-3", rule_level=3)
    _seed_alert(clean_db, wazuh_alert_id="lvl-12", rule_level=12)
    _seed_alert(clean_db, wazuh_alert_id="lvl-7", rule_level=7)

    resp = client.get("/api/v1/alerts?sort_by=rule_level&sort_order=asc")
    assert resp.status_code == 200
    levels = [item["rule_level"] for item in resp.json()["items"]]
    assert levels == [3, 7, 12]


def test_sorting_by_id_and_rule_id_and_created_at(client, clean_db):
    """Test sorting on id, rule_id, and created_at."""
    _seed_alert(clean_db, wazuh_alert_id="r1", rule_id="5000")
    _seed_alert(clean_db, wazuh_alert_id="r2", rule_id="1000")

    resp_rule = client.get("/api/v1/alerts?sort_by=rule_id&sort_order=asc")
    assert resp_rule.status_code == 200
    assert resp_rule.json()["items"][0]["rule_id"] == "1000"

    resp_id = client.get("/api/v1/alerts?sort_by=id&sort_order=desc")
    assert resp_id.status_code == 200
    assert resp_id.json()["items"][0]["id"] > resp_id.json()["items"][1]["id"]

    resp_created = client.get("/api/v1/alerts?sort_by=created_at&sort_order=desc")
    assert resp_created.status_code == 200
    assert len(resp_created.json()["items"]) == 2


def test_sorting_deterministic_tie_breaker(client, clean_db):
    """Alerts with identical timestamps are deterministically sorted by id desc."""
    same_time = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
    a1 = _seed_alert(clean_db, wazuh_alert_id="same-1", timestamp=same_time)
    a2 = _seed_alert(clean_db, wazuh_alert_id="same-2", timestamp=same_time)

    resp = client.get("/api/v1/alerts?sort_by=timestamp&sort_order=desc")
    assert resp.status_code == 200
    items = resp.json()["items"]
    # a2 was inserted second so has higher id
    assert items[0]["id"] == a2.id
    assert items[1]["id"] == a1.id


# ---------------------------------------------------------------------------
# 3 · Filtering Tests
# ---------------------------------------------------------------------------


def test_filter_exact_rule_level(client, clean_db):
    """Test exact rule_level match."""
    _seed_alert(clean_db, wazuh_alert_id="lvl-5", rule_level=5)
    _seed_alert(clean_db, wazuh_alert_id="lvl-8", rule_level=8)

    resp = client.get("/api/v1/alerts?rule_level=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["rule_level"] == 5


def test_filter_rule_level_range(client, clean_db):
    """Test min_rule_level and max_rule_level ranges."""
    _seed_alert(clean_db, wazuh_alert_id="l3", rule_level=3)
    _seed_alert(clean_db, wazuh_alert_id="l7", rule_level=7)
    _seed_alert(clean_db, wazuh_alert_id="l12", rule_level=12)

    resp_min = client.get("/api/v1/alerts?min_rule_level=7")
    assert resp_min.status_code == 200
    assert resp_min.json()["total"] == 2

    resp_max = client.get("/api/v1/alerts?max_rule_level=7")
    assert resp_max.status_code == 200
    assert resp_max.json()["total"] == 2

    resp_both = client.get("/api/v1/alerts?min_rule_level=4&max_rule_level=10")
    assert resp_both.status_code == 200
    assert resp_both.json()["total"] == 1
    assert resp_both.json()["items"][0]["rule_level"] == 7


def test_filter_by_agent_and_rule_id(client, clean_db):
    """Test agent_id, agent_name, and rule_id filtering."""
    _seed_alert(clean_db, wazuh_alert_id="a-win", agent_id="001", agent_name="win-host", rule_id="60100")
    _seed_alert(clean_db, wazuh_alert_id="a-lin", agent_id="002", agent_name="linux-host", rule_id="5715")

    resp_id = client.get("/api/v1/alerts?agent_id=001")
    assert resp_id.status_code == 200
    assert resp_id.json()["total"] == 1
    assert resp_id.json()["items"][0]["agent_id"] == "001"

    resp_name = client.get("/api/v1/alerts?agent_name=linux-host")
    assert resp_name.status_code == 200
    assert resp_name.json()["total"] == 1
    assert resp_name.json()["items"][0]["agent_name"] == "linux-host"

    resp_rule = client.get("/api/v1/alerts?rule_id=60100")
    assert resp_rule.status_code == 200
    assert resp_rule.json()["total"] == 1
    assert resp_rule.json()["items"][0]["rule_id"] == "60100"


def test_filter_by_time_range(client, clean_db):
    """Test start_time and end_time range filtering."""
    t1 = datetime(2026, 9, 25, 6, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 25, 7, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)

    _seed_alert(clean_db, wazuh_alert_id="t1", timestamp=t1)
    _seed_alert(clean_db, wazuh_alert_id="t2", timestamp=t2)
    _seed_alert(clean_db, wazuh_alert_id="t3", timestamp=t3)

    resp = client.get(
        "/api/v1/alerts?start_time=2026-09-25T06:30:00Z&end_time=2026-09-25T07:30:00Z"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["wazuh_alert_id"] == "t2"


# ---------------------------------------------------------------------------
# 4 · MITRE JSONB Filtering Tests
# ---------------------------------------------------------------------------


def test_filter_by_mitre_tactic(client, clean_db):
    """Test filtering by MITRE tactic containment."""
    _seed_alert(
        clean_db,
        wazuh_alert_id="m1",
        mitre_tactics=["Privilege Escalation", "Defense Evasion"],
    )
    _seed_alert(
        clean_db,
        wazuh_alert_id="m2",
        mitre_tactics=["Persistence"],
    )

    resp = client.get("/api/v1/alerts?mitre_tactic=Defense+Evasion")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["wazuh_alert_id"] == "m1"

    # Non-existent tactic
    resp_empty = client.get("/api/v1/alerts?mitre_tactic=NonExistentTactic")
    assert resp_empty.status_code == 200
    assert resp_empty.json()["total"] == 0


def test_filter_by_mitre_technique(client, clean_db):
    """Test filtering by MITRE technique containment."""
    _seed_alert(
        clean_db,
        wazuh_alert_id="tech1",
        mitre_techniques=["Domain Policy Modification", "Token Manipulation"],
    )
    _seed_alert(
        clean_db,
        wazuh_alert_id="tech2",
        mitre_techniques=["Pass the Hash"],
    )

    resp = client.get("/api/v1/alerts?mitre_technique=Pass+the+Hash")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["wazuh_alert_id"] == "tech2"


# ---------------------------------------------------------------------------
# 5 · Combined Filter Tests
# ---------------------------------------------------------------------------


def test_combined_filters(client, clean_db):
    """Test multiple filters active at once."""
    t1 = datetime(2026, 9, 25, 9, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 25, 11, 0, 0, tzinfo=timezone.utc)

    # Matches everything
    _seed_alert(
        clean_db,
        wazuh_alert_id="match",
        agent_id="001",
        rule_level=10,
        rule_id="8888",
        timestamp=t1,
        mitre_tactics=["Execution"],
    )
    # Matches agent and rule_level but wrong rule_id
    _seed_alert(
        clean_db,
        wazuh_alert_id="no-match-rule",
        agent_id="001",
        rule_level=10,
        rule_id="9999",
        timestamp=t1,
        mitre_tactics=["Execution"],
    )
    # Matches rule_id and agent but outside time range
    _seed_alert(
        clean_db,
        wazuh_alert_id="no-match-time",
        agent_id="001",
        rule_level=10,
        rule_id="8888",
        timestamp=t2,
        mitre_tactics=["Execution"],
    )

    url = (
        "/api/v1/alerts"
        "?agent_id=001"
        "&min_rule_level=8"
        "&rule_id=8888"
        "&mitre_tactic=Execution"
        "&start_time=2026-09-25T08:00:00Z"
        "&end_time=2026-09-25T10:00:00Z"
    )
    resp = client.get(url)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["wazuh_alert_id"] == "match"


# ---------------------------------------------------------------------------
# 6 · Lookups & Investigation View
# ---------------------------------------------------------------------------


def test_get_alert_by_id(client, clean_db):
    """GET /api/v1/alerts/{id} returns AlertDetailOut with raw_alert and created_at."""
    alert = _seed_alert(
        clean_db,
        wazuh_alert_id="investigate-01",
        raw_alert={"event": "suspicious_powershell", "pid": 4321},
    )

    resp = client.get(f"/api/v1/alerts/{alert.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == alert.id
    assert data["wazuh_alert_id"] == "investigate-01"
    assert "raw_alert" in data
    assert data["raw_alert"]["pid"] == 4321
    assert "created_at" in data


def test_get_alert_by_wazuh_id(client, clean_db):
    """GET /api/v1/alerts/wazuh/{wazuh_alert_id} returns AlertDetailOut."""
    alert = _seed_alert(
        clean_db,
        wazuh_alert_id="wazuh-unique-xyz",
        raw_alert={"agent": "001", "rule": {"id": "100"}},
    )

    resp = client.get(f"/api/v1/alerts/wazuh/{alert.wazuh_alert_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == alert.id
    assert data["wazuh_alert_id"] == "wazuh-unique-xyz"
    assert data["raw_alert"]["agent"] == "001"


def test_get_alert_not_found(client, clean_db):
    """Lookups for non-existent alerts return 404."""
    resp_id = client.get("/api/v1/alerts/999999")
    assert resp_id.status_code == 404
    assert "not found" in resp_id.json()["detail"].lower()

    resp_wazuh = client.get("/api/v1/alerts/wazuh/non-existent-wazuh-id")
    assert resp_wazuh.status_code == 404
    assert "not found" in resp_wazuh.json()["detail"].lower()


def test_list_response_excludes_raw_alert(client, clean_db):
    """List endpoint AlertOut must NOT expose raw_alert."""
    _seed_alert(clean_db, wazuh_alert_id="hide-raw", raw_alert={"secret": "blob"})

    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    item = resp.json()["items"][0]
    assert "raw_alert" not in item
    assert "created_at" not in item


# ---------------------------------------------------------------------------
# 7 · Query Validation & Error Handling
# ---------------------------------------------------------------------------


def test_invalid_pagination_parameters(client):
    """page < 1 or page_size < 1 or page_size > 100 returns 422."""
    assert client.get("/api/v1/alerts?page=0").status_code == 422
    assert client.get("/api/v1/alerts?page_size=0").status_code == 422
    assert client.get("/api/v1/alerts?page_size=101").status_code == 422


def test_invalid_sort_parameters(client):
    """Invalid sort_by or sort_order returns 422."""
    resp_field = client.get("/api/v1/alerts?sort_by=non_existent_column")
    assert resp_field.status_code == 422
    assert "Invalid sort_by" in resp_field.json()["detail"]

    resp_order = client.get("/api/v1/alerts?sort_order=invalid_dir")
    assert resp_order.status_code == 422


def test_inverted_time_range_returns_400(client):
    """start_time > end_time returns 400 Bad Request."""
    url = "/api/v1/alerts?start_time=2026-09-25T12:00:00Z&end_time=2026-09-25T10:00:00Z"
    resp = client.get(url)
    assert resp.status_code == 400
    assert "start_time must be before or equal to end_time" in resp.json()["detail"]


def test_inverted_rule_level_range_returns_400(client):
    """min_rule_level > max_rule_level returns 400 Bad Request."""
    resp = client.get("/api/v1/alerts?min_rule_level=12&max_rule_level=5")
    assert resp.status_code == 400
    assert "min_rule_level cannot be greater than max_rule_level" in resp.json()["detail"]


def test_conflicting_rule_level_filters_returns_400(client):
    """Combining exact rule_level with min or max returns 400 Bad Request."""
    resp1 = client.get("/api/v1/alerts?rule_level=5&min_rule_level=3")
    assert resp1.status_code == 400
    assert "Cannot combine rule_level" in resp1.json()["detail"]

    resp2 = client.get("/api/v1/alerts?rule_level=5&max_rule_level=8")
    assert resp2.status_code == 400
    assert "Cannot combine rule_level" in resp2.json()["detail"]


def test_malformed_timestamp_returns_422(client):
    """Malformed start_time or end_time returns 422 Unprocessable Entity."""
    resp = client.get("/api/v1/alerts?start_time=not-a-timestamp")
    assert resp.status_code == 422
