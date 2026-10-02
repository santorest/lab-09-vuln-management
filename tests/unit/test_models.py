from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from vulnmgmt.models import ConfigError, load_assets, load_exceptions, load_policy

ROOT = Path(__file__).resolve().parents[2]


def test_repository_policy_loads():
    policy = load_policy(ROOT / "policy" / "policy.yaml")
    assert policy.sla_days == {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
    assert policy.gate == ("P1", "P2")
    assert (policy.cvss_floor, policy.epss_threshold, policy.high_cvss, policy.critical_cvss) == (4.0, 0.10, 7.0, 9.0)


def test_repository_assets_and_exceptions_load():
    assets = load_assets(ROOT / "policy" / "assets.csv")
    assert [a.name for a in assets] == ["web", "files", "db"]
    assert assets[0].criticality == 3 and assets[0].exposure == "internet-facing"
    assert load_exceptions(ROOT / "policy" / "exceptions.yaml") == []


def test_policy_needs_every_priority(tmp_path: Path):
    path = tmp_path / "p.yaml"
    path.write_text(
        "scan_frequency: weekly\ncvss_floor: 4\nthresholds: {epss: 0.1, high_cvss: 7, critical_cvss: 9}\n"
        "sla_days: {P1: 7, P2: 30, P3: 90}\ngate: [P1]\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="sla_days must define P1, P2, P3, P4"):
        load_policy(path)


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("web,172.30.0.11,web team,4,internal", "criticality must be 1, 2 or 3"),
        ("web,172.30.0.11,web team,3,dmz", "exposure must be internet-facing or internal"),
        ("web,172.30.0.11,,3,internal", "owner is required"),
    ],
)
def test_assets_reject_bad_rows(tmp_path: Path, row: str, message: str):
    path = tmp_path / "a.csv"
    path.write_text("name,address,owner,criticality,exposure\n" + row + "\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_assets(path)


def test_assets_reject_duplicates(tmp_path: Path):
    path = tmp_path / "a.csv"
    path.write_text(
        "name,address,owner,criticality,exposure\nweb,10.0.0.1,t,1,internal\nweb,10.0.0.2,t,1,internal\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate asset name web"):
        load_assets(path)


def test_exceptions_parse_and_validate(tmp_path: Path):
    path = tmp_path / "e.yaml"
    path.write_text(
        "exceptions:\n  - {host: files, oid: 1.3.6.1.4.1.25623.1.0.900600, reason: 'legacy partner upload',"
        " approver: CISO, expires: 2026-12-31}\n",
        encoding="utf-8",
    )
    [e] = load_exceptions(path)
    assert (e.host, e.expires, e.approver) == ("files", date(2026, 12, 31), "CISO")
    path.write_text(
        "exceptions:\n  - {host: files, oid: 1.2, reason: '', approver: CISO, expires: 2026-12-31}\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="reason is required"):
        load_exceptions(path)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ("reason: , approver: CISO", "reason is required"),
        ("reason: 'legacy upload', approver: ", "approver is required"),
        ("reason: 'legacy upload', approver: 3", "approver is required"),
    ],
)
def test_exceptions_reject_empty_or_non_text_reason_and_approver(tmp_path: Path, fields: str, message: str):
    # An empty YAML value is None, and str(None) is "None": it must not pass as a reason or an approver.
    path = tmp_path / "e.yaml"
    path.write_text(f"exceptions:\n  - {{host: files, oid: 1.2, {fields}, expires: 2026-12-31}}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_exceptions(path)
