from __future__ import annotations

import pytest

from vulnmgmt.intel import Intel, load_intel
from vulnmgmt.normalize import Finding, parse_report
from vulnmgmt.prioritize import prioritize, prioritize_all


def finding(cvss, cves=(), host="files"):
    return Finding(
        host=host,
        address="x",
        oid="1.2.3",
        name="n",
        cves=tuple(cves),
        cvss=cvss,
        ports=("general/tcp",),
        qod=97,
        solution="",
    )


INTEL = Intel(
    epss={"CVE-1": 0.5, "CVE-2": 0.05, "CVE-3": 0.10}, kev=frozenset({"CVE-K"}), epss_date="d", kev_version="v"
)


def asset_named(assets, name):
    return next(a for a in assets if a.name == name)


@pytest.mark.parametrize(
    ("cvss", "cves", "host", "expected"),
    [
        (2.0, ["CVE-K"], "files", "P1"),  # KEV wins even below the floor
        (7.0, ["CVE-1"], "files", "P1"),  # EPSS >= 0.10 and CVSS >= 7.0 (boundaries inclusive)
        (6.9, ["CVE-1"], "files", "P3"),  # high EPSS, CVSS just under 7: P3
        (9.0, [], "files", "P2"),  # critical CVSS
        (7.0, ["CVE-2"], "db", "P2"),  # high CVSS on a criticality-3 asset
        (7.0, ["CVE-2"], "web", "P2"),  # high CVSS on an internet-facing asset
        (7.0, ["CVE-2"], "files", "P3"),  # high CVSS, internal criticality-2 asset
        (5.0, ["CVE-3"], "files", "P3"),  # EPSS exactly 0.10
        (4.0, [], "files", "P4"),  # exactly the floor
        (3.9, [], "files", "info"),  # under the floor
    ],
)
def test_rules(assets, policy, cvss, cves, host, expected):
    assert prioritize(finding(cvss, cves, host), asset_named(assets, host), INTEL, policy).priority == expected


def test_worst_value_of_each_input_decides(assets, policy):
    p = prioritize(finding(7.5, ["CVE-2", "CVE-1", "CVE-9"]), asset_named(assets, "files"), INTEL, policy)
    assert (p.priority, p.epss, p.kev) == ("P1", 0.5, False)


def test_missing_epss_is_zero_and_reported_as_unknown(assets, policy):
    p = prioritize(finding(7.5, ["CVE-9"]), asset_named(assets, "files"), INTEL, policy)
    assert (p.priority, p.epss) == ("P3", None)
    assert "EPSS unknown" in p.rule


def test_rule_text_names_the_inputs(assets, policy):
    p = prioritize(finding(7.0, ["CVE-2"]), asset_named(assets, "db"), INTEL, policy)
    assert p.rule == "P2: CVSS 7.0 >= 7.0 on a criticality-3 asset (EPSS 0.05)"


def test_fixture_report_priorities(fixtures, assets, policy):
    result = parse_report((fixtures / "report-v1.xml").read_bytes(), assets)
    got = {
        p.finding.oid.rsplit(".", 2)[-2] + "." + p.finding.oid.rsplit(".", 1)[-1]: p.priority
        for p in prioritize_all(result.findings, assets, load_intel(fixtures / "intel"), policy)
    }
    assert got == {
        "2023.5514": "P1",
        "2024.5724": "P1",
        "2024.5755": "P4",
        "0.900600": "P4",
        "2023.5532": "P3",
        "2024.5812": "P2",
        "2024.5770": "P2",
        "0.105610": "info",
    }
