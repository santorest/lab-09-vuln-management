from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vulnmgmt.normalize import ReportError, parse_report


def v1(fixtures):
    return (fixtures / "report-v1.xml").read_bytes()


def test_parses_times_hosts_and_findings(fixtures, assets):
    result = parse_report(v1(fixtures), assets)
    assert result.started == datetime(2026, 10, 1, 18, 0, tzinfo=UTC)
    assert result.finished == datetime(2026, 10, 1, 18, 20, tzinfo=UTC)
    assert result.hosts == ("web", "files", "db")
    assert len(result.findings) == 8  # 11 results: 1 log, 1 low quality, 2 merged into one


def test_merges_the_same_oid_on_one_host(fixtures, assets):
    [ssh] = [f for f in parse_report(v1(fixtures), assets).findings if f.oid.endswith("2024.5724")]
    assert (ssh.host, ssh.ports, ssh.cves, ssh.cvss) == ("web", ("22/tcp", "general/tcp"), ("CVE-2024-6387",), 8.1)


def test_keeps_findings_without_cve_and_sorts_cves(fixtures, assets):
    found = {f.oid: f for f in parse_report(v1(fixtures), assets).findings}
    assert found["1.3.6.1.4.1.25623.1.0.900600"].cves == ()
    assert found["1.3.6.1.4.1.25623.1.0.900600"].solution == "Disable anonymous logins <if not required>."
    assert found["1.3.6.1.4.1.25623.1.1.1.1.2024.5770"].cves == ("CVE-2024-45491", "CVE-2024-45492")


def test_drops_log_and_low_quality_results(fixtures, assets):
    oids = {f.oid for f in parse_report(v1(fixtures), assets).findings}
    assert "1.3.6.1.4.1.25623.1.0.105937" not in oids  # severity 0.0
    assert "1.3.6.1.4.1.25623.1.0.111111" not in oids  # QoD 30
    assert "1.3.6.1.4.1.25623.1.0.111111" in {f.oid for f in parse_report(v1(fixtures), assets, min_qod=30).findings}


def test_unfinished_scan_is_an_error(fixtures, assets):
    xml = v1(fixtures).replace(b"<scan_run_status>Done", b"<scan_run_status>Interrupted")
    with pytest.raises(ReportError, match="scan status is Interrupted, not Done"):
        parse_report(xml, assets)


def test_host_missing_from_the_report_is_an_error(fixtures, assets):
    xml = v1(fixtures).replace(b'<host><ip>172.30.0.13</ip><asset asset_id=""/></host>', b"")
    with pytest.raises(ReportError, match="db \\(172.30.0.13\\) is missing from the report"):
        parse_report(xml, assets)


def test_result_for_an_unknown_address_is_an_error(fixtures, assets):
    xml = v1(fixtures).replace(b"<host>172.30.0.13<asset", b"<host>10.9.9.9<asset", 1)
    with pytest.raises(ReportError, match="result for 10.9.9.9, which is not in the asset inventory"):
        parse_report(xml, assets)


def test_not_a_report(assets):
    with pytest.raises(ReportError, match="no report"):
        parse_report(b"<get_reports_response/>", assets)
    with pytest.raises(ReportError, match="not XML"):
        parse_report(b"not xml", assets)
