from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

from vulnmgmt.intel import load_intel
from vulnmgmt.models import RiskAcceptance
from vulnmgmt.normalize import parse_report
from vulnmgmt.prioritize import prioritize_all
from vulnmgmt.tracker import build, gating, read_csv, to_markdown, update, write_csv

FTP = "1.3.6.1.4.1.25623.1.0.900600"
NGINX = "1.3.6.1.4.1.25623.1.1.1.1.2024.5755"


def items(fixtures, assets, policy, name):
    result = parse_report((fixtures / name).read_bytes(), assets)
    return result, prioritize_all(result.findings, assets, load_intel(fixtures / "intel"), policy)


def cycle(fixtures, assets, policy, exceptions=()):
    first, before = items(fixtures, assets, policy, "report-v1.xml")
    second, after = items(fixtures, assets, policy, "report-v2.xml")
    rows = build(before, first.started, policy, list(exceptions))
    return rows, update(rows, after, second.started, policy, list(exceptions))


def test_first_scan_opens_rows_with_sla_due_dates(fixtures, assets, policy):
    rows, _ = cycle(fixtures, assets, policy)
    by_oid = {r.oid: r for r in rows}
    glibc = by_oid["1.3.6.1.4.1.25623.1.1.1.1.2023.5514"]
    assert (glibc.status, glibc.priority, glibc.due, glibc.owner, glibc.kev) == (
        "open",
        "P1",
        "2026-10-08",
        "web team",
        "yes",
    )
    assert by_oid["1.3.6.1.4.1.25623.1.0.105610"].status == "info"
    assert by_oid["1.3.6.1.4.1.25623.1.0.105610"].due == ""
    assert by_oid[NGINX].due == "2027-03-30"  # P4: 180 days


def test_rescan_fixes_keeps_and_adds(fixtures, assets, policy):
    _, after = cycle(fixtures, assets, policy)
    status = {r.oid: r.status for r in after}
    assert status[NGINX] == "open"
    assert status["1.3.6.1.4.1.25623.1.0.999001"] == "new"
    assert status["1.3.6.1.4.1.25623.1.1.1.1.2023.5514"] == "fixed"
    fixed = next(r for r in after if r.oid == "1.3.6.1.4.1.25623.1.1.1.1.2023.5514")
    assert fixed.closed == "2026-10-01T18:40:00+00:00"
    assert gating(after, policy) == []


def test_valid_exception_accepts_risk_and_leaves_the_gate(fixtures, assets, policy):
    acceptance = RiskAcceptance("web", NGINX, "vendor fix pending", "CISO", date(2026, 12, 31))
    _, after = cycle(fixtures, assets, policy, [acceptance])
    row = next(r for r in after if r.oid == NGINX)
    assert row.status == "risk accepted"
    assert row.note == "accepted by CISO until 2026-12-31: vendor fix pending"


def test_expired_exception_reopens_and_gates(fixtures, assets, policy):
    first, before = items(fixtures, assets, policy, "report-v1.xml")
    expired = RiskAcceptance("web", "1.3.6.1.4.1.25623.1.1.1.1.2023.5514", "legacy", "CISO", date(2026, 9, 30))
    rows = build(before, first.started, policy, [expired])
    row = next(r for r in rows if r.oid.endswith("2023.5514"))
    assert (row.status, row.note) == ("reopened", "exception expired 2026-09-30")
    assert row in gating(rows, policy)


def test_exception_for_another_host_or_a_fixed_finding_does_nothing(fixtures, assets, policy):
    wrong_host = RiskAcceptance("files", NGINX, "x", "CISO", date(2026, 12, 31))
    gone = RiskAcceptance("files", FTP, "x", "CISO", date(2026, 12, 31))
    _, after = cycle(fixtures, assets, policy, [wrong_host, gone])
    status = {r.oid: r.status for r in after}
    assert status[NGINX] == "open" and status[FTP] == "fixed"


def test_open_p1_gates(fixtures, assets, policy):
    rows, _ = cycle(fixtures, assets, policy)
    assert {r.priority for r in gating(rows, policy)} == {"P1", "P2"}


def test_csv_round_trip_and_markdown_board(fixtures, assets, policy, tmp_path: Path):
    _, after = cycle(fixtures, assets, policy)
    path = tmp_path / "tracker.csv"
    write_csv(after, path)
    assert read_csv(path) == after
    board = to_markdown(after)
    assert board.splitlines()[0] == "| Priority | Status | Host | Finding | CVSS | EPSS | KEV | Owner | Due |"
    assert "| P4 | new | db | PostgreSQL Default Port Exposed |" in board


def test_markdown_escapes_pipes(fixtures, assets, policy):
    _, before = items(fixtures, assets, policy, "report-v1.xml")
    rows = build(before, datetime(2026, 10, 1, tzinfo=UTC), policy, [])
    rows[0].name = "a | b"
    assert "a \\| b" in to_markdown(rows)
