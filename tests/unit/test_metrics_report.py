from __future__ import annotations

from vulnmgmt.intel import load_intel
from vulnmgmt.metrics import compute
from vulnmgmt.normalize import parse_report
from vulnmgmt.prioritize import prioritize_all
from vulnmgmt.report import render_html, render_markdown
from vulnmgmt.tracker import build, update

META = {
    "scan_v1": "2026-10-01T18:00:00+00:00",
    "scan_v2": "2026-10-01T18:40:00+00:00",
    "epss_date": "2026-10-01",
    "kev_version": "2026.10.01",
}


def cycle(fixtures, assets, policy):
    intel = load_intel(fixtures / "intel")
    r1 = parse_report((fixtures / "report-v1.xml").read_bytes(), assets)
    r2 = parse_report((fixtures / "report-v2.xml").read_bytes(), assets)
    before = build(prioritize_all(r1.findings, assets, intel, policy), r1.started, policy, [])
    after = update(before, prioritize_all(r2.findings, assets, intel, policy), r2.started, policy, [])
    return before, after


def test_metrics(fixtures, assets, policy):
    before, after = cycle(fixtures, assets, policy)
    m = compute(before, after, policy)
    assert m["before"] == {"P1": 2, "P2": 2, "P3": 1, "P4": 2}
    assert m["after_open"] == {"P1": 0, "P2": 0, "P3": 0, "P4": 2}
    assert (m["fixed"], m["fixed_pct"], m["new"], m["risk_accepted"], m["reopened"]) == (6, 85.7, 1, 0, 0)
    assert (m["kev_before"], m["high_epss_before"], m["gating"]) == (1, 3, 0)
    assert m["mean_minutes_to_fix"] == 40.0


def test_markdown_summary(fixtures, assets, policy):
    before, after = cycle(fixtures, assets, policy)
    md = render_markdown(compute(before, after, policy), after, META)
    assert md.startswith("## Vulnerability management cycle")
    assert "| P1 | 2 | 0 |" in md
    assert "EPSS snapshot 2026-10-01 · CISA KEV catalog 2026.10.01" in md


def test_html_escapes_scanner_text(fixtures, assets, policy):
    before, after = cycle(fixtures, assets, policy)
    after[0].name = "<script>alert(1)</script>"
    page = render_html(compute(before, after, policy), after, META)
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert render_html(compute(before, after, policy), after, META) == page
