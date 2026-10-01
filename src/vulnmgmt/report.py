"""Markdown summary (job summary, write-up) and a self-contained HTML report. All scanner text is escaped."""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from typing import Any

from vulnmgmt.models import PRIORITIES
from vulnmgmt.tracker import Row, to_markdown


def _summary_rows(metrics: Mapping[str, Any]) -> list[tuple[str, int, int]]:
    return [(p, metrics["before"][p], metrics["after_open"][p]) for p in PRIORITIES]


def render_markdown(metrics: Mapping[str, Any], rows: Sequence[Row], meta: Mapping[str, str]) -> str:
    lines = [
        "## Vulnerability management cycle",
        "",
        f"Scan v1 {meta['scan_v1']} · rescan v2 {meta['scan_v2']} · EPSS snapshot {meta['epss_date']} · "
        f"CISA KEV catalog {meta['kev_version']}",
        "",
        "| Priority | Open before | Open after |",
        "|---|---|---|",
        *[f"| {p} | {b} | {a} |" for p, b, a in _summary_rows(metrics)],
        "",
        f"Fixed {metrics['fixed']} ({metrics['fixed_pct']} %) · new {metrics['new']} · risk accepted "
        f"{metrics['risk_accepted']} · reopened {metrics['reopened']} · in KEV before {metrics['kev_before']} · "
        f"EPSS above threshold before {metrics['high_epss_before']} · mean time to fix "
        f"{metrics['mean_minutes_to_fix']} min · gating {metrics['gating']}",
        "",
        to_markdown(rows),
    ]
    return "\n".join(lines)


def render_html(metrics: Mapping[str, Any], rows: Sequence[Row], meta: Mapping[str, str]) -> str:
    e = html.escape
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8"><title>Vulnerability management cycle</title>',
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1b1f24}table{border-collapse:collapse;"
        "margin:.5rem 0 1.5rem}th,td{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left;vertical-align:top}"
        "th{background:#f6f8fa}</style></head><body>",
        "<h1>Vulnerability management cycle</h1>",
        f"<p>Scan v1 {e(meta['scan_v1'])} &middot; rescan v2 {e(meta['scan_v2'])} &middot; EPSS snapshot "
        f"{e(meta['epss_date'])} &middot; CISA KEV catalog {e(meta['kev_version'])}</p>",
        "<table><tr><th>Priority</th><th>Open before</th><th>Open after</th></tr>",
        *[f"<tr><td>{p}</td><td>{b}</td><td>{a}</td></tr>" for p, b, a in _summary_rows(metrics)],
        "</table>",
        f"<p>Fixed {metrics['fixed']} ({metrics['fixed_pct']} %), new {metrics['new']}, risk accepted "
        f"{metrics['risk_accepted']}, reopened {metrics['reopened']}, gating {metrics['gating']}.</p>",
        "<table><tr><th>Priority</th><th>Status</th><th>Host</th><th>Finding</th><th>CVSS</th><th>EPSS</th>"
        "<th>KEV</th><th>Owner</th><th>Due</th><th>Why</th></tr>",
    ]
    for r in rows:
        parts.append(
            f"<tr><td>{e(r.priority)}</td><td>{e(r.status)}</td><td>{e(r.host)}</td><td>{e(r.name)}</td>"
            f"<td>{e(r.cvss)}</td><td>{e(r.epss or 'unknown')}</td><td>{e(r.kev or 'no')}</td><td>{e(r.owner)}</td>"
            f"<td>{e(r.due or '-')}</td><td>{e(r.rule)}{' — ' + e(r.note) if r.note else ''}</td></tr>"
        )
    parts.append("</table></body></html>")
    return "\n".join(parts) + "\n"
