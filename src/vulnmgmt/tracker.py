"""Remediation tracker: one row per (host, Greenbone NVT OID), with priority, owner, SLA due date and status."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta
from pathlib import Path

from vulnmgmt.models import INFORMATIONAL, PRIORITIES, Policy, RiskAcceptance
from vulnmgmt.prioritize import Prioritized

OPEN_STATES = ("open", "new", "reopened")
STATUS_ORDER = ("reopened", "new", "open", "risk accepted", "fixed", "info")


@dataclass
class Row:
    host: str
    oid: str
    name: str
    priority: str
    cvss: str
    epss: str
    kev: str
    rule: str
    owner: str
    opened: str
    due: str
    status: str
    closed: str
    note: str


def _row(item: Prioritized, at: datetime, policy: Policy, status: str) -> Row:
    info = item.priority == INFORMATIONAL
    due = "" if info else (at.date() + timedelta(days=policy.sla_days[item.priority])).isoformat()
    return Row(
        host=item.asset.name,
        oid=item.finding.oid,
        name=item.finding.name,
        priority=item.priority,
        cvss=f"{item.cvss:.1f}",
        epss="" if item.epss is None else f"{item.epss:.4f}",
        kev="yes" if item.kev else "",
        rule=item.rule,
        owner=item.asset.owner,
        opened=at.isoformat(),
        due=due,
        status="info" if info else status,
        closed="",
        note="",
    )


def _apply_exceptions(rows: list[Row], exceptions: Sequence[RiskAcceptance], at: datetime) -> None:
    by_key = {(e.host, e.oid): e for e in exceptions}
    for row in rows:
        acceptance = by_key.get((row.host, row.oid))
        if acceptance is None or row.status not in OPEN_STATES:
            continue
        if acceptance.expires >= at.date():
            row.status = "risk accepted"
            row.note = f"accepted by {acceptance.approver} until {acceptance.expires.isoformat()}: {acceptance.reason}"
        else:
            row.status = "reopened"
            row.note = f"exception expired {acceptance.expires.isoformat()}"


def build(
    items: Sequence[Prioritized], scanned_at: datetime, policy: Policy, exceptions: Sequence[RiskAcceptance]
) -> list[Row]:
    rows = [_row(item, scanned_at, policy, "open") for item in items]
    _apply_exceptions(rows, exceptions, scanned_at)
    return rows


def update(
    rows: Sequence[Row],
    items: Sequence[Prioritized],
    rescanned_at: datetime,
    policy: Policy,
    exceptions: Sequence[RiskAcceptance],
) -> list[Row]:
    current = {(i.asset.name, i.finding.oid): i for i in items}
    out: list[Row] = []
    for old in rows:
        row = Row(**asdict(old))
        if (row.host, row.oid) in current:
            if row.status != "info":
                row.status, row.note = "open", ""
        else:
            row.status, row.closed = "fixed", rescanned_at.isoformat()
        out.append(row)
    known = {(r.host, r.oid) for r in rows}
    out += [_row(item, rescanned_at, policy, "new") for key, item in current.items() if key not in known]
    _apply_exceptions(out, exceptions, rescanned_at)
    return out


def gating(rows: Sequence[Row], policy: Policy) -> list[Row]:
    return [r for r in rows if r.priority in policy.gate and r.status in OPEN_STATES]


def write_csv(rows: Sequence[Row], path: Path) -> None:
    names = [f.name for f in fields(Row)]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names, lineterminator="\n")
        writer.writeheader()
        writer.writerows(asdict(r) for r in rows)


def read_csv(path: Path) -> list[Row]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [Row(**row) for row in csv.DictReader(handle)]


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _sort_key(row: Row) -> tuple[int, int, str, str]:
    order = list(PRIORITIES) + [INFORMATIONAL]
    return (order.index(row.priority), STATUS_ORDER.index(row.status), row.host, row.oid)


def to_markdown(rows: Sequence[Row]) -> str:
    lines = [
        "| Priority | Status | Host | Finding | CVSS | EPSS | KEV | Owner | Due |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=_sort_key):
        lines.append(
            f"| {r.priority} | {r.status} | {_md(r.host)} | {_md(r.name)} | {r.cvss} | {r.epss or 'unknown'} "
            f"| {r.kev or 'no'} | {_md(r.owner)} | {r.due or '-'} |"
        )
    return "\n".join(lines) + "\n"
