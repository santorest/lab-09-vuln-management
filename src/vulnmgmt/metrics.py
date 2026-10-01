"""Before/after metrics of one cycle."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from vulnmgmt.models import PRIORITIES, Policy
from vulnmgmt.tracker import OPEN_STATES, Row, gating


def _count(rows: Sequence[Row]) -> dict[str, int]:
    return {p: sum(1 for r in rows if r.priority == p) for p in PRIORITIES}


def compute(before: Sequence[Row], after: Sequence[Row], policy: Policy) -> dict[str, Any]:
    tracked_before = [r for r in before if r.status != "info"]
    fixed = [r for r in after if r.status == "fixed" and r.priority in PRIORITIES]
    minutes = [
        (datetime.fromisoformat(r.closed) - datetime.fromisoformat(r.opened)).total_seconds() / 60 for r in fixed
    ]
    return {
        "before": _count(tracked_before),
        "after_open": _count([r for r in after if r.status in OPEN_STATES]),
        "fixed": len(fixed),
        "fixed_pct": round(100 * len(fixed) / len(tracked_before), 1) if tracked_before else 0.0,
        "new": sum(1 for r in after if r.status == "new"),
        "risk_accepted": sum(1 for r in after if r.status == "risk accepted"),
        "reopened": sum(1 for r in after if r.status == "reopened"),
        "kev_before": sum(1 for r in tracked_before if r.kev),
        "high_epss_before": sum(1 for r in tracked_before if r.epss and float(r.epss) >= policy.epss_threshold),
        "mean_minutes_to_fix": round(sum(minutes) / len(minutes), 1) if minutes else None,
        "gating": len(gating(after, policy)),
    }
