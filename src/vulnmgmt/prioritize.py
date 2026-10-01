"""The prioritization formula (docs/prioritization.md). First matching rule wins; every input is kept."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from vulnmgmt.intel import Intel
from vulnmgmt.models import INFORMATIONAL, Asset, Policy
from vulnmgmt.normalize import Finding


@dataclass(frozen=True)
class Prioritized:
    finding: Finding
    asset: Asset
    priority: str
    cvss: float
    epss: float | None
    kev: bool
    rule: str


def _epss_text(epss: float | None) -> str:
    return "EPSS unknown" if epss is None else f"EPSS {epss:.2f}"


def prioritize(finding: Finding, asset: Asset, intel: Intel, policy: Policy) -> Prioritized:
    known = [intel.epss[c] for c in finding.cves if c in intel.epss]
    epss = max(known) if known else None
    e = epss or 0.0
    kev = any(c in intel.kev for c in finding.cves)
    cvss = finding.cvss
    high, critical, threshold = policy.high_cvss, policy.critical_cvss, policy.epss_threshold
    where = f"({_epss_text(epss)})"
    if kev:
        priority, rule = "P1", f"P1: a CVE is in CISA KEV {where}"
    elif e >= threshold and cvss >= high:
        priority, rule = "P1", f"P1: EPSS {e:.2f} >= {threshold:.2f} and CVSS {cvss:.1f} >= {high:.1f}"
    elif cvss >= critical:
        priority, rule = "P2", f"P2: CVSS {cvss:.1f} >= {critical:.1f} {where}"
    elif cvss >= high and asset.criticality == 3:
        priority, rule = "P2", f"P2: CVSS {cvss:.1f} >= {high:.1f} on a criticality-3 asset {where}"
    elif cvss >= high and asset.exposure == "internet-facing":
        priority, rule = "P2", f"P2: CVSS {cvss:.1f} >= {high:.1f} on an internet-facing asset {where}"
    elif cvss >= high:
        priority, rule = "P3", f"P3: CVSS {cvss:.1f} >= {high:.1f} {where}"
    elif e >= threshold:
        priority, rule = "P3", f"P3: EPSS {e:.2f} >= {threshold:.2f} (CVSS {cvss:.1f})"
    elif cvss >= policy.cvss_floor:
        priority, rule = "P4", f"P4: CVSS {cvss:.1f} >= floor {policy.cvss_floor:.1f} {where}"
    else:
        priority, rule = INFORMATIONAL, f"info: CVSS {cvss:.1f} below floor {policy.cvss_floor:.1f} {where}"
    return Prioritized(finding, asset, priority, cvss, epss, kev, rule)


def prioritize_all(
    findings: Sequence[Finding], assets: Sequence[Asset], intel: Intel, policy: Policy
) -> list[Prioritized]:
    by_name = {a.name: a for a in assets}
    return [prioritize(f, by_name[f.host], intel, policy) for f in findings]
