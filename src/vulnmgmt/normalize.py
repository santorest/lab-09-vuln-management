"""Greenbone GMP report (XML report format) → findings per asset. A scan that covered less than the inventory is an
error, never an empty result."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as ET

from vulnmgmt.models import Asset


class ReportError(ValueError):
    """The report is unusable: unfinished scan, missing host, unknown address, not a report."""


@dataclass(frozen=True)
class Finding:
    host: str
    address: str
    oid: str
    name: str
    cves: tuple[str, ...]
    cvss: float
    ports: tuple[str, ...]
    qod: int
    solution: str


@dataclass(frozen=True)
class ScanResult:
    started: datetime
    finished: datetime
    hosts: tuple[str, ...]
    findings: tuple[Finding, ...]


def _time(text: str | None, what: str) -> datetime:
    if not text:
        raise ReportError(f"report has no {what}")
    return datetime.fromisoformat(text.strip().replace("Z", "+00:00")).astimezone(UTC)


def _inner_report(root: Any) -> Any:
    for element in root.iter("report"):
        if element.find("scan_run_status") is not None:
            return element
    raise ReportError("no report with a scan status in the XML")


def parse_report(xml: bytes | str, assets: Sequence[Asset], min_qod: int = 70) -> ScanResult:
    try:
        root = ET.fromstring(xml)
    except ParseError as exc:
        raise ReportError(f"not XML: {exc}") from exc
    report = _inner_report(root)
    status = (report.findtext("scan_run_status") or "").strip()
    if status != "Done":
        raise ReportError(f"scan status is {status or 'empty'}, not Done")
    started = _time(report.findtext("scan_start"), "scan_start")
    finished = _time(report.findtext("scan_end"), "scan_end")
    by_address = {a.address: a for a in assets}
    scanned = {(ip.text or "").strip() for ip in report.findall("host/ip")}
    missing = [f"{a.name} ({a.address})" for a in assets if a.address not in scanned]
    if missing:
        raise ReportError(", ".join(missing) + (" is" if len(missing) == 1 else " are") + " missing from the report")

    merged: dict[tuple[str, str], Finding] = {}
    for result in report.findall("results/result"):
        severity = float(result.findtext("severity") or 0)
        if severity <= 0:
            continue
        address = (result.findtext("host") or "").strip()
        asset = by_address.get(address)
        if asset is None:
            raise ReportError(f"result for {address}, which is not in the asset inventory")
        qod = int(float(result.findtext("qod/value") or 0))
        if qod < min_qod:
            continue
        nvt = result.find("nvt")
        if nvt is None or not nvt.get("oid"):
            raise ReportError(f"result {result.get('id')} has no NVT OID")
        oid = str(nvt.get("oid"))
        cves = tuple(sorted({str(r.get("id")) for r in nvt.findall("refs/ref") if r.get("type") == "cve"}))
        port = (result.findtext("port") or "").strip()
        finding = Finding(
            host=asset.name,
            address=address,
            oid=oid,
            name=(result.findtext("name") or nvt.findtext("name") or oid).strip(),
            cves=cves,
            cvss=severity,
            ports=(port,),
            qod=qod,
            solution=(nvt.findtext("solution") or "").strip(),
        )
        key = (asset.name, oid)
        if key in merged:
            old = merged[key]
            finding = Finding(
                host=old.host,
                address=old.address,
                oid=oid,
                name=old.name,
                cves=tuple(sorted(set(old.cves) | set(cves))),
                cvss=max(old.cvss, severity),
                ports=tuple(sorted(set(old.ports) | {port})),
                qod=max(old.qod, qod),
                solution=old.solution,
            )
        merged[key] = finding
    order = {a.name: i for i, a in enumerate(assets)}
    findings = sorted(merged.values(), key=lambda f: (order[f.host], -f.cvss, f.oid))
    hosts = tuple(a.name for a in assets)
    return ScanResult(started, finished, hosts, tuple(findings))
