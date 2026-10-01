"""vulnmgmt: scan | intel | track | gate. Exit 0 ok, 1 gate failed, 2 error."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from vulnmgmt.intel import IntelError, fetch_intel, load_intel
from vulnmgmt.metrics import compute
from vulnmgmt.models import ConfigError, load_assets, load_exceptions, load_policy
from vulnmgmt.normalize import ReportError, parse_report
from vulnmgmt.prioritize import prioritize_all
from vulnmgmt.report import render_html, render_markdown
from vulnmgmt.scan import ScanError, Timeouts
from vulnmgmt.tracker import build, gating, read_csv, to_markdown, update, write_csv


def cmd_scan(args: argparse.Namespace) -> int:
    from vulnmgmt.scan import scan

    password = os.environ.get("GVM_PASSWORD")
    if not password:
        raise ConfigError("GVM_PASSWORD is not set")
    xml = scan(
        password,
        load_assets(args.assets),
        args.key.read_text(encoding="utf-8"),
        args.name,
        Timeouts(ready=args.ready_timeout, scan=args.scan_timeout),
    )
    args.out.write_bytes(xml)
    parse_report(xml, load_assets(args.assets))  # fail now if the report is unusable
    print(f"{args.name}: report saved to {args.out}")
    return 0


def cmd_intel(args: argparse.Namespace) -> int:
    assets = load_assets(args.assets)
    cves: set[str] = set()
    for path in args.reports:
        for finding in parse_report(path.read_bytes(), assets).findings:
            cves.update(finding.cves)
    intel = fetch_intel(sorted(cves), args.out_dir)
    print(
        f"EPSS {intel.epss_date}: {len(intel.epss)} of {len(cves)} CVEs scored; KEV {intel.kev_version}: "
        f"{len(cves & intel.kev)} listed"
    )
    return 0


def cmd_track(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy_dir / "policy.yaml")
    assets = load_assets(args.policy_dir / "assets.csv")
    exceptions = load_exceptions(args.policy_dir / "exceptions.yaml")
    intel = load_intel(args.intel)
    first = parse_report(args.before.read_bytes(), assets)
    second = parse_report(args.after.read_bytes(), assets)
    before = build(prioritize_all(first.findings, assets, intel, policy), first.started, policy, exceptions)
    after = update(before, prioritize_all(second.findings, assets, intel, policy), second.started, policy, exceptions)
    metrics = compute(before, after, policy)
    meta = {
        "scan_v1": first.started.isoformat(),
        "scan_v2": second.started.isoformat(),
        "epss_date": intel.epss_date,
        "kev_version": intel.kev_version,
    }
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    write_csv(before, out / "tracker-v1.csv")
    write_csv(after, out / "tracker.csv")
    (out / "tracker.md").write_text(to_markdown(after), encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps({**metrics, **meta}, indent=2) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(render_markdown(metrics, after, meta), encoding="utf-8")
    (out / "report.html").write_text(render_html(metrics, after, meta), encoding="utf-8")
    print(json.dumps(metrics))
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy_dir / "policy.yaml")
    blocking = gating(read_csv(args.tracker), policy)
    if blocking:
        print(
            f"FAIL: {len(blocking)} finding(s) at {'/'.join(policy.gate)} still open without a valid exception:",
            file=sys.stderr,
        )
        for r in blocking:
            print(f"  {r.priority} {r.status} {r.host} {r.oid} {r.name} (due {r.due})", file=sys.stderr)
        return 1
    print(f"gate passed: no open {'/'.join(policy.gate)} findings")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnmgmt")
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("scan", help="run one Greenbone scan of the fleet (inside the runner container)")
    p.add_argument("--assets", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--ready-timeout", type=float, default=2400)
    p.add_argument("--scan-timeout", type=float, default=3000)
    p.set_defaults(func=cmd_scan)
    p = sub.add_parser("intel", help="fetch EPSS and KEV for the CVEs of the reports and save snapshots")
    p.add_argument("--reports", type=Path, nargs="+", required=True)
    p.add_argument("--assets", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.set_defaults(func=cmd_intel)
    p = sub.add_parser("track", help="prioritize both scans, build and update the tracker, write the reports")
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--intel", type=Path, required=True)
    p.add_argument("--policy-dir", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.set_defaults(func=cmd_track)
    p = sub.add_parser("gate", help="fail if a gating finding is still open")
    p.add_argument("--tracker", type=Path, required=True)
    p.add_argument("--policy-dir", type=Path, required=True)
    p.set_defaults(func=cmd_gate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (ConfigError, ReportError, IntelError, ScanError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
