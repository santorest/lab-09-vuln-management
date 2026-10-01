from __future__ import annotations

import json
import shutil
from pathlib import Path

from vulnmgmt.cli import main

ROOT = Path(__file__).resolve().parents[2]


def test_track_and_gate_pass_on_the_fixture_cycle(fixtures, tmp_path: Path, capsys):
    out = tmp_path / "out"
    code = main(
        [
            "track",
            "--before",
            str(fixtures / "report-v1.xml"),
            "--after",
            str(fixtures / "report-v2.xml"),
            "--intel",
            str(fixtures / "intel"),
            "--policy-dir",
            str(ROOT / "policy"),
            "--out-dir",
            str(out),
        ]
    )
    assert code == 0
    for name in ("tracker-v1.csv", "tracker.csv", "tracker.md", "metrics.json", "summary.md", "report.html"):
        assert (out / name).exists(), name
    assert json.loads((out / "metrics.json").read_text(encoding="utf-8"))["gating"] == 0
    assert main(["gate", "--tracker", str(out / "tracker.csv"), "--policy-dir", str(ROOT / "policy")]) == 0


def test_gate_fails_on_open_p1(fixtures, tmp_path: Path, capsys):
    out = tmp_path / "out"
    # "after" = the v1 report again: nothing was remediated
    main(
        [
            "track",
            "--before",
            str(fixtures / "report-v1.xml"),
            "--after",
            str(fixtures / "report-v1.xml"),
            "--intel",
            str(fixtures / "intel"),
            "--policy-dir",
            str(ROOT / "policy"),
            "--out-dir",
            str(out),
        ]
    )
    assert main(["gate", "--tracker", str(out / "tracker.csv"), "--policy-dir", str(ROOT / "policy")]) == 1
    assert "4 finding(s) at P1/P2 still open" in capsys.readouterr().err


GATING = [
    ("web", "1.3.6.1.4.1.25623.1.1.2.2023.5514"),
    ("web", "1.3.6.1.4.1.25623.1.1.2.2024.5724"),
    ("db", "1.3.6.1.4.1.25623.1.1.2.2024.5812"),
    ("db", "1.3.6.1.4.1.25623.1.1.2.2024.5770"),
]


def gate_with_exceptions(fixtures, tmp_path: Path, last_expiry: str) -> int:
    """Nothing remediated (v1 scanned twice); every P1/P2 has an exception; only the last one's expiry varies."""
    policy_dir = tmp_path / "policy"
    shutil.copytree(ROOT / "policy", policy_dir)
    entries = [
        f"  - {{host: {host}, oid: {oid}, reason: 'compensating control', approver: security lead, "
        f"expires: {'2026-12-31' if i < 3 else last_expiry}}}"
        for i, (host, oid) in enumerate(GATING)
    ]
    (policy_dir / "exceptions.yaml").write_text("exceptions:\n" + "\n".join(entries) + "\n", encoding="utf-8")
    out = tmp_path / "out"
    main(
        [
            "track",
            "--before",
            str(fixtures / "report-v1.xml"),
            "--after",
            str(fixtures / "report-v1.xml"),
            "--intel",
            str(fixtures / "intel"),
            "--policy-dir",
            str(policy_dir),
            "--out-dir",
            str(out),
        ]
    )
    return main(["gate", "--tracker", str(out / "tracker.csv"), "--policy-dir", str(policy_dir)])


def test_valid_exceptions_pass_the_gate(fixtures, tmp_path: Path):
    assert gate_with_exceptions(fixtures, tmp_path, "2026-12-31") == 0


def test_one_expired_exception_fails_the_gate(fixtures, tmp_path: Path, capsys):
    assert gate_with_exceptions(fixtures, tmp_path, "2026-09-30") == 1
    assert "reopened db 1.3.6.1.4.1.25623.1.1.2.2024.5770" in capsys.readouterr().err


def test_bad_report_exits_two(fixtures, tmp_path: Path, capsys):
    bad = tmp_path / "bad.xml"
    bad.write_bytes((fixtures / "report-v1.xml").read_bytes().replace(b">Done<", b">Stopped<"))
    code = main(
        [
            "track",
            "--before",
            str(bad),
            "--after",
            str(fixtures / "report-v2.xml"),
            "--intel",
            str(fixtures / "intel"),
            "--policy-dir",
            str(ROOT / "policy"),
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    assert "scan status is Stopped" in capsys.readouterr().err


def test_intel_command_collects_cves_from_both_reports(fixtures, tmp_path: Path, monkeypatch):
    seen: list[list[str]] = []

    def fake_fetch(cves, out_dir, get=None):
        seen.append(sorted(cves))
        from vulnmgmt.intel import load_intel

        return load_intel(fixtures / "intel")

    monkeypatch.setattr("vulnmgmt.cli.fetch_intel", fake_fetch)
    code = main(
        [
            "intel",
            "--reports",
            str(fixtures / "report-v1.xml"),
            str(fixtures / "report-v2.xml"),
            "--assets",
            str(ROOT / "policy" / "assets.csv"),
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert seen == [
        [
            "CVE-2023-4911",
            "CVE-2023-5678",
            "CVE-2024-10979",
            "CVE-2024-45491",
            "CVE-2024-45492",
            "CVE-2024-6387",
            "CVE-2024-7347",
        ]
    ]
