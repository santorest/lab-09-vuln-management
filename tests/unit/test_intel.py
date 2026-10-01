from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnmgmt.intel import EPSS_URL, KEV_URL, IntelError, fetch_intel, load_intel


def test_load_fixture_intel(fixtures):
    intel = load_intel(fixtures / "intel")
    assert intel.epss["CVE-2024-6387"] == 0.99506
    assert "CVE-2024-45492" not in intel.epss
    assert intel.kev == frozenset({"CVE-2023-4911"})
    assert (intel.epss_date, intel.kev_version) == ("2026-10-01", "2026.10.01")


class FakeWeb:
    def __init__(self, kev):
        self.kev = kev
        self.urls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.urls.append(url)
        if url == KEV_URL:
            return json.dumps(self.kev).encode()
        cves = url.split("cve=", 1)[1].split(",")
        data = [
            {"cve": c, "epss": "0.5", "percentile": "0.9", "date": "2026-10-02"} for c in cves if c != "CVE-2024-0002"
        ]
        return json.dumps({"status": "OK", "data": data}).encode()


def test_fetch_batches_epss_and_saves_both_snapshots(tmp_path: Path):
    web = FakeWeb({"catalogVersion": "2026.10.02", "vulnerabilities": [{"cveID": "CVE-2024-0001"}]})
    cves = [f"CVE-2024-{n:04d}" for n in range(1, 151)] + ["CVE-2024-0001"]  # 150 unique, one duplicate
    intel = fetch_intel(cves, tmp_path, get=web)
    epss_calls = [u for u in web.urls if u.startswith(EPSS_URL)]
    assert len(epss_calls) == 2  # 100 + 50
    assert len(intel.epss) == 149 and "CVE-2024-0002" not in intel.epss
    assert intel.kev == frozenset({"CVE-2024-0001"}) and intel.kev_version == "2026.10.02"
    assert load_intel(tmp_path) == intel


def test_rejects_malformed_cve_ids(tmp_path: Path):
    with pytest.raises(IntelError, match="not a CVE id"):
        fetch_intel(["CVE-2024-1,DROP"], tmp_path, get=FakeWeb({"vulnerabilities": []}))


def test_bad_feed_is_an_error(tmp_path: Path):
    def broken(url: str) -> bytes:
        return b"<html>maintenance</html>"

    with pytest.raises(IntelError, match="unreadable"):
        fetch_intel(["CVE-2024-0001"], tmp_path, get=broken)


def test_no_cves_still_saves_kev(tmp_path: Path):
    intel = fetch_intel([], tmp_path, get=FakeWeb({"catalogVersion": "v", "vulnerabilities": []}))
    assert intel.epss == {} and (tmp_path / "kev.json").exists() and (tmp_path / "epss.json").exists()
