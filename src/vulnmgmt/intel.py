"""Exploit intelligence: FIRST EPSS scores and the CISA KEV catalog, fetched at run time and saved as snapshots so
every priority can be recomputed from exactly what the run used."""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
BATCH = 100


class IntelError(RuntimeError):
    """A feed could not be read."""


@dataclass(frozen=True)
class Intel:
    epss: dict[str, float]
    kev: frozenset[str]
    epss_date: str
    kev_version: str


def http_get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise IntelError(f"refusing non-HTTPS URL {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "lab09-vulnmgmt"})  # noqa: S310 - HTTPS only
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - HTTPS only, checked above
        body: bytes = response.read()
    return body


def _json(raw: bytes, what: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelError(f"{what} response unreadable: {exc}") from exc


def fetch_intel(cves: Iterable[str], out_dir: Path, get: Callable[[str], bytes] = http_get) -> Intel:
    wanted = sorted(set(cves))
    bad = [c for c in wanted if not CVE_ID.match(c)]
    if bad:
        raise IntelError(f"not a CVE id: {', '.join(bad)}")
    scores: dict[str, float] = {}
    dates: set[str] = set()
    for start in range(0, len(wanted), BATCH):
        batch = wanted[start : start + BATCH]
        body = _json(get(f"{EPSS_URL}?cve={','.join(batch)}"), "EPSS")
        try:
            for item in body["data"]:
                scores[str(item["cve"])] = float(item["epss"])
                dates.add(str(item["date"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise IntelError(f"EPSS response unreadable: {exc}") from exc
    kev_catalog = _json(get(KEV_URL), "KEV")
    try:
        kev = frozenset(str(v["cveID"]) for v in kev_catalog["vulnerabilities"])
    except (KeyError, TypeError) as exc:
        raise IntelError(f"KEV response unreadable: {exc}") from exc
    epss_date = max(dates) if dates else datetime.now(UTC).date().isoformat()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "epss.json").write_text(
        json.dumps({"date": epss_date, "source": EPSS_URL, "scores": scores}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "kev.json").write_text(json.dumps(kev_catalog, indent=2) + "\n", encoding="utf-8")
    return Intel(scores, kev, epss_date, str(kev_catalog.get("catalogVersion", "")))


def load_intel(directory: Path) -> Intel:
    try:
        epss = json.loads((directory / "epss.json").read_text(encoding="utf-8"))
        kev = json.loads((directory / "kev.json").read_text(encoding="utf-8"))
        return Intel(
            {str(k): float(v) for k, v in epss["scores"].items()},
            frozenset(str(v["cveID"]) for v in kev["vulnerabilities"]),
            str(epss["date"]),
            str(kev.get("catalogVersion", "")),
        )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise IntelError(f"cannot load intel from {directory}: {exc}") from exc
