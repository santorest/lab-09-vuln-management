"""Policy, asset inventory and risk acceptances: the human decisions the cycle runs on."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

PRIORITIES = ("P1", "P2", "P3", "P4")
INFORMATIONAL = "info"
EXPOSURES = ("internet-facing", "internal")


class ConfigError(ValueError):
    """A policy, inventory or exception file is invalid."""


@dataclass(frozen=True)
class Policy:
    scan_frequency: str
    cvss_floor: float
    epss_threshold: float
    high_cvss: float
    critical_cvss: float
    sla_days: dict[str, int]
    gate: tuple[str, ...]


@dataclass(frozen=True)
class Asset:
    name: str
    address: str
    owner: str
    criticality: int
    exposure: str


@dataclass(frozen=True)
class RiskAcceptance:
    host: str
    oid: str
    reason: str
    approver: str
    expires: date


def _yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping")
    return data


def load_policy(path: Path) -> Policy:
    data = _yaml(path)
    try:
        sla = {str(k): int(v) for k, v in data["sla_days"].items()}
        thresholds = data["thresholds"]
        policy = Policy(
            scan_frequency=str(data["scan_frequency"]),
            cvss_floor=float(data["cvss_floor"]),
            epss_threshold=float(thresholds["epss"]),
            high_cvss=float(thresholds["high_cvss"]),
            critical_cvss=float(thresholds["critical_cvss"]),
            sla_days=sla,
            gate=tuple(str(p) for p in data["gate"]),
        )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    if set(sla) != set(PRIORITIES):
        raise ConfigError(f"{path}: sla_days must define P1, P2, P3, P4")
    if not set(policy.gate) <= set(PRIORITIES):
        raise ConfigError(f"{path}: gate may only list P1..P4")
    return policy


def load_assets(path: Path) -> list[Asset]:
    assets: list[Asset] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            name, address, owner = row["name"].strip(), row["address"].strip(), row["owner"].strip()
            if not owner:
                raise ConfigError(f"{path}: {name}: owner is required")
            if row["criticality"].strip() not in ("1", "2", "3"):
                raise ConfigError(f"{path}: {name}: criticality must be 1, 2 or 3")
            if row["exposure"].strip() not in EXPOSURES:
                raise ConfigError(f"{path}: {name}: exposure must be internet-facing or internal")
            assets.append(Asset(name, address, owner, int(row["criticality"]), row["exposure"].strip()))
    for attr in ("name", "address"):
        seen: set[str] = set()
        for asset in assets:
            value = getattr(asset, attr)
            if value in seen:
                raise ConfigError(f"{path}: duplicate asset {attr} {value}")
            seen.add(value)
    if not assets:
        raise ConfigError(f"{path}: no assets")
    return assets


def load_exceptions(path: Path) -> list[RiskAcceptance]:
    data = _yaml(path)
    out: list[RiskAcceptance] = []
    for item in data.get("exceptions") or []:
        try:
            expires = item["expires"]
            acceptance = RiskAcceptance(
                host=str(item["host"]),
                oid=str(item["oid"]),
                reason=str(item["reason"]).strip(),
                approver=str(item["approver"]).strip(),
                expires=expires if isinstance(expires, date) else date.fromisoformat(str(expires)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        if not acceptance.reason:
            raise ConfigError(f"{path}: {acceptance.host} {acceptance.oid}: reason is required")
        if not acceptance.approver:
            raise ConfigError(f"{path}: {acceptance.host} {acceptance.oid}: approver is required")
        out.append(acceptance)
    return out
