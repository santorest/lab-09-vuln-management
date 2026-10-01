from __future__ import annotations

from pathlib import Path

import pytest

from vulnmgmt.models import Asset, Policy, load_assets, load_policy

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def assets() -> list[Asset]:
    return load_assets(ROOT / "policy" / "assets.csv")


@pytest.fixture
def policy() -> Policy:
    return load_policy(ROOT / "policy" / "policy.yaml")


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
