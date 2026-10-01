"""Greenbone orchestration over GMP: wait for the feed, create credential/target/task, run, download the report.
An interrupted scan or a timeout is an error, never an empty report."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from gvm.errors import GvmError
from lxml import etree

from vulnmgmt.models import Asset

FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_DEFAULT = "08b69003-5fc2-4037-a479-93b440211c73"
ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
XML_REPORT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
REPORT_FILTER = "apply_overrides=0 min_qod=70 rows=-1 first=1"
FINAL_BAD = ("Interrupted", "Stopped")


class ScanError(RuntimeError):
    """The scan could not be run to completion."""


@dataclass(frozen=True)
class Timeouts:
    ready: float = 2400
    scan: float = 3000
    poll: float = 30


Clock = Callable[[], float]
Sleep = Callable[[float], None]


def wait_until_ready(gmp: Any, timeouts: Timeouts, clock: Clock = time.monotonic, sleep: Sleep = time.sleep) -> int:
    start = clock()
    while True:
        try:
            gmp.verify_scanner(OPENVAS_DEFAULT)
            text = gmp.get_scan_config(FULL_AND_FAST).findtext("config/nvt_count") or "0"
            count = int(text.strip() or 0)
            if count > 0:
                return count
        except GvmError:
            pass
        if clock() - start >= timeouts.ready:
            raise ScanError(f"feed not ready after {timeouts.ready:.0f} s")
        sleep(timeouts.poll)


def run_scan(
    gmp: Any,
    assets: Sequence[Asset],
    private_key: str,
    name: str,
    timeouts: Timeouts,
    clock: Clock = time.monotonic,
    sleep: Sleep = time.sleep,
) -> bytes:
    from gvm.protocols.gmp.requests.v225 import AliveTest, CredentialType

    credential = gmp.create_credential(
        f"{name} ssh key", CredentialType.USERNAME_SSH_KEY, login="scan", private_key=private_key
    ).get("id")
    target = gmp.create_target(
        f"{name} fleet",
        hosts=[a.address for a in assets],
        port_list_id=ALL_IANA_TCP,
        ssh_credential_id=credential,
        alive_test=AliveTest.CONSIDER_ALIVE,
    ).get("id")
    task = gmp.create_task(name, FULL_AND_FAST, target, OPENVAS_DEFAULT).get("id")
    report_id = gmp.start_task(task).findtext("report_id")
    start = clock()
    while True:
        status = (gmp.get_task(task).findtext("task/status") or "").strip()
        if status == "Done":
            break
        if status in FINAL_BAD:
            raise ScanError(f"scan ended with status {status}")
        if clock() - start >= timeouts.scan:
            raise ScanError(f"scan not finished after {timeouts.scan:.0f} s (last status {status})")
        sleep(timeouts.poll)
    report = gmp.get_report(
        report_id, filter_string=REPORT_FILTER, report_format_id=XML_REPORT, ignore_pagination=True, details=True
    )
    xml: bytes = etree.tostring(report)
    return xml


def scan(
    password: str, assets: Sequence[Asset], private_key: str, name: str, timeouts: Timeouts
) -> bytes:  # pragma: no cover - needs a live gvmd
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import GMP
    from gvm.transforms import EtreeCheckCommandTransform

    with GMP(UnixSocketConnection(timeout=600), transform=EtreeCheckCommandTransform()) as gmp:  # type: ignore[no-untyped-call]
        gmp.authenticate("admin", password)
        count = wait_until_ready(gmp, timeouts)
        print(f"feed ready: {count} VTs in Full and fast", flush=True)
        return run_scan(gmp, assets, private_key, name, timeouts)
