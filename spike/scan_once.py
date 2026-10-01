"""Throwaway feasibility spike: wait for the feed, scan one host authenticated, save the XML report."""

import os
import sys
import time

from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.protocols.gmp.requests.v225 import AliveTest, CredentialType
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS = "08b69003-5fc2-4037-a479-93b440211c73"
ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
XML_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
start = time.monotonic()


def log(message):
    print(f"[{time.monotonic() - start:7.1f}s] {message}", flush=True)


with GMP(UnixSocketConnection(timeout=600), transform=EtreeCheckCommandTransform()) as gmp:
    log(f"GMP {gmp.get_version().findtext('version')}")
    gmp.authenticate("admin", os.environ["GVM_PASSWORD"])
    while True:
        try:
            gmp.verify_scanner(OPENVAS)
            count = gmp.get_scan_config(FULL_AND_FAST).findtext("config/nvt_count") or "0"
            if int(count.strip() or 0) > 0:
                log(f"feed ready: Full and fast has {count.strip()} VTs")
                break
            log("Full and fast has no VTs yet")
        except GvmError as exc:
            log(f"not ready: {exc}")
        if time.monotonic() - start > 2400:
            sys.exit("feed not ready after 40 minutes")
        time.sleep(30)
    key = open("/out/keys/scan_key", encoding="utf-8").read()
    cred = gmp.create_credential("spike ssh", CredentialType.USERNAME_SSH_KEY, login="scan", private_key=key).get("id")
    target = gmp.create_target(
        "spike target", hosts=["172.30.0.11"], port_list_id=ALL_IANA_TCP, ssh_credential_id=cred,
        alive_test=AliveTest.CONSIDER_ALIVE,
    ).get("id")
    task = gmp.create_task("spike", FULL_AND_FAST, target, OPENVAS).get("id")
    report_id = gmp.start_task(task).findtext("report_id")
    log(f"scan started, report {report_id}")
    while True:
        status = gmp.get_task(task).findtext("task/status")
        progress = gmp.get_task(task).findtext("task/progress")
        log(f"status {status} progress {progress}")
        if status in ("Done", "Interrupted", "Stopped"):
            break
        time.sleep(30)
    report = gmp.get_report(
        report_id, filter_string="apply_overrides=0 min_qod=70 rows=-1 first=1", report_format_id=XML_FORMAT,
        ignore_pagination=True, details=True,
    )
    open("/out/spike-report.xml", "wb").write(etree.tostring(report))
    results = report.findall(".//results/result")
    log(f"final status {status}; {len(results)} results; "
        f"{sum(1 for r in results if r.find('nvt/refs/ref[@type=\"cve\"]') is not None)} with CVEs")
    sys.exit(0 if status == "Done" and results else 1)
