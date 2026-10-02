from __future__ import annotations

import pytest
from gvm.errors import GvmError
from lxml import etree

from vulnmgmt.scan import ScanError, Timeouts, require_cve_refs, run_scan, wait_until_ready


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeGmp:
    def __init__(self, statuses=("Running", "Done"), ready_after=0, vt_count="90000"):
        self.statuses = list(statuses)
        self.ready_after = ready_after
        self.vt_count = vt_count
        self.calls: list[tuple[object, ...]] = []

    def verify_scanner(self, scanner_id):
        self.calls.append(("verify_scanner", scanner_id))
        if self.ready_after > 0:
            self.ready_after -= 1
            raise GvmError("Scanner is still loading VTs")
        return etree.fromstring(
            "<verify_scanner_response status='200'><version>23.0</version></verify_scanner_response>"
        )

    def get_scan_config(self, config_id):
        return etree.fromstring(
            f"<get_configs_response><config><nvt_count>{self.vt_count}<growing>1</growing></nvt_count></config></get_configs_response>"
        )

    def create_credential(self, name, credential_type, **kwargs):
        self.calls.append(("create_credential", name, kwargs["login"]))
        return etree.fromstring("<create_credential_response id='cred-1'/>")

    def create_target(self, name, **kwargs):
        self.calls.append(("create_target", tuple(kwargs["hosts"]), kwargs["ssh_credential_id"]))
        return etree.fromstring("<create_target_response id='target-1'/>")

    def create_task(self, name, config_id, target_id, scanner_id):
        self.calls.append(("create_task", config_id, target_id, scanner_id))
        return etree.fromstring("<create_task_response id='task-1'/>")

    def start_task(self, task_id):
        return etree.fromstring("<start_task_response><report_id>report-1</report_id></start_task_response>")

    def get_task(self, task_id):
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return etree.fromstring(
            f"<get_tasks_response><task><status>{status}</status><progress>50</progress></task></get_tasks_response>"
        )

    def get_report(self, report_id, **kwargs):
        self.calls.append(("get_report", report_id, kwargs["report_format_id"], kwargs["ignore_pagination"]))
        return etree.fromstring(
            "<get_reports_response><report><report><scan_run_status>Done</scan_run_status></report></report></get_reports_response>"
        )


def test_waits_for_the_scanner_then_reports_the_vt_count():
    clock, gmp = Clock(), FakeGmp(ready_after=3)
    assert wait_until_ready(gmp, Timeouts(), clock, clock.sleep) == 90000
    assert clock.now == 90  # three failed checks, 30 s apart


def test_feed_never_ready_is_an_error():
    clock, gmp = Clock(), FakeGmp(vt_count="0")
    with pytest.raises(ScanError, match="feed not ready after 2400 s"):
        wait_until_ready(gmp, Timeouts(), clock, clock.sleep)


def test_runs_one_task_for_all_hosts(assets):
    clock, gmp = Clock(), FakeGmp(statuses=("Requested", "Running", "Done"))
    xml = run_scan(gmp, assets, "KEY", "v1", Timeouts(), clock, clock.sleep)
    assert b"<scan_run_status>Done</scan_run_status>" in xml
    assert ("create_target", ("172.30.0.11", "172.30.0.12", "172.30.0.13"), "cred-1") in gmp.calls
    assert (
        "create_task",
        "daba56c8-73ec-11df-a475-002264764cea",
        "target-1",
        "08b69003-5fc2-4037-a479-93b440211c73",
    ) in gmp.calls
    assert ("get_report", "report-1", "a994b278-1f62-11e1-96ac-406186ea4fc5", True) in gmp.calls
    assert ("create_credential", "v1 ssh key", "scan") in gmp.calls


@pytest.mark.parametrize("status", ["Interrupted", "Stopped"])
def test_interrupted_scan_is_an_error(assets, status):
    clock, gmp = Clock(), FakeGmp(statuses=("Running", status))
    with pytest.raises(ScanError, match=f"scan ended with status {status}"):
        run_scan(gmp, assets, "KEY", "v1", Timeouts(), clock, clock.sleep)


def test_scan_timeout_is_an_error(assets):
    clock, gmp = Clock(), FakeGmp(statuses=("Running",))
    with pytest.raises(ScanError, match="scan not finished after 3000 s"):
        run_scan(gmp, assets, "KEY", "v1", Timeouts(), clock, clock.sleep)


def _report(*results: str) -> bytes:
    return (
        "<get_reports_response><report><report><results>" + "".join(results) + "</results></report></report>"
        "</get_reports_response>"
    ).encode()


def _lsc(refs: str) -> str:
    family = "<family>Debian Local Security Checks</family>"
    return f"<result><nvt oid='1.3.6.1.4.1.25623.1.1.1.1.2023.5514'>{family}{refs}</nvt></result>"


def test_package_results_without_cve_refs_are_an_error():
    # gvmd answered every GMP call with <refs/> while its VT cache was stale: the CVEs exist, the report lost them.
    with pytest.raises(ScanError, match="no CVE references"):
        require_cve_refs(_report(_lsc("<refs/>")))


def test_package_results_with_cve_refs_pass():
    require_cve_refs(_report(_lsc("<refs><ref type='cve' id='CVE-2023-4911'/></refs>")))


def test_reports_without_package_results_pass():
    require_cve_refs(_report("<result><nvt oid='1.3.6.1.4.1.25623.1.0.80091'><family>General</family></nvt></result>"))
