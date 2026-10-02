"""Throwaway diagnostic: where do the CVE refs of a finished report go? Run on a fresh GMP connection."""

import os

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.protocols.gmp.requests.v225 import InfoType
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

XML = "a994b278-1f62-11e1-96ac-406186ea4fc5"
OID = os.environ.get("DIAG_OID", "1.3.6.1.4.1.25623.1.1.1.2.2023.5514")


def show(label, fn):
    try:
        x = fn()
        refs = x.findall(".//refs/ref")
        print(f"== {label}: {len(refs)} refs; cve: {[r.get('id') for r in refs if r.get('type') == 'cve'][:8]}")
        return x
    except Exception as exc:  # noqa: BLE001 - diagnostic
        print(f"== {label}: {type(exc).__name__}: {exc}")


with GMP(UnixSocketConnection(timeout=600), transform=EtreeCheckCommandTransform()) as gmp:
    print("GMP", gmp.get_version().findtext("version"))
    gmp.authenticate("admin", os.environ["GVM_PASSWORD"])
    rid = gmp.get_reports(filter_string="rows=1 sort-reverse=date").find("report").get("id")
    r = show("get_report fresh connection", lambda: gmp.get_report(
        rid, filter_string="apply_overrides=0 min_qod=70 rows=-1 first=1", report_format_id=XML,
        ignore_pagination=True, details=True))
    if r is not None:
        res = r.findall(".//results/result")
        print("   results", len(res), "with refs", sum(1 for x in res if x.find("nvt/refs") is not None))
    show(f"get_info NVT {OID}", lambda: gmp.get_info(OID, info_type=InfoType.NVT))
    x = show(f"get_scan_config_nvt {OID}", lambda: gmp.get_scan_config_nvt(OID))
    if x is not None:
        print(etree.tostring(x).decode()[:1500])
