import json

import defusedxml.ElementTree as ET


def test_fixture_reports_are_well_formed(fixtures):
    for name in ("report-v1.xml", "report-v2.xml"):
        root = ET.fromstring((fixtures / name).read_bytes())
        assert root.find(".//scan_run_status").text == "Done"
    assert len(ET.fromstring((fixtures / "report-v1.xml").read_bytes()).findall(".//results/result")) == 11


def test_intel_fixtures_are_marked(fixtures):
    assert "illustrative" in json.loads((fixtures / "intel" / "epss.json").read_text(encoding="utf-8"))["note"]
    kev = json.loads((fixtures / "intel" / "kev.json").read_text(encoding="utf-8"))
    assert [v["cveID"] for v in kev["vulnerabilities"]] == ["CVE-2023-4911"]
