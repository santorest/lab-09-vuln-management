# Prioritization

Every finding gets one priority from one formula (`src/vulnmgmt/prioritize.py`). The thresholds come from
[`policy/policy.yaml`](../policy/policy.yaml); the values below are the repository's.

## The formula (first matching rule wins)

| # | Rule | Priority |
|---|---|---|
| 1 | Any CVE of the finding is in the CISA KEV catalog | P1 |
| 2 | EPSS ≥ 0.10 and CVSS ≥ 7.0 | P1 |
| 3 | CVSS ≥ 9.0 | P2 |
| 4 | CVSS ≥ 7.0 on an asset of criticality 3 | P2 |
| 5 | CVSS ≥ 7.0 on an internet-facing asset | P2 |
| 6 | CVSS ≥ 7.0 | P3 |
| 7 | EPSS ≥ 0.10 | P3 |
| 8 | CVSS ≥ 4.0 (the floor) | P4 |
| 9 | below the floor | informational |

The inputs:

- **CVSS** — the severity Greenbone reports for the check (CVSS base score of the vulnerability test).
- **EPSS** — FIRST's probability that the CVE is exploited in the next 30 days, fetched during the run.
- **KEV** — whether the CVE is in CISA's Known Exploited Vulnerabilities catalog, fetched during the run.
- **Asset criticality and exposure** — from [`policy/assets.csv`](../policy/assets.csv).

Each tracker row keeps all four inputs and the text of the rule that decided, for example
`P2: CVSS 8.8 >= 7.0 on a criticality-3 asset (EPSS 0.03)`.

## Rules for awkward inputs

- **Worst value decides.** A finding with several CVEs takes the highest EPSS of its CVEs and is KEV-listed if any of
  them is. CVSS is Greenbone's single score for the check.
- **EPSS unknown.** A CVE without an EPSS score counts as 0 for the rules and is shown as "EPSS unknown"; the finding
  is never dropped.
- **No CVE.** A configuration finding (anonymous FTP, weak SSH algorithms) has no CVE: it is prioritized on CVSS and
  the asset only.
- **Noise.** Log-only results and results with a quality of detection (QoD) below 70 are not findings. The same check
  reported on several ports of a host is one finding.

## Why KEV overrides CVSS

CVSS describes how bad a vulnerability would be if exploited; KEV records that it **is** being exploited. A
medium-scored CVE in KEV is a better use of this week than a 9.8 nobody has weaponized, and EPSS ranks the large
middle ground in between. The formula therefore asks "is it exploited?" first, "is it likely to be?" second and "how
bad and where?" last.

## Worked examples (from the unit-test fixture)

The fixture values are test data, not real EPSS scores; the real run uses the snapshot saved with it.

| Finding | Host | CVSS | EPSS | KEV | Rule | Priority |
|---|---|---|---|---|---|---|
| glibc advisory (CVE-2023-4911) | web | 7.8 | 0.81 | yes | 1 | P1 |
| openssh advisory (CVE-2024-6387) | web | 8.1 | 1.00 | no | 2 | P1 |
| expat advisory (CVE-2024-45491, CVE-2024-45492) | db | 9.8 | 0.02 (second CVE unknown) | no | 3 | P2 |
| postgresql advisory (CVE-2024-10979) | db (criticality 3) | 8.8 | 0.03 | no | 4 | P2 |
| openssl advisory (CVE-2023-5678) | files | 5.3 | 0.12 | no | 7 | P3 |
| nginx advisory (CVE-2024-7347) | web | 4.7 | 0.00 | no | 8 | P4 |
| anonymous FTP login (no CVE) | files | 6.4 | — | no | 8 | P4 |
| weak SSH MAC algorithms (no CVE) | db | 2.6 | — | no | 9 | informational |
