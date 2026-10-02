---
title: "Vulnerability Management Workflow (Greenbone, EPSS, KEV)"
id: "lab-09-vuln-management"
category: "Vulnerability Assessment & Pentesting"
type: "Lab"
status: "completed"
date: "2026-10-01"
time_to_reproduce: "One CI run (fork, enable Actions, run CI); the measured duration is in the Results"
skills: [Greenbone, OpenVAS, Python, python-gvm, EPSS, CISA KEV, CVSS, Docker, Debian, GitHub Actions]
frameworks: [CIS Controls v8 (1.1, 7.1, 7.2, 7.5, 7.6, 7.7), MITRE ATT&CK (T1190, T1210, T1068)]
repo: "https://github.com/santorest/lab-09-vuln-management"
bundle: "Published on the portfolio site with its SHA-256 checksum"
---

# Vulnerability Management Workflow (Greenbone, EPSS, KEV)

> **TL;DR:** Three deliberately outdated lab hosts are scanned with Greenbone (network and authenticated over SSH),
> every finding is prioritized with CVSS, EPSS, CISA KEV and asset criticality under a written policy, tracked with an
> owner and an SLA due date, remediated, rescanned and reported. A gate fails the run if a P1 or P2 is still open
> without a valid exception. Everything runs in GitHub Actions against containers. **The CI runs are real; the hosts
> are lab containers.** No real network is scanned.

| | |
|---|---|
| **Role played** | Security engineer setting up a vulnerability-management process for a small fleet |
| **Environment** | Public GitHub repository, GitHub-hosted Ubuntu runners, Greenbone Community Edition containers, three Debian 12 containers |
| **Tools** | Greenbone CE (gvmd, ospd-openvas, openvasd), python-gvm, Python 3.12, FIRST EPSS API, CISA KEV catalog, pytest, ruff, mypy, gitleaks |
| **Deliverable** | Scan orchestration, normalization, prioritization, tracker, metrics and report toolkit; policy files; fleet before/after images; CI with a gate; branch ruleset |

---

## 1. Problem

A scanner produces hundreds of results; a team can fix a handful this week. Vulnerability management is the process
around the scanner: know what you own, scan it on a schedule, decide what matters first with a rule anyone can
re-run, give every finding an owner and a due date, prove the fix with a rescan, and accept the rest of the risk on
purpose, with a name and an expiry. This lab builds that process end to end and measures it.

## 2. Design

- **Cycle.** Scan fleet v1 → normalize → enrich with EPSS and KEV → prioritize → tracker → remediate (fleet v2) →
  rescan → update the tracker → metrics and report → gate. `scripts/run-cycle.sh` is the whole cycle, in CI and
  locally.
- **Inventory first.** `policy/assets.csv` lists each host with its address, owner role, criticality (1–3) and
  exposure. The scan targets exactly that list.
- **Policy as files.** `policy/policy.yaml` holds the frequency, the SLA days per priority, the CVSS floor and the
  thresholds; `policy/exceptions.yaml` holds risk acceptances. `docs/policy.md` says the same in prose.
- **No silent coverage loss.** A scan that does not finish, a timeout, an inventory host missing from the report, a
  host whose authenticated checks did not run (no SSH login, or no output from its commands), a host that stopped
  during the scan, or package results without any CVE are errors (exit 2), never "0 findings". A rescan that silently
  missed a host, or saw it only from the network, would otherwise look like a perfect remediation.
- **Greenbone in CI.** The community containers run without the web UI; the feed is a set of data images, not a live
  sync; Greenbone keeps only their current version, so each run pulls the latest and records the digests it used. The orchestration talks GMP over gvmd's Unix socket with
  python-gvm: it waits until the scanner and the "Full and fast" configuration are ready, creates a throwaway SSH
  credential and one target, runs one task and downloads the XML report.

## 3. Prioritization

First matching rule wins (`docs/prioritization.md` has worked examples):

| Rule | Priority |
|---|---|
| Any CVE of the finding is in CISA KEV | P1 |
| EPSS ≥ 0.10 and CVSS ≥ 7.0 | P1 |
| CVSS ≥ 9.0, or CVSS ≥ 7.0 on a criticality-3 or internet-facing asset | P2 |
| CVSS ≥ 7.0, or EPSS ≥ 0.10 | P3 |
| CVSS ≥ 4.0 | P4 |
| below 4.0 | informational |

KEV comes first because it records exploitation that is happening; EPSS ranks what is likely; CVSS and the asset say
how bad and where. A finding with several CVEs takes the worst value of each input; a CVE without an EPSS score
counts as 0 and is shown as "EPSS unknown"; a configuration finding without a CVE is ranked on CVSS and the asset.
Every row keeps its inputs and the text of the rule that decided.

## 4. Tracker and exceptions

One row per host and Greenbone check: priority, CVSS, EPSS, KEV, rule, owner, date opened, due date (scan date plus
the SLA), status and date closed. After the rescan a row is `fixed` (absent on the rescan of the same host), `open`
(still there) or `new` (only on the rescan). An exception needs a reason, an approver role and an expiry: while valid
the row is `risk accepted`; once expired it is `reopened` and gates again. Output: `tracker.csv` and `tracker.md`.

## 5. Fleet and remediation

| Host | Role | v1 ("as found") | Criticality / exposure | v2 (remediated) |
|---|---|---|---|---|
| `web` | web server | Debian 12.0, openssh-server and nginx from the 2023-06-15 snapshot | 3, internet-facing | current packages and security updates; `server_tokens off` |
| `files` | file server | Debian 12.0, openssh-server and vsftpd, anonymous FTP on | 2, internal | current packages; anonymous FTP off |
| `db` | database host | Debian 12.0, openssh-server and postgresql-15 | 3, internal | current packages |

The v1 images are pinned to the Debian snapshot archive on purpose, so every run scans the same "as found" state.
Remediation is what a team would do: upgrade the packages and fix the configuration, then rebuild on the same
addresses and rescan.

## 6. Pipeline

| Job | What it proves |
|---|---|
| `lint` | ruff and mypy (strict) |
| `unit` | every pure module against fixtures (no-CVE finding, several CVEs, missing EPSS, KEV over a low score, expired exception, new on rescan, missing host), scan orchestration against a fake GMP; coverage gate 90 % |
| `scan` | the whole cycle against Greenbone and the fleet; artifacts: both reports, the EPSS/KEV snapshots, tracker, metrics, HTML report; Markdown job summary |
| `secrets` | gitleaks over the full history |

It runs on every pull request, on pushes to `main`, weekly (the policy's frequency) and on demand. A ruleset on `main`
requires a pull request and all four jobs.

## 7. Results

From the first complete CI run on `main`,
[run 36951611428](https://github.com/santorest/lab-09-vuln-management/actions/runs/36951611428) (2026-10-02). The
next push ([run 36954263327](https://github.com/santorest/lab-09-vuln-management/actions/runs/36954263327)) produced
exactly the same numbers. `docs/example-report.html` and `docs/example-tracker.md` are that run's report and tracker.
After the final-review fixes, [run 37009563738](https://github.com/santorest/lab-09-vuln-management/actions/runs/37009563738)
(same day, newer feed: 189,015 tests) passed the new authenticated-checks requirement on all three hosts and again
produced the same counts; only the mean time to fix differed (8.5 minutes).

| | |
|---|---|
| Greenbone | gvmd 26.40.2; "Full and fast" with 188,961 vulnerability tests; feed images used by that run (`vulnerability-tests@sha256:86a44fb7a9f9…`, `notus-data@sha256:f53836e6ac0e…`) |
| Scans | v1 8 min 50 s, v2 8 min 50 s; v1 report 202 results, v2 94 (QoD ≥ 70) |
| Enrichment | EPSS of 2026-10-01: 163 of 163 CVEs scored; CISA KEV catalog 2026.10.01: 1 of them listed |
| Whole job | 31 minutes (47 on the second run), including starting Greenbone and loading the feed |

**Findings by host and priority** (one row per host and Greenbone check; informational rows not counted):

| Host | Criticality / exposure | P1 | P2 | P3 | P4 | In KEV | EPSS ≥ 0.10 | Open after v2 |
|---|---|---|---|---|---|---|---|---|
| `web` | 3, internet-facing | 4 | 13 | 4 | 16 | 1 | 8 | P3 2, P4 1 |
| `files` | 2, internal | 4 | 3 | 10 | 17 | 1 | 8 | P3 2, P4 1 |
| `db` | 3, internal | 4 | 17 | 4 | 19 | 1 | 8 | P3 2, P4 1 |
| **Total** | | **12** | **33** | **18** | **52** | **3** | **24** | **P3 6, P4 3** |

- **Fixed 106 of 115 (92.2 %)**, none new, none risk-accepted or reopened; mean time to fix 9.5 minutes (scan to
  rescan inside the run). The gate passed: no P1 or P2 open.
- **The four P1s are the same on every host:** glibc DSA-5514 (CVE-2023-4911, the one KEV entry: P1 by rule 1),
  openssh DSA-5724 (CVE-2024-6387, EPSS 0.995), and openssl DSA-5764 (EPSS 0.67) and DSA-6113 (EPSS 0.52), each with
  CVSS ≥ 7.0 (rule 2).
- **Criticality moved findings.** The same CVSS ≥ 7.0 advisories are P2 on `web` and `db` (criticality 3) and P3 on
  `files` (criticality 2, internal): 3 P2 there against 13 and 17.
- **What stayed open is outside the images.** On each host: missing kernel mitigations for Speculative Store Bypass
  (P3, its CVE has EPSS 0.61) and for Speculative Return Stack Overflow (P4) — the containers share the runner's
  kernel — and the ICMP timestamp reply (CVSS 2.1, but P3 because its CVE has EPSS 0.32: rule 7 working as written,
  and a reminder that EPSS scores the CVE, not this particular exposure).
- **Configuration findings were fixed by configuration.** Anonymous FTP and cleartext FTP login on `files` (P4) were
  found on v1 and gone on v2.
- **The gate is unit-tested, not demonstrated.** An open P1/P2 and an expired exception that reopens a row are covered
  by unit tests, and the ruleset makes the `scan` job a required check, so a pull request that leaves a P1 or P2 open
  cannot be merged. No demo pull request was run against it.

## 8. Lessons

- **Greenbone loads its data in order.** On a runner gvmd spent about 38 minutes importing the SCAP and CERT feeds
  before it started on the vulnerability tests, and the scan configurations only exist after those. The findings do
  not need SCAP or CERT data (the CVE references come with the tests, EPSS and KEV come from this toolkit), so the
  lab does not load them.
- **An authenticated scan fails quietly.** The first scan finished "Done" with only network results: Greenbone could
  not log in. Two OpenSSH rules were in the way: without PAM, sshd refuses key logins to an account created by
  `useradd` (its password field is `!`, "locked"), and `StrictModes` rejects an `authorized_keys` file owned by
  anyone but root or the user (it was bind-mounted from the runner). The report said so in a log-level result,
  "SSH Login Failed For Authenticated Checks", that no severity filter would ever surface.
- **The data can be in the database and still missing from the API.** With the logins fixed, 75 Debian advisories
  were found but none carried a CVE, so EPSS and KEV had nothing to score. gvmd's database held the CVE references;
  its in-memory cache of the tests, built when gvmd started on an empty database, did not, and every GMP answer
  came back with empty `<refs/>`. The cycle now restarts gvmd once the first load is done, and a scan whose package
  results carry no CVE at all is an error instead of a clean run.
- **A dead host looks like a clean host.** The file server reported a successful SSH login and then nothing: its
  container had stopped, because vsftpd was its main process and crashed on Greenbone's FTP probes. sshd is now the
  main process, vsftpd is restarted if it dies, and the cycle fails if any host stops during a scan.
- **A pin can expire.** The feed data images were pinned by digest like everything else; one day later the registry
  answered "not found" for four of them. Greenbone rebuilds them daily and keeps only the current one, so the lab
  now pins the software, pulls the current feed and records its digests with each run.
- **Check the library, not the docs you remember.** The first spike would have failed at import: the python-gvm
  transform is `EtreeCheckCommandTransform`. mypy found it before CI did.

## 9. Limits

- Containers, not real hosts; no real network is scanned.
- The containers share the runner's kernel, so kernel findings (missing CPU-vulnerability mitigations) stay open after
  remediation: rebuilding an image cannot fix them.
- The feed data images cannot be pinned (Greenbone deletes old versions within about a day); each run records the
  digests it used, and a later run may use newer tests. The SCAP and CERT feeds are not loaded.
- EPSS and KEV are fetched on the run date, so a later run may prioritize the same finding differently; each run saves
  the snapshots it used.
- Time to remediate is measured in minutes inside one run, not in days.
- No real ticketing system: the tracker is a CSV/Markdown file.
- Authenticated web-application scanning is out of scope.

## 10. Reproduce it

Fork the repository and enable Actions: every push runs the whole cycle. Locally (Linux, macOS or WSL with Docker),
follow the README's quick start: `bash scripts/run-cycle.sh` writes the reports, snapshots, tracker and
`out/report.html`.

## 11. Mapping

| Framework | Items |
|---|---|
| CIS Controls v8 | 1.1 establish and maintain a detailed enterprise asset inventory, 7.1 establish and maintain a vulnerability management process, 7.2 establish and maintain a remediation process, 7.5 perform automated vulnerability scans of internal enterprise assets (authenticated), 7.6 perform automated vulnerability scans of externally exposed enterprise assets, 7.7 remediate detected vulnerabilities |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application, T1210 Exploitation of Remote Services, T1068 Exploitation for Privilege Escalation — the techniques the unpatched services and packages in fleet v1 enable |
