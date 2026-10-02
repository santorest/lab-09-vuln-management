---
title: "Vulnerability Management Workflow (Greenbone, EPSS, KEV)"
id: "lab-09-vuln-management"
category: "Vulnerability Assessment & Pentesting"
type: "Lab"
status: "in progress"
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
| **Deliverable** | Scan orchestration, normalization, prioritization, tracker, metrics and report toolkit; policy files; fleet before/after images; CI with a gate; branch ruleset; demo PRs |

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
- **No silent coverage loss.** A scan that does not finish, a timeout, or an inventory host missing from the report
  is an error (exit 2), never "0 findings". A rescan that silently missed a host would otherwise look like a perfect
  remediation.
- **Greenbone in CI.** The community containers run without the web UI; the feed is a set of data images pinned by
  digest, so a run does not depend on a live feed sync. The orchestration talks GMP over gvmd's Unix socket with
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

Results are added from the first CI runs.

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
- **Check the library, not the docs you remember.** The first spike would have failed at import: the python-gvm
  transform is `EtreeCheckCommandTransform`. mypy found it before CI did.

## 9. Limits

- Containers, not real hosts; no real network is scanned.
- The containers share the runner's kernel, so kernel findings (missing CPU-vulnerability mitigations) stay open after
  remediation: rebuilding an image cannot fix them.
- The Greenbone community feed is a pinned snapshot; the SCAP and CERT feeds are not loaded.
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
