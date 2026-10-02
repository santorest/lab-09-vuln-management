# Vulnerability management policy (lab fleet)

The machine-readable version is [`policy/policy.yaml`](../policy/policy.yaml),
[`policy/assets.csv`](../policy/assets.csv) and [`policy/exceptions.yaml`](../policy/exceptions.yaml). This page says
the same in prose.

## Scope

Every host listed in `policy/assets.csv`, and nothing else: `web`, `files` and `db` on the lab network
172.30.0.0/24. Each asset has an owner (a team role), a criticality from 1 (low) to 3 (high) and an exposure
(`internet-facing` or `internal`). A host in the inventory that does not appear in the scan report is an error, so
coverage cannot shrink silently.

## Frequency

Weekly, and after every change. In this repository that means the CI workflow's weekly schedule (Mondays 05:17 UTC),
every pull request and push to `main`, and manual runs.

## How a scan is run

One Greenbone task with the "Full and fast" configuration over all TCP ports registered with IANA, authenticated over
SSH with a key pair generated for the run (local security checks), plus the unauthenticated network checks.

## Priorities and service levels

Priorities come from the formula in [`prioritization.md`](prioritization.md). The due date is the date of the scan
that first found the finding plus:

| Priority | Days to remediate |
|---|---|
| P1 | 7 |
| P2 | 30 |
| P3 | 90 |
| P4 | 180 |

Findings with CVSS below **4.0** (the floor) are tracked as informational, with no due date and never gating, unless
a CVE of theirs is in KEV or has EPSS ≥ 0.10: exploitation outranks severity, so such a finding is prioritized
whatever its CVSS (the published run has CVSS 2.1 findings at P3 for that reason).

## What "fixed" means

A finding is fixed when the rescan of the same host, with the same scan configuration and credentials, no longer
reports the same Greenbone check. A host that could not be scanned proves nothing, which is why a missing host, or a
host whose authenticated checks did not run (no SSH login, or no output from its commands), is an error rather than
an empty result.

## Exceptions (risk acceptance)

A finding that cannot be fixed in time can be accepted, never ignored. Each entry names the host, the Greenbone check
(OID), the reason, the approver's role and an expiry date. While it is valid the row is `risk accepted`; once the
expiry passes the row is `reopened` and counts as open again. The repository ships with no exceptions.

## Gate

After remediation and the rescan, any P1 or P2 that is open, new or reopened without a valid exception fails the
cycle (and the CI run).
