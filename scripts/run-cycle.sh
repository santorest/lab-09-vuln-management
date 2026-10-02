#!/usr/bin/env bash
# One vulnerability-management cycle: Greenbone + fleet v1 -> scan -> fleet v2 (remediated) -> rescan ->
# EPSS/KEV snapshots -> tracker, metrics, report -> gate. Same script in CI and locally (needs Docker and
# `pip install -r requirements.txt && pip install --no-deps -e .`; run scripts/make-secrets.sh first).
set -euo pipefail
: "${GVM_PASSWORD:?run scripts/make-secrets.sh first}"
compose() { docker compose -f lab/compose.yaml "$@"; }
mkdir -p out

FLEET_VERSION=v1 compose up -d --build
for i in $(seq 1 90); do
  if compose exec -T -u gvmd gvmd gvmd --get-users 2>/dev/null | grep -qx admin; then break; fi
  sleep 10
done
if compose exec -T -u gvmd gvmd gvmd --get-users 2>/dev/null | grep -qx admin; then
  compose exec -T -u gvmd gvmd gvmd --user=admin --new-password="$GVM_PASSWORD" >/dev/null
else
  # The image's entrypoint creates admin with `|| true`; once (ci run 36949663919) it silently did not. Do what it
  # does: create the user and make it the feed import owner, without which the scan configs never load.
  echo "gvmd has no admin user: creating it and setting the feed import owner" >&2
  compose exec -T -u gvmd gvmd gvmd --create-user=admin --password="$GVM_PASSWORD" >/dev/null
  uid=$(compose exec -T -u gvmd gvmd gvmd --get-users --verbose | awk '$1 == "admin" {print $2}')
  compose exec -T -u gvmd gvmd gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value "$uid"
fi

# gvmd builds its in-memory VT cache at start, while its database has no VTs yet, and answers every GMP request
# with empty <refs/> until it restarts (the CVE refs are in its database). Restart it once the first VT load is done.
for i in $(seq 1 240); do
  if compose logs gvmd 2>/dev/null | grep -q "Updating VTs in database ... done"; then break; fi
  sleep 10
done
sleep 60      # discovery VTs and EPSS assignment follow the VT load
compose restart gvmd
sleep 60

scan() {
  FLEET_VERSION="$1" compose --profile tools run --rm --build runner \
    vulnmgmt scan --assets /policy/assets.csv --key /out/keys/scan_key --name "$1" --out "/out/report-$1.xml"
  # A host that stopped during the scan answers nothing over SSH, so its report would look clean. Fail instead.
  running=$(FLEET_VERSION="$1" compose ps --status running --services web files db | sort | tr '\n' ' ')
  if [ "$running" != "db files web " ]; then
    echo "fleet $1: a host stopped during the scan (running: $running)" >&2
    exit 2
  fi
}
scan v1
FLEET_VERSION=v2 compose up -d --build web files db      # remediated images, same addresses
scan v2

vulnmgmt intel --reports out/report-v1.xml out/report-v2.xml --assets policy/assets.csv --out-dir out/intel
vulnmgmt track --before out/report-v1.xml --after out/report-v2.xml --intel out/intel --policy-dir policy --out-dir out
vulnmgmt gate --tracker out/tracker.csv --policy-dir policy
