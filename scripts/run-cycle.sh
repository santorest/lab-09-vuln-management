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
compose exec -T -u gvmd gvmd gvmd --user=admin --new-password="$GVM_PASSWORD" >/dev/null

scan() {
  FLEET_VERSION="$1" compose --profile tools run --rm --build runner \
    vulnmgmt scan --assets /policy/assets.csv --key /out/keys/scan_key --name "$1" --out "/out/report-$1.xml"
}
scan v1
FLEET_VERSION=v2 compose up -d --build web files db      # remediated images, same addresses
scan v2

vulnmgmt intel --reports out/report-v1.xml out/report-v2.xml --assets policy/assets.csv --out-dir out/intel
vulnmgmt track --before out/report-v1.xml --after out/report-v2.xml --intel out/intel --policy-dir policy --out-dir out
vulnmgmt gate --tracker out/tracker.csv --policy-dir policy
