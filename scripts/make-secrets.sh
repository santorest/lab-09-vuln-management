#!/usr/bin/env bash
# Per-run secrets: a gvmd admin password and the scanner's SSH key pair. Nothing here is ever committed.
set -euo pipefail
mkdir -p out/keys
rm -f out/keys/scan_key out/keys/scan_key.pub
ssh-keygen -q -t ed25519 -N "" -C "lab09 scanner" -f out/keys/scan_key
chmod 644 out/keys/scan_key.pub
password="Lab9-$(openssl rand -hex 16)"
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "::add-mask::$password"
  echo "GVM_PASSWORD=$password" >> "$GITHUB_ENV"
else
  echo "export GVM_PASSWORD='$password'"
fi
