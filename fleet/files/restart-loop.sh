#!/bin/sh
# Runs "$@" forever and logs every exit. A crash must lead to a restart even when the caller runs with `set -e`
# (vsftpd died with exit 139 under Greenbone's FTP probes in CI), so the exit status is captured, never fatal.
log=${RESTART_LOG:-/var/log/vsftpd-restarts.log}
while true; do
  "$@" && status=0 || status=$?
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $1 exited ($status), restarting" >> "$log"
  sleep "${RESTART_DELAY:-1}"
done
