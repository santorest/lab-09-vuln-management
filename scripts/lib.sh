# Helpers for run-cycle.sh.

# True if stdin contains the fixed string $1. Reads all of its input: `grep -q` stops at the first match, and under
# `set -o pipefail` the writer (`docker compose logs`) then dies of SIGPIPE, which turns a match into a failure.
log_contains() { grep -F -- "$1" >/dev/null; }
