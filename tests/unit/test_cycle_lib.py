from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[2] / "scripts" / "lib.sh"
BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_log_contains_finds_a_match_followed_by_a_long_log_under_pipefail():
    # run-cycle.sh uses `set -o pipefail`; gvmd's log keeps growing after the line it waits for. If the reader stops
    # at the first match, `docker compose logs` dies of SIGPIPE and the match counts as a failure (40 min lost).
    script = (
        f"set -euo pipefail; . '{LIB.as_posix()}'; "
        "{ echo 'Updating VTs in database ... done'; for i in $(seq 1 20000); do echo 'md manage: INFO line'; done; }"
        " | log_contains 'Updating VTs in database ... done'"
    )
    assert subprocess.run([str(BASH), "-c", script], check=False).returncode == 0  # noqa: S603 - fixed script


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_log_contains_is_false_without_the_line():
    script = f". '{LIB.as_posix()}'; printf 'a\nb\n' | log_contains 'Updating VTs in database ... done'"
    assert subprocess.run([str(BASH), "-c", script], check=False).returncode == 1  # noqa: S603 - fixed script
