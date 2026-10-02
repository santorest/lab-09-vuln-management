from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

LOOP = Path(__file__).resolve().parents[2] / "fleet" / "files" / "restart-loop.sh"
SHELL = shutil.which("dash") or shutil.which("sh")


@pytest.mark.skipif(SHELL is None, reason="needs a POSIX shell")
def test_a_crashing_service_is_logged_and_restarted_even_under_set_e(tmp_path: Path):
    # vsftpd died with exit 139 in CI. Under `set -e` (start.sh has it) a plain loop ends at the first crash.
    log = tmp_path / "restarts.log"
    env = {**os.environ, "RESTART_LOG": str(log), "RESTART_DELAY": "0"}
    args = [str(SHELL), "-e", str(LOOP), Path(str(SHELL)).stem, "-c", "exit 139"]
    proc = subprocess.Popen(args, env=env)  # noqa: S603 - fixed arguments, no untrusted input
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (not log.exists() or len(log.read_text().splitlines()) < 2):
            time.sleep(0.05)
        assert proc.poll() is None, "the loop ended instead of restarting"
        lines = log.read_text().splitlines()
        assert len(lines) >= 2 and "exited (139), restarting" in lines[0]
    finally:
        proc.kill()
        proc.wait()
