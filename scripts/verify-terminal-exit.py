#!/usr/bin/env python3
"""Verify that a guarded Claude TUI stops when its terminal disappears.

This starts Claude without a prompt, waits until the pinned client is running,
closes the PTY master, and checks for lifecycle leftovers. It does not invoke a
model or read Claude credentials.
"""

from __future__ import annotations

import json
import os
import pty
import select
import signal
import subprocess
import sys
import time
from pathlib import Path


def process_command(pid: int) -> str:
    return subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        text=True,
        capture_output=True,
        check=False,
    ).stdout.strip()


def terminate_group(pid: int) -> None:
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        return


def main() -> int:
    home = Path.home()
    entry = Path(os.environ.get("CLAUDE_GUARD_ENTRY", home / ".local/bin/claude"))
    config_path = Path(
        os.environ.get(
            "CLAUDE_GUARD_CONFIG",
            os.environ.get("SAFE_CLAUDE_CONFIG", home / ".safe-claude-official.json"),
        )
    )

    with config_path.open(encoding="utf-8") as handle:
        config = json.load(handle)
        client = str(Path(config["command"]).resolve())
        config_dir = str(
            Path(config.get("config_dir", home / ".claude-official")).resolve()
        )

    if not entry.is_file():
        raise SystemExit(f"guard entry does not exist: {entry}")

    log_path = Path(
        os.environ.get("CLAUDE_GUARD_EXIT_TEST_LOG", "/tmp/claude-guard-terminal-exit.log")
    )
    log_path.unlink(missing_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "CLAUDE_GUARD_ASSUME_YES": "1",
            "CLAUDE_GUARD_WATCHDOG": "1",
            "CLAUDE_GUARD_WATCHDOG_TICK_SECONDS": "1",
            "CLAUDE_GUARD_LOG_FILE": str(log_path),
        }
    )

    baseline_pids = {
        line.strip()
        for line in subprocess.run(
            ["ps", "-axo", "pid="],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.splitlines()
        if line.strip()
    }

    pid, master_fd = pty.fork()
    if pid == 0:
        os.execve(str(entry), [str(entry), "--safe-mode"], env)

    started = False
    captured = bytearray()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            ready, _, _ = select.select([master_fd], [], [], 0.2)
            if ready:
                captured.extend(os.read(master_fd, 4096))
        except OSError:
            break
        if client in process_command(pid):
            started = True
            break

    if not started:
        terminate_group(pid)
        detail = bytes(captured[-3000:]).decode("utf-8", "replace")
        print("FAIL: guarded entry did not reach the pinned client", file=sys.stderr)
        print(detail, file=sys.stderr)
        return 1

    pgid = os.getpgid(pid)
    time.sleep(2)
    os.close(master_fd)

    exited = False
    for _ in range(100):
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            exited = True
            break
        time.sleep(0.1)

    if not exited:
        terminate_group(pid)
        print("FAIL: Claude survived 10 seconds after its PTY closed", file=sys.stderr)
        return 1

    time.sleep(3)
    processes = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,pgid=,command="],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    markers = (
        client,
        f"{config_dir}/daemon",
        "claude bg-pty-host",
        "claude bg-spare",
    )
    leftovers = []
    for line in processes:
        fields = line.split(maxsplit=3)
        same_process_group = len(fields) >= 3 and fields[2] == str(pgid)
        new_marker_process = (
            len(fields) >= 4
            and fields[0] not in baseline_pids
            and any(marker in line for marker in markers)
        )
        if same_process_group or new_marker_process:
            leftovers.append(line)
    if leftovers:
        print("FAIL: Claude lifecycle leftovers detected", file=sys.stderr)
        print("\n".join(leftovers), file=sys.stderr)
        return 1

    print(
        f"PASS: PTY close stopped guarded Claude pid={pid}; "
        "no supervisor/worker remained"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
