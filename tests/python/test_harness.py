from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


def test_command_runner_preserves_success_and_failure(command_runner) -> None:
    success = command_runner.run(
        [sys.executable, "-c", "print('stdout-value')"]
    ).assert_success()
    failure = command_runner.run(
        [
            sys.executable,
            "-c",
            "import sys; print('stderr-value', file=sys.stderr); sys.exit(23)",
        ]
    ).assert_failure()

    assert success.argv[0] == sys.executable
    assert success.returncode == 0
    assert success.stdout == "stdout-value\n"
    assert success.stderr == ""
    assert success.duration_seconds >= 0
    assert failure.returncode == 23
    assert failure.stdout == ""
    assert failure.stderr == "stderr-value\n"


def test_command_runner_redacts_failure_diagnostics(command_runner) -> None:
    secret = "fixture secret's overlapping-value"
    suffix = "overlapping-value"
    result = command_runner.run(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1]); print(sys.argv[1], file=sys.stderr); sys.exit(1)",
            secret,
        ],
        redactions=[suffix, secret],
    )

    with pytest.raises(AssertionError) as error:
        result.assert_success()

    assert secret not in str(error.value)
    assert suffix not in str(error.value)
    assert "<redacted>" in str(error.value)
    assert secret in result.stdout
    assert secret in result.stderr


def test_command_runner_redacts_timeout_diagnostics(command_runner) -> None:
    secret = "timeout-secret"

    with pytest.raises(AssertionError) as error:
        command_runner.run(
            [
                sys.executable,
                "-c",
                "import sys, time; print(sys.argv[1], flush=True); print(sys.argv[1], file=sys.stderr, flush=True); time.sleep(30)",
                secret,
            ],
            redactions=[secret],
            timeout=1,
        )

    assert secret not in str(error.value)
    assert "<redacted>" in str(error.value)


def test_isolated_environment_uses_worker_local_paths(
    isolated_test_dir: Path,
    test_environment: dict[str, str],
    worker_name: str,
) -> None:
    assert test_environment["PLATFORM_CONFIG_TEST_WORKER"] == worker_name
    assert Path(test_environment["TMPDIR"]).parent == isolated_test_dir
    assert Path(test_environment["ANSIBLE_LOCAL_TEMP"]).parent == isolated_test_dir
    assert Path(test_environment["ANSIBLE_REMOTE_TEMP"]).parent == isolated_test_dir
    assert Path(test_environment["HOME"]).parent == isolated_test_dir
    assert test_environment["ANSIBLE_CONFIG"].endswith("/ansible.cfg")
    assert "SSH_AUTH_SOCK" not in test_environment


def test_timeout_reaps_owned_process_group_only(
    command_runner,
    isolated_test_dir: Path,
) -> None:
    child_pid_path = isolated_test_dir / "child.pid"
    command = """
import pathlib
import signal
import subprocess
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_DFL); time.sleep(30)",
])
pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding="ascii")
while child.poll() is None:
    time.sleep(0.01)
time.sleep(30)
"""
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )

    try:
        with pytest.raises(AssertionError, match="command timed out"):
            command_runner.run(
                [sys.executable, "-c", command, child_pid_path],
                timeout=2,
            )

        child_pid = int(child_pid_path.read_text(encoding="ascii"))
        deadline = time.monotonic() + 2
        while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)

        assert not Path(f"/proc/{child_pid}").exists()
        assert unrelated.poll() is None
    finally:
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGTERM)
        try:
            unrelated.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait(timeout=2)


def test_timeout_final_drain_is_bounded(command_runner, monkeypatch) -> None:
    class Pipe:
        closed = False

        def close(self) -> None:
            self.closed = True

    class EscapedPipeProcess:
        pid = 999_999_999
        returncode = -signal.SIGKILL
        stdout = Pipe()
        stderr = Pipe()

        def communicate(self, *, timeout):
            assert timeout == 0.5
            raise subprocess.TimeoutExpired(
                ["fixture"],
                timeout,
                output="partial stdout",
                stderr="partial stderr",
            )

        def wait(self, *, timeout):
            assert timeout == 0.5
            return self.returncode

    process = EscapedPipeProcess()
    monkeypatch.setattr(os, "killpg", lambda _pid, _signal: None)

    stdout, stderr = type(command_runner)._terminate_group(process)

    assert stdout == "partial stdout"
    assert stderr == "partial stderr"
    assert process.stdout.closed
    assert process.stderr.closed
