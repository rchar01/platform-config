from __future__ import annotations

import fcntl
import json
import os
import pty
import re
import select
import signal
import subprocess
import termios
import time
from pathlib import Path

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


PLAYBOOK = "playbooks/maintenance/monitoring-etcd-bootstrap.yml"
FIXTURE = "tests/fixtures/monitoring-etcd-orchestration/inventory.yml"
APPROVAL = (
    "bootstrap-monitoring-etcd|"
    "monitoring-stage-1,monitoring-stage-2,monitoring-stage-3|consistent"
)
EXECUTION_FIXTURE = (
    "tests/fixtures/monitoring-etcd-orchestration/bootstrap-execution.yml"
)
STATUS_FIXTURE = (
    "tests/fixtures/monitoring-etcd-orchestration/bootstrap-status-validation.yml"
)


def _environment(repo_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "ANSIBLE_FORCE_COLOR": "0",
            "ANSIBLE_ROLES_PATH": os.pathsep.join(
                [
                    str(
                        repo_root
                        / "tests/fixtures/monitoring-etcd-orchestration/roles"
                    ),
                    str(repo_root / "roles"),
                ]
            ),
        }
    )
    return environment


def _variables(**overrides: object) -> dict[str, object]:
    variables: dict[str, object] = {
        "monitoring_etcd_bootstrap_preflight_ready": True,
        "monitoring_etcd_bootstrap_ready": True,
        "monitoring_etcd_data_fstype": "xfs",
        "monitoring_etcd_data_mount_source": "/dev/mapper/synthetic-etcd",
        "monitoring_etcd_bootstrap_require_selinux_enforcing": True,
        "monitoring_etcd_bootstrap_stability_delay": 1,
    }
    variables.update(overrides)
    return variables


def _run_tty_bootstrap(
    repo_root: Path,
    *,
    approval: str = APPROVAL,
    variables: dict[str, object] | None = None,
    timeout: float = 30,
) -> tuple[int, str]:
    command = [
        "ansible-playbook",
        "-i",
        str(repo_root / FIXTURE),
        str(repo_root / PLAYBOOK),
        "--extra-vars",
        json.dumps(variables or _variables(), separators=(",", ":")),
    ]
    master_fd, slave_fd = pty.openpty()

    def establish_controlling_terminal() -> None:
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        command,
        cwd=repo_root,
        env=_environment(repo_root),
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=establish_controlling_terminal,
    )
    os.close(slave_fd)
    output = bytearray()
    approval_sent = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
                raise AssertionError(
                    "monitoring etcd bootstrap PTY timed out\n"
                    + output.decode(errors="replace")
                )
            readable, _, _ = select.select([master_fd], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError:
                    chunk = b""
                output.extend(chunk)
                if APPROVAL.encode() in output and not approval_sent:
                    time.sleep(0.2)
                    os.write(master_fd, approval.encode() + b"\r")
                    approval_sent = True
            if process.poll() is not None:
                while True:
                    readable, _, _ = select.select([master_fd], [], [], 0)
                    if not readable:
                        break
                    try:
                        chunk = os.read(master_fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                break
    finally:
        os.close(master_fd)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
    return process.returncode, output.decode(errors="replace")


def test_monitoring_etcd_bootstrap_source_is_confirmation_gated(
    repo_root: Path,
) -> None:
    playbook = (repo_root / PLAYBOOK).read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    marker = (
        repo_root / "roles/monitoring_etcd/tasks/bootstrap_marker.yml"
    ).read_text(encoding="utf-8")

    for fragment in (
        "monitoring_etcd_bootstrap_ready",
        "not ansible_check_mode",
        "ansible.builtin.pause:",
        "bootstrap-monitoring-etcd|",
        "monitoring-etcd-bootstrap-preflight.yml",
        "tasks_from: bootstrap_start.yml",
        "tasks_from: bootstrap_status.yml",
        "tasks_from: bootstrap_stop.yml",
        "tasks_from: bootstrap_marker.yml",
        "No completion marker will be published",
    ):
        assert fragment in playbook
    assert playbook.count("import_playbook: monitoring-etcd-bootstrap-preflight.yml") == 1
    assert "groups: monitoring_etcd_bootstrap_start" in playbook
    assert "monitoring-etcd-bootstrap.yml" not in site
    assert "monitoring_etcd_data_dir" not in marker
    assert not re.search(r"\brm\s+-rf\b", playbook + marker)
    assert "/usr/bin/ln" in marker
    assert "mode: \"0600\"" in marker


def test_monitoring_etcd_bootstrap_rejects_noninteractive_execution(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(_variables(),),
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "Exact monitoring etcd bootstrap approval did not match")
    assert "Record mocked monitoring etcd bootstrap member start" not in result.stdout


def test_monitoring_etcd_bootstrap_rejects_piped_exact_approval(
    repo_root: Path,
) -> None:
    result = subprocess.run(
        (
            "ansible-playbook",
            "-i",
            str(repo_root / FIXTURE),
            str(repo_root / PLAYBOOK),
            "--extra-vars",
            json.dumps(_variables(), separators=(",", ":")),
        ),
        cwd=repo_root,
        env=_environment(repo_root),
        input=APPROVAL + "\n",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode != 0
    assert "Not waiting for response to prompt as stdin is not interactive" in (
        result.stdout + result.stderr
    )
    assert "Record mocked monitoring etcd bootstrap member start" not in result.stdout


def test_monitoring_etcd_bootstrap_accepts_exact_tty_approval(
    repo_root: Path,
) -> None:
    returncode, output = _run_tty_bootstrap(repo_root)
    assert returncode == 0, output
    assert "Record mocked monitoring etcd bootstrap marker" in output


def test_monitoring_etcd_bootstrap_rejects_wrong_tty_approval(
    repo_root: Path,
) -> None:
    returncode, output = _run_tty_bootstrap(repo_root, approval="wrong")
    assert returncode != 0
    assert "Exact monitoring etcd bootstrap approval did not match" in output
    assert "Record mocked monitoring etcd bootstrap member start" not in output


def test_monitoring_etcd_bootstrap_rejects_check_mode(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run(
        (
            "ansible-playbook",
            "-i",
            repo_root / FIXTURE,
            repo_root / PLAYBOOK,
            "--check",
            "--extra-vars",
            json.dumps(_variables(), separators=(",", ":")),
        ),
        environment=_environment(repo_root),
        timeout=120,
    )
    assert_failed_with(result, "requires its explicit readiness gate, normal apply mode")
    assert "Record mocked monitoring etcd bootstrap member start" not in result.stdout


def test_monitoring_etcd_bootstrap_rejects_failed_post_approval_preflight(
    repo_root: Path,
) -> None:
    returncode, output = _run_tty_bootstrap(
        repo_root,
        variables=_variables(
            monitoring_etcd_bootstrap_test_post_approval_preflight_failure=True
        ),
    )
    assert returncode != 0
    assert "Mocked post-approval monitoring etcd bootstrap preflight failed" in output
    assert "Record mocked monitoring etcd bootstrap member start" not in output


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        (
            {"monitoring_etcd_bootstrap_test_start_failure_host": "monitoring-stage-2"},
            "failed to start every member",
        ),
        (
            {"monitoring_etcd_bootstrap_test_health_failure": True},
            "did not reach stable health",
        ),
        (
            {"monitoring_etcd_bootstrap_test_unstable": True},
            "did not reach stable health",
        ),
        (
            {"monitoring_etcd_bootstrap_test_stop_failure_host": "monitoring-stage-3"},
            "did not reach stable health or could not stop",
        ),
    ),
)
def test_monitoring_etcd_bootstrap_playbook_rejects_incomplete_execution(
    repo_root: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    returncode, output = _run_tty_bootstrap(
        repo_root,
        variables=_variables(**overrides),
    )
    assert returncode != 0
    assert message in output
    assert "Record mocked monitoring etcd bootstrap marker" not in output


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        (
            {"monitoring_etcd_bootstrap_test_start_failure_host": "monitoring-stage-2"},
            "Mocked monitoring etcd bootstrap member failed to start",
        ),
        (
            {"monitoring_etcd_bootstrap_test_health_failure": True},
            "Mocked monitoring etcd bootstrap health failed",
        ),
        (
            {"monitoring_etcd_bootstrap_test_unstable": True},
            "Mocked monitoring etcd bootstrap status is unstable",
        ),
        (
            {"monitoring_etcd_bootstrap_test_stop_failure_host": "monitoring-stage-3"},
            "Mocked monitoring etcd bootstrap member failed to stop",
        ),
    ),
)
def test_monitoring_etcd_bootstrap_components_reject_incomplete_execution(
    command_runner: CommandRunner,
    repo_root: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / EXECUTION_FIXTURE,
        inventory=repo_root / FIXTURE,
        extra_vars=(_variables(**overrides),),
        environment=_environment(repo_root),
    )
    assert_failed_with(result, message)
    assert "Record mocked monitoring etcd bootstrap marker" not in result.stdout


def test_monitoring_etcd_bootstrap_components_preserve_safe_order(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / EXECUTION_FIXTURE,
        inventory=repo_root / FIXTURE,
        extra_vars=(_variables(),),
        environment=_environment(repo_root),
    )
    result.assert_success()
    assert "Record mocked monitoring etcd bootstrap marker" in result.stdout


def test_monitoring_etcd_bootstrap_status_accepts_exact_three_voter_cluster(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / STATUS_FIXTURE,
        inventory=repo_root / FIXTURE,
        environment=_environment(repo_root),
    ).assert_success()


@pytest.mark.parametrize(
    "variables",
    (
        {"monitoring_etcd_bootstrap_test_learner": True},
        {"monitoring_etcd_bootstrap_test_leader": 0},
        {"monitoring_etcd_bootstrap_test_unhealthy": True},
        {"monitoring_etcd_bootstrap_test_endpoint_drift": True},
    ),
)
def test_monitoring_etcd_bootstrap_status_rejects_unsafe_cluster(
    repo_root: Path,
    command_runner: CommandRunner,
    variables: dict[str, object],
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / STATUS_FIXTURE,
        inventory=repo_root / FIXTURE,
        extra_vars=(variables,),
        environment=_environment(repo_root),
    )
    result.assert_failure()


def test_monitoring_etcd_bootstrap_rejects_partial_selection(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(_variables(),),
        limit="monitoring-stage-1",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires all three monitoring inventory hosts")


def test_monitoring_etcd_bootstrap_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()
