from __future__ import annotations

import fcntl
import json
import os
import pty
import select
import signal
import subprocess
import termios
import time
from pathlib import Path

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


PLAYBOOK = "playbooks/maintenance/monitoring-etcd-activate.yml"
STATUS_PLAYBOOK = "playbooks/maintenance/monitoring-etcd-status.yml"
FIXTURE = "tests/fixtures/monitoring-etcd-orchestration/inventory.yml"
APPROVAL = (
    "activate-monitoring-etcd|"
    "monitoring-stage-1,monitoring-stage-2,monitoring-stage-3|"
    + "a" * 64
    + "|100|consistent"
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
        "monitoring_etcd_activation_ready": True,
        "monitoring_etcd_status_stability_delay": 1,
    }
    variables.update(overrides)
    return variables


def _run_tty_activation(
    repo_root: Path,
    *,
    approval: str = APPROVAL,
    variables: dict[str, object] | None = None,
    timeout: float = 45,
) -> tuple[int, str]:
    command = [
        "ansible-playbook",
        "-i",
        str(repo_root / FIXTURE),
        str(repo_root / PLAYBOOK),
        "--limit",
        "monitoring",
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
                    "monitoring etcd activation PTY timed out\n"
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
                break
    finally:
        os.close(master_fd)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
    return process.returncode, output.decode(errors="replace")


def test_monitoring_etcd_activation_source_preserves_staging_boundary(
    repo_root: Path,
) -> None:
    playbook = (repo_root / PLAYBOOK).read_text(encoding="utf-8")
    role_main = (
        repo_root / "roles/monitoring_etcd/tasks/main.yml"
    ).read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")

    for fragment in (
        "monitoring_etcd_activation_ready",
        "ansible_limit is defined",
        "not ansible_check_mode",
        "activate-monitoring-etcd|",
        "ansible.builtin.pause:",
        "tasks_from: activation_preflight.yml",
        "groups: monitoring_etcd_activation_start",
        "tasks_from: activation_rollback.yml",
        "tasks_from: activation_enable.yml",
        "tasks_from: runtime_status.yml",
    ):
        assert fragment in playbook
    assert "not monitoring_etcd_service_enabled" in role_main
    assert "monitoring-etcd-activate.yml" not in site
    assert "monitoring_etcd_data_dir" not in (
        repo_root / "roles/monitoring_etcd/tasks/activation_rollback.yml"
    ).read_text(encoding="utf-8")


def test_monitoring_etcd_activation_accepts_exact_tty_approval(
    repo_root: Path,
) -> None:
    returncode, output = _run_tty_activation(repo_root)
    assert returncode == 0, output
    assert "Record mocked persistent monitoring etcd activation" in output


def test_monitoring_etcd_activation_accepts_stable_new_leader(
    repo_root: Path,
) -> None:
    returncode, output = _run_tty_activation(
        repo_root,
        variables=_variables(monitoring_etcd_activation_test_new_leader=True),
    )
    assert returncode == 0, output
    assert "Record mocked persistent monitoring etcd activation" in output


def test_monitoring_etcd_activation_rejects_wrong_tty_approval(
    repo_root: Path,
) -> None:
    returncode, output = _run_tty_activation(repo_root, approval="wrong")
    assert returncode != 0
    assert "Exact monitoring etcd activation approval did not match" in output
    assert "Record mocked persistent monitoring etcd activation" not in output


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        (
            {"monitoring_etcd_activation_test_post_approval_failure": True},
            "Mocked post-approval monitoring etcd activation preflight failed",
        ),
        (
            {"monitoring_etcd_activation_test_uniform_post_approval_drift": True},
            "activation evidence changed after approval",
        ),
        (
            {"monitoring_etcd_bootstrap_test_start_failure_host": "monitoring-stage-2"},
            "failed to start every member",
        ),
        (
            {"monitoring_etcd_activation_test_start_unreachable_host": "monitoring-stage-2"},
            "failed to start every member",
        ),
        (
            {"monitoring_etcd_activation_test_initial_health_failure": True},
            "activation health failed",
        ),
        (
            {"monitoring_etcd_activation_test_initial_health_unreachable": True},
            "activation health failed",
        ),
        (
            {"monitoring_etcd_activation_test_unstable": True},
            "activation health failed",
        ),
        (
            {"monitoring_etcd_activation_test_runtime_identity_drift": True},
            "does not match the approved bootstrap identity",
        ),
        (
            {"monitoring_etcd_activation_test_enable_failure_host": "monitoring-stage-3"},
            "persistent activation failed",
        ),
        (
            {"monitoring_etcd_activation_test_enable_unreachable_host": "monitoring-stage-3"},
            "persistent activation failed",
        ),
        (
            {"monitoring_etcd_activation_test_final_health_failure": True},
            "Final monitoring etcd activation health failed",
        ),
        (
            {"monitoring_etcd_activation_test_final_health_unreachable": True},
            "Final monitoring etcd activation health failed",
        ),
    ),
)
def test_monitoring_etcd_activation_rejects_failed_transition(
    repo_root: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    returncode, output = _run_tty_activation(
        repo_root,
        variables=_variables(**overrides),
    )
    assert returncode != 0
    assert message in output
    assert "Reject activation limits outside monitoring" not in output
    if "post_approval" not in str(overrides):
        assert "Record mocked monitoring etcd activation rollback" in output


def test_monitoring_etcd_activation_rejects_partial_selection(
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
    assert_failed_with(result, "requires an explicit limit selecting exactly")


def test_monitoring_etcd_activation_rejects_omitted_limit(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(_variables(),),
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires an explicit limit selecting exactly")


def test_monitoring_etcd_activation_rejects_mixed_selection(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(_variables(),),
        limit="monitoring:localhost",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires an explicit limit selecting exactly")


def test_monitoring_etcd_status_source_is_read_only(repo_root: Path) -> None:
    paths = (
        repo_root / STATUS_PLAYBOOK,
        repo_root / "roles/monitoring_etcd_status/tasks/main.yml",
        repo_root / "roles/monitoring_etcd/tasks/activation_preflight.yml",
        repo_root / "roles/monitoring_etcd/tasks/runtime_status.yml",
        repo_root / "roles/monitoring_etcd/tasks/bootstrap_validate_status.yml",
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for action in (
        "ansible.builtin.copy:",
        "ansible.builtin.file:",
        "ansible.builtin.template:",
        "ansible.builtin.systemd_service:",
        "ansible.builtin.service:",
        "ansible.builtin.package:",
        "ansible.builtin.dnf:",
        "ansible.builtin.shell:",
    ):
        assert action not in source
    assert "monitoring_etcd_activation_ready" not in (
        repo_root / STATUS_PLAYBOOK
    ).read_text(encoding="utf-8")
    assert "ansible_limit is defined" in (
        repo_root / STATUS_PLAYBOOK
    ).read_text(encoding="utf-8")
    assert "podman\n      - exec" in source
    for forbidden in ("member add", "member remove", " put ", " del "):
        assert forbidden not in source


def test_monitoring_etcd_status_accepts_active_stable_cluster(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / STATUS_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(
            {
                "monitoring_etcd_activation_test_lifecycle": "active",
                "monitoring_etcd_bootstrap_test_started": True,
                "monitoring_etcd_status_stability_delay": 1,
            },
        ),
        limit="monitoring",
        environment=_environment(repo_root),
    ).assert_success()


def test_monitoring_etcd_status_rejects_inactive_cluster(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / STATUS_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(
            {
                "monitoring_etcd_activation_test_lifecycle": "inactive",
                "monitoring_etcd_bootstrap_test_started": True,
            },
        ),
        limit="monitoring",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires the exact persistently active Quadlet")


def test_monitoring_etcd_status_rejects_omitted_limit(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / STATUS_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(
            {
                "monitoring_etcd_activation_test_lifecycle": "active",
                "monitoring_etcd_bootstrap_test_started": True,
            },
        ),
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires an explicit limit selecting exactly")


def test_monitoring_etcd_status_rejects_runtime_identity_drift(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / STATUS_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=(
            {
                "monitoring_etcd_activation_test_lifecycle": "active",
                "monitoring_etcd_bootstrap_test_started": True,
                "monitoring_etcd_activation_test_runtime_identity_drift": True,
            },
        ),
        limit="monitoring",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "does not match bootstrap completion identity")


@pytest.mark.parametrize("playbook", (PLAYBOOK, STATUS_PLAYBOOK))
def test_monitoring_etcd_activation_playbook_syntax(
    playbook: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / playbook,
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()
