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


FIXTURE = "tests/fixtures/openbao-bootstrap/inventory.yml"
START_PLAYBOOK = "playbooks/maintenance/openbao-bootstrap-start.yml"
COMPLETE_PLAYBOOK = "playbooks/maintenance/openbao-bootstrap-complete.yml"
HAPROXY_PLAYBOOK = "playbooks/maintenance/openbao-haproxy-activate.yml"
STATUS_PLAYBOOK = "playbooks/maintenance/openbao-status.yml"


def _environment(repo_root: Path, path_prefix: Path | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "ANSIBLE_FORCE_COLOR": "0",
            "ANSIBLE_ROLES_PATH": os.pathsep.join(
                [
                    str(repo_root / "tests/fixtures/openbao-bootstrap/roles"),
                    str(repo_root / "roles"),
                ]
            ),
        }
    )
    if path_prefix is not None:
        environment["PATH"] = os.pathsep.join(
            [str(path_prefix), environment.get("PATH", "")]
        )
    return environment


def _run_tty_playbook(
    repo_root: Path,
    playbook: str,
    root: Path,
    approval_pattern: str,
    *,
    variables: dict[str, object] | None = None,
    approval: str | None = None,
    path_prefix: Path | None = None,
    timeout: float = 45,
) -> tuple[int, str]:
    extra_vars: dict[str, object] = {"openbao_test_root": str(root)}
    extra_vars.update(variables or {})
    command = [
        "ansible-playbook",
        "-i",
        str(repo_root / FIXTURE),
        str(repo_root / playbook),
        "--limit",
        "openbao",
        "--extra-vars",
        json.dumps(extra_vars, separators=(",", ":")),
    ]
    master_fd, slave_fd = pty.openpty()

    def establish_controlling_terminal() -> None:
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        command,
        cwd=repo_root,
        env=_environment(repo_root, path_prefix),
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
        while process.poll() is None:
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
                raise AssertionError(output.decode(errors="replace"))
            readable, _, _ = select.select([master_fd], [], [], 0.1)
            if not readable:
                continue
            try:
                output.extend(os.read(master_fd, 65536))
            except OSError:
                break
            rendered = output.decode(errors="replace")
            match = re.search(approval_pattern, rendered)
            if match and not approval_sent:
                time.sleep(0.2)
                os.write(master_fd, ((approval or match.group(0)) + "\r").encode())
                approval_sent = True
    finally:
        os.close(master_fd)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
    return process.returncode, output.decode(errors="replace")


def _start_pattern() -> str:
    return (
        r"start-openbao-bootstrap\|"
        r"bao-bootstrap-1,bao-bootstrap-2,bao-bootstrap-3\|"
        r"[a-f0-9]{64}\|shamir-5-of-3"
    )


def _complete_pattern() -> str:
    return (
        r"complete-openbao-bootstrap\|"
        r"bao-bootstrap-1,bao-bootstrap-2,bao-bootstrap-3\|"
        r"[a-f0-9]{64}\|shamir-5-of-3"
    )


def _haproxy_pattern() -> str:
    return (
        r"activate-openbao-haproxy\|"
        r"bao-bootstrap-1,bao-bootstrap-2,bao-bootstrap-3\|"
        r"test-cluster\|[a-f0-9]{64}"
    )


def test_openbao_bootstrap_source_keeps_custody_outside_ansible(
    repo_root: Path,
) -> None:
    sources = "\n".join(
        (repo_root / path).read_text(encoding="utf-8")
        for path in (START_PLAYBOOK, COMPLETE_PLAYBOOK, HAPROXY_PLAYBOOK)
    )
    for fragment in (
        "ansible_limit is defined",
        "shamir-5-of-3",
        "ansible.builtin.pause:",
        "bootstrap_preflight.yml",
        "bootstrap_pending_preflight.yml",
        "activation_enable.yml",
        "openbao_status",
    ):
        assert fragment in sources
    assert "operator init" not in sources
    assert "operator unseal" not in sources
    assert "unseal_key" not in sources
    assert "root_token" not in sources


def test_openbao_smoke_and_rollback_source_contract(repo_root: Path) -> None:
    smoke = (repo_root / "playbooks/openbao-smoke.yml").read_text(encoding="utf-8")
    rollback = (
        repo_root / "roles/openbao_haproxy/tasks/activation_rollback.yml"
    ).read_text(encoding="utf-8")
    for fragment in (
        "openbao_smoke_active_observations",
        "runtime cluster identity does not match active markers",
        "--noproxy",
        "--connect-timeout",
        "--max-time",
    ):
        assert fragment in smoke
    assert "stdout == 'inactive'" in rollback
    assert "stdout == 'disabled'" in rollback


@pytest.mark.parametrize(
    "playbook",
    [START_PLAYBOOK, COMPLETE_PLAYBOOK, HAPROXY_PLAYBOOK],
)
def test_openbao_bootstrap_playbook_syntax(
    playbook: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / playbook,
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()


def test_openbao_bootstrap_rejects_omitted_limit(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / START_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=({"openbao_test_root": str(isolated_test_dir)},),
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires an explicit limit selecting exactly")


def test_openbao_bootstrap_rejects_non_tty_approval(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / START_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=({"openbao_test_root": str(isolated_test_dir)},),
        limit="openbao",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "approval did not match")


def test_openbao_bootstrap_rejects_post_approval_drift(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    returncode, output = _run_tty_playbook(
        repo_root,
        START_PLAYBOOK,
        isolated_test_dir,
        _start_pattern(),
        variables={"openbao_bootstrap_test_drift": True},
    )
    assert returncode != 0
    assert "evidence changed after approval" in output


def test_openbao_bootstrap_rolls_back_failed_pristine_start(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    returncode, output = _run_tty_playbook(
        repo_root,
        START_PLAYBOOK,
        isolated_test_dir,
        _start_pattern(),
        variables={"openbao_bootstrap_test_start_failure_host": "bao-bootstrap-2"},
    )
    assert returncode != 0
    assert "failed before initialization" in output
    for host in ("bao-bootstrap-1", "bao-bootstrap-2", "bao-bootstrap-3"):
        assert (isolated_test_dir / f"{host}-rollback").exists()


def test_openbao_bootstrap_completion_and_haproxy_activation(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    ca_path = isolated_test_dir / "ca.crt"
    ca_path.write_text("test-ca\n", encoding="utf-8")

    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output

    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    for host in ("bao-bootstrap-1", "bao-bootstrap-2", "bao-bootstrap-3"):
        marker = json.loads(
            (isolated_test_dir / f"{host}-bootstrap.json").read_text(
                encoding="utf-8"
            )
        )
        assert marker["state"] == "active"
        assert marker["cluster_id"] == "test-cluster"

    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text("#!/bin/sh\nprintf 200\n", encoding="utf-8")
    fake_curl.chmod(0o755)
    fake_systemctl = fake_bin / "systemctl"
    fake_systemctl.write_text("#!/bin/sh\nprintf enabled\n", encoding="utf-8")
    fake_systemctl.chmod(0o755)
    haproxy_code, haproxy_output = _run_tty_playbook(
        repo_root,
        HAPROXY_PLAYBOOK,
        isolated_test_dir,
        _haproxy_pattern(),
        path_prefix=fake_bin,
    )
    assert haproxy_code == 0, haproxy_output


def test_openbao_completion_recovers_missing_pending_marker(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    (isolated_test_dir / "bao-bootstrap-2-bootstrap.json").unlink()

    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output
    marker = json.loads(
        (isolated_test_dir / "bao-bootstrap-2-bootstrap.json").read_text(
            encoding="utf-8"
        )
    )
    assert marker["state"] == "active"


def test_openbao_completion_rejects_all_missing_pending_markers(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    for host in ("bao-bootstrap-1", "bao-bootstrap-2", "bao-bootstrap-3"):
        (isolated_test_dir / f"{host}-bootstrap.json").unlink()

    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code != 0
    assert "Existing OpenBao markers do not match" in complete_output


def test_openbao_completion_resumes_partial_enablement(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output

    failed_code, failed_output = _run_tty_playbook(
        repo_root,
        COMPLETE_PLAYBOOK,
        isolated_test_dir,
        _complete_pattern(),
        variables={"openbao_bootstrap_test_enable_failure_host": "bao-bootstrap-2"},
    )
    assert failed_code != 0
    assert "Mocked persistent OpenBao activation failed" in failed_output

    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output


def test_openbao_completion_resumes_partial_active_marker_publication(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output

    marker_path = isolated_test_dir / "bao-bootstrap-1-bootstrap.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker.update({"state": "active", "cluster_id": "test-cluster"})
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (isolated_test_dir / "bao-bootstrap-1.container").write_text(
        "active-openbao", encoding="utf-8"
    )

    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output
    for host in ("bao-bootstrap-1", "bao-bootstrap-2", "bao-bootstrap-3"):
        active_marker = json.loads(
            (isolated_test_dir / f"{host}-bootstrap.json").read_text(
                encoding="utf-8"
            )
        )
        assert active_marker["state"] == "active"
        assert active_marker["cluster_id"] == "test-cluster"
        assert active_marker["cluster_signature"] == marker["cluster_signature"]


def test_openbao_completion_rejects_final_cluster_identity_drift(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output

    complete_code, complete_output = _run_tty_playbook(
        repo_root,
        COMPLETE_PLAYBOOK,
        isolated_test_dir,
        _complete_pattern(),
        variables={"openbao_bootstrap_test_final_cluster_drift": True},
    )
    assert complete_code != 0
    assert "cluster identity changed during persistent activation" in complete_output


def test_openbao_haproxy_rejects_running_keepalived_after_approval(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    haproxy_code, haproxy_output = _run_tty_playbook(
        repo_root,
        HAPROXY_PLAYBOOK,
        isolated_test_dir,
        _haproxy_pattern(),
        variables={"openbao_haproxy_test_keepalived_running": True},
    )
    assert haproxy_code != 0
    assert "safety gates changed after approval" in haproxy_output


def test_openbao_haproxy_rejects_staged_config_drift_after_approval(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    haproxy_code, haproxy_output = _run_tty_playbook(
        repo_root,
        HAPROXY_PLAYBOOK,
        isolated_test_dir,
        _haproxy_pattern(),
        variables={"openbao_haproxy_test_config_drift": True},
    )
    assert haproxy_code != 0
    assert "staged evidence changed after approval" in haproxy_output


def test_openbao_status_rejects_active_marker_cluster_drift(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    marker_path = isolated_test_dir / "bao-bootstrap-2-bootstrap.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["cluster_id"] = "unexpected-cluster"
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    result = run_playbook(
        command_runner,
        repo_root / STATUS_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=({"openbao_test_root": str(isolated_test_dir)},),
        limit="openbao",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "requires one exact marked active cluster")


def test_openbao_status_rejects_malformed_active_marker_signature(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    marker_path = isolated_test_dir / "bao-bootstrap-2-bootstrap.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["cluster_signature"] = "invalid"
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    result = run_playbook(
        command_runner,
        repo_root / STATUS_PLAYBOOK,
        inventory=repo_root / FIXTURE,
        extra_vars=({"openbao_test_root": str(isolated_test_dir)},),
        limit="openbao",
        environment=_environment(repo_root),
    )
    assert_failed_with(result, "marker identity is invalid")


def test_openbao_haproxy_path_failure_rolls_back_every_host(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    fake_bin = isolated_test_dir / "failing-bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_curl.chmod(0o755)
    fake_systemctl = fake_bin / "systemctl"
    fake_systemctl.write_text("#!/bin/sh\nprintf enabled\n", encoding="utf-8")
    fake_systemctl.chmod(0o755)

    haproxy_code, haproxy_output = _run_tty_playbook(
        repo_root,
        HAPROXY_PLAYBOOK,
        isolated_test_dir,
        _haproxy_pattern(),
        path_prefix=fake_bin,
    )
    assert haproxy_code != 0
    assert "path qualification failed" in haproxy_output
    for host in ("bao-bootstrap-1", "bao-bootstrap-2", "bao-bootstrap-3"):
        assert (
            isolated_test_dir / f"{host}-haproxy-rollback"
        ).exists(), haproxy_output


def test_openbao_haproxy_reports_unverified_path_rollback(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    start_code, start_output = _run_tty_playbook(
        repo_root, START_PLAYBOOK, isolated_test_dir, _start_pattern()
    )
    assert start_code == 0, start_output
    complete_code, complete_output = _run_tty_playbook(
        repo_root, COMPLETE_PLAYBOOK, isolated_test_dir, _complete_pattern()
    )
    assert complete_code == 0, complete_output

    fake_bin = isolated_test_dir / "unverified-bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake_curl.chmod(0o755)
    fake_systemctl = fake_bin / "systemctl"
    fake_systemctl.write_text("#!/bin/sh\nprintf enabled\n", encoding="utf-8")
    fake_systemctl.chmod(0o755)

    haproxy_code, haproxy_output = _run_tty_playbook(
        repo_root,
        HAPROXY_PLAYBOOK,
        isolated_test_dir,
        _haproxy_pattern(),
        variables={"openbao_haproxy_test_rollback_failure_host": "bao-bootstrap-2"},
        path_prefix=fake_bin,
    )
    assert haproxy_code != 0
    assert "Unverified rollback hosts: bao-bootstrap-2" in haproxy_output
    assert (isolated_test_dir / "bao-bootstrap-1-haproxy-rollback").exists()
    assert not (isolated_test_dir / "bao-bootstrap-2-haproxy-rollback").exists()
    assert (isolated_test_dir / "bao-bootstrap-3-haproxy-rollback").exists()
