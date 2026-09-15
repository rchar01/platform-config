"""Offline launcher contracts; fake Ansible records argv, not live readiness."""

from __future__ import annotations

import json
import os
import pty
import select
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from conftest import CommandRunner
from test_operation_summary import _append, _initialize, _phase, _recap, _render
from test_rke2_operations import _operation_fake_script, _write_executable


EDGE_ROUTES = (
    "openbao-haproxy-plan",
    "openbao-haproxy-activate",
    "openbao-keepalived-plan",
    "openbao-keepalived-activate",
)
SMOKE_ROUTES = ("openbao-smoke", "openbao-vip-smoke")
ROUTES = (*EDGE_ROUTES, *SMOKE_ROUTES)
HOSTS = ("openbao-a", "openbao-b", "openbao-c")


@pytest.fixture
def launcher(repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner):
    root = isolated_test_dir / "paths with 'quotes' \" $HOME;$(false) [*]\\"
    root.mkdir(mode=0o700)
    inventory = root / "hosts.yml"
    controller_vars = root / "controller vars.json"
    inventory.write_text("all: {}\n", encoding="utf-8")
    # These must not choose the lane or substitute an unreviewed plan.
    controller_vars.write_text(json.dumps({
        "openbao_activation_mode": "bogus-controller-mode",
        "openbao_activation_plan_path": "/bogus/controller-plan.json",
        "openbao_haproxy_activation_ready": False,
        "openbao_keepalived_activation_ready": False,
    }), encoding="utf-8")
    controller_vars.chmod(0o600)
    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir()
    probe = """#!/usr/bin/env python3
import json
import os
import pathlib
import select
import sys

name = pathlib.Path(sys.argv[0]).name
phase = os.environ.get("PLATFORM_CONFIG_OPERATION_PHASE")
with pathlib.Path(os.environ["EDGE_PHASE_LOG"]).open("a") as stream:
    stream.write(json.dumps([name, phase, os.isatty(0)]) + "\\n")
if name == "ansible-playbook" and os.environ.get("EDGE_READ_STDIN") == "1":
    if not os.isatty(0):
        raise SystemExit(97)
    print("EDGE_STDIN_READY", flush=True)
    if not select.select([sys.stdin], [], [], 3)[0]:
        raise SystemExit(98)
    if sys.stdin.readline() != "synthetic approval\\n":
        raise SystemExit(99)
"""
    for name in ("ansible", "ansible-inventory", "ansible-playbook"):
        _write_executable(fake_bin / name, probe + _operation_fake_script())
    log = isolated_test_dir / "argv.jsonl"
    phases = isolated_test_dir / "phases.jsonl"
    return SimpleNamespace(
        script=repo_root / "scripts/platform-config-operation",
        inventory=inventory,
        controller_vars=controller_vars,
        plan=root / "activation plan.json",
        log=log,
        phases=phases,
        environment={
            **command_runner.environment,
            "PATH": f"{fake_bin}:{command_runner.environment['PATH']}",
            "PLATFORM_CONFIG_OPERATION_LOG": str(log),
            "EDGE_PHASE_LOG": str(phases),
        },
    )


def _argv(launcher, operation: str) -> list[str]:
    args = [str(launcher.script), operation, "--inventory", str(launcher.inventory),
            "--controller-vars", str(launcher.controller_vars)]
    if operation in EDGE_ROUTES:
        args += ["--plan", str(launcher.plan)]
    return args


def _records(path: Path) -> list:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("ci", ["", "true"])
def test_routes_use_exact_argv_and_summary_phases(
    repo_root: Path, launcher, command_runner: CommandRunner, operation: str, ci: str,
) -> None:
    if operation.endswith("-activate"):
        launcher.plan.write_text("{}\n", encoding="utf-8")
        launcher.plan.chmod(0o600)
    result = command_runner.run(
        _argv(launcher, operation), environment={**launcher.environment, "CI": ci}, timeout=10,
    )
    if operation.endswith("-activate") and ci != "true":
        assert result.returncode == 2, result.diagnostics()
        assert "operator activation requires an interactive terminal" in result.stderr
        assert not launcher.log.exists()
        return
    result.assert_success()
    extra = ["--extra-vars", f"@{launcher.controller_vars}"]
    expected = [["ansible-inventory", "-i", str(launcher.inventory), "--list", *extra]]
    if operation in EDGE_ROUTES:
        edge = operation.split("-")[1]
        phase = "edge-plan" if operation.endswith("-plan") else "edge-activate"
        mode = "plan" if operation.endswith("-plan") else "ci"
        playbook = f"playbooks/maintenance/openbao-{edge}-activate.yml"
        extra += ["--extra-vars", json.dumps({
            "openbao_activation_mode": mode,
            "openbao_activation_plan_path": str(launcher.plan),
        })]
    else:
        phase = operation
        playbook = f"playbooks/{operation}.yml"
    expected.append(["ansible-playbook", "-i", str(launcher.inventory),
                     str(repo_root / playbook), "--limit", "openbao", *extra])
    assert _records(launcher.log) == expected
    assert _records(launcher.phases) == [
        ["ansible-inventory", "inventory", False], ["ansible-playbook", phase, False],
    ]
    assert "Overall: PASS" in result.stdout
    rows = [line.split() for line in result.stdout.splitlines() if line.startswith(HOSTS)]
    assert rows == [[host, "openbao", step, "PASS", "0", "0", "0", "PASS"]
                    for host in HOSTS for step in ("inventory", phase)]
    assert "server-a" not in result.stdout and "agent-a" not in result.stdout
    assert not list(Path(launcher.environment["TMPDIR"]).glob("platform-config-operation.*"))


@pytest.mark.parametrize("flag", ["--inventory", "--controller-vars", "--plan"])
@pytest.mark.parametrize("case", ["omitted", "missing-value", "duplicate", "empty-duplicate"])
def test_required_flags_fail_before_ansible(
    launcher, command_runner: CommandRunner, flag: str, case: str,
) -> None:
    args = _argv(launcher, "openbao-haproxy-plan")
    index = args.index(flag)
    value = args[index + 1]
    if case in {"omitted", "missing-value"}:
        del args[index:index + 2]
        if case == "missing-value":
            args.append(flag)
    elif case == "duplicate":
        args += [flag, value]
    else:
        args[index:index] = [flag, ""]
    result = command_runner.run(args, environment=launcher.environment, timeout=10)
    assert result.returncode == 2, result.diagnostics()
    assert not launcher.log.exists()
    assert "Overall: FAIL" in result.stdout


@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("extra", [
    ["--limit", "openbao-a"], ["--extra-vars", "openbao_activation_mode=ci"],
    ["--check"], ["--unknown"],
])
def test_fixed_routes_reject_passthrough_flags(
    launcher, command_runner: CommandRunner, operation: str, extra: list[str],
) -> None:
    result = command_runner.run(
        [*_argv(launcher, operation), *extra], environment=launcher.environment, timeout=10,
    )
    assert result.returncode == 2, result.diagnostics()
    assert f"unsupported argument: {extra[0]}" in result.stderr
    assert not launcher.log.exists()


@pytest.mark.parametrize("operation", [*SMOKE_ROUTES, "openbao-status", "rke2-bootstrap-plan"])
@pytest.mark.parametrize("empty", [False, True])
def test_non_edge_routes_reject_plan(
    launcher, command_runner: CommandRunner, operation: str, empty: bool,
):
    result = command_runner.run(
        [*_argv(launcher, operation), "--plan", "" if empty else str(launcher.plan)],
        environment=launcher.environment, timeout=10,
    )
    assert result.returncode == 2, result.diagnostics()
    if not empty:
        assert "--plan is only accepted by edge plan/activation or failover plan/test routes" in result.stderr
    assert not launcher.log.exists()


@pytest.mark.parametrize("operation", ["openbao-edge-plan", "openbao-haproxy", "openbao-keepalived-deploy"])
def test_unknown_edge_routes_never_invoke_ansible(
    launcher, command_runner: CommandRunner, operation: str,
) -> None:
    result = command_runner.run(
        _argv(launcher, operation), environment=launcher.environment, timeout=10,
    )
    assert result.returncode == 2, result.diagnostics()
    assert f"unsupported operation: {operation}" in result.stderr
    assert not launcher.log.exists()


@pytest.mark.parametrize("operation", EDGE_ROUTES)
@pytest.mark.parametrize("kind", ["relative", "directory", "symlink", "existing-or-missing", "public"])
def test_edge_plan_path_validation(
    launcher, command_runner: CommandRunner, operation: str, kind: str,
) -> None:
    args = _argv(launcher, operation)
    if kind == "relative":
        args[-1] = "relative-plan.json"
    elif kind == "directory":
        launcher.plan.mkdir()
    elif kind == "symlink":
        launcher.plan.symlink_to(launcher.plan.parent / "missing-target")
    elif kind == "public" or not operation.endswith("-activate"):
        launcher.plan.write_text("unchanged\n", encoding="utf-8")
        launcher.plan.chmod(0o644 if kind == "public" else 0o600)
    result = command_runner.run(
        args, environment={**launcher.environment, "CI": "true"}, timeout=10,
    )
    assert result.returncode == 2, result.diagnostics()
    assert not launcher.log.exists()
    if launcher.plan.is_file():
        assert launcher.plan.read_text(encoding="utf-8") == "unchanged\n"


@pytest.mark.serial
@pytest.mark.parametrize("edge", ["haproxy", "keepalived"])
def test_interactive_activation_preserves_pty_stdin(
    repo_root: Path, launcher, edge: str,
) -> None:
    launcher.plan.write_text("{}\n", encoding="utf-8")
    launcher.plan.chmod(0o600)
    master, slave = pty.openpty()
    process = None
    try:
        process = subprocess.Popen(
            _argv(launcher, f"openbao-{edge}-activate"), cwd=repo_root,
            env={**launcher.environment, "CI": "false", "EDGE_READ_STDIN": "1"},
            stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        os.close(slave)
        slave = -1
        assert process.stdout is not None
        assert select.select([process.stdout], [], [], 5)[0], "child never requested stdin"
        assert process.stdout.readline() == "EDGE_STDIN_READY\n"
        os.write(master, b"synthetic approval\n")
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stdout + stderr
        assert "Overall: PASS" in stdout
        assert _records(launcher.phases) == [
            ["ansible-inventory", "inventory", True], ["ansible-playbook", "edge-activate", True],
        ]
        command = _records(launcher.log)[-1]
        assert command == [
            "ansible-playbook", "-i", str(launcher.inventory),
            str(repo_root / f"playbooks/maintenance/openbao-{edge}-activate.yml"),
            "--limit", "openbao", "--extra-vars", f"@{launcher.controller_vars}",
            "--extra-vars", json.dumps({"openbao_activation_mode": "interactive",
                                        "openbao_activation_plan_path": str(launcher.plan)}),
        ]
    finally:
        os.close(master)
        if slave != -1:
            os.close(slave)
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2)


@pytest.mark.parametrize("edge", ["haproxy", "keepalived"])
def test_activation_source_keeps_readiness_gate_before_preparation(repo_root: Path, edge: str):
    plays = yaml.safe_load((repo_root / f"playbooks/maintenance/openbao-{edge}-activate.yml").read_text())
    tasks = plays[0]["tasks"]
    assert tasks[0]["ansible.builtin.include_tasks"] == f"tasks/openbao-{edge}-preflight.yml"
    assert tasks[1]["ansible.builtin.include_tasks"] == "tasks/openbao-edge-prepare.yml"
    preflight = yaml.safe_load((repo_root / f"playbooks/maintenance/tasks/openbao-{edge}-preflight.yml").read_text())
    conditions = preflight[0]["ansible.builtin.assert"]["that"]
    assert f"openbao_{edge}_activation_ready | default(false) is boolean" in conditions
    assert ("openbao_activation_mode | default('interactive') == 'plan' or "
            f"openbao_{edge}_activation_ready | default(false)") in conditions
    assert "ansible_play_hosts_all | sort == groups.get('openbao', []) | sort" in conditions
    assert "not ansible_check_mode" in conditions


@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("failure", ["missing-recap", "two-hosts", "failed-phase"])
def test_new_summary_routes_fail_closed(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    operation: str, failure: str,
) -> None:
    events = _initialize(repo_root, command_runner, isolated_test_dir, operation)
    phase = ("edge-plan" if operation.endswith("-plan") else "edge-activate"
             if operation.endswith("-activate") else operation)
    assert _records(events)[0]["phases"] == ["inventory", phase]
    hosts = HOSTS[:2] if failure == "two-hosts" else HOSTS
    for host in hosts:
        _append(events, {"schema": 1, "kind": "host", "host": host, "role": "openbao"})
    _append(events, *_phase("inventory"), *_phase(phase, 7 if failure == "failed-phase" else 0))
    for host in hosts:
        if failure != "missing-recap" or host != HOSTS[-1]:
            _append(events, _recap(phase, host))
    result = _render(repo_root, command_runner, events, 0)
    assert result.returncode == 2, result.diagnostics()
    assert "Overall: FAIL" in result.stdout


@pytest.mark.parametrize("operation", ROUTES)
def test_launcher_propagates_edge_or_smoke_failure(
    launcher, command_runner: CommandRunner, operation: str,
) -> None:
    if operation.endswith("-activate"):
        launcher.plan.write_text("{}\n", encoding="utf-8")
        launcher.plan.chmod(0o600)
    result = command_runner.run(
        _argv(launcher, operation), timeout=10,
        environment={**launcher.environment, "CI": "true", "PLATFORM_CONFIG_FAIL_MATCH": ".yml"},
    )
    assert result.returncode == 1, result.diagnostics()
    assert "Overall: FAIL" in result.stdout
    assert len(_records(launcher.log)) == 2


@pytest.mark.parametrize("early_failure", [False, True])
def test_non_ci_summary_does_not_claim_gitlab_runner(
    launcher, command_runner: CommandRunner, early_failure: bool,
) -> None:
    args = _argv(launcher, "openbao-haproxy-plan")
    if early_failure:
        args = args[:2]
    result = command_runner.run(args, environment=launcher.environment, timeout=10)
    assert result.returncode == (2 if early_failure else 0), result.diagnostics()
    assert "=== PLATFORM CONFIG OPERATION SUMMARY ===" in result.stdout
    assert "Execution context: GitLab Runner" not in result.stdout
