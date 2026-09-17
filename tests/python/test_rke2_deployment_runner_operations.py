from __future__ import annotations

import json
import os

import pytest
import yaml

from test_rke2_operations import _operation_fake_script, _write_executable
from test_operation_summary import _append, _initialize, _phase, _recap, _render


SMOKE = "rke2-deployment-runners-smoke"


def test_standalone_smoke_real_ansible_empty_defaults(repo_root, isolated_test_dir, command_runner):
    inventory = isolated_test_dir / "hosts.yml"
    inventory.write_text(yaml.safe_dump({"all": {
        "vars": {"ansible_connection": "local", "ansible_become": False},
        "children": {"rke2_cluster": {"children": {
            "rke2_servers": {"hosts": {"server-a": {}, "server-b": {}}},
            "rke2_agents": {"hosts": {"agent-a": {}}},
        }}},
    }}))
    controller = isolated_test_dir / "controller.json"
    controller.write_text("{}\n")
    controller.chmod(0o600)
    result = command_runner.run([
        repo_root / "scripts/platform-config-operation", SMOKE,
        "--inventory", inventory, "--controller-vars", controller,
    ]).assert_success()
    assert "Overall: PASS" in result.stdout
    for host in ("server-a", "server-b"):
        assert any(line.split()[:7] == [host, "server", SMOKE, "PASS", "0", "0", "0"]
                   for line in result.stdout.splitlines())


def run_launcher(repo_root, root, command_runner, operation, *, environment=None, values=None, args=(), fake=None):
    inventory = root / "hosts.yml"
    inventory.write_text("all: {}\n")
    controller = root / "controller.json"
    controller.write_text(json.dumps(values if values is not None else {}))
    controller.chmod(0o600)
    log = root / "commands.jsonl"
    bin_dir = root / "bin"
    bin_dir.mkdir()
    for name in ("ansible-inventory", "ansible", "ansible-playbook"):
        _write_executable(bin_dir / name, fake or _operation_fake_script())
    result = command_runner.run(
        [repo_root / "scripts/platform-config-operation", operation,
         "--inventory", inventory, "--controller-vars", controller, *args],
        environment={"PATH": f"{bin_dir}:{os.environ['PATH']}",
                     "PLATFORM_CONFIG_OPERATION_LOG": str(log), **(environment or {})},
    )
    commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return result, commands


def test_standalone_smoke_fixed_scope_and_snapshot(repo_root, isolated_test_dir, command_runner):
    result, commands = run_launcher(repo_root, isolated_test_dir, command_runner, SMOKE)
    result.assert_success()
    assert [command[0] for command in commands] == ["ansible-inventory", "ansible", "ansible-playbook"]
    assert commands[1][3:6] == ["rke2_cluster", "-m", "ansible.builtin.ping"]
    assert commands[2][3:6] == [str(repo_root / "playbooks/rke2-gitlab-deployment-runners-smoke.yml"), "--limit", "rke2_servers"]
    snapshots = {command[-1] for command in commands}
    assert len(snapshots) == 1
    snapshot = snapshots.pop()
    assert snapshot.endswith("/controller-vars.json")
    assert snapshot != "@" + str(isolated_test_dir / "controller.json")
    assert "Overall: PASS" in result.stdout
    assert any(line.split()[:4] == ["agent-a", "agent", SMOKE, "N/A"] for line in result.stdout.splitlines())


@pytest.mark.parametrize("case", ["role-vars", "missing-key", "partial-scope", "playbook", "limit", "extra-vars", "node"])
def test_standalone_smoke_rejects_overrides_and_incomplete_transport(repo_root, isolated_test_dir, command_runner, case):
    values, args, fake = {}, (), None
    if case == "role-vars":
        values = {"rke2_gitlab_deployment_runners": []}
    elif case == "missing-key":
        values = {"platform_ci_ssh_private_key_files": {"server-a": "/outside/key"}}
    elif case == "partial-scope":
        fake = _operation_fake_script().replace('"rke2_cluster": {"hosts": ["server-a", "agent-a"]}', '"rke2_cluster": {"hosts": ["server-a"]}')
    else:
        args = ("--" + case, "unreviewed")
    result, commands = run_launcher(repo_root, isolated_test_dir, command_runner, SMOKE, values=values, args=args, fake=fake)
    result.assert_failure()
    assert all(command[0] == "ansible-inventory" for command in commands)


@pytest.mark.parametrize("operation,phase", [
    ("rke2-bootstrap", "rke2-deployment-runners-apply"),
    ("rke2-deploy", "rke2-deployment-runners-apply"),
    ("rke2-deploy", SMOKE),
    ("rke2-converge-plan", "rke2-deployment-runners-plan"),
    (SMOKE, "connectivity"),
    (SMOKE, SMOKE),
])
@pytest.mark.parametrize("fault", ["MISSING", "IGNORED", "RESCUED"])
def test_new_phase_evidence_stops_next_command(repo_root, isolated_test_dir, command_runner, operation, phase, fault):
    result, commands = run_launcher(repo_root, isolated_test_dir, command_runner, operation,
                                   environment={f"PLATFORM_CONFIG_{fault}_PHASE": phase})
    result.assert_failure()
    assert "Overall: FAIL" in result.stdout
    last = commands[-1]
    if phase == "connectivity":
        assert last[0] == "ansible"
    else:
        expected = "rke2-gitlab-deployment-runners-smoke.yml" if phase == SMOKE else "rke2-gitlab-deployment-runners.yml"
        assert last[3].endswith("/" + expected)


@pytest.mark.parametrize("fault", [None, "missing", "ignored", "rescued", "unreachable", "failures", "changed", "agent", "foreign"])
def test_summary_requires_every_server_clean_post_check(repo_root, isolated_test_dir, command_runner, fault):
    events = _initialize(repo_root, command_runner, isolated_test_dir, "rke2-deploy")
    phases = json.loads(events.read_text().splitlines()[0])["phases"]
    for host, role in (("server-a", "server"), ("server-b", "server"), ("agent-a", "agent")):
        _append(events, {"schema": 1, "kind": "host", "host": host, "role": role})
    for phase in phases:
        _append(events, *_phase(phase))
        for host in ("server-a", "server-b", "agent-a"):
            if host == "agent-a" and phase.startswith(("kube-vip-", "rke2-gitlab-runner-", "rke2-deployment-runners-")):
                continue
            if phase == "rke2-deployment-runners-post-check" and host == "server-b":
                if fault == "missing":
                    continue
                if fault in {"agent", "foreign"}:
                    host = "agent-a" if fault == "agent" else "unselected"
                recap = _recap(phase, host)
                if fault in {"ignored", "rescued", "unreachable", "failures", "changed"}:
                    counters = recap["counters"]
                    assert isinstance(counters, dict)
                    counters[fault] = 1
            else:
                recap = _recap(phase, host)
            _append(events, recap)
    result = _render(repo_root, command_runner, events, 0)
    assert result.returncode == (0 if fault is None else 2)
