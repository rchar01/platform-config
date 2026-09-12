from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from test_storage_apply import CI_CONTROLLER_VARS


HOSTS = [f"node-{index}" for index in range(9)]
PHASES = ["connectivity", "host-aliases-check", "host-aliases-apply", "host-aliases-post-check", "host-aliases-verify"]


@pytest.fixture
def aliases_launcher(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    root.chmod(0o700)
    inv = root / "inventory.json"
    variables = root / "vars.json"
    variables.write_text("{}")
    variables.chmod(0o600)
    log = root / "commands.jsonl"
    binary = root / "bin"
    binary.mkdir()
    code = '''#!/usr/bin/env python3
import json, os, pathlib, signal, sys
name = pathlib.Path(sys.argv[0]).name
controller = pathlib.Path(sys.argv[sys.argv.index("--extra-vars") + 1][1:])
with open(os.environ["CALL_LOG"], "a") as out:
    out.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
with open(os.environ["VARS_LOG"], "a") as out:
    out.write(json.dumps(json.loads(controller.read_text())) + "\\n")
if name == "ansible-inventory":
    print(pathlib.Path(os.environ["INVENTORY"]).read_text())
    if os.environ.get("TAMPER") == "1":
        pathlib.Path(os.environ["ORIGINAL"]).write_text('{"platform_host_aliases": []}')
    raise SystemExit(0)
phase = os.environ["PLATFORM_CONFIG_OPERATION_PHASE"]
fault = os.environ.get("FAULT", "") if phase == os.environ.get("PHASE") else ""
if fault == "interrupt":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    os.kill(os.getppid(), signal.SIGTERM)
    signal.pause()
hosts = [f"node-{index}" for index in range(9)]
if fault == "missing":
    hosts.pop()
if fault == "extra":
    hosts.append("unrelated")
with open(os.environ["PLATFORM_CONFIG_OPERATION_SUMMARY_PATH"], "a") as out:
    for host in hosts:
        counts = dict(ok=1, changed=int(phase in ("host-aliases-check", "host-aliases-apply")),
                      failures=0, unreachable=0, skipped=0, ignored=0, rescued=0)
        if host == "node-8" and fault in counts:
            counts[fault] = 0 if fault == "ok" else 1
        out.write(json.dumps(dict(schema=1, kind="recap", phase=phase, host=host, counters=counts)) + "\\n")
raise SystemExit(7 if fault == "exit" else 0)
'''
    for name in ("ansible-inventory", "ansible", "ansible-playbook"):
        path = binary / name
        path.write_text(code)
        path.chmod(0o755)

    def run(operation="rke2-host-aliases-apply", controller=None, bad_scope=None,
            phase="", fault="", extra=(), tamper=False):
        data = {"rke2_cluster": {"hosts": HOSTS}, "rke2_servers": {"hosts": HOSTS[:3]},
                "rke2_agents": {"hosts": HOSTS[3:]}}
        if bad_scope == "empty":
            data["rke2_cluster"]["hosts"] = []
        elif bad_scope == "no-server":
            data["rke2_servers"]["hosts"] = []
        elif bad_scope == "no-role":
            data["rke2_agents"]["hosts"] = HOSTS[3:-1]
        elif bad_scope == "dual-role":
            data["rke2_agents"]["hosts"] = HOSTS
        elif bad_scope == "outside":
            data["rke2_agents"]["hosts"] = [*HOSTS[3:], "outside"]
        inv.write_text(json.dumps(data))
        if controller is not None:
            variables.write_text(controller if isinstance(controller, str) else json.dumps(controller))
        result = command_runner.run([
            repo_root / "scripts/platform-config-operation", operation,
            "--inventory", inv, "--controller-vars", variables, *extra,
        ], environment={
            "PATH": f"{binary}:{os.environ['PATH']}", "CALL_LOG": str(log), "INVENTORY": str(inv),
            "VARS_LOG": str(root / "used-vars.jsonl"), "ORIGINAL": str(variables),
            "TAMPER": str(int(tamper)), "PHASE": phase, "FAULT": fault,
        }, timeout=30)
        commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, commands

    return run


@pytest.mark.parametrize("operation,count", [("rke2-host-aliases-plan", 3), ("rke2-host-aliases-apply", 6)])
def test_fixed_alias_calls_and_complete_nine_host_summary(repo_root, aliases_launcher, operation, count):
    result, commands = aliases_launcher(operation=operation)
    result.assert_success()
    assert "Overall: PASS" in result.stdout
    assert "N/A" not in result.stdout
    assert all(host in result.stdout for host in HOSTS)
    assert len(commands) == count
    assert commands[0][:1] == ["ansible-inventory"]
    assert commands[1][3:6] == ["rke2_cluster", "-m", "ansible.builtin.ping"]
    common = commands[0][-2:]
    assert common[0] == "--extra-vars"
    assert not Path(common[1][1:]).exists()  # snapshot and scratch cleaned after exit
    inv = commands[0][2]
    play = ["ansible-playbook", "-i", inv, str(repo_root / "playbooks/rke2-host-aliases.yml"), "--limit", "rke2_cluster"]
    assert commands[2] == [*play, "--check", "--diff", *common]
    if count == 6:
        assert commands[3] == [*play, *common]
        assert commands[4] == [*play, "--check", "--diff", *common]
        assert commands[5] == [*play[:3], str(repo_root / "playbooks/rke2-host-aliases-verify.yml"),
                               "--limit", "rke2_cluster", *common]


@pytest.mark.parametrize("phase,count", list(zip(PHASES, range(2, 7))))
@pytest.mark.parametrize("fault", ["exit", "missing", "extra", "failures", "unreachable", "ignored", "rescued", "ok"])
def test_alias_launcher_stops_on_incomplete_or_failed_evidence(aliases_launcher, phase, count, fault):
    result, commands = aliases_launcher(phase=phase, fault=fault)
    result.assert_failure()
    assert result.returncode == (7 if fault == "exit" else 2)
    assert len(commands) == count
    assert "Overall: FAIL" in result.stdout


@pytest.mark.parametrize("phase,count", [("host-aliases-post-check", 5), ("host-aliases-verify", 6)])
def test_alias_final_phases_require_zero_changes(aliases_launcher, phase, count):
    result, commands = aliases_launcher(phase=phase, fault="changed")
    result.assert_failure()
    assert len(commands) == count


def test_alias_interruption_propagates_and_cleans_without_retry(aliases_launcher):
    result, commands = aliases_launcher(phase="host-aliases-apply", fault="interrupt")
    assert result.returncode == 143
    assert len(commands) == 4
    assert "Overall: FAIL" in result.stdout
    assert not Path(commands[0][-1][1:]).parent.exists()


@pytest.mark.parametrize("scope", ["empty", "no-server", "no-role", "dual-role", "outside"])
def test_alias_scope_fails_before_ping_without_storage_or_installed_rke2_dependency(aliases_launcher, scope):
    result, commands = aliases_launcher(bad_scope=scope)
    result.assert_failure()
    assert len(commands) == 1


@pytest.mark.parametrize("operation", ["rke2-host-aliases-plan", "rke2-host-aliases-apply"])
@pytest.mark.parametrize("extra", [
    ["--node", "node-0"], ["--limit", "all"], ["--plan", "/tmp/plan"],
    ["--extra-vars", "platform_host_aliases=[]"], ["--playbook", "other.yml"],
    ["--group", "rke2_cluster"], ["--apply"], ["--retry"],
])
def test_alias_routes_reject_selectors_and_extra_arguments(aliases_launcher, operation, extra):
    result, commands = aliases_launcher(operation=operation, extra=extra)
    result.assert_failure()
    assert commands == []


@pytest.mark.parametrize("controller", [
    {"platform_host_aliases": []}, {"platform_host_aliases_cloud_init_template": "/tmp/file"},
    {"ansible_connection": "local"}, {"ansible_become": False}, {"ansible_host": "127.0.0.1"},
    "aliases: []", "null", '{"ansible_ssh_args":"one","ansible_ssh_args":"two"}',
    {"platform_ci_ssh_private_key_files": {}}, {"ansible_ssh_args": "{{ command }}"},
])
def test_alias_transport_schema_fails_before_inventory(aliases_launcher, controller):
    result, commands = aliases_launcher(controller=controller)
    result.assert_failure()
    assert "transport-only JSON" in result.stderr
    assert commands == []


def test_alias_key_map_must_cover_complete_cluster_before_ping(aliases_launcher):
    result, commands = aliases_launcher(controller=CI_CONTROLLER_VARS)
    result.assert_failure()
    assert len(commands) == 1


def test_alias_generated_transport_snapshot_is_shared_and_immutable(aliases_launcher, isolated_test_dir):
    controller = {**CI_CONTROLLER_VARS, "platform_ci_ssh_private_key_files": {host: f"/synthetic/{host}" for host in HOSTS}}
    result, commands = aliases_launcher(controller=controller, tamper=True)
    result.assert_success()
    assert len(commands) == 6
    assert json.loads((isolated_test_dir / "vars.json").read_text()) == {"platform_host_aliases": []}
    assert [json.loads(line) for line in (isolated_test_dir / "used-vars.jsonl").read_text().splitlines()] == [controller] * 6
