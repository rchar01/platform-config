from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


def inventory():
    return {
        "rke2_cluster": {"hosts": ["server-a", "agent-a"]},
        "rke2_servers": {"hosts": ["server-a"]},
        "rke2_agents": {"hosts": ["agent-a"]},
        "storage_volume_hosts": {"hosts": ["runner"], "children": ["rke2_cluster"]},
        "_meta": {"hostvars": {host: {"storage_volumes": [{"lv_name": "data"}]}
                                for host in ("server-a", "agent-a", "runner")}},
    }


@pytest.fixture
def summary(repo_root):
    loader = importlib.machinery.SourceFileLoader("storage_summary", str(repo_root / "scripts/platform-config-operation-summary"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("operation", ["storage-check", "storage-apply"])
@pytest.mark.parametrize("bad", ["outside", "vault", "empty", "group", "dual-role", "no-role", "not-storage", "address"])
def test_storage_selection_rejects_invalid_hosts(summary, isolated_test_dir, bad, operation):
    data = inventory()
    node = "server-a"
    if bad == "outside":
        node = "runner"
    elif bad == "vault":
        node = "vault-a"
        data["storage_volume_hosts"]["hosts"].append(node)
        data["_meta"]["hostvars"][node] = {"storage_volumes": [{}]}
    elif bad == "empty":
        data["_meta"]["hostvars"][node]["storage_volumes"] = []
    elif bad == "group":
        data[node] = {"hosts": ["agent-a"]}
    elif bad == "dual-role":
        data["rke2_agents"]["hosts"].append(node)
    elif bad == "no-role":
        data["rke2_servers"]["hosts"] = []
    elif bad == "address":
        node = "192.0.2.1"
        data["rke2_cluster"]["hosts"] = [node]
        data["rke2_servers"]["hosts"] = [node]
        data["_meta"]["hostvars"][node] = {"storage_volumes": [{}]}
    else:
        data["storage_volume_hosts"] = {"hosts": ["runner"]}
    path = isolated_test_dir / "inventory.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    with pytest.raises(summary.SummaryError):
        summary.command_hosts(SimpleNamespace(operation=operation, node=node,
                                              inventory=path, output=isolated_test_dir / "unused"))


@pytest.mark.parametrize("failed,missing_recap", [(False, False), (True, False), (False, True)])
def test_storage_launcher_is_single_host_check_only(repo_root, isolated_test_dir, command_runner, failed, missing_recap):
    root = isolated_test_dir
    root.chmod(0o700)
    inv = root / "inventory.json"
    inv.write_text(json.dumps(inventory()))
    inv.chmod(0o600)
    variables = root / "vars.json"
    variables.write_text("{}")
    variables.chmod(0o600)
    log = root / "commands.jsonl"
    bin_dir = root / "bin"
    bin_dir.mkdir()
    code = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["FAKE_LOG"], "a") as out:
    out.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
if name == "ansible-inventory":
    print(pathlib.Path(os.environ["FAKE_INVENTORY"]).read_text())
    raise SystemExit(0)
phase = os.environ["PLATFORM_CONFIG_OPERATION_PHASE"]
failed = phase == "storage-check" and os.environ["FAKE_FAILED"] == "1"
if not (phase == "storage-check" and os.environ["FAKE_MISSING"] == "1"):
    counters = dict(ok=1, changed=int(phase == "storage-check"), failures=int(failed), unreachable=0, skipped=0, rescued=0, ignored=0)
    with open(os.environ["PLATFORM_CONFIG_OPERATION_SUMMARY_PATH"], "a") as out:
        out.write(json.dumps(dict(schema=1, kind="recap", phase=phase, host="server-a", counters=counters)) + "\\n")
raise SystemExit(2 if failed else 0)
'''
    for name in ("ansible-inventory", "ansible", "ansible-playbook"):
        path = bin_dir / name
        path.write_text(code)
        path.chmod(0o755)
    result = command_runner.run([
        repo_root / "scripts/platform-config-operation", "storage-check",
        "--inventory", inv, "--controller-vars", variables, "--node", "server-a",
    ], environment={"PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_LOG": str(log),
            "FAKE_INVENTORY": str(inv), "FAKE_FAILED": str(int(failed)),
            "FAKE_MISSING": str(int(missing_recap))})
    if failed or missing_recap:
        result.assert_failure()
        assert "Overall: FAIL" in result.stdout
    else:
        result.assert_success()
        assert "Overall: PASS" in result.stdout  # planned changes are expected
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(commands) == 3
    assert commands[1] == ["ansible", "-i", str(inv), "server-a", "-m", "ansible.builtin.ping", "--extra-vars", f"@{variables}"]
    assert commands[2] == ["ansible-playbook", "-i", str(inv), str(repo_root / "playbooks/storage-volumes.yml"),
                           "--limit", "server-a", "--check", "--diff", "--extra-vars", f"@{variables}"]
    assert "agent-a" not in result.stdout


@pytest.mark.parametrize("operation", ["storage-check", "storage-apply"])
@pytest.mark.parametrize("node", [None, "all", "ungrouped", "rke2_cluster:runner", "*", "--help", "server-a,agent-a"])
def test_storage_launcher_rejects_host_patterns(repo_root, isolated_test_dir, command_runner, node, operation):
    path = isolated_test_dir / "private.json"
    path.write_text("{}")
    path.chmod(0o600)
    args = [repo_root / "scripts/platform-config-operation", operation, "--inventory", path, "--controller-vars", path]
    if node is not None:
        args += ["--node", node]
    result = command_runner.run(args)
    result.assert_failure()
    assert "requires --node with one literal" in result.stderr


def test_node_argument_is_rejected_by_other_routes(repo_root, isolated_test_dir, command_runner):
    path = isolated_test_dir / "private.json"
    path.write_text("{}")
    path.chmod(0o600)
    result = command_runner.run([repo_root / "scripts/platform-config-operation", "rke2-bootstrap-plan",
                                 "--inventory", path, "--controller-vars", path, "--node", "server-a"])
    result.assert_failure()
    assert "only accepted by storage-check" in result.stderr


@pytest.mark.parametrize("operation", ["storage-check", "storage-apply"])
@pytest.mark.parametrize("extra", [["--apply"], ["--limit", "all"], ["--node", "agent-a"],
                                   ["--playbook", "other.yml"], ["--extra-vars", "initialize=true"],
                                   ["--list"], ["--all"], ["--retry"]])
def test_storage_check_rejects_broad_or_duplicate_arguments(repo_root, isolated_test_dir, command_runner, extra, operation):
    path = isolated_test_dir / "private.json"
    path.write_text("{}")
    path.chmod(0o600)
    result = command_runner.run([
        repo_root / "scripts/platform-config-operation", operation,
        "--inventory", path, "--controller-vars", path, "--node", "server-a", *extra,
    ])
    result.assert_failure()
    assert "unsupported argument" in result.stderr or "exactly once" in result.stderr
