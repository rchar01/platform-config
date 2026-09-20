from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from test_storage_apply import CI_CONTROLLER_VARS


REGISTRY = "registry-a"
CLIENTS = ["client-a", "client-b"]
PREFIX = ["inventory", "connectivity", "registry-preflight"]
ROUTES = {
    "registry-host-plan": ["registry-bootstrap-check", "registry-base-os-check"],
    "registry-host-apply": [
        "registry-bootstrap-check", "registry-bootstrap-apply", "registry-bootstrap-post-check",
        "registry-base-os-check", "registry-base-os-apply", "registry-base-os-post-check",
    ],
    "registry-storage-plan": ["storage-check"],
    "registry-storage-apply": ["storage-check", "storage-apply", "storage-idempotence", "storage-verify"],
    "registry-stage-plan": ["registry-stage-check"],
    "registry-stage-apply": ["registry-stage-check", "registry-stage-apply", "registry-stage-post-check"],
    "registry-clients-plan": ["registry-clients-check"],
    "registry-clients-apply": ["registry-clients-check", "registry-clients-apply", "registry-clients-post-check"],
    "registry-pki-request-plan": ["registry-pki-preflight"],
    "registry-pki-request": ["registry-pki-preflight", "registry-pki-request"],
    "registry-pki-activate-plan": ["registry-pki-preflight"],
    "registry-pki-activate": ["registry-pki-preflight", "registry-pki-activate"],
    "registry-smoke-plan": [],
    "registry-smoke": ["registry-smoke", "registry-smoke-post-check"],
}


def inventory():
    return {
        "registry": {"children": ["registry_nodes"]},
        "registry_nodes": {"hosts": [REGISTRY]},
        "registry_clients": {"hosts": CLIENTS},
        "rocky": {"hosts": [REGISTRY]},
        "container_hosts": {"hosts": [REGISTRY]},
        "storage_volume_hosts": {"hosts": [REGISTRY]},
        "gitlab_runners": {"hosts": [CLIENTS[0]]},
        "rke2_cluster": {"hosts": [CLIENTS[1]]},
        "_meta": {"hostvars": {REGISTRY: {
            "storage_volumes": [{"lv_name": "data", "state": "mounted"}],
            "storage_volume_layouts": [],
        }}},
    }


def selected_hosts(operation):
    if operation.startswith("registry-clients-"):
        return CLIENTS
    return sorted([REGISTRY, *CLIENTS]) if operation.startswith("registry-smoke") else [REGISTRY]


@pytest.fixture
def registry_launcher(repo_root, isolated_test_dir, command_runner):
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
phase = os.environ["PLATFORM_CONFIG_OPERATION_PHASE"]
fault = os.environ.get("FAULT", "") if phase == os.environ.get("FAULT_PHASE") else ""
with open(os.environ["CALL_LOG"], "a") as out:
    out.write(json.dumps(dict(phase=phase, argv=[name, *sys.argv[1:]])) + "\\n")
controller = pathlib.Path(next(arg[1:] for arg in sys.argv if arg.startswith("@")))
with open(os.environ["VARS_LOG"], "a") as out:
    out.write(json.dumps(json.loads(controller.read_text())) + "\\n")
if fault == "interrupt":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    os.kill(os.getppid(), signal.SIGTERM)
    signal.pause()
if name == "ansible-inventory":
    print("{}" if fault == "missing" else pathlib.Path(os.environ["INVENTORY"]).read_text())
    if os.environ.get("TAMPER") == "1":
        pathlib.Path(os.environ["ORIGINAL"]).write_text('{"registry_operation_action":"smoke"}')
    raise SystemExit(7 if fault == "exit" else 0)
if os.environ.get("NATIVE") == "1":
    args = [os.environ["REAL_PLAYBOOK"], "-i", os.environ["LOCAL_INVENTORY"],
            os.environ["LOCAL_PLAYBOOK"], "--limit",
            sys.argv[sys.argv.index("--limit") + 1] if "--limit" in sys.argv else sys.argv[3]]
    if "--check" in sys.argv:
        args += ["--check", "--diff"]
    os.execv(args[0], args)
hosts = json.loads(os.environ["HOSTS"])
if fault == "missing":
    hosts.pop()
if fault == "extra":
    hosts.append("unrelated")
with open(os.environ["PLATFORM_CONFIG_OPERATION_SUMMARY_PATH"], "a") as out:
    for host in hosts:
        changed = phase.endswith(("-check", "-apply")) and not phase.endswith("-post-check")
        counts = dict(ok=1, changed=int(changed), failures=0, unreachable=0, skipped=0, ignored=0, rescued=0)
        if host == hosts[-1] and fault in counts:
            counts[fault] = 0 if fault == "ok" else 1
        record = dict(schema=1, kind="recap", phase=phase, host=host, counters=counts)
        out.write(json.dumps(record) + "\\n")
        if fault == "duplicate":
            out.write(json.dumps(record) + "\\n")
if phase == "registry-pki-request":
    print('request_id: 0123456789abcdef0123456789abcdef')
raise SystemExit(7 if fault == "exit" else 0)
'''
    for name in ("ansible-inventory", "ansible", "ansible-playbook"):
        path = binary / name
        path.write_text(code)
        path.chmod(0o755)

    def run(operation="registry-stage-apply", data=None, controller=None, extra=(),
            phase="", fault="", tamper=False, native=False):
        inv.write_text(json.dumps(inventory() if data is None else data))
        if controller is not None:
            variables.write_text(controller if isinstance(controller, str) else json.dumps(controller))
        environment = {
            "PATH": f"{binary}:{os.environ['PATH']}", "CALL_LOG": str(log), "INVENTORY": str(inv),
            "VARS_LOG": str(root / "used-vars.jsonl"), "ORIGINAL": str(variables),
            "TAMPER": str(int(tamper)), "FAULT_PHASE": phase, "FAULT": fault,
            "HOSTS": json.dumps(selected_hosts(operation)),
        }
        if native:
            local_inv = root / "local.yml"
            local_inv.write_text(yaml.safe_dump({"all": {"hosts": {
                host: {"ansible_connection": "local"} for host in selected_hosts(operation)
            }}}))
            play = root / "local-play.yml"
            play.write_text(yaml.safe_dump([{
                "hosts": "all", "gather_facts": False,
                "tasks": [{
                    "name": "Observe native check mode and callback evidence",
                    "ansible.builtin.assert": {"that": [
                        "ansible_check_mode == lookup('env', 'PLATFORM_CONFIG_OPERATION_PHASE').endswith('-check')",
                    ]},
                    "changed_when": "lookup('env', 'PLATFORM_CONFIG_OPERATION_PHASE') == lookup('env', 'FAULT_PHASE') and lookup('env', 'FAULT') == 'changed'",
                }],
            }]))
            real_playbook = shutil.which("ansible-playbook")
            assert real_playbook is not None
            environment.update(NATIVE="1", REAL_PLAYBOOK=real_playbook,
                               LOCAL_INVENTORY=str(local_inv), LOCAL_PLAYBOOK=str(play))
        result = command_runner.run([
            repo_root / "scripts/platform-config-operation", operation,
            "--inventory", inv, "--controller-vars", variables, *extra,
        ], environment=environment, timeout=90)
        commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, commands

    return run


@pytest.mark.parametrize("operation", ROUTES)
def test_registry_fixed_routes_and_scopes(registry_launcher, repo_root, operation):
    result, commands = registry_launcher(operation)
    result.assert_success()
    assert "Overall: PASS" in result.stdout
    assert "N/A" not in result.stdout
    assert [call["phase"] for call in commands] == PREFIX + ROUTES[operation]
    hosts = selected_hosts(operation)
    assert all(host in result.stdout for host in hosts)
    assert all(host not in result.stdout for host in {REGISTRY, *CLIENTS} - set(hosts))
    common = commands[0]["argv"][-2:]
    assert common[0] == "--extra-vars"
    assert not Path(common[1][1:]).parent.exists()
    inv = commands[0]["argv"][2]
    assert commands[0]["argv"] == ["ansible-inventory", "-i", inv, "--list", *common]
    limit = ",".join(hosts)
    assert commands[1]["argv"] == ["ansible", "-i", inv, limit, "-m", "ansible.builtin.ping", *common]
    action = operation.removeprefix("registry-").removesuffix("-plan").removesuffix("-apply")
    for call in commands[2:]:
        phase = call["phase"]
        args = []
        if phase == "registry-preflight":
            playbook = "registry-operation-preflight.yml"
            args = ["--extra-vars", f"registry_operation_action={action}"]
        elif phase == "registry-pki-preflight":
            playbook = "registry-pki-preflight.yml"
            if action == "pki-activate":
                args = ["--extra-vars", "registry_pki_preflight_action=activate"]
        elif phase.startswith("registry-bootstrap-"):
            playbook = "bootstrap.yml"
        elif phase.startswith("registry-base-os-"):
            playbook = "base-os.yml"
        elif phase.startswith("registry-clients-"):
            playbook = "registry-clients.yml"
        elif phase.startswith("registry-stage-") or phase == "registry-smoke-post-check":
            playbook = "registry.yml"
        elif phase == "storage-verify":
            playbook = "maintenance/storage-volumes-verify.yml"
            args = ["--extra-vars", "storage_verify_scope=registry"]
        elif phase.startswith("storage-"):
            playbook = "storage-volumes.yml"
        else:
            playbook = f"{phase}.yml"
        if phase.endswith("-check"):
            args += ["--check", "--diff"]
        assert call["argv"] == [
            "ansible-playbook", "-i", inv, str(repo_root / "playbooks" / playbook),
            "--limit", limit, *args, *common,
        ]
    if operation == "registry-pki-request":
        assert "request_id: 0123456789abcdef0123456789abcdef" in result.stdout


# Exercise every phase boundary, including later host bootstrap/base-OS writes,
# separately from the evidence fault matrix on a complete multi-client scope.
@pytest.mark.parametrize("operation,phase", [
    (operation, phase) for operation in ROUTES if not operation.endswith("-plan")
    for phase in PREFIX + ROUTES[operation]
])
def test_registry_each_phase_gates_next_command(registry_launcher, operation, phase):
    result, commands = registry_launcher(operation, phase=phase, fault="missing")
    result.assert_failure()
    assert result.returncode == 2
    assert "Overall: FAIL" in result.stdout
    assert [call["phase"] for call in commands] == (PREFIX + ROUTES[operation])[:(PREFIX + ROUTES[operation]).index(phase) + 1]


@pytest.mark.parametrize("fault", ["exit", "extra", "duplicate", "failures", "unreachable", "ignored", "rescued", "ok"])
def test_registry_rejects_incomplete_or_failed_evidence(registry_launcher, fault):
    # Phase wiring is covered above; exercise the shared evidence validator once.
    phase = "registry-smoke"
    result, commands = registry_launcher("registry-smoke", phase=phase, fault=fault)
    result.assert_failure()
    assert result.returncode == (7 if fault == "exit" else 2)
    assert commands[-1]["phase"] == phase
    assert "Overall: FAIL" in result.stdout


@pytest.mark.parametrize("operation,phase", [
    ("registry-stage-plan", "registry-preflight"),
    ("registry-pki-request-plan", "registry-pki-preflight"),
    ("registry-pki-activate-plan", "registry-pki-preflight"),
    ("registry-host-apply", "registry-bootstrap-post-check"),
    ("registry-host-apply", "registry-base-os-post-check"),
    ("registry-storage-apply", "storage-idempotence"),
    ("registry-storage-apply", "storage-verify"),
    ("registry-stage-apply", "registry-stage-post-check"),
    ("registry-clients-apply", "registry-clients-post-check"),
    ("registry-smoke", "registry-smoke-post-check"),
])
def test_registry_read_only_and_post_phases_require_zero_changes(registry_launcher, operation, phase):
    result, commands = registry_launcher(operation, phase=phase, fault="changed")
    result.assert_failure()
    assert commands[-1]["phase"] == phase


@pytest.mark.parametrize("extra", [
    ["--node", REGISTRY], ["--plan", "/tmp/plan"], ["--limit", "all"],
    ["--extra-vars", "registry_operation_action=smoke"], ["--playbook", "other.yml"],
])
def test_registry_accepts_only_inventory_and_transport_inputs(registry_launcher, extra):
    # All registry routes use the same parser, before any Ansible command.
    result, commands = registry_launcher(extra=extra)
    result.assert_failure()
    assert commands == []


@pytest.mark.parametrize("controller", [
    {"registry_operation_action": "smoke"}, {"registry_pki_preflight_action": "activate"},
    {"storage_verify_scope": "registry"}, {"storage_volume_initialize": True},
    {"ansible_connection": "local"}, {"ansible_host": "127.0.0.1"}, {"ansible_become": False},
    "null", "[]", "key: value", '{"ansible_ssh_args":"one","ansible_ssh_args":"two"}',
    {"platform_ci_ssh_private_key_files": {}}, {"ansible_ssh_args": "{{ command }}"},
])
def test_registry_transport_validation_precedes_inventory(registry_launcher, controller):
    result, commands = registry_launcher(controller=controller)
    result.assert_failure()
    assert "transport-only JSON" in result.stderr
    assert commands == []


@pytest.mark.parametrize("operation", ["registry-stage-apply", "registry-clients-apply", "registry-smoke"])
def test_registry_selected_only_key_coverage_and_snapshot(registry_launcher, isolated_test_dir, operation):
    controller = {**CI_CONTROLLER_VARS, "platform_ci_ssh_private_key_files": {
        host: f"/synthetic/{host}" for host in selected_hosts(operation)
    }}
    result, commands = registry_launcher(operation, controller=controller, tamper=True)
    result.assert_success()
    assert json.loads((isolated_test_dir / "vars.json").read_text()) == {"registry_operation_action": "smoke"}
    assert [json.loads(line) for line in (isolated_test_dir / "used-vars.jsonl").read_text().splitlines()] == [controller] * len(commands)


@pytest.mark.parametrize("operation", ["registry-stage-plan", "registry-clients-plan", "registry-smoke-plan"])
def test_registry_missing_selected_key_rejected_before_ping(registry_launcher, operation):
    result, commands = registry_launcher(operation, controller={
        "platform_ci_ssh_private_key_files": {"unrelated": "/synthetic/key"},
    })
    result.assert_failure()
    assert len(commands) == 1


@pytest.mark.parametrize("group", [
    "registry_clients", "gitlab_runners", "rke2_cluster", "rke2_servers", "rke2_agents", "openbao",
])
def test_registry_host_must_be_disjoint(registry_launcher, group):
    data = inventory()
    data[group] = {"hosts": [REGISTRY]}
    result, commands = registry_launcher(data=data)
    result.assert_failure()
    assert len(commands) == 1


@pytest.mark.parametrize("scope", ["empty", "multiple", "cycle", "rocky", "container_hosts", "storage_volume_hosts"])
def test_registry_requires_exact_coherent_host_scope(registry_launcher, scope):
    data = inventory()
    if scope == "empty":
        data["registry"] = {"hosts": []}
    elif scope == "multiple":
        data["registry_nodes"]["hosts"].append("registry-b")
    elif scope == "cycle":
        data["registry_nodes"]["children"] = ["registry"]
    else:
        del data[scope]
    result, commands = registry_launcher(data=data)
    result.assert_failure()
    assert len(commands) == 1


@pytest.mark.parametrize("host", ["all", "ungrouped", "rocky", "127.0.0.1", "a:b", "a,b", "a*", "-host", "a b"])
def test_registry_rejects_nonliteral_or_ambiguous_names(registry_launcher, host):
    data = inventory()
    for group in ("registry_nodes", "rocky", "container_hosts", "storage_volume_hosts"):
        data[group] = {"hosts": [host]}
    result, commands = registry_launcher(data=data)
    result.assert_failure()
    assert len(commands) == 1


@pytest.mark.parametrize("operation", ["registry-clients-plan", "registry-smoke-plan"])
@pytest.mark.parametrize("clients", [[], ["all"], ["127.0.0.1"], ["client:*"], ["container_hosts"]])
def test_registry_client_scope_is_nonempty_and_literal(registry_launcher, operation, clients):
    data = inventory()
    data["registry_clients"] = {"hosts": clients}
    result, commands = registry_launcher(operation, data=data)
    result.assert_failure()
    assert len(commands) == 1


def test_registry_host_route_does_not_require_clients_or_storage_declarations(registry_launcher):
    data = inventory()
    del data["registry_clients"]
    del data["_meta"]
    result, _ = registry_launcher("registry-host-plan", data=data)
    result.assert_success()


@pytest.mark.parametrize("values", [
    {}, {"storage_volumes": []}, {"storage_volumes": {}}, {"storage_volumes": [None]},
    {"storage_volumes": [{}], "storage_volume_layouts": {}},
    {"storage_volumes": [{"state": "mounted"}, {"state": "absent"}]},
    {"storage_volumes": [{}], "storage_volume_default_mount_state": "{{ state }}"},
    {"storage_volumes": [{"state": False}]},
])
def test_registry_storage_apply_validates_mounted_intent_before_ping(registry_launcher, values):
    data = inventory()
    data["_meta"]["hostvars"][REGISTRY] = values
    result, commands = registry_launcher("registry-storage-apply", data=data)
    result.assert_failure()
    assert len(commands) == 1


@pytest.mark.parametrize("operation,state", [("registry-storage-plan", "unmounted"), ("registry-storage-apply", "mounted")])
def test_registry_storage_state_preview_and_explicit_override(registry_launcher, operation, state):
    data = inventory()
    data["_meta"]["hostvars"][REGISTRY].update(
        storage_volume_default_mount_state="unmounted", storage_volumes=[{"state": state}],
    )
    result, _ = registry_launcher(operation, data=data)
    result.assert_success()


def test_registry_interrupt_stops_without_retry_and_cleans_snapshot(registry_launcher):
    result, commands = registry_launcher(phase="registry-stage-apply", fault="interrupt")
    assert result.returncode == 143
    assert commands[-1]["phase"] == "registry-stage-apply"
    assert "Overall: FAIL" in result.stdout
    assert not Path(commands[0]["argv"][-1][1:]).parent.exists()


@pytest.mark.parametrize("operation,phase", [
    ("registry-storage-apply", ""), ("registry-smoke", ""),
    ("registry-storage-apply", "storage-idempotence"),
])
def test_registry_native_callback_and_real_second_apply(registry_launcher, operation, phase):
    result, commands = registry_launcher(operation, native=True, phase=phase, fault="changed")
    if phase:
        result.assert_failure()
        assert commands[-1]["phase"] == phase
    else:
        result.assert_success()
        assert "Overall: PASS" in result.stdout
