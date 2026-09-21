from __future__ import annotations

import json
import os

import pytest


HOSTS = ["bao-a", "bao-b", "bao-c"]
PREFIX = ["inventory", "connectivity", "openbao-preflight"]
ROUTES = {
    "openbao-host-plan": [f"openbao-{step}-check" for step in ("bootstrap", "base-os", "runtime")],
    "openbao-host-apply": [f"openbao-{step}-{phase}" for step in ("bootstrap", "base-os", "runtime")
                           for phase in ("check", "apply", "post-check")],
    "openbao-stage-plan": ["openbao-stage-check"],
    "openbao-stage-apply": ["openbao-stage-check", "openbao-stage-apply", "openbao-stage-post-check"],
}


def inventory():
    return {"openbao": {"children": ["bao_nodes"]}, "bao_nodes": {"hosts": HOSTS},
            "rocky": {"hosts": HOSTS}, "storage_volume_hosts": {"hosts": HOSTS},
            "_meta": {"hostvars": {}}}


@pytest.fixture
def launcher(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    binaries = root / "bin"
    binaries.mkdir()
    inv, variables, log = (root / name for name in ("inventory.json", "vars.json", "calls.jsonl"))
    code = '''#!/usr/bin/env python3
import json, os, pathlib, sys
phase = os.environ['PLATFORM_CONFIG_OPERATION_PHASE']
fault = os.environ.get('FAULT') if phase == os.environ.get('FAULT_PHASE') else ''
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps(dict(phase=phase, args=sys.argv[1:])) + '\\n')
variables = pathlib.Path(next(arg[1:] for arg in sys.argv if arg.startswith('@')))
assert json.loads(variables.read_text()) == json.loads(os.environ['EXPECTED_VARS'])
if pathlib.Path(sys.argv[0]).name == 'ansible-inventory':
    print('{}' if fault == 'missing' else pathlib.Path(os.environ['INVENTORY']).read_text())
    if os.environ.get('TAMPER') == 'true':
        pathlib.Path(os.environ['ORIGINAL_VARS']).write_text('{"openbao_service_enabled":true}')
    sys.exit(0)
hosts = ['bao-a', 'bao-b', 'bao-c']
if '--limit' in sys.argv:
    limit = sys.argv[sys.argv.index('--limit') + 1]
    if limit != 'openbao': hosts = [limit]
elif pathlib.Path(sys.argv[0]).name == 'ansible' and sys.argv[3] != 'openbao':
    hosts = [sys.argv[3]]
if fault == 'missing': hosts.pop()
if fault == 'extra': hosts.append('foreign')
with open(os.environ['PLATFORM_CONFIG_OPERATION_SUMMARY_PATH'], 'a') as stream:
    for host in hosts:
        counts = dict(ok=1, changed=int(phase.endswith(('-apply', '-check')) and not phase.endswith('-post-check')),
                      failures=0, unreachable=0, skipped=0, rescued=0, ignored=0)
        if phase == 'openbao-bootstrap-complete-check': counts['changed'] = 0
        if fault in counts and host == hosts[-1]: counts[fault] = 0 if fault == 'ok' else 1
        record = dict(schema=1, kind='recap', phase=phase, host=host, counters=counts)
        stream.write(json.dumps(record) + '\\n')
        if fault == 'duplicate': stream.write(json.dumps(record) + '\\n')
sys.exit(7 if fault == 'exit' else 0)
'''
    for name in ("ansible-inventory", "ansible", "ansible-playbook"):
        path = binaries / name
        path.write_text(code)
        path.chmod(0o755)

    def run(operation="openbao-host-apply", data=None, controller=None, phase="", fault="", extra=(), ci="true", tamper=False):
        inv.write_text(json.dumps(inventory() if data is None else data))
        variables.write_text(json.dumps({} if controller is None else controller))
        variables.chmod(0o600)
        result = command_runner.run([
            repo_root / "scripts/platform-config-operation", operation,
            "--inventory", inv, "--controller-vars", variables, *extra,
        ], environment={
            "PATH": f"{binaries}:{os.environ['PATH']}", "CI": ci, "CALLS": str(log),
            "INVENTORY": str(inv), "ORIGINAL_VARS": str(variables), "TAMPER": str(tamper).lower(),
            "EXPECTED_VARS": variables.read_text(), "FAULT_PHASE": phase, "FAULT": fault,
        })
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls
    return run


@pytest.mark.parametrize("operation", ROUTES)
def test_fixed_routes(launcher, operation):
    result, calls = launcher(operation)
    result.assert_success()
    assert "Overall: PASS" in result.stdout and "N/A" not in result.stdout
    assert [call["phase"] for call in calls] == PREFIX + ROUTES[operation]
    assert calls[1]["args"][2] == "openbao"
    for call in calls[2:]:
        args = call["args"]
        assert args[args.index("--limit") + 1] == "openbao"
        assert ("--check" in args) == call["phase"].endswith("-check")
        if "runtime" in call["phase"]:
            assert args[2].endswith("/playbooks/openbao-runtime-prepare.yml")
        if "stage" in call["phase"]:
            assert args[2].endswith("/playbooks/openbao.yml")
        assert not any("storage-volumes" in arg or "status" in arg for arg in args)


@pytest.mark.parametrize("operation,phase", [(op, phase) for op in ROUTES if op.endswith("-apply")
                                            for phase in PREFIX + ROUTES[op]])
def test_every_phase_requires_complete_evidence(launcher, operation, phase):
    result, calls = launcher(operation, phase=phase, fault="missing")
    result.assert_failure()
    assert calls[-1]["phase"] == phase
    assert "Overall: FAIL" in result.stdout


@pytest.mark.parametrize("fault", ["extra", "duplicate", "exit", "failures", "unreachable", "rescued", "ignored", "ok", "changed"])
def test_fail_closed_evidence(launcher, fault):
    result, calls = launcher(phase="openbao-preflight", fault=fault)
    result.assert_failure()
    assert calls[-1]["phase"] == "openbao-preflight"


@pytest.mark.parametrize("operation", ["openbao-host-apply", "openbao-stage-apply"])
def test_one_target_preflight_failure_blocks_apply(launcher, operation):
    result, calls = launcher(operation, phase="openbao-preflight", fault="failures")
    result.assert_failure()
    assert result.returncode == 2
    assert [call["phase"] for call in calls] == PREFIX
    assert "Overall: FAIL" in result.stdout


@pytest.mark.parametrize("phase", ["openbao-bootstrap-post-check", "openbao-base-os-post-check", "openbao-runtime-post-check",
                                   "openbao-stage-post-check"])
def test_zero_change_post_checks(launcher, phase):
    operation = "openbao-stage-apply" if "stage" in phase else "openbao-host-apply"
    result, calls = launcher(operation, phase=phase, fault="changed")
    result.assert_failure()
    assert calls[-1]["phase"] == phase


@pytest.mark.parametrize("group", ["rke2_cluster", "rke2_servers", "rke2_agents", "registry", "registry_clients", "monitoring",
                                   "gitlab_runners", "gitlab", "k8s_bastion", "bastion", "load_balancers", "haproxy"])
def test_reject_other_service_scope(launcher, group):
    data = inventory()
    data[group] = {"hosts": [HOSTS[-1]]}
    result, calls = launcher(data=data)
    result.assert_failure()
    assert [call["phase"] for call in calls] == ["inventory"]


@pytest.mark.parametrize("operation", ROUTES)
def test_reject_storage_only_scope_before_connectivity(launcher, operation):
    data = inventory()
    data["openbao_storage"] = {"children": ["storage_only_nodes"]}
    data["storage_only_nodes"] = {"hosts": [HOSTS[-1]]}
    result, calls = launcher(operation, data=data)
    result.assert_failure()
    assert result.returncode == 2
    assert [call["phase"] for call in calls] == ["inventory"]


@pytest.mark.parametrize("change", ["partial", "nonrocky", "collision", "pattern", "ip"])
def test_reject_incoherent_scope(launcher, change):
    data = inventory()
    if change == "partial": data["bao_nodes"]["hosts"] = HOSTS[:2]
    if change == "nonrocky": data["rocky"]["hosts"] = HOSTS[:2]
    if change == "collision": data[HOSTS[0]] = {}
    if change in ("pattern", "ip"):
        data["bao_nodes"]["hosts"] = data["rocky"]["hosts"] = [*HOSTS[:2], "bao*" if change == "pattern" else "192.0.2.3"]
    result, calls = launcher(data=data)
    result.assert_failure()
    assert len(calls) == 1


@pytest.mark.parametrize("controller", [{"openbao_service_enabled": False}, {"root_lvm_enabled": False},
                                         {"openbao_orchestration_ready": True}, {"ansible_connection": "local"}])
def test_transport_rejected_before_inventory(launcher, controller):
    result, calls = launcher(controller=controller)
    result.assert_failure()
    assert calls == []


def test_transport_snapshot(launcher):
    result, _ = launcher(tamper=True)
    result.assert_success()


@pytest.mark.parametrize("extra", [("--node", "bao-a"), ("--plan", "/tmp/plan"), ("--limit", "bao-a")])
def test_no_selectors(launcher, extra):
    result, calls = launcher(extra=extra)
    result.assert_failure()
    assert calls == []


def test_ci_only(launcher):
    result, calls = launcher(ci="false")
    result.assert_failure()
    assert calls == []
