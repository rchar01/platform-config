"""Execute the shipped parser and activation flow with synthetic target SSH I/O."""

import json
import os
import subprocess
import sys

import pytest
import yaml

from test_openbao_haproxy_rollback import rollback_target  # noqa: F401


SOURCE_TASKS = "playbooks/maintenance/tasks/openbao-haproxy-caller-source.yml"
CONNECTION = "198.51.100.65 45678 192.0.2.1 22"
POLICY = ["198.51.100.0/24"]

# Only the target command boundary is doubled. The shipped Python, policy input,
# Ansible result checks, evidence collection, and source comparison still execute.
SOURCE_ACTION = '''
import json
import os
import subprocess
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        assert self._task.become is False
        assert self._play_context.become is False
        root = Path(task_vars.get('openbao_test_root', task_vars.get('fixture_root')))
        host = task_vars['inventory_hostname']
        log = root / (host + '-caller-probes.jsonl')
        count = len(log.read_text().splitlines()) if log.exists() else 0
        connections = task_vars.get('test_caller_connections',
                                   ['198.51.100.65 45678 192.0.2.1 22'])
        connection = connections[min(count, len(connections) - 1)]
        environment = os.environ.copy()
        environment.pop('SSH_CONNECTION', None)
        if connection is not None:
            environment['SSH_CONNECTION'] = connection
        argv = list(self._task.args['argv'])
        # Model a target SSH transport even though the isolated fixture is local.
        argv[-1] = task_vars.get('test_caller_transport', 'ssh')
        result = subprocess.run(argv, input=self._task.args['stdin'], env=environment,
                                text=True, capture_output=True, timeout=5)
        with log.open('a') as stream:
            stream.write(json.dumps(dict(rc=result.returncode, stdout=result.stdout)) + '\\n')
        return dict(changed=False, rc=result.returncode, stdout=result.stdout, stderr=result.stderr)
'''


def stage_caller_source(repo_root, tasks_dir, plugin_dir):
    tasks = yaml.safe_load((repo_root / SOURCE_TASKS).read_text())
    probe = tasks[0]
    probe["ansible.legacy.caller_source"] = probe.pop("ansible.builtin.command")
    probe["ansible.legacy.caller_source"]["argv"][0] = sys.executable
    (tasks_dir / "openbao-haproxy-caller-source.yml").write_text(yaml.safe_dump(tasks))
    (plugin_dir / "caller_source.py").write_text(SOURCE_ACTION)


def run_parser(repo_root, connection=CONNECTION, policy=POLICY, transport="ssh"):
    tasks = yaml.safe_load((repo_root / SOURCE_TASKS).read_text())
    snippet = tasks[0]["ansible.builtin.command"]["argv"][2]
    environment = os.environ.copy()
    environment.pop("SSH_CONNECTION", None)
    if connection is not None:
        environment["SSH_CONNECTION"] = connection
    return subprocess.run(
        [sys.executable, "-c", snippet, "bao-1", transport],
        input=json.dumps(policy), env=environment, text=True, capture_output=True, timeout=5,
    )


def test_parser_binds_stable_identity_without_ephemeral_port(repo_root):
    first = run_parser(repo_root, policy=["198.51.100.65/32"])
    second = run_parser(repo_root, CONNECTION.replace("45678", "65535"))
    assert first.returncode == second.returncode == 0
    assert json.loads(first.stdout) == json.loads(second.stdout) == {
        "inventory_host": "bao-1", "source_address": "198.51.100.65",
        "destination_address": "192.0.2.1", "destination_port": 22,
    }


@pytest.mark.parametrize("overrides", [
    {"connection": None}, {"connection": ""},
    {"connection": "198.51.100.65 45678 192.0.2.1"},
    {"connection": CONNECTION + " extra"},
    {"connection": CONNECTION.replace("198.51.100.65", "999.51.100.65")},
    {"connection": CONNECTION.replace("192.0.2.1", "::1")},
    {"connection": CONNECTION.replace("45678", "0")},
    {"connection": CONNECTION.replace("45678", "65536")},
    {"connection": CONNECTION.replace("45678", "+123")},
    {"connection": CONNECTION.replace(" 22", " -1")},
    {"connection": CONNECTION.replace(" 22", " 65536")},
    {"connection": CONNECTION.replace(" 22", " ２２")},
    {"policy": []}, {"policy": None}, {"policy": "198.51.100.0/24"},
    {"policy": ["198.51.100.64/32"]}, {"policy": ["198.51.100.65"]},
    {"policy": POLICY + ["invalid"]}, {"policy": POLICY + [True]},
    {"policy": ["198.51.100.65/24"]}, {"policy": ["198.51.100.0/33"]},
    {"policy": ["::/0"]}, {"transport": "local"}, {"transport": "community.docker.docker"},
])
def test_parser_fails_closed_without_raw_evidence(repo_root, overrides):
    result = run_parser(repo_root, **overrides)
    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr == "OpenBao HAProxy caller source could not be qualified.\n"


def test_real_command_rejects_local_transport_with_inherited_ssh_environment(
    repo_root, tmp_path, command_runner,
):
    playbook = tmp_path / "local.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "become": True,
        "vars": {"ansible_facts": {"python": {"executable": sys.executable}},
                 "openbao_haproxy_client_allowed_sources": POLICY},
        "environment": {"SSH_CONNECTION": CONNECTION},
        "tasks": [{"ansible.builtin.include_tasks": str(repo_root / SOURCE_TASKS)}],
    }]))
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)])
    result.assert_failure()
    assert "caller source could not be qualified" in result.stdout
    assert CONNECTION not in result.stdout
    assert "Record stable OpenBao HAProxy caller source" not in result.stdout


@pytest.mark.parametrize("declaration", ["inventory", "play"])
def test_probe_disables_inherited_become_overrides(
    declaration, repo_root, tmp_path, command_runner,
):
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    plugins = tmp_path / "action_plugins"
    plugins.mkdir()
    stage_caller_source(repo_root, tasks_dir, plugins)
    command_runner.environment["ANSIBLE_ACTION_PLUGINS"] = str(plugins)
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {
        "vars": {"ansible_become": True} if declaration == "inventory" else {},
        "hosts": {"bao-1": {"ansible_connection": "local"}},
    }}))
    variables = {"fixture_root": str(tmp_path), "openbao_haproxy_client_allowed_sources": POLICY}
    if declaration == "play":
        variables["ansible_become"] = True
    playbook = tmp_path / "become.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "become": True, "vars": variables,
        "tasks": [
            {"ansible.builtin.include_tasks": str(tasks_dir / "openbao-haproxy-caller-source.yml")},
            {"ansible.builtin.assert": {"that": [
                "ansible_become is sameas true",
                "openbao_haproxy_caller_source_observation.source_address == '198.51.100.65'",
            ]}},
        ],
    }]))
    # The existing action double checks the effective Ansible play context as
    # well as the task keyword before executing the shipped target parser.
    result = command_runner.run(["ansible-playbook", "-i", str(inventory), str(playbook)])
    result.assert_success()
    probes = (tmp_path / "bao-1-caller-probes.jsonl").read_text().splitlines()
    assert len(probes) == 1
    assert json.loads(probes[0])["rc"] == 0


@pytest.mark.parametrize("case", [
    "excluded", "missing", "missing-policy", "invalid", "local", "plan", "stable", "postguard-drift",
])
def test_caller_source_activation_control_flow(case, repo_root, isolated_test_dir):
    from test_openbao_bootstrap import HAPROXY_PLAYBOOK, _haproxy_pattern, _run_tty_playbook

    root = isolated_test_dir
    hosts = [f"bao-bootstrap-{i}" for i in range(1, 4)]
    for host in hosts:
        (root / f"{host}-bootstrap.json").write_text(json.dumps({
            "cluster_id": "test-cluster", "cluster_signature": "a" * 64,
        }))
    fake_bin = root / "bin"
    fake_bin.mkdir()
    for name, output in (("systemctl", "enabled"), ("curl", "200")):
        binary = fake_bin / name
        binary.write_text(f"#!/bin/sh\nprintf '{output}'\n")
        binary.chmod(0o755)
    variables = {}
    if case == "excluded":
        variables["openbao_haproxy_client_allowed_sources"] = ["198.51.100.64/32"]
    elif case == "missing":
        variables["test_caller_connections"] = [None]
    elif case == "missing-policy":
        # Role defaults need not be public: exercise the shipped default([]).
        variables["openbao_haproxy_client_allowed_sources"] = "{{ undef('No public role defaults') }}"
    elif case == "invalid":
        variables["openbao_haproxy_client_allowed_sources"] = POLICY + ["invalid"]
    elif case == "local":
        variables["test_caller_transport"] = "local"
    elif case == "plan":
        variables.update(openbao_activation_mode="plan", openbao_activation_plan_path=str(root / "plan.json"))
    elif case == "stable":
        variables["test_caller_connections"] = [CONNECTION.replace("45678", str(port))
                                                 for port in (12345, 23456, 34567)]
    elif case == "postguard-drift":
        variables["test_caller_connections"] = [CONNECTION, CONNECTION.replace(".65", ".66")]

    code, output = _run_tty_playbook(repo_root, HAPROXY_PLAYBOOK, root, _haproxy_pattern(),
                                   variables=variables, path_prefix=fake_bin)
    assert "198.51.100." not in output
    assert "192.0.2.1" not in output
    if case in ("plan", "stable"):
        assert code == 0, output
    else:
        assert code != 0, output
        assert "Enable verified staged local OpenBao HAProxy" not in output
    if case in ("excluded", "missing", "missing-policy", "invalid", "local"):
        assert "caller source could not be qualified" in output
        assert "Prepare the exact OpenBao edge activation plan" not in output
        assert "Type exactly" not in output
    if case == "postguard-drift":
        assert "Verify the same OpenBao HAProxy activation plan before mutation" in output
        assert len(list(root.glob("*-edge-lock"))) == 3
        assert len(list(root.glob("*-consumed-*"))) == 3
    else:
        assert not list(root.glob("*-edge-lock"))
        assert len(list(root.glob("*-consumed-*"))) == (3 if case == "stable" else 0)
    expected_probes = 3 if case == "stable" else 2 if case == "postguard-drift" else 1
    for host in hosts:
        probes = [json.loads(line) for line in (root / f"{host}-caller-probes.jsonl").read_text().splitlines()]
        assert len(probes) == expected_probes
        if case == "stable":
            assert len({probe["stdout"] for probe in probes}) == 1
    if case == "plan":
        evidence = json.loads((root / "plan.json").read_text())["evidence"]
        assert evidence["caller_sources"] == [{
            "inventory_host": host, "source_address": "198.51.100.65",
            "destination_address": "192.0.2.1", "destination_port": 22,
        } for host in hosts]


def test_service_boundary_source_drift_rolls_back_before_start(
    repo_root, tmp_path, command_runner, rollback_target,
):
    from test_openbao_haproxy_rollback import HOSTS, run_activation_and_check_report

    rollback_target["test_caller_connections"] = [CONNECTION.replace(".65", ".66")]
    for host in HOSTS:
        (tmp_path / f"{host}.json").write_text(json.dumps({"active": "inactive", "enabled": "disabled"}))
    result = run_activation_and_check_report(
        "caller", HOSTS, [], rollback_target, repo_root, tmp_path, command_runner,
    )
    assert "caller source changed after approval" in result.stdout
    assert "198.51.100." not in result.stdout
    for host in HOSTS:
        events = [json.loads(line) for line in (tmp_path / f"{host}.events").read_text().splitlines()]
        assert not any(event["args"].get("state") == "started" for event in events)
