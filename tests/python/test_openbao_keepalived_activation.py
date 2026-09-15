from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

import test_openbao_bootstrap as bootstrap
from ansible_test_helpers import assert_failed_with, run_playbook
from test_openbao_edge_guard import shadow_edge_tasks


PLAYBOOK = "playbooks/maintenance/openbao-keepalived-activate.yml"
FIXTURE = "tests/fixtures/openbao-keepalived-activation"
HOSTS = ["bao-1", "bao-2", "bao-3"]
APPROVAL = r"activate-openbao-keepalived\|[a-f0-9]{32}\|[a-f0-9]{64}"


@pytest.fixture
def activation(repo_root, isolated_test_dir, monkeypatch):
    """Keep orchestration intact; route builtin actions to offline shadows."""
    fixture = repo_root / FIXTURE
    root = isolated_test_dir
    plugins = root / "action_plugins"
    plugins.mkdir()
    for name in ("setup", "service_facts", "systemd_service", "activation_probe", "election_pause", "firewall_probe"):
        shutil.copyfile(fixture / "action.py", plugins / f"{name}.py")
    playbook = shadow_edge_tasks(repo_root, root, 'keepalived')
    tasks = root / "playbooks/tasks"
    tasks.mkdir()
    shutil.copyfile(fixture / "openbao-vip-status.yml", tasks / "openbao-vip-status.yml")
    inventory = root / "inventory.yml"
    shutil.copyfile(fixture / "inventory.yml", inventory)
    environment = os.environ.copy()
    environment.update({
        "ANSIBLE_FORCE_COLOR": "0",
        "ANSIBLE_ROLES_PATH": str(fixture / "roles"),
        "ANSIBLE_ACTION_PLUGINS": str(plugins),
    })
    monkeypatch.setattr(bootstrap, "FIXTURE", str(inventory))
    monkeypatch.setattr(bootstrap, "_environment", lambda *args: environment)
    return root, playbook, inventory, environment


def _events(root):
    path = root / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _run(repo_root, activation, variables=None, approval=None):
    root, playbook, _, _ = activation
    return bootstrap._run_tty_playbook(
        repo_root, str(playbook), root, APPROVAL,
        variables=variables, approval=approval, timeout=60,
    )


def test_keepalived_activation_starts_backups_before_preferred_and_qualifies_all(
    repo_root, activation,
):
    code, output = _run(repo_root, activation)
    assert code == 0, output
    events = _events(activation[0])
    starts = [event["host"] for event in events if event["phase"] == "start"]
    assert set(starts[:2]) == {"bao-1", "bao-3"}
    assert starts[2:] == ["bao-2"]
    assert any(event["phase"] == "election" for event in events)
    assert sorted(event["host"] for event in events if event["phase"] == "qualification") == HOSTS
    assert not any(event["phase"] == "rollback" for event in events)
    for host in HOSTS:
        phases = [event["phase"] for event in events if event["host"] == host]
        assert phases.index("firewall") < phases.index("start")
    assert output.count("Record mocked strict runtime observations") == 3
    guards = [json.loads(line) for line in (activation[0] / 'guard-events.jsonl').read_text().splitlines()]
    assert [event['host'] for event in guards if event['phase'] == 'acquire'] == HOSTS
    assert sorted(event['host'] for event in guards if event['phase'] == 'release') == HOSTS
    assert not list(activation[0].glob('*-edge-lock'))
    assert len(list(activation[0].glob('*-consumed-*'))) == 3


@pytest.mark.parametrize("host", ["bao-1", "bao-2"])
@pytest.mark.parametrize("failure", ["failure", "unreachable"])
def test_keepalived_firewall_boundary_failure_rolls_back_all(
    repo_root, activation, host, failure,
):
    code, output = _run(repo_root, activation, {f"test_firewall_{failure}": [host]})
    assert code != 0, output
    assert f"Mocked firewall {failure} on {host}" in output, output
    if failure == "unreachable":
        assert "assertion: test_firewall_result is not unreachable" in output, output
    events = _events(activation[0])
    assert not any(event["phase"] == "start" and event["host"] == host for event in events), output
    if host != "bao-2":
        assert not any(event["phase"] == "start" and event["host"] == "bao-2" for event in events), output
    assert sorted(event["host"] for event in events if event["phase"] == "rollback") == HOSTS, output


@pytest.mark.parametrize("limit", [None, "bao-1", "openbao,other"])
def test_keepalived_activation_rejects_inexact_selection(activation, command_runner, limit):
    root, playbook, inventory, environment = activation
    result = run_playbook(
        command_runner, playbook, inventory=inventory, limit=limit,
        environment=environment, extra_vars=({"openbao_test_root": str(root)},),
    )
    assert_failed_with(result, "exactly all three hosts")
    assert not _events(root)


@pytest.mark.parametrize("count", [2, 4])
def test_keepalived_activation_requires_exactly_three_members(repo_root, activation, count):
    inventory = activation[2]
    data = yaml.safe_load(inventory.read_text())
    hosts = data["all"]["children"]["openbao"]["hosts"]
    if count == 2:
        del hosts["bao-3"]
    else:
        hosts["bao-4"] = {"test_priority": 120}
    inventory.write_text(yaml.safe_dump(data))
    code, output = _run(repo_root, activation)
    assert code != 0, output
    assert "Type exactly" not in output
    assert not _events(activation[0])


@pytest.mark.parametrize("variable,value", [
    ("openbao_keepalived_activation_ready", False),
    ("openbao_keepalived_activation_ready", "true"),
    ("openbao_keepalived_activation_ready", 1),
    ("openbao_haproxy_service_enabled", "true"),
    ("openbao_haproxy_service_enabled", False),
    ("openbao_haproxy_service_state", "stopped"),
    ("keepalived_vip_service_enabled", "false"),
    ("keepalived_vip_service_enabled", True),
    ("keepalived_vip_service_state", "started"),
    ("test_haproxy_state", "stopped"),
    ("test_haproxy_status", "disabled"),
    ("test_keepalived_state", "running"),
    ("test_keepalived_status", "enabled"),
    ("openbao_service_dns", "different.example.invalid"),
    ("openbao_client_port", 8209),
])
def test_keepalived_activation_requires_every_host_lifecycle(
    repo_root, activation, variable, value,
):
    inventory = activation[2]
    data = yaml.safe_load(inventory.read_text())
    data["all"]["children"]["openbao"]["hosts"]["bao-3"][variable] = value
    inventory.write_text(yaml.safe_dump(data))
    code, output = _run(repo_root, activation)
    assert code != 0, output
    assert "Type exactly" not in output
    assert not _events(activation[0])


def test_keepalived_activation_defaults_readiness_closed(repo_root, activation):
    inventory = activation[2]
    data = yaml.safe_load(inventory.read_text())
    del data["all"]["vars"]["openbao_keepalived_activation_ready"]
    inventory.write_text(yaml.safe_dump(data))
    code, output = _run(repo_root, activation)
    assert code != 0, output
    assert "explicit boolean readiness" in output
    assert not _events(activation[0])


def test_keepalived_activation_rejects_check_mode(activation, command_runner):
    root, playbook, inventory, environment = activation
    result = command_runner.run([
        "ansible-playbook", "-i", inventory, playbook, "--limit", "openbao", "--check",
        "-e", json.dumps({"openbao_test_root": str(root)}),
    ], environment=environment)
    assert_failed_with(result, "normal apply")
    assert not _events(root)


@pytest.mark.parametrize("variables", [
    {"test_invalid_marker_hosts": ["bao-3"]},
    {"test_cluster_mismatch_pass": 1},
    {"test_cluster_mismatch_pass": 2},
    {"test_status_failure_pass": 1},
    {"test_status_failure_pass": 2},
    {"test_drift": "cluster"},
    {"test_drift": "haproxy"},
    {"test_drift": "keepalived"},
    {"test_drift": "keepalived-selinux"},
    {"test_drift": "raft"},
    {"test_service_drift": True},
])
def test_keepalived_activation_rejects_unqualified_or_changed_evidence(
    repo_root, activation, variables,
):
    code, output = _run(repo_root, activation, variables)
    assert code != 0, output
    assert not _events(activation[0])
    if "test_drift" in variables:
        assert "Verify the same OpenBao Keepalived activation plan before mutation" in output
        assert len(list(activation[0].glob('*-edge-lock'))) == 3
    if variables.get("test_cluster_mismatch_pass") == 1 or variables.get("test_status_failure_pass") == 1:
        assert "Type exactly" not in output


def test_keepalived_activation_requires_exact_interactive_approval(repo_root, activation):
    code, output = _run(repo_root, activation, approval="yes")
    assert code != 0, output
    assert not _events(activation[0])


def test_keepalived_activation_rejects_noninteractive_approval(activation, command_runner):
    root, playbook, inventory, environment = activation
    result = run_playbook(
        command_runner, playbook, inventory=inventory, limit="openbao",
        environment=environment, extra_vars=({"openbao_test_root": str(root)},),
    )
    result.assert_failure()
    assert not _events(root)


@pytest.mark.parametrize("variables", [
    {"test_start_failure": ["bao-1"]},
    {"test_start_failure": ["bao-2"]},
    {"test_start_unreachable": ["bao-3"]},
    {"test_start_unreachable": ["bao-2"]},
    {"test_start_unreachable": HOSTS},
    {"test_qualification_failure": ["bao-3"]},
    {"test_qualification_unreachable": ["bao-1"]},
    {"test_qualification_unreachable": HOSTS},
    {"test_global_endpoint_failure": True},
    {"test_owner_count": 0},
    {"test_owner_count": 2},
    {"test_stable_owner": False},
    {"test_strict_tls": False},
    {"test_status_failure_pass": 3},
    {"test_cluster_mismatch_pass": 3},
])
def test_keepalived_activation_rolls_back_all_hosts_on_any_failure(
    repo_root, activation, variables,
):
    code, output = _run(repo_root, activation, variables)
    assert code != 0, output
    assert "Unverified rollback hosts: none" in output, output
    events = _events(activation[0])
    assert sorted(event["host"] for event in events if event["phase"] == "rollback") == HOSTS
    assert not list(activation[0].glob('*-edge-lock'))
    backup_failures = variables.get("test_start_failure", []) + variables.get("test_start_unreachable", [])
    if set(backup_failures) & {"bao-1", "bao-3"}:
        assert {"phase": "start", "host": "bao-2"} not in events


@pytest.mark.parametrize("kind,hosts", [
    ("failure", ["bao-2"]), ("unreachable", ["bao-3"]), ("unreachable", HOSTS),
])
def test_keepalived_activation_reports_every_unverified_rollback(
    repo_root, activation, kind, hosts,
):
    code, output = _run(repo_root, activation, {
        "test_owner_count": 0, f"test_rollback_{kind}": hosts,
    })
    assert code != 0, output
    assert f"Unverified rollback hosts: {', '.join(hosts)}" in output
    assert sorted(event["host"] for event in _events(activation[0]) if event["phase"] == "rollback") == HOSTS
    assert sorted(path.name.removesuffix('-edge-lock') for path in activation[0].glob('*-edge-lock')) == hosts


def test_keepalived_plan_allows_closed_readiness_without_locks_or_prompt(activation, command_runner):
    root, playbook, inventory, environment = activation
    plan = root / 'activation-plan.json'
    result = run_playbook(
        command_runner, playbook, inventory=inventory, limit='openbao', environment=environment,
        extra_vars=({'openbao_test_root': str(root), 'openbao_activation_mode': 'plan',
                     'openbao_activation_plan_path': str(plan), 'openbao_keepalived_activation_ready': False},),
    )
    result.assert_success()
    assert plan.exists()
    assert 'Type exactly' not in result.stdout
    assert not _events(root)
    assert not list(root.glob('*-edge-lock'))
    assert not list(root.glob('*-consumed-*'))


def test_keepalived_guard_conflict_aborts_before_start_and_retains_partial_guards(repo_root, activation):
    code, output = _run(repo_root, activation, {'test_guard_conflict': ['bao-2']})
    assert code != 0, output
    assert not _events(activation[0])
    assert (activation[0] / 'bao-1-edge-lock').exists()
    assert not (activation[0] / 'bao-2-edge-lock').exists()


def test_keepalived_ci_lane_uses_prepared_plan_without_terminal(activation, command_runner):
    root, playbook, inventory, environment = activation
    plan = root / 'activation-plan.json'
    variables = {'openbao_test_root': str(root), 'openbao_activation_plan_path': str(plan)}
    for mode in ('plan', 'ci'):
        result = run_playbook(
            command_runner, playbook, inventory=inventory, limit='openbao', environment=environment,
            extra_vars=({**variables, 'openbao_activation_mode': mode},),
        )
        result.assert_success()
        assert 'Type exactly' not in result.stdout
    plan_id = json.loads(plan.read_text())['plan_id']
    assert len(list(root.glob(f'*-consumed-{plan_id}'))) == 3
    assert not list(root.glob('*-edge-lock'))
    # Even a mocked valid plan/provenance cannot reuse a consumed target plan.
    replay = run_playbook(
        command_runner, playbook, inventory=inventory, limit='openbao', environment=environment,
        extra_vars=({**variables, 'openbao_activation_mode': 'ci'},),
    )
    replay.assert_failure()
    assert len([event for event in _events(root) if event['phase'] == 'start']) == 3


def test_keepalived_ci_lane_without_plan_fails_before_guard_or_prompt(activation, command_runner):
    root, playbook, inventory, environment = activation
    result = run_playbook(
        command_runner, playbook, inventory=inventory, limit='openbao', environment=environment,
        extra_vars=({'openbao_test_root': str(root), 'openbao_activation_mode': 'ci'},),
    )
    result.assert_failure()
    assert 'Type exactly' not in result.stdout
    assert not _events(root)
    assert not list(root.glob('*-edge-lock'))


def test_keepalived_activation_never_reconverges_approved_candidates(repo_root):
    plays = yaml.safe_load((repo_root / PLAYBOOK).read_text())

    def walk(tasks):
        for task in tasks:
            yield task
            for key in ("block", "rescue", "always"):
                yield from walk(task.get(key, []))

    task_lists = [play['tasks'] for play in plays]
    task_lists.append(yaml.safe_load((repo_root / 'playbooks/maintenance/tasks/openbao-keepalived-preflight.yml').read_text()))
    roles = [task["ansible.builtin.include_role"] for tasks in task_lists for task in walk(tasks)
             if "ansible.builtin.include_role" in task]
    assert all(role.get("tasks_from") in {"activation_preflight.yml", "activation_rollback.yml", "runtime_firewall_guard.yml"}
               for role in roles if role["name"] in {"keepalived_vip", "openbao_haproxy"})
