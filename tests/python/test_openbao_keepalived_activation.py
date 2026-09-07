from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

import test_openbao_bootstrap as bootstrap
from ansible_test_helpers import assert_failed_with, run_playbook


PLAYBOOK = "playbooks/maintenance/openbao-keepalived-activate.yml"
FIXTURE = "tests/fixtures/openbao-keepalived-activation"
HOSTS = ["bao-1", "bao-2", "bao-3"]
APPROVAL = (
    r"activate-openbao-keepalived\|bao-1,bao-2,bao-3\|"
    r"192\.0\.2\.200\|test-cluster\|[a-f0-9]{64}"
)


@pytest.fixture
def activation(repo_root, isolated_test_dir, monkeypatch):
    """Keep orchestration intact; route builtin actions to offline shadows."""
    fixture = repo_root / FIXTURE
    root = isolated_test_dir
    plugins = root / "action_plugins"
    plugins.mkdir()
    for name in ("setup", "service_facts", "systemd_service", "activation_probe", "election_pause"):
        shutil.copyfile(fixture / "action.py", plugins / f"{name}.py")
    playbook = root / "playbooks/maintenance/activate.yml"
    playbook.parent.mkdir(parents=True)
    source = (repo_root / PLAYBOOK).read_text()
    for name in ("setup", "service_facts", "systemd_service"):
        source = source.replace(f"ansible.builtin.{name}:", f"ansible.legacy.{name}:")
    source = source.replace("ansible.builtin.pause:\n                seconds:",
                            "ansible.legacy.election_pause:\n                seconds:")
    playbook.write_text(source)
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
    assert output.count("Record mocked strict runtime observations") == 3


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
        assert "evidence changed after approval" in output
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


def test_keepalived_activation_never_reconverges_approved_candidates(repo_root):
    plays = yaml.safe_load((repo_root / PLAYBOOK).read_text())

    def walk(tasks):
        for task in tasks:
            yield task
            for key in ("block", "rescue", "always"):
                yield from walk(task.get(key, []))

    roles = [task["ansible.builtin.include_role"] for play in plays for task in walk(play["tasks"])
             if "ansible.builtin.include_role" in task]
    assert all(role.get("tasks_from") in {"activation_preflight.yml", "activation_rollback.yml"}
               for role in roles if role["name"] in {"keepalived_vip", "openbao_haproxy"})
