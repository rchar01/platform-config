"""Focused public-play routing and fresh-stage admission; no lifecycle crypto."""

from __future__ import annotations

import json
import shutil

import pytest
import yaml

from test_alloy_initial_role import STATE, role_case, tree
from test_grafana_alloy_tls import _assert_guard_stat, _events, _evidence_environment


ENTRIES = {
    "pki-client-request.yml": ("pki_host_local_certificate", "client_request_publish"),
    "pki-client-stage.yml": ("pki_host_local_certificate", "client_response_stage"),
    "grafana-alloy-boundary.yml": ("grafana_alloy", "initial_boundary"),
    "grafana-alloy-stage.yml": ("grafana_alloy", "initial_stage"),
    "grafana-alloy-initial-prepare.yml": ("grafana_alloy", "initial_prepare"),
    "grafana-alloy-initial-start.yml": ("grafana_alloy", "initial_activate"),
    "grafana-alloy-initial-status.yml": ("grafana_alloy", "initial_status"),
    "grafana-alloy-initial-recover.yml": ("grafana_alloy", "initial_recover"),
}
CHECK_ALLOWED = {
    "grafana-alloy-boundary.yml", "grafana-alloy-stage.yml", "grafana-alloy-initial-status.yml",
}
STAGE_ARGV = [
    "/usr/bin/systemctl", "show", "alloy.service", "--no-pager",
    "--property=LoadState,ActiveState,UnitFileState,FragmentPath,SourcePath",
]
ABSENT = ["LoadState=not-found", "ActiveState=inactive", "UnitFileState=", "FragmentPath=", "SourcePath="]
STOPPED = ["LoadState=loaded", "ActiveState=inactive", "UnitFileState=disabled",
           "FragmentPath=/usr/lib/systemd/system/alloy.service", "SourcePath="]


NO_CONNECTION = '''
from ansible.plugins.connection.local import Connection as LocalConnection

class Connection(LocalConnection):
    transport = 'fixture_no_connection'

    def exec_command(self, *args, **kwargs):
        raise AssertionError('Forbidden target command')

    def put_file(self, *args, **kwargs):
        raise AssertionError('Forbidden target file write')

    def fetch_file(self, *args, **kwargs):
        raise AssertionError('Forbidden target file read')
'''

ENTRY_SPY = '''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        event = dict(self._task.args, host=task_vars['inventory_hostname'],
                     check=self._task.check_mode, become=self._play_context.become)
        with Path(task_vars['fixture_events']).open('a') as stream:
            stream.write(json.dumps(event) + '\\n')
        return dict(changed=False, failed=self._task.args.get('forbidden', False))
'''

STAGE_MAIN_SPY = '''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        event = dict(entry='ordinary-main', check=self._task.check_mode,
                     enabled=task_vars['grafana_alloy_enabled'],
                     service_enabled=task_vars['grafana_alloy_service_enabled'],
                     state=task_vars['grafana_alloy_service_state'])
        with Path(task_vars['fixture_events']).open('a') as stream:
            stream.write(json.dumps(event) + '\\n')
        return dict(changed=False, failed=task_vars.get('fixture_forbid_main', False))
'''


def no_connection_environment(root):
    plugins = root / "connection_plugins"
    plugins.mkdir()
    (plugins / "fixture_no_connection.py").write_text(NO_CONNECTION)
    return {"ANSIBLE_CONNECTION_PLUGINS": str(plugins)}


@pytest.fixture
def entry_case(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    roles = root / "roles"
    plugins = root / "action_plugins"
    plugins.mkdir()
    (plugins / "fixture_entry.py").write_text(ENTRY_SPY)
    # Keep shipped dependency declarations, including PKI's repository policy.
    # Alloy task-only routes still reject any dependency event below.
    for name in ("grafana_alloy", "pki_host_local_certificate", "rocky_repository_policy"):
        role = roles / name
        (role / "tasks").mkdir(parents=True)
        metadata = repo_root / "roles" / name / "meta"
        if metadata.exists():
            shutil.copytree(metadata, role / "meta")
        selected = {entry for owner, entry in ENTRIES.values() if owner == name}
        for entry in selected | {"main"}:
            (role / "tasks" / f"{entry}.yml").write_text(yaml.safe_dump([{
                "name": f"Record {name}/{entry}",
                "fixture_entry": {"role": name, "entry": entry,
                                  "forbidden": entry == "main" and name != "rocky_repository_policy"},
            }]))
    environment = {
        **_evidence_environment(repo_root, root), **no_connection_environment(root),
        "ANSIBLE_ROLES_PATH": str(roles), "ANSIBLE_ACTION_PLUGINS": str(plugins),
    }
    events_file = root / "entries.jsonl"
    evidence_file = root / "events.jsonl"

    def run(playbook, *, check=False, limit="collector-01", hosts=("collector-01", "collector-02")):
        for path in (events_file, evidence_file):
            path.unlink(missing_ok=True)
        inventory = root / "inventory.yml"
        inventory.write_text(yaml.safe_dump({"all": {"children": {
            "collectors": {"hosts": {host: {} for host in hosts}},
        }}}))
        _, entry = ENTRIES[playbook]
        result = command_runner.run([
            "ansible-playbook", "-i", inventory, repo_root / "playbooks" / playbook,
            *(["--limit", limit] if limit is not None else []),
            *(["--check"] if check else []),
            "--extra-vars", json.dumps({
                "ansible_connection": "fixture_no_connection", "fixture_events": str(events_file),
                "grafana_alloy_initial_action": "recover" if entry == "initial_activate" else "activate",
            }),
        ], environment=environment, timeout=45)
        events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
        evidence = _events(root) if evidence_file.exists() else []
        return result, events, evidence

    return run


@pytest.mark.parametrize("playbook", ENTRIES)
def test_public_play_selects_only_fixed_entry(repo_root, entry_case, playbook):
    plays = yaml.safe_load((repo_root / "playbooks" / playbook).read_text())
    assert len(plays) == 1
    play = plays[0]
    assert play["hosts"] == "all" and play["gather_facts"] is False
    become = playbook != "grafana-alloy-boundary.yml"
    assert play.get("become", False) is become
    # Execute every play below; also retain both scope clauses on every route
    # without multiplying each CLI spelling by every identical admission guard.
    assertions = [clause for task in play.get("pre_tasks", []) + play.get("tasks", [])
                  for clause in task.get("ansible.builtin.assert", {}).get("that", [])]
    assert "ansible_play_hosts_all == [inventory_hostname]" in assertions
    assert any(clause.replace(" ", "") == "ansible_limit|default('')==inventory_hostname"
               for clause in assertions)
    result, events, evidence = entry_case(playbook)
    result.assert_success()
    role, entry = ENTRIES[playbook]
    expected = [{"role": role, "entry": entry, "forbidden": False,
                 "host": "collector-01", "check": False, "become": become}]
    if role == "pki_host_local_certificate":
        metadata = yaml.safe_load((repo_root / "roles" / role / "meta/main.yml").read_text())
        assert metadata["dependencies"] == [{"role": "rocky_repository_policy"}]
        policy = {**expected[0], "role": "rocky_repository_policy", "entry": "main"}
        # Let real include_role semantics decide whether the declared dependency
        # runs; only one exact policy event before the client entry is permitted.
        assert events in (expected, [policy, *expected])
    else:
        assert events == expected
    assert evidence and not any(event["changed"] for event in evidence)


@pytest.mark.parametrize("playbook", ENTRIES)
def test_public_play_check_mode_contract(entry_case, playbook):
    result, events, evidence = entry_case(playbook, check=True)
    if playbook in CHECK_ALLOWED:
        result.assert_success()
        role, entry = ENTRIES[playbook]
        assert events == [{"role": role, "entry": entry, "forbidden": False,
                           "host": "collector-01", "check": True,
                           "become": playbook != "grafana-alloy-boundary.yml"}]
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
        assert events == []
        failed = [event for event in evidence if event["status"] == "failed"]
        assert len(failed) == 1 and failed[0]["action"] == "ansible.builtin.assert"
        assert any(item.get("assertion") == "not ansible_check_mode"
                   and item.get("evaluated_to") is False for item in failed[0]["failed_assertions"])


@pytest.mark.parametrize("playbook,limit,hosts", [
    pytest.param("grafana-alloy-boundary.yml", None, ("collector-01", "collector-02"), id="no-limit"),
    pytest.param("grafana-alloy-initial-status.yml", None, ("collector-01",), id="singleton-no-limit"),
    pytest.param("grafana-alloy-stage.yml", "collector-*", ("collector-01",), id="singleton-wildcard"),
    pytest.param("pki-client-request.yml", "collectors", ("collector-01",), id="singleton-group"),
    pytest.param("pki-client-stage.yml", "collector-01,collector-02", ("collector-01", "collector-02"), id="list"),
    pytest.param("grafana-alloy-initial-prepare.yml", "all", ("collector-01",), id="singleton-all"),
    pytest.param("grafana-alloy-initial-start.yml", "collector-01,", ("collector-01",), id="singleton-list"),
    pytest.param("grafana-alloy-initial-recover.yml", "collector-01:collector-02", ("collector-01", "collector-02"), id="union"),
])
def test_public_play_rejects_nonliteral_scope_before_role(entry_case, playbook, limit, hosts):
    result, events, evidence = entry_case(playbook, limit=limit, hosts=hosts)
    result.assert_failure()
    assert events == [] and evidence
    assert all(event["action"] == "ansible.builtin.assert" for event in evidence), evidence
    failed = [event for event in evidence if event["status"] == "failed"]
    assert failed and all(event["failed_assertions"] for event in failed)
    assert all(item.get("evaluated_to") is False
               and any(name in item.get("assertion", "") for name in ("ansible_play_hosts_all", "ansible_limit"))
               for event in failed for item in event["failed_assertions"])


def test_public_boundary_real_chain_is_controller_only_in_check(role_case):
    c = role_case
    before = tree(c.target)
    inputs = {**c.inputs, "ansible_connection": "fixture_no_connection",
              "grafana_alloy_initial_action": "activate"}
    # Pre-CSR boundary calculation must not require staged client paths.
    for prefix in ("grafana_alloy_loki_", "grafana_alloy_prometheus_remote_write_"):
        inputs.update({prefix + "client_cert_file": "", prefix + "client_key_file": ""})
    result = c.namespace_root_runner.run([
        "ansible-playbook", "-i", "localhost,", c.repo_root / "playbooks/grafana-alloy-boundary.yml",
        "--limit", "localhost", "--check", "--extra-vars", json.dumps(inputs),
    ], environment={**c.environment, **no_connection_environment(c.root)}, timeout=60)
    result.assert_success()
    assert "changed=0" in result.stdout and tree(c.target) == before
    assert not c.events_file.exists()
    assert all(event["action"] in {"ansible.builtin.assert", "ansible.builtin.include_role",
                                  "ansible.builtin.set_fact", "ansible.builtin.debug"}
               for event in c.observations())
    assert any(event["action"] == "ansible.builtin.debug" for event in c.observations())


@pytest.fixture
def stage_case(role_case):
    c = role_case
    (c.plugins / "fixture_stage_main.py").write_text(STAGE_MAIN_SPY)
    # Only ordinary convergence is replaced; initial_stage, initial_guard and
    # the actual initial input filter are retained by role_case.
    (c.role / "tasks/main.yml").write_text(yaml.safe_dump([{
        "name": "Record admission to stopped ordinary convergence", "fixture_stage_main": {},
    }]))
    c.inputs["fixture_stage_lines"] = STOPPED
    return c


@pytest.mark.parametrize("lines,check", [
    pytest.param(ABSENT, False, id="absent"), pytest.param(STOPPED, False, id="stopped-disabled"),
    pytest.param(ABSENT, True, id="absent-check"), pytest.param(STOPPED, True, id="stopped-disabled-check"),
])
def test_stage_admits_only_stopped_convergence(stage_case, lines, check):
    c = stage_case
    before = tree(c.target)
    result, events = c.run("initial_stage.yml", check=check, overrides={"fixture_stage_lines": lines},
                           extra_vars="grafana_alloy_initial_action=activate")
    result.assert_success()
    assert events == [{"argv": STAGE_ARGV, "check": False},
                      {"entry": "ordinary-main", "check": check, "enabled": True,
                       "service_enabled": False, "state": "stopped"}]
    observed = c.observations()
    guard = next(event for event in observed if event["action"] == "ansible.builtin.stat")
    _assert_guard_stat(guard, path=str(c.target / STATE.lstrip("/")))
    assert observed.index(guard) < next(i for i, event in enumerate(observed) if event["action"] == "fixture_command")
    assert "changed=0" in result.stdout and tree(c.target) == before


def reject_stage_cases(c, cases):
    case_file = c.root / "reject-stage-case.yml"
    keys = set().union(*(case.keys() for case in cases))
    case_file.write_text(yaml.safe_dump([
        {"ansible.builtin.set_fact": {"fixture_rejected": False}},
        {"block": [{"ansible.builtin.include_role": {"name": str(c.role), "tasks_from": "initial_stage.yml"},
                    "vars": {key: "{{ fixture_case.get('" + key + "', fixture_base['" + key + "']) }}" for key in keys}}],
         "rescue": [{"ansible.builtin.set_fact": {"fixture_rejected": True}}]},
        {"ansible.builtin.assert": {"that": ["fixture_rejected"]}},
    ], sort_keys=False))
    before = tree(c.target)
    result, events = c.run("unused", check=True, overrides={"fixture_base": c.inputs, "fixture_forbid_main": True}, tasks=[{
        "ansible.builtin.include_tasks": str(case_file), "loop": cases,
        "loop_control": {"loop_var": "fixture_case", "label": "rejected-fresh-stage"},
    }])
    result.assert_success()
    assert tree(c.target) == before
    assert len([event for event in c.observations() if event["status"] == "failed"]) == len(cases)
    assert not any(event.get("entry") == "ordinary-main" or "policy" in event for event in events), events
    return events


def test_stage_rejects_observed_nonpristine_units_before_main(stage_case):
    # Keep all other properties valid so each case rejects its actual fault,
    # including foreign owners that the former three-property guard admitted.
    replacements = [
        ("ActiveState=inactive", "ActiveState=active"),
        ("UnitFileState=disabled", "UnitFileState=enabled"),
        ("UnitFileState=disabled", "UnitFileState=masked"),
        ("ActiveState=inactive", "ActiveState=failed"),
        ("LoadState=loaded", "LoadState=error"),
        (STOPPED[3], "FragmentPath=/etc/systemd/system/alloy.service"),
        (STOPPED[3], "FragmentPath=/run/systemd/generator/alloy.service"),
        ("SourcePath=", "SourcePath=/etc/containers/systemd/alloy.container"),
    ]
    lines = [[replacement if line == original else line for line in STOPPED]
             for original, replacement in replacements] + [STOPPED + ["Unexpected=value"]]
    events = reject_stage_cases(stage_case, [{"fixture_stage_lines": value} for value in lines])
    assert events == [{"argv": STAGE_ARGV, "check": False}] * len(lines)
    assert all(event["action"] == "ansible.builtin.assert"
               for event in stage_case.observations() if event["status"] == "failed")


def test_stage_rejects_invalid_intent_and_direct_mtls_inputs_before_unit_io(stage_case):
    cases = [
        {"grafana_alloy_enabled": False}, {"grafana_alloy_enabled": "true"},
        {"grafana_alloy_service_enabled": True}, {"grafana_alloy_service_enabled": "false"},
        {"grafana_alloy_service_state": "started"},
        {"grafana_alloy_initial_writers": {}},
        {"grafana_alloy_loki_client_cert_file": ""},
        {"grafana_alloy_loki_client_key_file": "/etc/alloy/pki/loki/current/tls.key"},
        {"grafana_alloy_storage_dir": "/other"},
    ]
    assert reject_stage_cases(stage_case, cases) == []
    assert all(event["action"] in {"ansible.builtin.assert", "ansible.builtin.set_fact"}
               for event in stage_case.observations() if event["status"] == "failed")


@pytest.mark.parametrize("marker", ["directory", "dangling-symlink"])
def test_stage_retains_process_owner_before_other_work(stage_case, marker):
    c = stage_case
    owner = c.target / STATE.lstrip("/")
    owner.parent.mkdir(parents=True)
    if marker == "directory":
        owner.mkdir(mode=0o700)
        (owner / "unknown.json").write_text("retained")
    else:
        owner.symlink_to(c.target / "missing-owner")
    before = tree(c.target)
    result, events = c.run("initial_stage.yml", check=True)
    result.assert_failure()
    assert events == [] and tree(c.target) == before
    observed = c.observations()
    guards = [event for event in observed if event["action"] == "ansible.builtin.stat"]
    assert len(guards) == 1
    _assert_guard_stat(guards[0], path=str(owner))
    assert all(event["action"] in {"ansible.builtin.include_role", "ansible.builtin.include_tasks",
                                  "ansible.builtin.assert", "ansible.builtin.stat"}
               for event in observed), observed
    assert "ordinary convergence and handlers cannot bypass takeover" in result.stdout


@pytest.mark.parametrize("limit", [None, "all"])
def test_stage_direct_entry_requires_literal_limit_before_io(stage_case, limit):
    c = stage_case
    before = tree(c.target)
    result, events = c.run("initial_stage.yml", limit=limit, check=True)
    result.assert_failure()
    assert events == [] and tree(c.target) == before
    assert all(event["action"] in {"ansible.builtin.include_role", "ansible.builtin.assert"}
               for event in c.observations())
