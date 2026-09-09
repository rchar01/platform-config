from __future__ import annotations

import json

import pytest
import yaml


ROLE = "roles/openbao_haproxy"
PLAYBOOK = "playbooks/maintenance/openbao-haproxy-activate.yml"
HOSTS = [f"bao-{i}" for i in range(1, 4)]

# Only target I/O is doubled; Ansible executes the production control flow.
ACTION = '''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        root = Path(task_vars['fixture_root'])
        host = task_vars['inventory_hostname']
        if 'report' in args:
            (root / (args['report'] + '.json')).write_text(json.dumps(args['values']))
            return dict(changed=False)
        state_file = root / (host + '.json')
        state = json.loads(state_file.read_text())
        case = task_vars.get('fixture_case', 'reset-ok')
        argv = args.get('argv', [])
        event = dict(args=args, become=self._play_context.become)
        with (root / (host + '.events')).open('a') as stream:
            stream.write(json.dumps(event) + '\\n')
        if 'state' in args:
            assert self._play_context.become is True
            assert args['name'] == 'haproxy.service'
            if args['state'] == 'started':
                assert args['enabled'] is True
                state.update(active='active', enabled='enabled')
                if host in task_vars.get('fixture_start_failure_hosts', []):
                    state['active'] = 'failed'
                    state_file.write_text(json.dumps(state))
                    return dict(failed=True, msg='fixture startup failure')
            else:
                assert args == dict(name='haproxy.service', state='stopped', enabled=False)
                if case == 'stop-fail':
                    return dict(failed=True, msg='fixture stop failure')
                if case == 'stop-unreachable':
                    return dict(unreachable=True, msg='fixture stop unreachable')
                state['enabled'] = 'disabled'
                if state['active'] != 'failed':
                    state['active'] = 'inactive'
            state_file.write_text(json.dumps(state))
            return dict(changed=True)
        if argv == ['guard-release']:
            assert self._play_context.become is True
            (root / (host + '.guard')).unlink()
            return dict(changed=True, rc=0)
        if argv and argv[0] == 'curl':
            assert self._play_context.become is False
            return dict(rc=0, stdout='503' if host in task_vars.get('fixture_path_failure_hosts', []) else '200')
        assert argv[0] == 'systemctl' and argv[2:] == ['haproxy.service'], argv
        assert self._play_context.become is True
        if argv[1] == 'reset-failed':
            assert state['enabled'] == 'disabled', 'reset must follow stop/disable'
            if case == 'reset-fail' and host in task_vars.get('fixture_reset_failure_hosts', [host]):
                return dict(failed=True, rc=1, msg='fixture reset failure')
            if case == 'reset-unreachable':
                return dict(unreachable=True, msg='fixture reset unreachable')
            if case == 'reset-missing':
                return dict(changed=False)
            if case == 'reset-skipped':
                return dict(skipped=True, rc=0)
            if case != 'still-failed':
                state['active'] = 'inactive'
            if case == 'still-enabled':
                state['enabled'] = 'enabled'
            state_file.write_text(json.dumps(state))
            return dict(changed=True, rc=0, stdout='')
        if argv[1] == 'is-active':
            if case == 'active-unreachable':
                return dict(unreachable=True, stdout='inactive', rc=3)
            return dict(rc=3 if state['active'] != 'active' else 0, stdout=state['active'])
        assert argv[1] == 'is-enabled', argv
        if case == 'enabled-unreachable':
            return dict(unreachable=True, stdout='disabled', rc=1)
        return dict(rc=1 if state['enabled'] == 'disabled' else 0, stdout=state['enabled'])
'''


@pytest.fixture
def rollback_target(repo_root, tmp_path, command_runner):
    plugins = tmp_path / "action_plugins"
    plugins.mkdir()
    (plugins / "fixture_io.py").write_text(ACTION, encoding="utf-8")
    command_runner.environment["ANSIBLE_ACTION_PLUGINS"] = str(plugins)
    role = tmp_path / "roles/openbao_haproxy/tasks"
    role.mkdir(parents=True)
    rollback = (repo_root / ROLE / "tasks/activation_rollback.yml").read_text()
    (role / "activation_rollback.yml").write_text(
        rollback.replace("ansible.builtin.systemd_service:", "fixture_io:")
        .replace("ansible.builtin.command:", "fixture_io:"), encoding="utf-8",
    )
    (role / "activation_enable.yml").write_text(yaml.safe_dump([{
        "fixture_io": {"name": "haproxy.service", "state": "started", "enabled": True},
    }]), encoding="utf-8")
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"children": {"openbao": {"hosts": {
        host: {"ansible_connection": "local"} for host in HOSTS
    }}}}}), encoding="utf-8")
    for host in HOSTS:
        (tmp_path / f"{host}.json").write_text(json.dumps({"active": "failed", "enabled": "enabled"}))
        (tmp_path / f"{host}.guard").write_text("owned guard")
        (tmp_path / f"{host}.consumed").write_text("permanent consumption")
    return {
        "fixture_root": str(tmp_path),
        "openbao_haproxy_service_name": "haproxy.service",
        "openbao_cluster_members": [{"name": host, "address": f"192.0.2.{i}"}
                                    for i, host in enumerate(HOSTS, 1)],
        "openbao_service_dns": "bao.test.invalid", "openbao_client_port": 8200,
        "openbao_tls_ca_src": "/fixture/ca.crt",
    }


def run_rollback_plays(plays, tmp_path, command_runner):
    playbook = tmp_path / "test.yml"
    playbook.write_text(yaml.safe_dump(plays, sort_keys=False), encoding="utf-8")
    return command_runner.run([
        "ansible-playbook", "-i", str(tmp_path / "inventory.yml"), str(playbook),
    ], timeout=30)


@pytest.mark.parametrize("case", [
    "reset-ok", "reset-fail", "reset-unreachable", "reset-missing", "reset-skipped", "still-failed",
    "stop-fail", "stop-unreachable", "still-enabled", "active-unreachable", "enabled-unreachable",
])
def test_rollback_requires_verified_reset_and_strict_state(
    case, rollback_target, tmp_path, command_runner,
):
    rollback_target["fixture_case"] = case
    result = run_rollback_plays([{
        "hosts": HOSTS[0], "gather_facts": False, "become": True,
        "vars": rollback_target,
        "tasks": [
            {"ansible.builtin.set_fact": {"openbao_haproxy_activation_rollback_confirmed": True}},
            {"ansible.builtin.include_role": {"name": "openbao_haproxy",
                "tasks_from": "activation_rollback.yml", "apply": {"ignore_unreachable": True}}},
            {"ansible.builtin.assert": {"that": [
                "openbao_haproxy_activation_rollback_confirmed is " +
                ("true" if case == "reset-ok" else "false"),
            ]}},
        ],
    }], tmp_path, command_runner)
    result.assert_success()
    events = [json.loads(line) for line in (tmp_path / f"{HOSTS[0]}.events").read_text().splitlines()]
    assert events[0]["args"] == {"name": "haproxy.service", "enabled": False, "state": "stopped"}
    resets = [event for event in events if event["args"].get("argv", [])[:2] == ["systemctl", "reset-failed"]]
    assert len(resets) == (0 if case.startswith("stop-") else 1)
    if case.startswith("stop-") or case in {"reset-fail", "reset-unreachable", "reset-missing", "reset-skipped"}:
        assert not any(event["args"].get("argv", [])[:2] == ["systemctl", "is-active"] for event in events)
    if case == "reset-ok":
        assert events[1] == resets[0]
        assert json.loads((tmp_path / f"{HOSTS[0]}.json").read_text()) == {
            "active": "inactive", "enabled": "disabled",
        }


@pytest.mark.parametrize("phase,failed,unverified", [
    ("startup", HOSTS, HOSTS),
    ("startup", HOSTS[:2], []),
    ("path", HOSTS[:2], HOSTS),
    ("path", HOSTS[:2], HOSTS[1:]),
    ("path", HOSTS[:2], []),
    ("path", [], []),
])
def test_failure_reports_preserve_every_host_and_guard(
    phase, failed, unverified, rollback_target, repo_root, tmp_path, command_runner,
):
    rollback_target.update({
        "fixture_start_failure_hosts": failed if phase == "startup" else [],
        "fixture_path_failure_hosts": failed if phase == "path" else [],
        "fixture_case": "reset-fail" if unverified else "reset-ok",
        "fixture_reset_failure_hosts": unverified,
    })
    plays = yaml.safe_load((repo_root / PLAYBOOK).read_text())[2:]
    if phase == "startup":
        plays = plays[:1]
    release = yaml.safe_load((repo_root / "playbooks/maintenance/tasks/openbao-edge-release.yml").read_text())
    release[0].pop("ansible.builtin.command")
    release[0]["fixture_io"] = {"argv": ["guard-release"]}
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    (tasks_dir / "openbao-edge-release.yml").write_text(yaml.safe_dump(release), encoding="utf-8")
    fields = ["failed_hosts", "unverified_rollback_hosts", "failed_path_hosts", "unverified_path_rollback_hosts"]
    for index, play in enumerate(plays):
        play["vars"] = rollback_target
        for task in play["tasks"]:
            if "ansible.builtin.command" in task:
                task["fixture_io"] = task.pop("ansible.builtin.command")
            for child in task.get("block", []):
                if "ansible.builtin.command" in child:
                    child["fixture_io"] = child.pop("ansible.builtin.command")
        play["tasks"] = [{"block": play["tasks"], "always": [{
            "fixture_io": {"report": f"report-{index}", "values": {
                field: "{{ hostvars['localhost'].openbao_haproxy_" + field + " | default([]) }}"
                for field in fields
            }}, "run_once": True, "delegate_to": "localhost", "become": False,
        }]}]
    result = run_rollback_plays(plays, tmp_path, command_runner)
    if failed:
        result.assert_failure()
        assert ("activation failed." if phase == "startup" else "path qualification failed on") in result.stdout
        assert "Unverified rollback hosts: " + (", ".join(unverified) or "none") in result.stdout
    else:
        result.assert_success()
    report = json.loads((tmp_path / f"report-{len(plays) - 1}.json").read_text())
    assert report["failed_hosts" if phase == "startup" else "failed_path_hosts"] == failed
    assert report["unverified_rollback_hosts" if phase == "startup" else "unverified_path_rollback_hosts"] == unverified
    assert sorted(path.stem for path in tmp_path.glob("*.guard")) == unverified
    assert sorted(path.stem for path in tmp_path.glob("*.consumed")) == HOSTS
    assert all((tmp_path / f"{host}.consumed").read_text() == "permanent consumption" for host in HOSTS)
