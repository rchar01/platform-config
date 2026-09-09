from __future__ import annotations

import json

import pytest
import yaml


ROLE = "roles/openbao_haproxy"
PLAYBOOK = "playbooks/maintenance/openbao-haproxy-activate.yml"
HOSTS = [f"bao-{i}" for i in range(1, 4)]
INVALID_INSPECTIONS = {
    "active": {"rc": 0, "stdout": "active"},
    "unknown": {"rc": 3, "stdout": "unknown"},
    "wrong-rc": {"rc": 0, "stdout": "inactive"},
    "string-rc": {"rc": "3", "stdout": "failed"},
    "missing-rc": {"stdout": "failed"},
    "missing-stdout": {"rc": 3},
    "missing": {},
    "unreachable": {"unreachable": True, "rc": 3, "stdout": "failed"},
    "skipped": {"skipped": True, "rc": 3, "stdout": "failed"},
}

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
        event = dict(args=args, become=self._play_context.become, register=self._task.register)
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
                if case == 'stop-skipped':
                    return dict(skipped=True)
                state['enabled'] = 'disabled'
                if host in task_vars.get('fixture_failed_latch_hosts', []):
                    state['active'] = 'failed'
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
            sequence = task_vars.get('fixture_curl_sequences', {}).get(host)
            if sequence:
                attempt_file = root / (host + '.attempts')
                attempt = int(attempt_file.read_text()) if attempt_file.exists() else 0
                attempt_file.write_text(str(attempt + 1))
                return dict(sequence[min(attempt, len(sequence) - 1)])
            return dict(rc=0, stdout='503' if host in task_vars.get('fixture_path_failure_hosts', []) else '200')
        assert argv[0] == 'systemctl' and argv[2:] == ['haproxy.service'], argv
        assert self._play_context.become is True
        if argv[1] == 'reset-failed':
            assert state['enabled'] == 'disabled', 'reset must follow stop/disable'
            if state['active'] == 'inactive':
                return dict(failed=True, rc=1, stderr='Unit haproxy.service not loaded.')
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
            if self._task.register == 'openbao_haproxy_activation_rollback_before_reset':
                overrides = task_vars.get('fixture_before_reset_results', {})
                if host in overrides:
                    return dict(overrides[host])
            elif case == 'active-unreachable':
                return dict(unreachable=True, stdout='inactive', rc=3)
            elif case == 'active-wrong-rc':
                return dict(stdout='inactive', rc=0)
            elif case == 'active-skipped':
                return dict(skipped=True, stdout='inactive', rc=3)
            return dict(rc=3 if state['active'] != 'active' else 0, stdout=state['active'])
        assert argv[1] == 'is-enabled', argv
        if case == 'enabled-unreachable':
            return dict(unreachable=True, stdout='disabled', rc=1)
        if case == 'enabled-wrong-rc':
            return dict(stdout='disabled', rc=0)
        if case == 'enabled-skipped':
            return dict(skipped=True, stdout='disabled', rc=1)
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


def test_clean_stop_skips_reset_for_inactive_unloaded_unit(
    rollback_target, tmp_path, command_runner,
):
    (tmp_path / f"{HOSTS[0]}.json").write_text(json.dumps({
        "active": "active", "enabled": "enabled",
    }))
    result = run_rollback_plays([{
        "hosts": HOSTS[0], "gather_facts": False, "become": True,
        "vars": rollback_target,
        "tasks": [
            {"ansible.builtin.include_role": {"name": "openbao_haproxy",
                "tasks_from": "activation_rollback.yml"}},
            {"ansible.builtin.assert": {"that": [
                "openbao_haproxy_activation_rollback_confirmed is true",
            ]}},
        ],
    }], tmp_path, command_runner)
    result.assert_success()
    events = [json.loads(line) for line in (tmp_path / f"{HOSTS[0]}.events").read_text().splitlines()]
    assert [event["args"] for event in events] == [
        {"name": "haproxy.service", "state": "stopped", "enabled": False},
        {"argv": ["systemctl", "is-active", "haproxy.service"]},
        {"argv": ["systemctl", "is-active", "haproxy.service"]},
        {"argv": ["systemctl", "is-enabled", "haproxy.service"]},
    ]
    assert json.loads((tmp_path / f"{HOSTS[0]}.json").read_text()) == {
        "active": "inactive", "enabled": "disabled",
    }


@pytest.mark.parametrize("case", [
    "reset-ok", "reset-fail", "reset-unreachable", "reset-missing", "reset-skipped", "still-failed",
    "stop-fail", "stop-unreachable", "stop-skipped", "still-enabled",
    "active-unreachable", "enabled-unreachable", "active-wrong-rc", "enabled-wrong-rc",
    "active-skipped", "enabled-skipped",
    *[f"before-{case}" for case in INVALID_INSPECTIONS],
])
def test_rollback_requires_verified_reset_and_strict_state(
    case, rollback_target, tmp_path, command_runner,
):
    rollback_target["fixture_case"] = case
    if case.startswith("before-"):
        rollback_target["fixture_before_reset_results"] = {
            HOSTS[0]: INVALID_INSPECTIONS[case.removeprefix("before-")],
        }
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
    assert len(resets) == (0 if case.startswith(("stop-", "before-")) else 1)
    if case.startswith(("stop-", "before-", "reset-")) and case != "reset-ok":
        assert not any(event["register"] == "openbao_haproxy_activation_rollback_active" for event in events)
    if not case.startswith("stop-"):
        assert events[1]["register"] == "openbao_haproxy_activation_rollback_before_reset"
    if case == "reset-ok":
        assert events[2] == resets[0]
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
    run_activation_and_check_report(
        phase, failed, unverified, rollback_target, repo_root, tmp_path, command_runner,
    )


def replace_target_io(tasks):
    for task in tasks:
        if "ansible.builtin.command" in task:
            task["fixture_io"] = task.pop("ansible.builtin.command")
            if task["fixture_io"].get("argv", [None])[0] == "curl" and "until" in task:
                # Keep production retries and until; only remove the wait in offline tests.
                task["delay"] = 0
        for section in ("block", "rescue", "always"):
            replace_target_io(task.get(section, []))


def run_activation_and_check_report(
    phase, failed, unverified, rollback_target, repo_root, tmp_path, command_runner,
):
    rollback_target.update({
        "fixture_start_failure_hosts": failed if phase == "startup" else [],
        "fixture_path_failure_hosts": failed if phase == "path" else [],
        "fixture_case": "reset-fail" if unverified else "reset-ok",
        "fixture_reset_failure_hosts": unverified,
        # A successful start clears the original failed latch. Inject a new latch
        # only where a reset failure is intended to leave rollback unverified.
        "fixture_failed_latch_hosts": unverified,
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
        replace_target_io(play["tasks"])
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
    for host in HOSTS:
        events = [json.loads(line) for line in (tmp_path / f"{host}.events").read_text().splitlines()]
        stops = [event for event in events if event["args"].get("state") == "stopped"]
        assert len(stops) == (1 if failed else 0)
        resets = [event for event in events if event["args"].get("argv", [])[:2] == ["systemctl", "reset-failed"]]
        invalid_inspection = host in rollback_target.get("fixture_before_reset_results", {})
        assert len(resets) == int(bool(failed) and not invalid_inspection and (
            host in unverified or (phase == "startup" and host in failed)
        ))
        if host not in unverified:
            assert json.loads((tmp_path / f"{host}.json").read_text()) == {
                "active": "inactive" if failed else "active",
                "enabled": "disabled" if failed else "enabled",
            }
    return result


@pytest.mark.parametrize("inspection", INVALID_INSPECTIONS)
def test_invalid_initial_inspection_retains_only_affected_guards(
    inspection, rollback_target, repo_root, tmp_path, command_runner,
):
    rollback_target["fixture_before_reset_results"] = {
        host: INVALID_INSPECTIONS[inspection] for host in HOSTS[1:]
    }
    run_activation_and_check_report(
        "path", HOSTS[:1], HOSTS[1:], rollback_target, repo_root, tmp_path, command_runner,
    )


@pytest.mark.parametrize("sequence,attempts,failed", [
    pytest.param([{"rc": 7, "stdout": "000"}, {"rc": 0, "stdout": "429"},
                  {"rc": 0, "stdout": "503"}, {"rc": 0, "stdout": "200"}], 4, False,
                 id="connect-standby-sealed-healthy"),
    pytest.param([{"rc": 0, "stdout": "503"}] * 9 + [{"rc": 0, "stdout": "200"}],
                 10, False, id="healthy-on-final-attempt"),
    pytest.param([{"rc": 60, "stdout": "000"}], 10, True, id="persistent-tls"),
    pytest.param([{"rc": 7, "stdout": "000"}], 10, True, id="persistent-connect"),
    pytest.param([{"rc": 0, "stdout": "429"}], 10, True, id="persistent-standby"),
    pytest.param([{"rc": 0, "stdout": "503"}], 10, True, id="persistent-sealed"),
    pytest.param([{"rc": 0, "stdout": "503"}] * 10 + [{"rc": 0, "stdout": "200"}],
                 10, True, id="healthy-too-late"),
    pytest.param([{"rc": 7, "stdout": "200"}], 10, True, id="nonzero-rc-with-200"),
])
def test_path_retry_bound_and_all_host_rollback(
    sequence, attempts, failed, rollback_target, repo_root, tmp_path, command_runner,
):
    raw_diagnostic = "fixture-raw-curl-diagnostic-must-not-be-repeated"
    rollback_target["fixture_curl_sequences"] = {
        HOSTS[0]: [dict(response, stderr=raw_diagnostic) for response in sequence],
    }
    result = run_activation_and_check_report(
        "path", HOSTS[:1] if failed else [], [],
        rollback_target, repo_root, tmp_path, command_runner,
    )
    for host in HOSTS:
        events = [json.loads(line) for line in (tmp_path / f"{host}.events").read_text().splitlines()]
        curls = [event for event in events if event["args"].get("argv", [None])[0] == "curl"]
        assert len(curls) == (attempts if host == HOSTS[0] else 1)
    if failed:
        assert raw_diagnostic not in result.stdout
        qualification = yaml.safe_load((repo_root / PLAYBOOK).read_text())[-1]
        query = next(task for task in qualification["tasks"]
                     if task.get("name") == "Query local OpenBao HAProxy client path")
        diagnostics = [task for task in query["rescue"] if "ansible.builtin.debug" in task]
        assert diagnostics, "exhausted retries must emit a sanitized rescue diagnostic"
        for task in diagnostics:
            marker = f"TASK [{task['name']}]"
            assert marker in result.stdout
            output = result.stdout.split(marker, 1)[1].split("\nTASK [", 1)[0]
            diagnostic = yaml.safe_load(output.split(f"ok: [{HOSTS[0]}] =>", 1)[1])["msg"]
            response = sequence[min(attempts, len(sequence)) - 1]
            assert diagnostic == {
                "host": HOSTS[0], "curl_rc": response["rc"],
                "http_status": response["stdout"], "attempt_limit": 10,
            }
