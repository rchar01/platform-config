from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml


ROLE = "roles/openbao_haproxy"
RULES = sorted([
    'rule family="ipv4" source address="198.51.100.0/24" port port="8200" protocol="tcp" accept',
    'rule family="ipv4" source address="127.0.0.1/32" port port="8404" protocol="tcp" accept',
])

# Only target I/O is synthetic. Task conditions, loops, failure handling,
# includes, manifest comparison and observation construction run in Ansible.
TARGET_ACTION = r'''
import base64
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        result = self.target_result(task_vars)
        kind = self._task.action.removeprefix('fixture_')
        argv = self._task.args.get('argv', [])
        phase = kind
        if kind == 'command':
            phase = argv[1]
            if argv[-1].startswith('--query-rich-rule='):
                phase = 'permanent' if argv[0] == 'firewall-offline-cmd' or '--permanent' in argv else 'runtime'
                if argv[-1] != '--query-rich-rule=' + task_vars['fixture_rules'][0]:
                    phase = 'later-rule'
        if phase == task_vars.get('fixture_unreachable_at'):
            # Retain plausible fields so rejection cannot depend on undefined
            # attributes. Later commands and loop iterations still succeed.
            result.update(unreachable=True, msg='Synthetic unreachable ' + phase)
        return result

    def target_result(self, task_vars):
        v = task_vars
        kind = self._task.action.removeprefix('fixture_')
        args = self._task.args
        with Path(v['fixture_log']).open('a') as log:
            log.write(json.dumps({'kind': kind, 'args': args, 'check_mode': self._task.check_mode}) + '\n')
        if kind == 'stat':
            assert args['follow'] is False
            if v.get('fixture_unreachable'):
                return {'unreachable': True, 'msg': 'Synthetic unreachable target'}
            return {'changed': False, 'stat': dict(
                exists=True, isreg=True, islnk=False, uid=0, gid=0,
                mode='0644', checksum='b' * 64,
            ) | v.get('fixture_stat', {})}
        if kind == 'slurp':
            content = v.get('fixture_manifest', json.dumps({'rich_rules': v['fixture_rules']}))
            return {'changed': False, 'content': base64.b64encode(content.encode()).decode()}
        if kind == 'systemd_service':
            assert args['name'] == 'haproxy.service'
            return {'changed': False}
        if kind in ('firewalld', 'copy'):
            phase = 'manifest' if kind == 'copy' else ('enable' if args['state'] == 'enabled' else 'disable')
            return {'changed': v.get('fixture_policy_change') == phase}
        argv = args['argv']
        enabled = v.get('fixture_active', False)
        if argv == ['systemctl', 'is-active', 'firewalld.service']:
            return {'changed': False, 'rc': v.get('fixture_active_rc', 0 if enabled else 3),
                    'stdout': v.get('fixture_active_stdout', 'active' if enabled else 'inactive')}
        if argv == ['systemctl', 'is-enabled', 'firewalld.service']:
            return {'changed': False, 'rc': v.get('fixture_enabled_rc', 0 if enabled else 1),
                    'stdout': v.get('fixture_enabled_stdout', 'enabled' if enabled else 'disabled')}
        if argv == ['firewall-offline-cmd', '--check-config']:
            return {'changed': False, 'rc': v.get('fixture_config_rc', 0), 'stdout': 'success'}
        assert argv[0] in ['firewall-cmd', 'firewall-offline-cmd'], argv
        permanent = argv[0] == 'firewall-offline-cmd' or '--permanent' in argv
        prefix = ['firewall-offline-cmd'] if argv[0] == 'firewall-offline-cmd' else (
            ['firewall-cmd', '--permanent'] if permanent else ['firewall-cmd'])
        assert argv[:-1] == prefix, argv
        assert argv[-1].startswith('--query-rich-rule='), argv
        rule = argv[-1].removeprefix('--query-rich-rule=')
        assert rule in v['fixture_rules'], argv
        missing = v.get('fixture_missing_permanent' if permanent else 'fixture_missing_runtime') == rule
        return {'changed': False, 'rc': 1 if missing else 0, 'stdout': 'no' if missing else 'yes'}
'''


def stage_firewall_target(role: Path, tmp_path: Path, command_runner) -> dict:
    plugins = tmp_path / "action_plugins"
    plugins.mkdir()
    for name in ("command", "stat", "slurp", "systemd_service", "firewalld", "copy"):
        (plugins / f"fixture_{name}.py").write_text(TARGET_ACTION, encoding="utf-8")
    command_runner.environment["ANSIBLE_ACTION_PLUGINS"] = str(plugins)
    # Change only action dispatch, preserving all real guard arguments and logic.
    path = role / "tasks/firewall_guard.yml"
    tasks = yaml.safe_load(path.read_text())
    for task in tasks[1]["block"]:
        for name in ("command", "stat", "slurp"):
            if f"ansible.builtin.{name}" in task:
                assert task["check_mode"] is False
                if name == "command":
                    assert task["changed_when"] is False
                task[f"fixture_{name}"] = task.pop(f"ansible.builtin.{name}")
    path.write_text(yaml.safe_dump(tasks), encoding="utf-8")
    return {"fixture_rules": RULES, "fixture_log": str(tmp_path / "firewall-events.jsonl"),
            "firewalld_service_enabled": False, "firewalld_service_state": "stopped"}


@pytest.mark.parametrize("case", [
    "disabled", "active", "unexpected-active", "unexpected-inactive", "bad-active-rc",
    "bad-enabled-rc", "masked", "failed", "missing-permanent", "missing-runtime",
    "bad-config", "bad-content", "bad-mode", "bad-owner", "bad-group", "symlink",
    "missing-manifest", "nonregular", "missing-enabled", "missing-state", "string-false",
    "string-true", "mixed-disabled", "mixed-enabled", "invalid-state", "integer-enabled",
    "unreachable", "active-missing-permanent",
])
def test_firewall_guard_real_tasks(case, repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_firewall_target(role, tmp_path, command_runner)
    variables.update({"openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"]})
    if case in {"active", "unexpected-inactive", "missing-runtime", "active-missing-permanent"}:
        variables.update(firewalld_service_enabled=True, firewalld_service_state="started",
                         fixture_active=True)
    changes = {
        "unexpected-active": {"fixture_active": True},
        "unexpected-inactive": {"fixture_active": False},
        "bad-active-rc": {"fixture_active_rc": 0},
        "bad-enabled-rc": {"fixture_enabled_rc": 0},
        "masked": {"fixture_enabled_stdout": "masked"},
        "failed": {"fixture_active_stdout": "failed"},
        "missing-permanent": {"fixture_missing_permanent": RULES[-1]},
        "missing-runtime": {"fixture_missing_runtime": RULES[-1]},
        "bad-config": {"fixture_config_rc": 1},
        "bad-content": {"fixture_manifest": json.dumps({"rich_rules": RULES[:1]})},
        "bad-mode": {"fixture_stat": {"mode": "0664"}},
        "bad-owner": {"fixture_stat": {"uid": 1000}},
        "bad-group": {"fixture_stat": {"gid": 1000}},
        "symlink": {"fixture_stat": {"islnk": True}},
        "missing-manifest": {"fixture_stat": {"exists": False}},
        "nonregular": {"fixture_stat": {"isreg": False}},
        "string-false": {"firewalld_service_enabled": "false"},
        "string-true": {"firewalld_service_enabled": "true"},
        "mixed-disabled": {"firewalld_service_state": "started"},
        "mixed-enabled": {"firewalld_service_enabled": True},
        "invalid-state": {"firewalld_service_state": "restarted"},
        "integer-enabled": {"firewalld_service_enabled": 0},
        "unreachable": {"fixture_unreachable": True},
        "active-missing-permanent": {"fixture_missing_permanent": RULES[-1]},
    }
    variables.update(changes.get(case, {}))
    if case in {"missing-enabled", "missing-state"}:
        del variables[f"firewalld_service_{case.removeprefix('missing-')}"]
    guard = {"ansible.builtin.include_role": {"name": str(role), "tasks_from": "firewall_guard.yml"}}
    tasks = [guard]
    if case in {"disabled", "active"}:
        tasks += [{"ansible.builtin.assert": {"that": [
            "openbao_haproxy_firewall_observation.managed is sameas true",
            "openbao_haproxy_firewall_observation.service_enabled == firewalld_service_enabled",
            "openbao_haproxy_firewall_observation.service_state == firewalld_service_state",
            "openbao_haproxy_firewall_observation.rules == fixture_rules",
            "openbao_haproxy_firewall_observation.permanent == ['yes', 'yes']",
            "openbao_haproxy_firewall_observation.runtime == (['yes', 'yes'] if firewalld_service_enabled else [])",
        ]}}, {"ansible.builtin.set_fact": {"openbao_haproxy_firewalld_manage": False}}, guard,
            {"ansible.builtin.assert": {"that": "openbao_haproxy_firewall_observation == {'managed': false}"}}]
    else:
        # Inherited permissive error settings must not bypass the guard.
        tasks += [{"ansible.builtin.fail": {"msg": "UNEXPECTED SERVICE MANAGEMENT"}}]
    playbook = tmp_path / "guard.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "ignore_errors": case not in {"disabled", "active"}, "ignore_unreachable": True,
        "tasks": tasks,
    }]), encoding="utf-8")
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)])
    if case in {"disabled", "active"}:
        result.assert_success()
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
        assert "UNEXPECTED SERVICE MANAGEMENT" not in result.stdout
    log = Path(variables["fixture_log"])
    events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    commands = [event["args"]["argv"] for event in events if event["kind"] == "command"]
    if case == "disabled":
        assert commands == [
            ["systemctl", "is-active", "firewalld.service"],
            ["systemctl", "is-enabled", "firewalld.service"],
            ["firewall-offline-cmd", "--check-config"],
            *[["firewall-offline-cmd", f"--query-rich-rule={rule}"] for rule in RULES],
        ]
    elif case == "active":
        assert commands == [
            ["systemctl", "is-active", "firewalld.service"],
            ["systemctl", "is-enabled", "firewalld.service"],
            *[["firewall-cmd", "--permanent", f"--query-rich-rule={rule}"] for rule in RULES],
            *[["firewall-cmd", f"--query-rich-rule={rule}"] for rule in RULES],
        ]
    elif not variables.get("firewalld_service_enabled"):
        assert not any(argv[0] == "firewall-cmd" for argv in commands)


@pytest.mark.parametrize("route", ["start", "stop", "reload"])
@pytest.mark.parametrize("valid", [True, False])
@pytest.mark.parametrize("active", [True, False])
def test_firewall_guard_precedes_service_actions(route, valid, active, repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_firewall_target(role, tmp_path, command_runner)
    variables.update({"openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"],
                      "openbao_haproxy_service_enabled": route != "stop",
                      "openbao_haproxy_service_state": "stopped" if route == "stop" else "started",
                      "openbao_haproxy_binary_ready": True, "firewalld_dependencies_ready": True})
    variables.update(firewalld_service_enabled=active,
                     firewalld_service_state="started" if active else "stopped", fixture_active=active)
    if not valid:
        variables["fixture_missing_permanent"] = RULES[-1]
    main = yaml.safe_load((role / "tasks/main.yml").read_text())[0]["block"]
    assert main[-2]["ansible.builtin.include_tasks"] == "firewall_guard.yml"
    assert "ansible.builtin.systemd_service" in main[-1]
    reload_path = role / "tasks/reload.yml"
    reload_tasks = yaml.safe_load(reload_path.read_text())
    assert reload_tasks[-2]["ansible.builtin.include_tasks"] == "firewall_guard.yml"
    assert "ansible.builtin.systemd_service" in reload_tasks[-1]
    for tasks in (main[-3:], reload_tasks):
        for task in tasks:
            if "ansible.builtin.systemd_service" in task:
                task["fixture_systemd_service"] = task.pop("ansible.builtin.systemd_service")
    reload_path.write_text(yaml.safe_dump(reload_tasks), encoding="utf-8")
    entry = main[-3:] if route != "reload" else [{
        "ansible.builtin.debug": {"msg": "Notify actual reload handler"},
        "changed_when": True, "notify": "Reload OpenBao HAProxy",
    }, {"ansible.builtin.meta": "flush_handlers"}]
    (role / "tasks/fixture.yml").write_text(yaml.safe_dump(entry), encoding="utf-8")
    playbook = tmp_path / "service.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "tasks": [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": "fixture.yml"}}],
    }]), encoding="utf-8")
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)])
    events = [json.loads(line) for line in Path(variables["fixture_log"]).read_text().splitlines()]
    if valid:
        result.assert_success()
        assert events[-1]["kind"] == "systemd_service"
        assert events[-2]["args"]["argv"] == [
            "firewall-cmd" if active else "firewall-offline-cmd", f"--query-rich-rule={RULES[-1]}",
        ]
        if not active:
            commands = [event["args"]["argv"] for event in events if event["kind"] == "command"]
            assert ["firewall-offline-cmd", "--check-config"] in commands
            assert not any(argv[0] == "firewall-cmd" for argv in commands)
    else:
        result.assert_failure()
        assert not any(event["kind"] == "systemd_service" for event in events)


@pytest.mark.parametrize("phase", [
    "stat", "slurp", "is-active", "is-enabled", "--check-config", "permanent", "runtime",
])
@pytest.mark.parametrize("continued", [False, True])
def test_firewall_guard_rejects_unreachable_before_start(phase, continued, repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_firewall_target(role, tmp_path, command_runner)
    if continued:
        # Deliberately allow target I/O to continue after unreachable results.
        # This exercises result assertions independently of Ansible inheritance.
        guard_path = role / "tasks/firewall_guard.yml"
        guard = yaml.safe_load(guard_path.read_text())
        for task in guard[1]["block"]:
            if any(f"fixture_{kind}" in task for kind in ("stat", "slurp", "command")):
                task["ignore_unreachable"] = True
        guard_path.write_text(yaml.safe_dump(guard), encoding="utf-8")
    active = phase == "runtime"
    variables.update({
        "openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"],
        "openbao_haproxy_service_enabled": True, "openbao_haproxy_service_state": "started",
        "openbao_haproxy_binary_ready": True, "firewalld_dependencies_ready": True,
        "firewalld_service_enabled": active, "firewalld_service_state": "started" if active else "stopped",
        "fixture_active": active, "fixture_unreachable_at": phase,
    })
    tasks = yaml.safe_load((role / "tasks/main.yml").read_text())[0]["block"][-3:]
    tasks[-1]["fixture_systemd_service"] = tasks[-1].pop("ansible.builtin.systemd_service")
    (role / "tasks/fixture.yml").write_text(yaml.safe_dump(tasks), encoding="utf-8")
    playbook = tmp_path / "unreachable.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "ignore_errors": True, "ignore_unreachable": True,
        "tasks": [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": "fixture.yml"}}],
    }]), encoding="utf-8")
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)])
    events = [json.loads(line) for line in Path(variables["fixture_log"]).read_text().splitlines()]
    assert not any(event["kind"] == "systemd_service" for event in events), result.diagnostics()
    result.assert_failure()
    assert "Record verified OpenBao HAProxy firewall observation" not in result.stdout
    if continued and phase == "--check-config":
        assert "Require verified disabled OpenBao HAProxy firewall configuration" in result.stdout
        assert not any("--query-rich-rule=" in event["args"].get("argv", [""])[-1] for event in events)


@pytest.mark.parametrize("scope", ["permanent", "runtime"])
@pytest.mark.parametrize("damage", ["missing", "unreachable", "missing-rc", "missing-stdout"])
def test_firewall_guard_requires_every_loop_result(scope, damage, repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_firewall_target(role, tmp_path, command_runner)
    variables.update({"firewalld_service_enabled": True,
                      "openbao_haproxy_current_firewalld_rules": RULES})
    for name in ("permanent", "runtime"):
        variables[f"openbao_haproxy_firewall_{name}"] = {
            "results": [{"item": rule, "rc": 0, "stdout": "yes"} for rule in RULES],
        }
    results = variables[f"openbao_haproxy_firewall_{scope}"]["results"]
    if damage == "missing":
        results.pop(0)
    elif damage == "unreachable":
        # No aggregate unreachable flag: the per-item check must catch this.
        results[0]["unreachable"] = True
    else:
        del results[0][damage.removeprefix("missing-")]
    guard = yaml.safe_load((role / "tasks/firewall_guard.yml").read_text())[1]["block"]
    assertion = next(task for task in guard if task["name"] ==
                     "Require complete reachable OpenBao HAProxy firewall rule observations")
    (role / "tasks/fixture.yml").write_text(yaml.safe_dump([
        assertion, {"fixture_systemd_service": {"name": "haproxy.service", "state": "started"}},
    ]), encoding="utf-8")
    playbook = tmp_path / "incomplete.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "tasks": [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": "fixture.yml"}}],
    }]), encoding="utf-8")
    result = command_runner.run([
        "ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
    ]).assert_failure()
    assert "evaluated_to: false" in result.stdout, result.diagnostics()
    assert not Path(variables["fixture_log"]).exists()


@pytest.mark.parametrize("check_mode", [True, False], ids=["check", "apply"])
@pytest.mark.parametrize("case", [
    "enable", "disable", "manifest", "dependencies", "unchanged", "missing-rule", "unmanaged",
])
def test_firewall_guard_check_mode_deferral(case, check_mode, repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_firewall_target(role, tmp_path, command_runner)
    variables.update({
        "openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"],
        "openbao_haproxy_current_firewalld_rules": RULES,
        "openbao_haproxy_previous_firewalld_rules": ['rule family="ipv4" source address="192.0.2.0/24" accept'],
        "openbao_haproxy_binary_ready": True,
        "firewalld_dependencies_ready": case != "dependencies",
        "fixture_policy_change": case,
    })
    if case == "missing-rule":
        variables["fixture_missing_permanent"] = RULES[-1]
    if case == "manifest" and check_mode:
        variables["fixture_stat"] = {"exists": False}
    main = yaml.safe_load((role / "tasks/main.yml").read_text())[0]["block"]
    start = next(i for i, task in enumerate(main) if task["name"] == "Enable current OpenBao HAProxy firewalld policy")
    tasks = main[start:]
    if case == "unmanaged":
        # No convergence results or dependency fact exist on this path.
        tasks = main[-3:]
        variables["openbao_haproxy_firewalld_manage"] = False
        del variables["firewalld_dependencies_ready"]
    for task in tasks:
        for action in ("ansible.posix.firewalld", "ansible.builtin.copy", "ansible.builtin.systemd_service"):
            if action in task:
                assert "check_mode" not in task
                task[f"fixture_{action.rsplit('.', 1)[-1]}"] = task.pop(action)
    (role / "tasks/fixture.yml").write_text(yaml.safe_dump(tasks), encoding="utf-8")
    playbook = tmp_path / "check-mode.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "tasks": [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": "fixture.yml"}}],
    }]), encoding="utf-8")
    result = command_runner.run([
        "ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
        *(["--check"] if check_mode else []),
    ])
    events = [json.loads(line) for line in Path(variables["fixture_log"]).read_text().splitlines()]
    if case == "missing-rule":
        result.assert_failure()
        assert not any(event["kind"] == "systemd_service" for event in events)
    else:
        result.assert_success()
        assert events[-1]["kind"] == "systemd_service"
        assert events[-1]["args"]["state"] == "stopped"
        assert events[-1]["check_mode"] is check_mode
    deferred = check_mode and case in {"enable", "disable", "manifest", "dependencies"}
    reads = [event for event in events if event["kind"] in {"stat", "slurp", "command"}]
    assert bool(reads) is (not deferred and case != "unmanaged"), result.diagnostics()
    if reads:
        assert any(event["args"].get("argv") == ["firewall-offline-cmd", "--check-config"] for event in reads)
    assert not any(event["args"].get("argv", [""])[0] == "firewall-cmd" for event in reads)
