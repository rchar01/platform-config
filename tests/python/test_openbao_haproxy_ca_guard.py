from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml


ROLE = "roles/openbao_haproxy"
GUARD = "ca_guard.yml"

# Only stat/slurp dispatch changes in the copied guard. No built-in action is
# globally shadowed, and the desired config comes from the actual role template.
TARGET_ACTION = r'''
import base64
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        v, args = task_vars, self._task.args
        kind = self._task.action.removeprefix('fixture_ca_')
        paths = {
            v['openbao_haproxy_config_path']: 'config',
            v['openbao_haproxy_backend_ca_src']: 'source',
            v['openbao_haproxy_backend_ca_path']: 'ca',
            str(Path(v['openbao_haproxy_backend_ca_path']).parent): 'directory',
        }
        path = args['path' if kind == 'stat' else 'src']
        label = paths[path] if kind == 'stat' else 'slurp'
        with Path(v['fixture_ca_log']).open('a') as log:
            log.write(json.dumps({'kind': kind, 'label': label, 'args': args}) + '\n')
        if kind == 'stat':
            assert args['follow'] is False and args['checksum_algorithm'] == 'sha256'
            directory = label == 'directory'
            metadata = dict(exists=True, isreg=not directory, isdir=directory,
                            islnk=False, uid=0, gid=0, nlink=2 if directory else 1,
                            mode='0755' if directory else '0640' if label == 'config' else '0644')
            if not directory:
                metadata['checksum'] = v['fixture_ca_checksums'][label]
            metadata.update(v.get('fixture_ca_stats', {}).get(label, {}))
            for field in v.get('fixture_ca_missing_fields', {}).get(label, []):
                metadata.pop(field, None)
            result = {'changed': False, 'stat': metadata}
        else:
            assert kind == 'slurp' and path == v['openbao_haproxy_config_path']
            content = self._templar.template(v['fixture_ca_config'])
            result = {'changed': False, 'content': base64.b64encode(content.encode()).decode()}
        result.update(v.get('fixture_ca_results', {}).get(label, {}))
        return result
'''


def stage_ca_target(role: Path, tmp_path: Path, command_runner, *, mock_policy=False) -> dict:
    """Stage CA-only I/O doubles; return vars to merge into a caller's play vars.

    fixture_ca_checksums uses config/source/ca keys; fixture_ca_stats and
    fixture_ca_missing_fields use config/source/ca/directory labels. Override
    fixture_ca_config for stale content, or fixture_ca_results[label] for an
    incomplete, skipped, failed or unreachable result (also accepts slurp).
    SELinux commands remain real: callers select unmanaged or stage bindings.
    """
    plugins = tmp_path / "action_plugins"
    plugins.mkdir(exist_ok=True)
    for name in ("stat", "slurp"):
        (plugins / f"fixture_ca_{name}.py").write_text(TARGET_ACTION, encoding="utf-8")
    existing = command_runner.environment.get("ANSIBLE_ACTION_PLUGINS", "")
    command_runner.environment["ANSIBLE_ACTION_PLUGINS"] = ":".join(
        dict.fromkeys(filter(None, [str(plugins), *existing.split(":")])),
    )
    path = role / "tasks" / GUARD
    text = path.read_text()
    for name in ("stat", "slurp"):
        text = text.replace(f"ansible.builtin.{name}:", f"fixture_ca_{name}:")
    path.write_text(text, encoding="utf-8")
    if mock_policy:
        # Port/firewall tests exercise their own native probes, not CA policy I/O.
        tasks = yaml.safe_load(text)
        for task in tasks[0]["block"]:
            if "ansible.builtin.command" in task:
                task.clear()
                task["ansible.builtin.set_fact"] = {
                    "openbao_haproxy_ca_probe": {"rc": 0, "stdout": '{"managed": false}'},
                }
        path.write_text(yaml.safe_dump(tasks), encoding="utf-8")
    return {
        "openbao_haproxy_backend_ca_src": "/etc/openbao/tls/ca.crt",
        "openbao_haproxy_backend_ca_path": "/etc/haproxy/openbao-ca.crt",
        "fixture_ca_checksums": {"config": "a" * 64, "source": "b" * 64, "ca": "b" * 64},
        "fixture_ca_config": "{{ lookup('ansible.builtin.template', '"
        + str(role / "templates/haproxy.cfg.j2") + "') }}",
        "fixture_ca_log": str(tmp_path / "ca-events.jsonl"),
    }


# API-shaped double: positive getfilecon lengths, policy-specific permission
# masks and the mandatory fifth OUT argument, never permissive-mode shortcuts.
SELINUX_BINDING = r'''
import json
import os
from pathlib import Path

case = os.environ.get('CA_TEST_CASE', 'ready')
log = Path(os.environ['CA_TEST_LOG'])
def event(*args):
    with log.open('a') as stream:
        stream.write(json.dumps(args) + '\n')
event('import selinux')
if case == 'missing-bindings':
    raise ModuleNotFoundError('Synthetic missing SELinux bindings')
source = 'system_u:system_r:init_t:s0:c1.c4'
executable = 'system_u:object_r:haproxy_exec_t:s0:c2.c5'
domain = 'system_u:system_r:haproxy_t:s0:c3.c6'
def getpidcon(pid):
    assert pid == 1
    event('getpidcon', pid)
    return (-1 if case == 'pid-error' else 0), (None if case == 'pid-none' else source)
def getfilecon(path):
    event('getfilecon', path)
    if path == '/usr/sbin/haproxy':
        context = executable.replace('haproxy_exec_t', 'bin_t') if case == 'wrong-exec' else executable
        return (-1 if case == 'exec-error' else len(context)), (None if case == 'exec-none' else context)
    context = 'system_u:object_r:cert_t:s0:c7.c9' if path.endswith('.crt') else 'system_u:object_r:etc_t:s0:c8.c10'
    if case == 'label-drift':
        context = context.replace('c8.c10', 'c11.c12')
    return (-1 if case == 'path-error' else len(context)), (None if case == 'path-none' else context)
classes = {'process': 19, 'dir': 27, 'file': 31}
permissions = {27: {'search': 8}, 31: {'open': 32, 'read': 2, 'getattr': 128}}
def string_to_security_class(name):
    event('class', name)
    return 0 if case == 'class-' + name else classes[name]
def security_compute_create(src, exe, cls):
    assert (src, exe, cls) == (source, executable, classes['process'])
    event('create', src, exe, cls)
    context = domain.replace('haproxy_t', 'init_t') if case == 'wrong-domain' else domain
    return (-1 if case == 'create-error' else 0), (None if case == 'domain-none' else context)
def string_to_av_perm(cls, name):
    event('permission', cls, name)
    return 0 if case == 'permission-' + name else permissions[cls][name]
class av_decision:
    def __init__(self):
        self.allowed = 0
def security_compute_av(src, target, cls, mask, decision):
    assert src == domain and isinstance(decision, av_decision)
    assert mask == (8 if cls == 27 else 162)
    event('av', src, target, cls, mask)
    decision.allowed = mask
    if case == 'deny-search' and cls == 27:
        decision.allowed &= ~8
    if case == 'deny-read' and cls == 31:
        decision.allowed &= ~2
    return -1 if case == 'av-error' else None if case == 'av-none' else 0
'''


def stage_native_target(tmp_path, command_runner, case="ready", mode="Enforcing"):
    log = tmp_path / "ca-native-events.jsonl"
    getenforce = tmp_path / "getenforce"
    getenforce.write_text(
        f"#!{sys.executable}\nimport json, os, sys\nfrom pathlib import Path\n"
        "assert sys.argv[1:] == []\n"
        "with Path(os.environ['CA_TEST_LOG']).open('a') as log:\n"
        "    log.write(json.dumps(['getenforce']) + '\\n')\n"
        "print(os.environ['CA_TEST_MODE'])\n"
        "sys.exit(1 if os.environ['CA_TEST_CASE'] == 'command-fail' else 0)\n",
        encoding="utf-8",
    )
    getenforce.chmod(0o755)
    (tmp_path / "selinux.py").write_text(SELINUX_BINDING, encoding="utf-8")
    return {
        "PATH": f"{tmp_path}:{command_runner.environment['PATH']}",
        "PYTHONPATH": str(tmp_path), "CA_TEST_CASE": case,
        "CA_TEST_MODE": mode, "CA_TEST_LOG": str(log),
    }, log


@pytest.mark.parametrize("case,mode", [
    (case, mode) for mode in ("Enforcing", "Permissive")
    for case in ("ready", "deny-search", "deny-read")
] + [(case, "Enforcing") for case in (
    "missing-bindings", "pid-error", "pid-none", "exec-error", "exec-none", "wrong-exec",
    "create-error", "domain-none", "wrong-domain", "path-error", "path-none",
    "class-process", "class-dir", "class-file", "permission-search", "permission-open",
    "permission-read", "permission-getattr", "av-error", "av-none", "command-fail", "label-drift",
)] + [("missing-bindings", "Disabled"), ("ready", "Unknown")])
def test_native_ca_probe(case, mode, repo_root, tmp_path, command_runner):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / GUARD).read_text())[0]["block"]
    command = next(task for task in tasks if "ansible.builtin.command" in task)
    code = command["ansible.builtin.command"]["argv"][2]
    ca = tmp_path / "haproxy/openbao-ca.crt"
    ca.parent.mkdir()
    ca.write_text("Synthetic public CA", encoding="utf-8")
    environment, log = stage_native_target(tmp_path, command_runner, case, mode)
    result = command_runner.run(
        [sys.executable, "-c", code, "/usr/sbin/haproxy", str(ca)], environment=environment,
    )
    events = [json.loads(line) for line in log.read_text().splitlines()]
    if mode == "Disabled":
        result.assert_success()
        assert json.loads(result.stdout) == {"managed": True, "mode": "Disabled"}
        assert events == [["getenforce"]]
    elif case in {"ready", "label-drift"} and mode != "Unknown":
        result.assert_success()
        observation = json.loads(result.stdout)
        directory_context = "system_u:object_r:etc_t:s0:" + ("c11.c12" if case == "label-drift" else "c8.c10")
        assert observation == {
            "managed": True, "mode": mode,
            "source_context": "system_u:system_r:init_t:s0:c1.c4",
            "executable_context": "system_u:object_r:haproxy_exec_t:s0:c2.c5",
            "prospective_domain": "system_u:system_r:haproxy_t:s0:c3.c6",
            "paths": {
                **{str(parent): {"context": directory_context, "class": "dir", "permissions": ["search"]}
                   for parent in ca.parents},
                str(ca): {"context": "system_u:object_r:cert_t:s0:c7.c9", "class": "file",
                          "permissions": ["open", "read", "getattr"]},
            },
        }
        paths = [entry[1] for entry in events if entry[0] == "getfilecon"]
        assert paths == ["/usr/sbin/haproxy", *map(str, reversed(ca.parents)), str(ca)]
        assert events.count(["permission", 27, "search"]) == len(ca.parents)
    else:
        result.assert_failure()
        assert not result.stdout.strip()


def test_native_ca_probe_rejects_symlink_ancestor(repo_root, tmp_path, command_runner):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / GUARD).read_text())[0]["block"]
    code = next(task["ansible.builtin.command"]["argv"][2] for task in tasks if "ansible.builtin.command" in task)
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    environment, _ = stage_native_target(tmp_path, command_runner)
    result = command_runner.run([
        sys.executable, "-c", code, "/usr/sbin/haproxy", str(tmp_path / "link/ca.crt"),
    ], environment=environment).assert_failure()
    assert "must not traverse symlinks" in result.stderr


@pytest.fixture
def ca_target(repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_ca_target(role, tmp_path, command_runner)
    variables.update({
        "openbao_haproxy_selinux_manage": False,
        "openbao_haproxy_ca_observation": {"selinux": {"managed": True, "mode": "stale"}},
        "openbao_haproxy_package_nevra": "haproxy-0:3.0.5-6.el10_2.1.x86_64",
        "openbao_haproxy_backend_health_host": "bao.example.invalid",
        "openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"],
        "openbao_cluster_members": [
            {"name": f"bao-{i}", "address": f"192.0.2.{i}", "dns": f"bao-{i}.example.invalid"}
            for i in range(1, 4)
        ],
        "ansible_python_interpreter": sys.executable,
        "ansible_facts": {"python": {"executable": sys.executable}},
    })
    collections = tmp_path / "empty-collections"
    collections.mkdir()
    command_runner.environment.update({
        "ANSIBLE_COLLECTIONS_PATH": str(collections), "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False",
    })
    return {
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "ignore_errors": True, "ignore_unreachable": True,
        "tasks": [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": GUARD}}],
    }


def run_guard(play, tmp_path, command_runner):
    path = tmp_path / "ca-guard.yml"
    path.write_text(yaml.safe_dump([play]), encoding="utf-8")
    return command_runner.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(path)])


@pytest.mark.parametrize("case", [
    "ready", "mismatch", "stale-config", "source-mode", "ca-owner", "config-group", "hardlink",
    "symlink", "directory-mode", "directory-symlink", "directory-nonfolder", "missing", "nonregular",
    "incomplete", "stat-skipped", "stat-unreachable", "slurp-skipped", "slurp-unreachable",
])
def test_ca_guard_real_tasks(case, ca_target, tmp_path, command_runner):
    changes = {
        "mismatch": {"fixture_ca_checksums": {"config": "a" * 64, "source": "b" * 64, "ca": "c" * 64}},
        "stale-config": {"fixture_ca_config": "stale configuration\n"},
        "source-mode": {"fixture_ca_stats": {"source": {"mode": "0600"}}},
        "ca-owner": {"fixture_ca_stats": {"ca": {"uid": 1000}}},
        "config-group": {"fixture_ca_stats": {"config": {"gid": 1000}}},
        "hardlink": {"fixture_ca_stats": {"ca": {"nlink": 2}}},
        "symlink": {"fixture_ca_stats": {"source": {"islnk": True}}},
        "directory-mode": {"fixture_ca_stats": {"directory": {"mode": "0775"}}},
        "directory-symlink": {"fixture_ca_stats": {"directory": {"islnk": True}}},
        "directory-nonfolder": {"fixture_ca_stats": {"directory": {"isdir": False}}},
        "missing": {"fixture_ca_stats": {"source": {"exists": False}}},
        "nonregular": {"fixture_ca_stats": {"ca": {"isreg": False}}},
        "incomplete": {"fixture_ca_missing_fields": {"ca": ["checksum"]}},
        "stat-skipped": {"fixture_ca_results": {"source": {"skipped": True}}},
        "stat-unreachable": {"fixture_ca_results": {"source": {"unreachable": True}}},
        "slurp-skipped": {"fixture_ca_results": {"slurp": {"skipped": True}}},
        "slurp-unreachable": {"fixture_ca_results": {"slurp": {"unreachable": True}}},
    }
    ca_target["vars"].update(changes.get(case, {}))
    if case == "ready":
        ca_target["tasks"].append({"ansible.builtin.assert": {"that": [
            "openbao_haproxy_ca_observation == {'source_checksum': fixture_ca_checksums.source, "
            "'ca_checksum': fixture_ca_checksums.ca, 'config_checksum': fixture_ca_checksums.config, "
            "'selinux': {'managed': false}}",
        ]}, "ignore_errors": False})
    else:
        ca_target["tasks"].append({"ansible.builtin.fail": {"msg": "UNEXPECTED SERVICE BOUNDARY"}})
    result = run_guard(ca_target, tmp_path, command_runner)
    if case == "ready":
        result.assert_success()
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
        assert "UNEXPECTED SERVICE BOUNDARY" not in result.stdout
    events = [json.loads(line) for line in Path(ca_target["vars"]["fixture_ca_log"]).read_text().splitlines()]
    assert [event["label"] for event in events[:4]] == ["config", "source", "ca", "directory"]


def test_ca_guard_binds_contexts_and_resets_each_call(ca_target, tmp_path, command_runner):
    environment, log = stage_native_target(tmp_path, command_runner)
    ca_target["vars"]["openbao_haproxy_selinux_manage"] = True
    ca_target["environment"] = environment | {"CA_TEST_CASE": "{{ fixture_native_case | default('ready') }}"}
    include = ca_target["tasks"][0]
    ca_target["tasks"] += [
        {"ansible.builtin.set_fact": {"approved_ca": "{{ openbao_haproxy_ca_observation }}",
                                     "fixture_native_case": "label-drift"}},
        include,
        {"ansible.builtin.assert": {"that": [
            "approved_ca != openbao_haproxy_ca_observation",
            "approved_ca.selinux.paths['/'].context != openbao_haproxy_ca_observation.selinux.paths['/'].context",
            "approved_ca.ca_checksum == openbao_haproxy_ca_observation.ca_checksum",
        ]}, "ignore_errors": False},
        {"ansible.builtin.set_fact": {"openbao_haproxy_selinux_manage": False}},
        include,
        {"ansible.builtin.assert": {"that": "openbao_haproxy_ca_observation.selinux == {'managed': false}"},
         "ignore_errors": False},
    ]
    result = run_guard(ca_target, tmp_path, command_runner).assert_success()
    assert "changed=0" in result.stdout
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert events.count(["getenforce"]) == 2


def test_ca_guard_binds_fresh_checksums(ca_target, tmp_path, command_runner):
    include = ca_target["tasks"][0]
    ca_target["tasks"] += [
        {"ansible.builtin.set_fact": {
            "approved_ca": "{{ openbao_haproxy_ca_observation }}",
            "fixture_ca_checksums": {"config": "d" * 64, "source": "c" * 64, "ca": "c" * 64},
        }},
        include,
        {"ansible.builtin.assert": {"that": [
            "approved_ca.source_checksum != openbao_haproxy_ca_observation.source_checksum",
            "approved_ca.ca_checksum != openbao_haproxy_ca_observation.ca_checksum",
            "approved_ca.config_checksum != openbao_haproxy_ca_observation.config_checksum",
            "approved_ca.selinux == openbao_haproxy_ca_observation.selinux",
        ]}, "ignore_errors": False},
    ]
    result = run_guard(ca_target, tmp_path, command_runner).assert_success()
    assert "changed=0" in result.stdout


def test_ca_guard_native_failure_clears_stale_observation(ca_target, tmp_path, command_runner):
    environment, _ = stage_native_target(tmp_path, command_runner, "deny-read", "Permissive")
    ca_target["vars"]["openbao_haproxy_selinux_manage"] = True
    ca_target["environment"] = environment
    ca_target["tasks"] = [{
        "block": ca_target["tasks"] + [{"ansible.builtin.fail": {"msg": "UNEXPECTED SERVICE BOUNDARY"}}],
        "rescue": [{"ansible.builtin.assert": {"that": [
            "openbao_haproxy_ca_observation == {'selinux': {'managed': false}}",
            "ansible_failed_result.rc == 1",
            "'SELinux denies HAProxy CA access: /etc/haproxy/openbao-ca.crt' in ansible_failed_result.stderr",
        ]}, "ignore_errors": False}],
    }]
    result = run_guard(ca_target, tmp_path, command_runner).assert_success()
    assert "UNEXPECTED SERVICE BOUNDARY" not in result.stdout


@pytest.mark.parametrize("probe", [
    {}, {"rc": -1}, {"rc": 0, "skipped": True},
    {"rc": 0, "unreachable": True}, {"rc": 0, "failed": True},
])
def test_ca_guard_rejects_incomplete_probe_before_json(probe, repo_root, tmp_path, command_runner):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / GUARD).read_text())[0]["block"]
    gate = next(task for task in tasks if task["name"] ==
                "Require a complete reachable OpenBao HAProxy CA access decision")
    # Execute the real gate with otherwise plausible fields, not a failing JSON
    # decoder. This isolates result completeness from the native probe itself.
    play = {
        "hosts": "localhost", "gather_facts": False,
        "vars": {"openbao_haproxy_selinux_manage": True,
                 "openbao_haproxy_ca_probe": {"stdout": '{"managed": true}'} | probe},
        "tasks": [gate, {"ansible.builtin.fail": {"msg": "UNEXPECTED JSON DECODE"}}],
    }
    result = run_guard(play, tmp_path, command_runner).assert_failure()
    assert "UNEXPECTED JSON DECODE" not in result.stdout


def test_ca_guard_builtin_read_only_contract(repo_root):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / GUARD).read_text())
    assert tasks[0]["ignore_errors"] is False and tasks[0]["ignore_unreachable"] is False
    allowed = {"ansible.builtin.set_fact", "ansible.builtin.stat", "ansible.builtin.slurp",
               "ansible.builtin.assert", "ansible.builtin.command"}
    for task in tasks[0]["block"]:
        actions = [key for key in task if key.startswith("ansible.")]
        assert len(actions) == 1 and actions[0] in allowed
        assert "delegate_to" not in task
        if actions[0] in {"ansible.builtin.stat", "ansible.builtin.slurp", "ansible.builtin.command"}:
            assert task["check_mode"] is False
        if actions[0] == "ansible.builtin.command":
            assert task["changed_when"] is False
            assert task["when"] == "openbao_haproxy_selinux_manage | bool"
            assert task[actions[0]]["argv"][:2] == ["{{ ansible_facts.python.executable }}", "-c"]
            assert task[actions[0]]["argv"][3:] == ["{{ openbao_haproxy_binary_path }}",
                                                   "{{ openbao_haproxy_backend_ca_path }}"]
    block = tasks[0]["block"]
    assert "ansible.builtin.command" in block[-3]
    assert "ansible.builtin.assert" in block[-2]
    assert "from_json" in block[-1]["ansible.builtin.set_fact"]["openbao_haproxy_ca_observation"]["selinux"]
