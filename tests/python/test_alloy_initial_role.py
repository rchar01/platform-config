"""Initial-role bridge: real Ansible and filesystem, fixed command-output spies.

Default tests use a non-UTF-8 synthetic ZIP with an exact-fixture response stub;
this is orchestration evidence, not inventory-parser semantic qualification.
PLATFORM_ALLOY_TEST_PKI_ZIPAPP selects the real reviewed public tools artifact for
all fixtures and enables the explicit parser-semantics and real-copy regressions.
Neither lane needs staged private keys, a native service or a live host.
The independent helper/native suites own authentication and service qualification.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace
import zipfile

import pytest
import yaml
from ansible.errors import AnsibleFilterError
from jinja2 import Environment, StrictUndefined

from test_grafana_alloy_tls import _assert_guard_stat, _events, _evidence_environment


ROLE = "roles/grafana_alloy"
STATE = "/var/lib/platform-config/pki/alloy/process-owner"
HELPER = "/usr/local/libexec/platform-alloy-initial-activate"
LIFECYCLE = "/usr/local/libexec/platform-pki-host-local-lifecycle"
CONTEXT = "/etc/alloy/pki/initial-activation.json"
PREFIXES = {"loki": "grafana_alloy_loki_", "mimir": "grafana_alloy_prometheus_remote_write_"}
REQUEST = "a" * 32


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def bridge(repo_root):
    spec = importlib.util.spec_from_file_location("alloy_initial_role_filter", repo_root / ROLE / "filter_plugins/initial_activation.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def values(repo_root):
    result = yaml.safe_load((repo_root / ROLE / "defaults/main.yml").read_text())
    result.update({"grafana_alloy_enabled": True, "inventory_hostname": "localhost",
                   "grafana_alloy_config_path": "/etc/alloy/config.alloy",
                   "grafana_alloy_environment": "test", "grafana_alloy_vm_name": "collector",
                   "grafana_alloy_ip": "192.0.2.10", "grafana_alloy_platform_role": "vm",
                   "grafana_alloy_initial_writers": {},
                   "grafana_alloy_feature_config": 'prometheus.exporter.unix "fixture" {}\n',
                   "grafana_alloy_external_labels": {"environment": "test"}})
    for name, prefix in PREFIXES.items():
        ca = f"/etc/alloy/pki/{name}-server-ca.crt"
        result["grafana_alloy_initial_writers"][name] = {
            "service": name + "-writer", "trust_id": "reviewed-v1", "ca_file": ca,
            "ca_sha256": digest((name + " CA\n").encode()),
        }
        for key, value in {"url": f"https://{name}.example.invalid/api/push", "ca_file": ca,
                           "server_name": name + ".example.invalid",
                           "client_cert_file": f"/etc/alloy/pki/{name}/tls-versions/{REQUEST}/fullchain.crt",
                           "client_key_file": f"/etc/alloy/pki/{name}/tls-versions/{REQUEST}/tls.key"}.items():
            result[prefix + key] = value
    return result


def reviewed_inventory():
    return {"services": {name + "-writer": {
        "profile": "client-p384-sha384-v1", "target": "localhost", "key_custody": "host-local",
        "subject_cn": name + ".sender", "subject_ou": "Telemetry", "subject_o": "Example", "subject_c": "US",
        "days": 397, "rollback_hold_seconds": 2592000,
        "validation_boundary_sha256": "0" * 64,
    } for name in PREFIXES}}


def inventory_bytes(inventory):
    return (yaml.safe_dump(inventory, sort_keys=False) + "\n").encode()


def parser_artifact(inventory):
    selected = os.environ.get("PLATFORM_ALLOY_TEST_PKI_ZIPAPP")
    if selected:
        return Path(selected).read_bytes()
    # Not a parser implementation: only this exact fixture input is accepted.
    # Real grammar/subject semantics are exercised with the opt-in tools artifact.
    services = [{"name": name, **{field: service[field] for field in
                 ("profile", "target", "key_custody", "days", "rollback_hold_seconds")},
                 "subject_dn": "CN={subject_cn},OU={subject_ou},O={subject_o},C={subject_c}".format(**service)}
                for name, service in inventory["services"].items()]
    source = ("from types import SimpleNamespace\n"
              "def parse_inventory(data):\n"
              f"    if data != {inventory_bytes(inventory)!r}:\n"
              "        raise ValueError('unsupported orchestration fixture bytes')\n"
              f"    return SimpleNamespace(services=[SimpleNamespace(**s) for s in {services!r}])\n")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("platform_pki/inventory.py", source)
        archive.writestr("fixture-binary", b"\x00\xff\x80")
    return buffer.getvalue()


def boundary_inputs(inventory):
    raw = inventory_bytes(inventory)
    artifact = parser_artifact(inventory)
    return {"inventory": raw.decode(), "inventory_sha256": digest(raw),
            "platform_pki": base64.b64encode(artifact).decode(), "platform_pki_sha256": digest(artifact)}


def source_variables(path, data):
    artifact = path.parent / "platform-pki"
    artifact.write_bytes(parser_artifact(reviewed_inventory()))
    return {"grafana_alloy_initial_inventory_src": str(path), "grafana_alloy_initial_inventory_sha256": digest(data),
            "grafana_alloy_initial_platform_pki_src": str(artifact),
            "grafana_alloy_initial_platform_pki_sha256": digest(artifact.read_bytes())}


def render(repo_root, inputs, template):
    env = Environment(undefined=StrictUndefined, trim_blocks=True, keep_trailing_newline=True)
    env.filters["to_json"] = json.dumps
    return env.from_string((repo_root / ROLE / "templates" / template).read_text()).render(inputs)


def test_boundary_matches_pure_helper_and_runtime_normalization_without_target_inputs(bridge, repo_root, monkeypatch):
    inputs = values(repo_root)
    plan = bridge.validate(inputs, True)
    normalized = render(repo_root, {**inputs, **plan["template_vars"]}, "config.alloy.j2")
    config = render(repo_root, inputs, "config.alloy.j2")
    dropin = render(repo_root, inputs, "alloy.service.override.conf.j2")
    inventory = reviewed_inventory()
    expected = bridge.boundary(plan, boundary_inputs(inventory), normalized, dropin)
    h = bridge.helper()
    subjects = {name: f"CN={name}.sender,OU=Telemetry,O=Example,C=US" for name in PREFIXES}
    assert expected == h.boundary_digests("localhost", subjects, plan["writers"], normalized.encode(), dropin.encode())
    # Exercise the production runtime recognizer on final-path template bytes,
    # without Initial.__init__, zipimport, target keys or service I/O.
    initial = h.Initial.__new__(h.Initial)
    initial.context = {"target": "localhost", "writers": plan["writers"], "config_path": h.CONFIG, "dropin_path": h.DROPIN}
    initial.services = {name: SimpleNamespace(subject_dn=subject) for name, subject in subjects.items()}
    initial.lc = SimpleNamespace(validate_dns=lambda value, _label: bridge.dns(value))
    data = {h.CONFIG: config.encode(), h.DROPIN: dropin.encode()}
    data.update({w["ca_file"]: (name + " CA\n").encode() for name, w in plan["writers"].items()})
    initial.read = lambda path, _mode: data[path]
    initial.recheck_sources = lambda: None
    monkeypatch.setattr(h.os, "lstat", lambda _path: SimpleNamespace(st_mode=stat.S_IFREG | 0o600))
    assert initial.config_boundary() == expected
    data[h.CONFIG] = config.replace(REQUEST, "b" * 32).encode()
    assert initial.config_boundary() == expected
    inventory["services"]["loki-writer"]["validation_boundary_sha256"] = expected["loki"]
    assert bridge.boundary(plan, boundary_inputs(inventory), normalized, dropin) == expected
    inventory["services"]["loki-writer"]["subject_o"] = "Other"
    assert bridge.boundary(plan, boundary_inputs(inventory), normalized, dropin)["loki"] != expected["loki"]


def test_controller_source_bytes_are_bounded_exact_and_direct(bridge, isolated_test_dir):
    path = isolated_test_dir / "snapshot.yml"
    data = b"services: {}\n\n"
    path.write_bytes(data)
    variables = source_variables(path, data)
    assert bridge.sources(variables, True)["inventory"].encode() == data
    for bad in ("0" * 64, digest(data.rstrip())):
        with pytest.raises(AnsibleFilterError, match="inputs rejected: sources"):
            bridge.sources({**variables, "grafana_alloy_initial_inventory_sha256": bad}, True)
    link = isolated_test_dir / "link.yml"
    link.symlink_to(path)
    with pytest.raises(AnsibleFilterError):
        bridge.sources({**variables, "grafana_alloy_initial_inventory_src": str(link)}, True)
    link.unlink()
    link.hardlink_to(path)
    with pytest.raises(AnsibleFilterError):
        bridge.sources(variables, True)
    link.unlink()
    path.write_bytes(b"x" * (bridge.helper().MAXIMUM + 1))
    with pytest.raises(AnsibleFilterError):
        bridge.sources(variables, True)
    path.unlink()
    path.mkdir()
    with pytest.raises(AnsibleFilterError):
        bridge.sources(variables, True)


def test_controller_source_read_accepts_stale_atime(bridge, isolated_test_dir):
    path = isolated_test_dir / "snapshot.yml"
    data = b"services: {}\n\n"
    path.write_bytes(data)
    mtime_ns = path.stat().st_mtime_ns
    os.utime(path, ns=(mtime_ns - 48 * 60 * 60 * 1_000_000_000, mtime_ns))
    before = path.stat()
    variables = source_variables(path, data)
    try:
        result = bridge.sources(variables, True)
    finally:
        after = path.stat()
        # Observable on relatime/strictatime mounts; also valid on noatime mounts.
        print(f"Normal source read advanced stale atime: {after.st_atime_ns > before.st_atime_ns}")
    assert result["inventory"].encode() == data
    assert result["inventory_sha256"] == digest(data)
    for field in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns"):
        assert getattr(after, field) == getattr(before, field), field


@pytest.mark.parametrize("mutation", ["replace", "in-place"])
def test_controller_source_rejects_change_during_read(bridge, isolated_test_dir, monkeypatch, mutation):
    path = isolated_test_dir / "snapshot.yml"
    replacement = isolated_test_dir / "replacement.yml"
    data = b"services: {}\n\n"
    path.write_bytes(data)
    replacement.write_bytes(data)
    before = path.stat()
    original_read = os.read
    mutated = False

    def read_and_mutate(fd, size):
        nonlocal mutated
        chunk = original_read(fd, size)
        if chunk and not mutated and os.fstat(fd).st_ino == before.st_ino:
            mutated = True
            if mutation == "replace":
                # Identical bytes and digest still cannot authorize a new inode.
                os.replace(replacement, path)
            else:
                with path.open("r+b") as stream:
                    stream.write(b"services: []\n\n")
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
        return chunk

    monkeypatch.setattr(bridge.os, "read", read_and_mutate)
    variables = source_variables(path, data)
    with pytest.raises(AnsibleFilterError, match="inputs rejected: sources"):
        bridge.sources(variables, True)
    assert mutated
    assert (path.stat().st_ino != before.st_ino) == (mutation == "replace")


COMMAND_SPY = '''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        argv = args['argv']
        with Path(task_vars['fixture_events']).open('a') as stream:
            stream.write(json.dumps({'argv': argv, 'check': self._task.check_mode}) + '\\n')
        if argv == ['/usr/bin/systemctl', 'show', 'alloy.service', '--no-pager',
                    '--property=LoadState,ActiveState,UnitFileState,FragmentPath,SourcePath']:
            lines = task_vars['fixture_stage_lines']
            return dict(changed=False, rc=0, stdout='\\n'.join(lines), stdout_lines=lines)
        if argv == ['/usr/bin/systemctl', 'show', 'alloy.service', '--no-pager',
                    '--property=LoadState,FragmentPath,SourcePath,DropInPaths,NeedDaemonReload,ActiveState,UnitFileState']:
            lines = ['LoadState=loaded', 'FragmentPath=/usr/lib/systemd/system/alloy.service', 'SourcePath=',
                     'DropInPaths=/etc/systemd/system/alloy.service.d/platform.conf', 'NeedDaemonReload=no',
                     'ActiveState=' + task_vars.get('fixture_active', 'inactive'), 'UnitFileState=disabled']
            return dict(changed=False, rc=0, stdout='\\n'.join(lines), stdout_lines=lines)
        assert argv[0] == '/usr/local/libexec/platform-alloy-initial-activate', argv
        if argv[1] == 'renewal-preflight':
            assert argv[2:] == ['--config', '/etc/alloy/pki/initial-activation.json',
                               '--writer', task_vars['grafana_alloy_renewal_writer']], argv
            return dict(changed=False, rc=task_vars.get('fixture_rc', 0),
                        stdout=task_vars.get('fixture_stdout', json.dumps(task_vars['fixture_outcome'])),
                        stderr=task_vars.get('fixture_stderr', ''))
        assert argv[1] in ('check', 'activate', 'status', 'recover'), argv
        assert argv[2:] == ['--config', '/etc/alloy/pki/initial-activation.json'], argv
        outcome = task_vars.get('fixture_outcome', {'schema': 1, 'status': 'prepared', 'changed': False})
        return dict(changed=False, rc=task_vars.get('fixture_rc', 0), stdout=json.dumps(outcome), stderr='fixture rejection')
'''

FORBIDDEN_SPY = '''
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        raise AssertionError('Forbidden ordinary mutation: ' + self._task.action)
'''

POLICY_SPY = '''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        with Path(task_vars['fixture_events']).open('a') as stream:
            stream.write(json.dumps({'policy': self._task.get_name(), 'args': self._task.args,
                                     'check': self._task.check_mode}) + '\\n')
        return dict(changed=False, rc=0, stdout='', stderr='',
                    path=task_vars['fixture_target'] + '/policy-temp')
'''


@pytest.fixture
def role_case(repo_root, isolated_test_dir, namespace_root_runner):
    root = isolated_test_dir
    role = root / ROLE
    shutil.copytree(repo_root / ROLE, role)
    source = root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    source.parent.mkdir(parents=True)
    shutil.copyfile(repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle", source)
    target = root / "target"
    target.mkdir(mode=0o755)
    lifecycle = target / LIFECYCLE.lstrip("/")
    lifecycle.parent.mkdir(parents=True)
    lifecycle.write_bytes(source.read_bytes())
    lifecycle.chmod(0o755)
    plugins = role / "action_plugins"
    plugins.mkdir()
    (plugins / "fixture_command.py").write_text(COMMAND_SPY)
    (plugins / "fixture_forbidden.py").write_text(FORBIDDEN_SPY)
    policy_role = root / "roles/rocky_repository_policy"
    shutil.copytree(repo_root / "roles/rocky_repository_policy", policy_role)
    policy_plugins = policy_role / "action_plugins"
    policy_plugins.mkdir()
    (policy_plugins / "fixture_policy.py").write_text(POLICY_SPY)
    # Preserve the dependency's real selectors/assertions and every task, but
    # record its target operations rather than inspecting container repositories.
    policy_tasks = policy_role / "tasks/main.yml"
    policy_source = policy_tasks.read_text()
    for module in ("tempfile", "copy", "command", "file"):
        policy_source = policy_source.replace("ansible.builtin." + module + ":", "fixture_policy:")
    policy_tasks.write_text(policy_source)
    # Keep all real guards, loops, includes, assertions, content hashes and modes.
    # Redirect filesystem module path slots into one synthetic host tree, and
    # replace only commands/service/package/native-render actions with spies.
    def redirect(tasks):
        for task in tasks:
            for key in ("block", "rescue", "always"):
                if key in task:
                    redirect(task[key])
            for module, field in (("stat", "path"), ("file", "path"), ("copy", "dest"), ("find", "paths")):
                args = task.get("ansible.builtin." + module)
                if args:
                    args[field] = "{{ fixture_target }}" + args[field]
            # find output must still be evaluated in the role's fixed namespace.
            if "ansible.builtin.find" in task:
                task["register"] = "fixture_find"
                task_index = tasks.index(task)
                tasks.insert(task_index + 1, {"name": "Translate synthetic find paths", "ansible.builtin.set_fact": {
                    "grafana_alloy_initial_retained": "{{ fixture_find | to_json | replace(fixture_target, '') | from_json }}"}})
            for module in ("command", "systemd_service", "dnf", "get_url", "template", "package"):
                key = "ansible.builtin." + module
                if key in task:
                    task["fixture_command" if module == "command" else "fixture_forbidden"] = task.pop(key)
    for folder in ("tasks", "handlers"):
        for path in (role / folder).glob("*.yml"):
            tasks = yaml.safe_load(path.read_text())
            redirect(tasks)
            path.write_text(yaml.safe_dump(tasks, sort_keys=False))
    inputs = values(repo_root)
    config = target / "etc/alloy/config.alloy"
    dropin = target / "etc/systemd/system/alloy.service.d/platform.conf"
    for destination, template, mode in ((config, "config.alloy.j2", 0o640),
                                         (dropin, "alloy.service.override.conf.j2", 0o644)):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(render(repo_root, inputs, template).encode("utf-8"))
        destination.chmod(mode)
    snapshot = root / "reviewed.yml"
    snapshot.write_bytes(inventory_bytes(reviewed_inventory()))
    artifact = root / "platform-pki"
    artifact.write_bytes(parser_artifact(reviewed_inventory()))
    inputs.update({"grafana_alloy_initial_inventory_src": str(snapshot),
                   "grafana_alloy_initial_inventory_sha256": digest(snapshot.read_bytes()),
                   "grafana_alloy_initial_platform_pki_src": str(artifact),
                   "grafana_alloy_initial_platform_pki_sha256": digest(artifact.read_bytes()),
                   "fixture_target": str(target), "fixture_events": str(root / "events.jsonl"),
                   "rocky_repository_policy_enabled": True,
                   "rocky_repository_policy_releasever": "10",
                   "rocky_repository_policy": {"fixture": {"enabled": True}}})
    events_file = root / "events.jsonl"
    evidence_dir = root / "evidence"
    evidence_dir.mkdir()
    environment = {**_evidence_environment(repo_root, evidence_dir),
                   "ANSIBLE_ROLES_PATH": str(root / "roles") + ":" + str(repo_root / "roles")}
    callback = evidence_dir / "callback_plugins/alloy_tls_evidence.py"
    callback.write_text(callback.read_text().replace('"action": result._task.action,', '''
            "action": result._task.action,
            "no_log": bool(result._task.no_log),
            "public_msg": value.get("msg") if result._task.action == "ansible.builtin.debug" else None,'''))

    def observations():
        return _events(evidence_dir)

    def run(entry, *, overrides=None, check=False, limit="localhost", tasks=None, extra_vars=None):
        if events_file.exists():
            events_file.unlink()
        evidence_file = evidence_dir / "events.jsonl"
        if evidence_file.exists():
            evidence_file.unlink()
        play = root / "play.yml"
        play.write_text(yaml.safe_dump([{
            "hosts": "localhost", "connection": "local", "gather_facts": False,
            "vars": {**inputs, **(overrides or {})},
            "tasks": tasks or [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": entry}}],
        }], sort_keys=False))
        result = namespace_root_runner.run([
            "ansible-playbook", "-i", "localhost,", play,
            *(["--limit", limit] if limit is not None else []), *(["--check", "--diff"] if check else []),
            *(["--extra-vars", extra_vars] if extra_vars is not None else []),
        ], timeout=180, environment=environment)
        events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
        return result, events

    return SimpleNamespace(**locals())


def tree(path):
    return {str(p.relative_to(path)): (p.lstat().st_mode, p.read_bytes() if p.is_file() and not p.is_symlink() else None)
            for p in path.rglob("*")}


def test_boundary_is_controller_only_before_csr_without_target_inputs(role_case, bridge):
    c = role_case
    before = tree(c.target)
    changes = {}
    for prefix in PREFIXES.values():
        changes.update({prefix + "client_cert_file": "", prefix + "client_key_file": ""})
    result, events = c.run("initial_boundary.yml", overrides=changes, check=True)
    result.assert_success()
    assert events == [] and tree(c.target) == before
    assert all(event["action"] in {"ansible.builtin.include_role", "ansible.builtin.set_fact", "ansible.builtin.debug"}
               for event in c.observations()), c.observations()
    assert "changed=0" in result.stdout
    plan = bridge.validate(c.inputs, True)
    normalized = render(c.repo_root, {**c.inputs, **plan["template_vars"]}, "config.alloy.j2")
    dropin = render(c.repo_root, c.inputs, "alloy.service.override.conf.j2")
    expected = bridge.boundary(plan, boundary_inputs(reviewed_inventory()), normalized, dropin)
    assert all(value in result.stdout for value in expected.values())
    assert "subject_cn" not in result.stdout and "Telemetry" not in result.stdout


@pytest.mark.parametrize("bad", ["missing", "wrong-sha", "not-a-zip", "missing-module"])
def test_boundary_rejects_missing_or_wrong_artifact_without_target_io(role_case, bad):
    c = role_case
    overrides = {}
    if bad == "missing":
        overrides["grafana_alloy_initial_platform_pki_src"] = ""
    elif bad == "wrong-sha":
        overrides["grafana_alloy_initial_platform_pki_sha256"] = "0" * 64
    else:
        if bad == "not-a-zip":
            c.artifact.write_bytes(b"not a zipapp\n")
        else:
            with zipfile.ZipFile(c.artifact, "w") as archive:
                archive.writestr("unrelated.py", "raise AssertionError('must not execute')\n")
        overrides["grafana_alloy_initial_platform_pki_sha256"] = digest(c.artifact.read_bytes())
    before = tree(c.target)
    result, events = c.run("initial_boundary.yml", check=True, overrides=overrides)
    result.assert_failure()
    assert events == [] and tree(c.target) == before
    assert all(event["action"] in {"ansible.builtin.include_role", "ansible.builtin.set_fact"}
               for event in c.observations()), c.observations()


def test_boundary_rechecks_snapshot_hashes_before_loading_parser(bridge, repo_root, monkeypatch):
    inputs = values(repo_root)
    plan = bridge.validate(inputs, True)
    config = render(repo_root, {**inputs, **plan["template_vars"]}, "config.alloy.j2")
    dropin = render(repo_root, inputs, "alloy.service.override.conf.j2")
    snapshot = boundary_inputs(reviewed_inventory())
    calls = []

    def reject_unverified_load(artifact):
        calls.append(artifact)
        raise AssertionError("unverified parser execution")

    monkeypatch.setattr(bridge.helper(), "load_inventory_parser", reject_unverified_load)
    for override in ({"inventory": snapshot["inventory"] + "\n"}, {"inventory_sha256": "0" * 64},
                     {"platform_pki": base64.b64encode(b"replacement").decode()}, {"platform_pki_sha256": "0" * 64},
                     {"platform_pki": "not-base64!"}):
        with pytest.raises(AnsibleFilterError, match="inputs rejected: boundary"):
            bridge.boundary(plan, {**snapshot, **override}, config, dropin)
    assert calls == []


def test_prepare_exact_bytes_repeat_and_read_only_entrypoints(role_case):
    c = role_case
    result, events = c.run("initial_prepare.yml")
    result.assert_success()
    assert [e["argv"][1] for e in events] == ["show", "check"]
    assert c.lifecycle.read_bytes() == c.source.read_bytes()
    assert (c.target / "usr/local/bin/platform-pki").read_bytes() == c.artifact.read_bytes()
    assert (c.target / "etc/alloy/pki/inventory.yml").read_bytes() == c.snapshot.read_bytes()
    assert (c.target / CONTEXT.lstrip("/")).stat().st_mode & 0o777 == 0o600
    assert (c.target / STATE.lstrip("/")).stat().st_mode & 0o777 == 0o700
    assert (c.target / STATE.lstrip("/") / "lock").read_bytes() == b""
    before = tree(c.target)
    for entry, check in (("initial_prepare.yml", False), ("initial_check.yml", True), ("initial_status.yml", True)):
        result, events = c.run(entry, check=check)
        result.assert_success()
        assert "changed=0" in result.stdout and tree(c.target) == before
        assert all(not e["check"] for e in events)
        assert "inventory_sha256" in result.stdout and digest(c.snapshot.read_bytes()) in result.stdout


@pytest.mark.skipif(not os.environ.get("PLATFORM_ALLOY_TEST_PKI_ZIPAPP"),
                    reason="requires the real tools inventory parser")
def test_real_inventory_parser_preserves_yaml_looking_subjects(role_case, bridge):
    c = role_case
    artifact = Path(os.environ["PLATFORM_ALLOY_TEST_PKI_ZIPAPP"])
    raw = (c.snapshot.read_bytes().replace(b"subject_cn: loki.sender", b"subject_cn: 17")
           .replace(b"subject_ou: Telemetry", b"subject_ou: true")
           .replace(b"subject_o: Example", b"subject_o: 0017")
           .replace(b"subject_c: US", b"subject_c: NO"))
    c.snapshot.write_bytes(raw)
    pin = digest(raw)
    parsed = bridge.helper().load_inventory_parser(artifact.read_bytes()).parse_inventory(raw)
    services = {service.name: service for service in parsed.services}
    assert services["loki-writer"].subject_dn == "CN=17,OU=true,O=0017,C=NO"
    plan = bridge.validate(c.inputs, True)
    normalized = render(c.repo_root, {**c.inputs, **plan["template_vars"]}, "config.alloy.j2")
    dropin = render(c.repo_root, c.inputs, "alloy.service.override.conf.j2")
    expected = bridge.helper().boundary_digests(
        plan["target"], {name: services[writer["service"]].subject_dn for name, writer in plan["writers"].items()},
        plan["writers"], normalized.encode(), dropin.encode())
    before = tree(c.target)
    result, events = c.run("initial_boundary.yml", check=True, overrides={
        "grafana_alloy_initial_inventory_sha256": pin,
        "grafana_alloy_initial_platform_pki_src": str(artifact),
        "grafana_alloy_initial_platform_pki_sha256": digest(artifact.read_bytes()),
    })
    result.assert_success()
    assert all(value in result.stdout for value in expected.values())
    assert "CN=17" not in result.stdout and "subject_c" not in result.stdout
    assert events == [] and tree(c.target) == before
    assert c.snapshot.read_bytes() == raw and digest(c.snapshot.read_bytes()) == pin


@pytest.mark.skipif(not os.environ.get("PLATFORM_ALLOY_TEST_PKI_ZIPAPP"),
                    reason="requires the real tools inventory parser")
def test_real_inventory_parser_rejects_unselected_invalid_policy(role_case):
    c = role_case
    raw = c.snapshot.read_bytes() + b"  unselected-service:\n    profile: unsupported\n"
    c.snapshot.write_bytes(raw)
    before = tree(c.target)
    result, events = c.run("initial_boundary.yml", check=True,
                           overrides={"grafana_alloy_initial_inventory_sha256": digest(raw)})
    result.assert_failure()
    assert events == [] and tree(c.target) == before
    assert c.snapshot.read_bytes() == raw
    failed = [event for event in c.observations() if event["status"] == "failed"]
    assert len(failed) == 1 and failed[0]["name"].endswith("Generate Grafana Alloy pre-CSR writer boundary digests")


@pytest.mark.skipif(not os.environ.get("PLATFORM_ALLOY_TEST_PKI_ZIPAPP"),
                    reason="requires the generated platform-tools platform-pki zipapp")
def test_prepare_copies_real_platform_pki_zipapp_exactly(role_case):
    c = role_case
    source = Path(os.environ["PLATFORM_ALLOY_TEST_PKI_ZIPAPP"])
    assert not source.is_symlink() and source.is_file()
    with zipfile.ZipFile(source) as archive:
        assert "platform_pki/inventory.py" in archive.namelist()
    expected = source.read_bytes()
    expected_sha256 = digest(expected)
    result, events = c.run("initial_prepare.yml", overrides={
        "grafana_alloy_initial_platform_pki_src": str(source),
        "grafana_alloy_initial_platform_pki_sha256": expected_sha256,
    })
    result.assert_success()
    assert [event["argv"][1] for event in events] == ["show", "check"]
    installed = c.target / "usr/local/bin/platform-pki"
    assert installed.read_bytes() == expected
    assert digest(installed.read_bytes()) == expected_sha256
    assert stat.S_ISREG(installed.lstat().st_mode)
    assert stat.S_IMODE(installed.lstat().st_mode) == 0o755
    context = json.loads((c.target / CONTEXT.lstrip("/")).read_text())
    assert context["platform_pki_path"] == "/usr/local/bin/platform-pki"
    assert context["platform_pki_sha256"] == expected_sha256


@pytest.mark.parametrize("injected_action", ["activate", "recover"])
def test_fixed_entries_ignore_extra_vars_action_override(role_case, injected_action):
    c = role_case
    for entry, expected in (("prepare", ["show", "check"]), ("check", ["check"]), ("status", ["status"])):
        result, events = c.run(f"initial_{entry}.yml", extra_vars=f"grafana_alloy_initial_action={injected_action}")
        assert [event["argv"][1] for event in events] == expected
        result.assert_success()
        assert all(not event["check"] for event in events)
        assert not any(event["argv"][1] in ("activate", "recover") for event in events)


def test_initial_commands_are_literal_and_reporting_is_command_free(repo_root):
    tasks_dir = repo_root / ROLE / "tasks"
    for entry, action in (("prepare", "check"), ("check", "check"), ("status", "status"),
                          ("activate", "activate"), ("recover", "recover")):
        tasks = yaml.safe_load((tasks_dir / f"initial_{entry}.yml").read_text())
        commands = [task for task in tasks if task.get("ansible.builtin.command", {}).get("argv", [None])[0] == HELPER]
        assert len(commands) == 1
        assert commands[0]["ansible.builtin.command"]["argv"] == [HELPER, action, "--config", CONTEXT]
        assert commands[0]["check_mode"] is False
        if action in ("check", "status"):
            assert commands[0]["changed_when"] is False
        else:
            assert f"grafana_alloy_initial_outcome('{action}')" in commands[0]["changed_when"]
        outcomes = [task["ansible.builtin.set_fact"]["grafana_alloy_initial_result"] for task in tasks
                    if "grafana_alloy_initial_result" in task.get("ansible.builtin.set_fact", {})]
        assert len(outcomes) == 1 and f"grafana_alloy_initial_outcome('{action}')" in outcomes[0]
    assert all("ansible.builtin.debug" in task for task in yaml.safe_load((tasks_dir / "initial_report.yml").read_text()))
    assert not (tasks_dir / "initial_run.yml").exists()
    assert all("grafana_alloy_initial_action" not in path.read_text() for path in tasks_dir.glob("initial_*.yml"))


def test_actual_entry_chain_active_and_recovery_outcomes(role_case):
    c = role_case
    c.run("initial_prepare.yml")[0].assert_success()
    before = tree(c.target)
    cases = [
        ("activate", "complete", True), ("activate", "complete", False),
        ("check", "complete", False), ("status", "complete", False),
        ("status", "recovery-required", False), ("recover", "failed", True),
        ("recover", "failed", False), ("recover", "prepared", False), ("recover", "complete", False),
    ]
    tasks = []
    for action, status, changed in cases:
        tasks += [{"ansible.builtin.include_role": {"name": str(c.role), "tasks_from": f"initial_{action}.yml"},
                   "vars": {"fixture_outcome": {"schema": 1, "status": status, "changed": changed}}},
                  {"ansible.builtin.assert": {"that": [f"grafana_alloy_initial_result.status == '{status}'",
                                                       f"grafana_alloy_initial_result.changed == {changed}"]}}]
    result, events = c.run("unused", tasks=tasks, overrides={"grafana_alloy_service_enabled": True,
                                                           "grafana_alloy_service_state": "started"},
                           extra_vars="grafana_alloy_initial_action=status")
    result.assert_success()
    assert [e["argv"][1] for e in events] == [case[0] for case in cases]
    assert all(not e["check"] for e in events)
    assert "Initial activation remains failed" in result.stdout
    assert tree(c.target) == before


@pytest.mark.parametrize("action,changes", [
    pytest.param("prepare", {"grafana_alloy_loki_url": "https://other.example.invalid/api/push"}, id="prepare-url"),
    pytest.param("prepare", {"grafana_alloy_external_labels": {"environment": "other"}}, id="prepare-labels"),
    pytest.param("prepare", {"grafana_alloy_feature_config": 'prometheus.exporter.unix "other" {}'}, id="prepare-feature"),
    pytest.param("activate", {"grafana_alloy_prometheus_remote_write_url": "https://other.example.invalid/api/push"}, id="activate-url"),
    pytest.param("activate", {"grafana_alloy_loki_server_name": "other.example.invalid"}, id="activate-sni"),
    pytest.param("check", {"grafana_alloy_external_labels": {"environment": "other"}}, id="check-labels"),
    pytest.param("status", {"grafana_alloy_feature_config": 'prometheus.exporter.unix "other" {}'}, id="status-feature"),
    pytest.param("recover", {"grafana_alloy_prometheus_remote_write_server_name": "other.example.invalid"}, id="recover-sni"),
])
def test_current_desired_config_drift_rejected_without_mutation(role_case, action, changes):
    c = role_case
    if action != "prepare":
        c.run("initial_prepare.yml")[0].assert_success()
    before = tree(c.target)
    old_config = c.config.read_bytes()
    old_dropin = c.dropin.read_bytes()
    assert render(c.repo_root, {**c.inputs, **changes}, "config.alloy.j2").encode() != old_config
    overrides = dict(changes)
    if action == "activate":
        overrides.update(grafana_alloy_service_enabled=True, grafana_alloy_service_state="started")
    result, events = c.run(f"initial_{action}.yml", overrides=overrides, check=action in ("check", "status"))
    result.assert_failure()
    assert [event["argv"][1] for event in events] == (["show"] if action == "prepare" else [])
    failed = [event for event in c.observations() if event["status"] == "failed"]
    assert len(failed) == 1 and failed[0]["name"].endswith("Reject any existing immutable source or context drift"), failed
    assert not any(event["action"] in {"ansible.builtin.copy", "ansible.builtin.file", "fixture_forbidden"}
                   for event in c.observations())
    assert c.config.read_bytes() == old_config and c.dropin.read_bytes() == old_dropin
    assert tree(c.target) == before


@pytest.mark.parametrize("filename", ["config", "dropin"])
@pytest.mark.parametrize("drift", ["missing", "trailing-newline"])
def test_prepare_requires_exact_config_and_dropin_without_copy_or_repair(role_case, filename, drift):
    c = role_case
    path = getattr(c, filename)
    if drift == "missing":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b"\n")
    before = tree(c.target)
    result, events = c.run("initial_prepare.yml")
    result.assert_failure()
    assert [event["argv"][1] for event in events] == ["show"]
    failed = [event for event in c.observations() if event["status"] == "failed"]
    expected = ("Reject missing prerequisites and unsafe immutable file metadata" if drift == "missing"
                else "Reject any existing immutable source or context drift")
    assert len(failed) == 1 and failed[0]["name"].endswith(expected), failed
    assert not any(event["action"] in {"ansible.builtin.copy", "ansible.builtin.file", "fixture_forbidden"}
                   for event in c.observations())
    assert tree(c.target) == before


def test_invalid_vars_batched_through_real_boundary_before_target_io(role_case):
    c = role_case
    cases = []
    for field in ("grafana_alloy_enabled", "grafana_alloy_service_enabled"):
        for bad in ("true", 1, None, []):
            cases.append({field: bad})
    cases += [{"grafana_alloy_initial_writers": value} for value in ({}, [], "loki", {"other": {}})]
    for name, prefix in PREFIXES.items():
        for field, value in (("url", "http://unsafe.test"), ("url", "https://user@unsafe.test"),
                             ("url", "https://host.test/?query=yes"), ("url", "https://host.test:0"),
                             ("url", []), ("server_name", "bad..name"), ("ca_file", "/etc/other.pem"),
                             ("client_key_file", False)):
            cases.append({prefix + field: value})
        for field, value in (("trust_id", "../unsafe"), ("ca_sha256", "bad"), ("service", "../service")):
            writers = copy.deepcopy(c.inputs["grafana_alloy_initial_writers"])
            writers[name][field] = value
            cases.append({"grafana_alloy_initial_writers": writers})
        for path in (CONTEXT, "/etc/alloy/pki/inventory.yml", "/etc/alloy/pki/loki/tls-pending/ca.crt",
                     "/etc/alloy/pki/mimir/tls-versions/ca.crt", "/etc/alloy/pki/../unsafe.crt"):
            writers = copy.deepcopy(c.inputs["grafana_alloy_initial_writers"])
            writers[name]["ca_file"] = path
            cases.append({"grafana_alloy_initial_writers": writers, prefix + "ca_file": path})
    cases += [{"grafana_alloy_prometheus_remote_write_bearer_token_file": "/etc/token"},
              {"grafana_alloy_http_listen_port": "12345"}, {"grafana_alloy_storage_dir": "/other"},
              {"grafana_alloy_service_state": "restarted"}]
    case_file = c.root / "invalid-case.yml"
    case_file.write_text(yaml.safe_dump([
        {"ansible.builtin.set_fact": {"fixture_rejected": False}},
        {"block": [{"ansible.builtin.include_role": {"name": str(c.role), "tasks_from": "initial_boundary.yml"},
                    "vars": {key: "{{ fixture_case.get('" + key + "', fixture_base['" + key + "']) }}" for key in c.inputs}}],
         "rescue": [{"ansible.builtin.set_fact": {"fixture_rejected": True}}]},
        {"ansible.builtin.assert": {"that": ["fixture_rejected"]}},
    ], sort_keys=False))
    result, events = c.run("unused", overrides={"fixture_base": c.inputs}, tasks=[{
        "ansible.builtin.include_tasks": str(case_file), "loop": cases,
        "loop_control": {"loop_var": "fixture_case", "label": "invalid-input"},
    }])
    result.assert_success()
    assert events == []
    assert not (c.target / STATE.lstrip("/")).exists()


@pytest.mark.parametrize("entry,overrides,check,limit", [
    ("initial_prepare.yml", {"grafana_alloy_enabled": False}, False, "localhost"),
    ("initial_prepare.yml", {"grafana_alloy_service_enabled": "false"}, False, "localhost"),
    ("initial_prepare.yml", {}, True, "localhost"),
    ("initial_prepare.yml", {}, False, "all"),
    ("initial_activate.yml", {}, False, "localhost"),
    ("initial_activate.yml", {"grafana_alloy_service_enabled": True, "grafana_alloy_service_state": "started"}, True, "localhost"),
    ("initial_recover.yml", {}, True, "localhost"),
    ("initial_recover.yml", {}, False, None),
])
def test_mutating_entry_intent_rejected_before_any_io(role_case, entry, overrides, check, limit):
    before = tree(role_case.target)
    result, events = role_case.run(entry, overrides=overrides, check=check, limit=limit,
                                  extra_vars="grafana_alloy_initial_action=activate")
    result.assert_failure()
    assert events == [] and tree(role_case.target) == before


def test_observed_active_prepare_rejected_before_writes(role_case):
    before = tree(role_case.target)
    result, events = role_case.run("initial_prepare.yml", overrides={"fixture_active": "active"})
    result.assert_failure()
    assert [e["argv"][1] for e in events] == ["show"]
    assert tree(role_case.target) == before


@pytest.mark.parametrize("drift", ["digest", "mode", "symlink", "hardlink", "ancestor", "journal", "complete", "failed", "unknown"])
def test_prepare_retains_immutable_drift_and_records_without_repair(role_case, drift):
    c = role_case
    c.run("initial_prepare.yml")[0].assert_success()
    context = c.target / CONTEXT.lstrip("/")
    if drift == "digest":
        context.write_bytes(context.read_bytes() + b"\n")
    elif drift == "mode":
        context.chmod(0o644)
    elif drift == "symlink":
        context.unlink()
        context.symlink_to(c.snapshot)
    elif drift == "hardlink":
        (c.root / "context-link").hardlink_to(context)
    elif drift == "ancestor":
        parent = context.parent
        parent.rename(c.target / "retained-pki")
        parent.symlink_to(c.target / "retained-pki", target_is_directory=True)
    else:
        record = c.target / STATE.lstrip("/") / (drift + ".json")
        record.write_text("retained")
        record.chmod(0o600)
    before = tree(c.target)
    result, events = c.run("initial_prepare.yml")
    result.assert_failure()
    assert [e["argv"][1] for e in events] == ["show"]
    assert tree(c.target) == before


@pytest.mark.parametrize("entry", ["main.yml", "preflight.yml", "restart", "reload"])
@pytest.mark.parametrize("marker", ["directory", "dangling-symlink"])
def test_ordinary_main_preflight_and_real_handlers_fail_closed_even_disabled_check(role_case, entry, marker):
    c = role_case
    state = c.target / STATE.lstrip("/")
    state.parent.mkdir(parents=True)
    if marker == "directory":
        state.mkdir(mode=0o700)
    else:
        state.symlink_to(c.target / "missing")
    before = tree(c.target)
    tasks = None
    if entry in ("restart", "reload"):
        tasks = [
            # Load the shipped handlers without executing ordinary convergence.
            {"ansible.builtin.include_role": {"name": str(c.role), "tasks_from": "initial_boundary.yml"}},
            {"ansible.builtin.debug": {"msg": "Notify the real role handler"}, "changed_when": True,
             "notify": "Restart Grafana Alloy" if entry == "restart" else "Reload systemd"},
            {"ansible.builtin.meta": "flush_handlers"},
        ]
    result, events = c.run(entry, tasks=tasks, check=True, overrides={"grafana_alloy_enabled": False})
    result.assert_failure()
    assert "ordinary convergence and handlers cannot bypass takeover" in result.stdout
    assert events == [] and tree(c.target) == before
    observed = c.observations()
    assert all(event["action"] in {"ansible.builtin.include_role", "ansible.builtin.set_fact", "ansible.builtin.debug",
                                   "ansible.builtin.meta", "ansible.builtin.include_tasks", "ansible.builtin.stat",
                                   "ansible.builtin.assert"} for event in observed), observed
    target_reads = [event for event in observed if event["action"] == "ansible.builtin.stat"]
    assert len(target_reads) == 1, observed
    _assert_guard_stat(target_reads[0], path=str(state))
    assert observed.index(target_reads[0]) < next(i for i, event in enumerate(observed) if event["status"] == "failed")


def test_ordinary_convergence_runs_policy_after_inputs_and_preserves_public_defaults(role_case):
    c = role_case
    # This ordinary disabled-role case has no previously managed service owner.
    c.dropin.unlink()
    result, events = c.run("main.yml", overrides={"grafana_alloy_enabled": False}, tasks=[
        {"ansible.builtin.include_role": {"name": str(c.role), "public": True}},
        {"ansible.builtin.assert": {"that": [
            "rocky_repository_policy_enabled is sameas true",
            "rocky_repository_policy_allow_http is sameas false",
            "rocky_repository_policy_releasever == '10'",
            "rocky_repository_policy == {'fixture': {'enabled': true}}",
        ]}},
    ])
    result.assert_success()
    assert len(events) == 4 and all("policy" in event for event in events), events
    assert events[0]["args"] == {"state": "directory", "prefix": "platform-rocky-repository-policy."}
    assert events[1]["args"]["src"] == "platform-rocky-repository-policy"
    assert events[2]["args"]["argv"][0] == "/usr/bin/python3"
    assert events[3]["args"]["state"] == "absent"
    observed = c.observations()
    first_policy = next(i for i, event in enumerate(observed) if event["action"] == "fixture_policy")
    assert any(event["name"].endswith("Validate Grafana Alloy lifecycle selector") for event in observed[:first_policy])
    guards = [event for event in observed[:first_policy] if event["action"] == "ansible.builtin.stat"]
    assert len(guards) == 2
    for event in guards:
        _assert_guard_stat(event, path=str(c.target / STATE.lstrip("/")))


def test_status_schema_rejects_invented_fields_and_wrong_types(bridge):
    valid = {"schema": 1, "status": "prepared", "changed": False}
    assert bridge.outcome(valid, "status") == valid
    for value in ({**valid, "schema": True}, {**valid, "changed": "false"}, {**valid, "sources": {}},
                  {**valid, "status": "success"}, {**valid, "changed": True}):
        with pytest.raises(AnsibleFilterError):
            bridge.outcome(value, "status")


def test_no_implicit_prepare_recover_or_success_on_command_failure(role_case):
    c = role_case
    active = {"grafana_alloy_service_enabled": True, "grafana_alloy_service_state": "started"}
    before = tree(c.target)
    result, events = c.run("initial_activate.yml", overrides=active)
    result.assert_failure()
    assert events == [] and tree(c.target) == before
    c.run("initial_prepare.yml")[0].assert_success()
    before = tree(c.target)
    for override in ({"fixture_rc": 1}, {"fixture_outcome": {"schema": 1, "status": "failed", "changed": True}},
                     {"fixture_outcome": {"schema": 1, "status": "complete", "changed": "false"}}):
        result, events = c.run("initial_activate.yml", overrides={**active, **override})
        result.assert_failure()
        assert [e["argv"][1] for e in events] == ["activate"]
        assert tree(c.target) == before


def renewal_observation(context, writer="loki"):
    observed = 1800000000
    entries = {}
    for index, (name, configured) in enumerate(context["writers"].items()):
        request_id = ("a" if name == "loki" else "b") * 32
        entries[name] = {
            "service": configured["service"], "profile": "client-p384-sha384-v1",
            "subject_dn": f"CN={name}.sender,OU=Telemetry,O=Example,C=US",
            "request_id": request_id, "request_sha256": digest((name + " request").encode()),
            "certificate_sha256": digest((name + " leaf").encode()),
            "certificate_spki_sha256": digest((name + " spki").encode()),
            "version_path": configured["versions_root"] + "/" + request_id,
            "validation_boundary_sha256": digest((name + " boundary").encode()),
            "rollback_hold_seconds": 2592000,
            "leaf_not_after_epoch": observed + 4000000 + index,
            "client_chain_not_after_epoch": observed + 5000000 - 2000000 * index,
            "remaining_lifetime_seconds": 4000000 if index == 0 else 3000000,
        }
    return {
        "schema": 1, "kind": "alloy-initial-renewal-preflight", "status": "predecessor-verified",
        "changed": False, "target": context["target"], "writer": writer,
        "initial_receipt_sha256": digest(b"initial receipt"), "inventory_sha256": context["inventory_sha256"],
        "observed_at_epoch": observed, "writers": entries,
    }


def test_renewal_outcome_batched_strict_schema_and_bindings(bridge, repo_root):
    inputs = values(repo_root)
    assert inputs["grafana_alloy_renewal_writer"] == ""
    context = {**bridge.validate(inputs), "inventory_sha256": digest(b"inventory")}
    valid = renewal_observation(context)
    filters = bridge.FilterModule().filters()
    assert filters["grafana_alloy_initial_renewal_outcome"] == bridge.renewal_outcome
    for selected in PREFIXES:
        outcome = {**valid, "writer": selected}
        assert bridge.renewal_outcome(outcome, context, selected) == outcome
        single_context = {**context, "writers": {selected: context["writers"][selected]}}
        single = {**outcome, "writers": {selected: outcome["writers"][selected]}}
        assert bridge.renewal_outcome(single, single_context, selected) == single

    cases = [None, [], "predecessor-verified", {**valid, "extra": "unexpected"}]
    for key in valid:
        cases.append({field: value for field, value in valid.items() if field != key})
    for field, replacements in {
        "schema": [True, False, "1", 1.0, 2], "kind": [None, "alloy-initial"],
        "status": ["complete", "failed", True], "changed": [True, 0, "false", None],
        "target": ["other-host", None], "writer": ["mimir", "other", None, []],
        "initial_receipt_sha256": ["A" * 64, "a" * 63, 0],
        "inventory_sha256": ["0" * 64, "bad", None],
        "observed_at_epoch": [True, False, 0, -1, "1800000000", 1800000000.0],
        "writers": [[], {}, {"loki": valid["writers"]["loki"]},
                    {**valid["writers"], "other": valid["writers"]["loki"]}],
    }.items():
        cases.extend({**valid, field: replacement} for replacement in replacements)
    entry = valid["writers"]["loki"]
    bad_entries = [None, [], {**entry, "extra": True}]
    bad_entries.extend({field: value for field, value in entry.items() if field != key} for key in entry)
    for field, replacements in {
        "service": ["mimir-writer", None], "profile": ["server-p384-sha384-v1", None],
        "subject_dn": ["CN=only", "CN=a,OU=b,O=c,C=us", "CN=a,OU=b,O=c,C=USA",
                       "CN=a,OU=b,O=c,C=US\n", "CN=a,OU=b,O=c,C=US,O=extra",
                       "CN=a b,OU=b,O=c,C=US", "CN=é,OU=b,O=c,C=US",
                       "CN=" + "a" * 65 + ",OU=b,O=c,C=US", "CN=,OU=b,O=c,C=US", None],
        "request_id": ["A" * 32, "a" * 31, "../unsafe", True],
        "version_path": [entry["version_path"] + "/", entry["version_path"].replace("loki", "mimir"),
                         context["writers"]["loki"]["versions_root"] + "/" + "b" * 32, None],
        **{field: ["A" * 64, "a" * 63, "a" * 65, "g" * 64, None, True]
           for field in ("request_sha256", "certificate_sha256", "certificate_spki_sha256", "validation_boundary_sha256")},
        **{field: [True, False, 0, -1, "1", 1.0, None]
           for field in ("rollback_hold_seconds", "leaf_not_after_epoch", "client_chain_not_after_epoch", "remaining_lifetime_seconds")},
    }.items():
        bad_entries.extend({**entry, field: replacement} for replacement in replacements)
    bad_entries += [
        {**entry, "remaining_lifetime_seconds": entry["remaining_lifetime_seconds"] + 1},
        {**entry, "leaf_not_after_epoch": valid["observed_at_epoch"]},
        {**entry, "client_chain_not_after_epoch": valid["observed_at_epoch"] - 1},
        {**entry, "subject_dn": valid["writers"]["mimir"]["subject_dn"]},
        {**entry, "certificate_spki_sha256": valid["writers"]["mimir"]["certificate_spki_sha256"]},
    ]
    cases.extend({**valid, "writers": {**valid["writers"], "loki": bad}} for bad in bad_entries)
    for index, outcome in enumerate(cases):
        with pytest.raises(AnsibleFilterError, match="inputs rejected: renewal_outcome") as error:
            bridge.renewal_outcome(outcome, context, "loki")
        assert str(error.value) == "Alloy initial inputs rejected: renewal_outcome", index
    for selected in ("", "other", "loki,mimir", "../loki", None, True, []):
        with pytest.raises(AnsibleFilterError):
            bridge.renewal_outcome(valid, context, selected)
    with pytest.raises(AnsibleFilterError):
        bridge.renewal_outcome(valid, {**context, "writers": {"mimir": context["writers"]["mimir"]}}, "loki")


def install_renewal_inputs(c, bridge):
    # Seed the already-installed fixture directly; renewal never invokes prepare.
    plan = bridge.validate(c.inputs)
    inputs = bridge.build(plan, bridge.sources(c.inputs), c.config.read_text(), c.dropin.read_text())
    for directory in inputs["directories"]:
        path = c.target / directory.lstrip("/")
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700 if directory.startswith("/var/lib/platform-config") or directory == "/etc/alloy/pki" else 0o755)
    for entry in inputs["files"]:
        if entry.get("required"):
            continue
        path = c.target / entry["path"].lstrip("/")
        content = base64.b64decode(entry["content"]) if entry.get("base64") else entry["content"].encode()
        path.write_bytes(content)
        path.chmod(int(entry["mode"], 8))
    return inputs["context"]


def assert_renewal_read_only(c, before):
    assert tree(c.target) == before
    observed = c.observations()
    assert all(not event["changed"] for event in observed), observed
    assert all(event["action"] in {"ansible.builtin.include_role", "ansible.builtin.include_tasks",
                                    "ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.stat",
                                    "fixture_command", "ansible.builtin.debug"} for event in observed), observed
    assert not any("prepare" in event["name"].lower() or "policy" in event["name"].lower() for event in observed)
    return observed


@pytest.mark.parametrize("check", [False, True], ids=["apply", "check"])
def test_renewal_preflight_selected_writers_read_only_real_entry_chain(role_case, bridge, check):
    c = role_case
    context = install_renewal_inputs(c, bridge)
    before = tree(c.target)
    tasks = []
    for writer in PREFIXES:
        tasks += [
            {"ansible.builtin.include_role": {"name": str(c.role), "tasks_from": "renewal_preflight.yml"},
             "vars": {"grafana_alloy_renewal_writer": writer, "fixture_outcome": renewal_observation(context, writer)}},
            {"ansible.builtin.assert": {"that": [
                f"grafana_alloy_renewal_result == fixture_expected_{writer}"]}, "no_log": True},
        ]
    # The inherited stopped/disabled declaration is valid for read-only observation;
    # the helper, rather than desired-state authorization, checks actual runtime.
    result, events = c.run("unused", tasks=tasks, check=check, overrides={
        "fixture_expected_" + writer: renewal_observation(context, writer) for writer in PREFIXES
    }, extra_vars="grafana_alloy_initial_action=activate")
    result.assert_success()
    assert events == [{"argv": [HELPER, "renewal-preflight", "--config", CONTEXT, "--writer", writer], "check": False}
                      for writer in PREFIXES]
    observed = assert_renewal_read_only(c, before)
    commands = [event for event in observed if event["action"] == "fixture_command"]
    assert len(commands) == 2 and all(event["no_log"] for event in commands)
    assert all(event["no_log"] for event in observed if event["action"] in {"ansible.builtin.stat", "ansible.builtin.set_fact"})
    reports = [event["public_msg"] for event in observed if event["action"] == "ansible.builtin.debug"]
    assert reports == [{"schema": 1, "status": "predecessor-verified", "changed": False,
                        "target": "localhost", "writer": writer} for writer in PREFIXES]
    assert "changed=0" in result.stdout
    for private in ("CN=", "Telemetry", "subject_dn", "version_path", CONTEXT, context["inventory_sha256"]):
        assert private not in result.stdout


def test_renewal_preflight_invalid_selection_batched_before_source_io(role_case):
    c = role_case
    before = tree(c.target)
    # Exercise omission with the shipped empty default, before the typed matrix.
    result, events = c.run("renewal_preflight.yml", check=True)
    result.assert_failure()
    assert events == []
    observed = assert_renewal_read_only(c, before)
    assert not any(event["action"] in {"ansible.builtin.stat", "ansible.builtin.set_fact"} for event in observed)
    cases = [{"grafana_alloy_renewal_writer": value} for value in
             ("", "other", "Loki", "loki,mimir", "../loki", "loki\n", "--writer=mimir", True, 1, None, [], {})]
    cases += [{"grafana_alloy_renewal_writer": "loki", "grafana_alloy_initial_writers": writers}
              for writers in ({}, [], "loki", {"mimir": c.inputs["grafana_alloy_initial_writers"]["mimir"]})]
    case_file = c.root / "invalid-renewal.yml"
    case_file.write_text(yaml.safe_dump([
        {"ansible.builtin.set_fact": {"fixture_rejected": False}},
        {"block": [{"ansible.builtin.include_role": {"name": str(c.role), "tasks_from": "renewal_preflight.yml"},
                    "vars": {key: "{{ fixture_case.get('" + key + "', fixture_base['" + key + "']) }}"
                             for key in ("grafana_alloy_renewal_writer", "grafana_alloy_initial_writers")}}],
         "rescue": [{"ansible.builtin.set_fact": {"fixture_rejected": True}}]},
        {"ansible.builtin.assert": {"that": ["fixture_rejected", "grafana_alloy_renewal_result is not defined"]}},
    ], sort_keys=False))
    result, events = c.run("unused", check=True, overrides={
        "fixture_base": c.inputs, "grafana_alloy_initial_inventory_src": "/must-not-read/inventory.yml",
        "grafana_alloy_initial_platform_pki_src": "/must-not-read/platform-pki",
    }, tasks=[{"ansible.builtin.include_tasks": str(case_file), "loop": cases,
               "loop_control": {"loop_var": "fixture_case", "label": "invalid-selection"}}])
    result.assert_success()
    assert events == []
    observed = assert_renewal_read_only(c, before)
    failed = [event for event in observed if event["status"] == "failed"]
    assert len(failed) == len(cases)
    assert all(event["name"].endswith("Require one literal host and a configured renewal writer") for event in failed)
    assert not any(event["name"].endswith("Validate Grafana Alloy immutable initial inputs") for event in observed)


@pytest.mark.parametrize("limit", [None, "all", "local*", "localhost,localhost"])
def test_renewal_preflight_requires_literal_limit_before_io(role_case, limit):
    c = role_case
    before = tree(c.target)
    result, events = c.run("renewal_preflight.yml", limit=limit, overrides={"grafana_alloy_renewal_writer": "loki"})
    result.assert_failure()
    assert events == []
    observed = assert_renewal_read_only(c, before)
    assert len([event for event in observed if event["status"] == "failed"]) == 1
    assert not any(event["action"] in {"ansible.builtin.stat", "ansible.builtin.set_fact"} for event in observed)


@pytest.mark.parametrize("fault", ["rc", "stderr", "malformed", "extra", "binding", "entry-extra", "writer-binding"])
def test_renewal_preflight_command_rejection_never_reports_success(role_case, bridge, fault):
    c = role_case
    context = install_renewal_inputs(c, bridge)
    outcome = renewal_observation(context)
    overrides = {"grafana_alloy_renewal_writer": "loki", "fixture_outcome": outcome}
    if fault == "rc":
        overrides["fixture_rc"] = 1
    elif fault == "stderr":
        overrides["fixture_stderr"] = "private diagnostic CN=must-not-leak"
    elif fault == "malformed":
        overrides["fixture_stdout"] = "not-json CN=must-not-leak"
    elif fault == "extra":
        outcome["authorization"] = True
    elif fault == "binding":
        outcome["inventory_sha256"] = "0" * 64
    elif fault == "entry-extra":
        outcome["writers"]["mimir"]["authorization"] = True
    else:
        outcome["writer"] = "mimir"
    before = tree(c.target)
    result, events = c.run("renewal_preflight.yml", check=True, overrides=overrides)
    result.assert_failure()
    assert events == [{"argv": [HELPER, "renewal-preflight", "--config", CONTEXT, "--writer", "loki"], "check": False}]
    observed = assert_renewal_read_only(c, before)
    assert not any(event["action"] == "ansible.builtin.debug" for event in observed)
    failed = [event for event in observed if event["status"] == "failed"]
    assert len(failed) == 1 and failed[0]["no_log"]
    assert failed[0]["name"].endswith("Run the fixed read-only renewal preflight" if fault in ("rc", "stderr")
                                    else "Validate and record the exact renewal predecessor observation")
    assert "predecessor-verified" not in result.stdout and "must-not-leak" not in result.stdout


@pytest.mark.parametrize("drift", ["missing", "helper", "lifecycle", "artifact", "inventory", "context",
                                   "config", "dropin", "source-pin", "desired-config"])
def test_renewal_preflight_requires_exact_sources_without_repair(role_case, bridge, drift):
    c = role_case
    overrides: dict = {"grafana_alloy_renewal_writer": "loki"}
    if drift != "missing":
        context = install_renewal_inputs(c, bridge)
        overrides["fixture_outcome"] = renewal_observation(context)
        if drift == "source-pin":
            overrides["grafana_alloy_initial_inventory_sha256"] = "0" * 64
        elif drift == "desired-config":
            overrides["grafana_alloy_loki_url"] = "https://other.example.invalid/api/push"
        else:
            path = {"helper": c.target / HELPER.lstrip("/"), "lifecycle": c.lifecycle,
                    "artifact": c.target / "usr/local/bin/platform-pki", "inventory": c.target / "etc/alloy/pki/inventory.yml",
                    "context": c.target / CONTEXT.lstrip("/"), "config": c.config, "dropin": c.dropin}[drift]
            path.write_bytes(path.read_bytes() + b"\n")
    before = tree(c.target)
    result, events = c.run("renewal_preflight.yml", check=True, overrides=overrides)
    result.assert_failure()
    assert events == []
    observed = assert_renewal_read_only(c, before)
    assert not any(event["action"] == "ansible.builtin.debug" for event in observed)
    failed = [event for event in observed if event["status"] == "failed"]
    assert len(failed) == 1 and failed[0]["no_log"]
    expected = ("Reject unsafe existing control directories without repair" if drift == "missing" else
                "Snapshot reviewed controller sources with exact byte hashes" if drift == "source-pin" else
                "Reject any existing immutable source or context drift")
    assert failed[0]["name"].endswith(expected)
