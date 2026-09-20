from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml


PKI = "pki_host_local_certificate_"
NAMES = ["approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers"]

# Execute the shipped Python probes against real sandbox files. Only inherited
# ancestor metadata, systemd, and authenticated lifecycle responses are synthetic.
# No command can reach a managed host or the container's systemd.
TARGET = r'''
import json, os, pathlib, stat, subprocess, sys
root = pathlib.Path(sys.argv[1])
scenario = json.loads((root / 'scenario.json').read_text())
argv = sys.argv[2:]
with (root / 'calls').open('a') as log:
    log.write(json.dumps(argv) + '\n')
def status():
    state, action = scenario.get('status', ['request-pending', 'await-response'])
    return dict(schema='2', kind='platform-config-target-local-certificate-status',
                service='registry-test', target='registry-a', request_id='1'*32,
                status=state, required_action=action)
if argv[0].endswith('platform-pki-host-local-lifecycle'):
    assert argv[1] == 'target-status', argv
    assert '--trust-id' in argv and '--dns-san=registry.example.invalid' in argv
    print(json.dumps(status()))
    sys.exit(0)
if argv[0] == '/usr/bin/realpath':
    target = root / 'target'
    result = subprocess.run([*argv[:-1], str(target / argv[-1].lstrip('/'))],
                            text=True, capture_output=True, check=True)
    resolved = result.stdout.strip()
    print(resolved.removeprefix(str(target)))
    sys.exit(0)
assert argv[:2] == ['python3', '-c'], argv
code, args = argv[2], argv[3:]
def relocate(value):
    if isinstance(value, str) and value.startswith(('/etc/', '/var/', '/usr/local/')):
        return str(root / 'target' / value.lstrip('/'))
    return value
if len(args) == 1 and args[0].startswith('{'):
    values = json.loads(args[0])
    args = [json.dumps({key: relocate(value) for key, value in values.items()})]
else:
    args = [relocate(value) for value in args]
# The actual probes still check every target-owned file and directory. The
# user-namespace's inherited /tmp and / ancestors are outside the target fixture.
native_lstat = os.lstat
ancestors = set((root / 'target').parents)
def lstat(path, *a, **kw):
    info = native_lstat(path, *a, **kw)
    if pathlib.Path(path) in ancestors:
        fields = list(info)
        fields[0], fields[4], fields[5] = stat.S_IFDIR | 0o755, 0, 0
        return os.stat_result(fields)
    return info
os.lstat = lstat
def run(command, **kw):
    if command[0] == 'systemctl':
        assert command == ['systemctl', 'show', '--all', 'zot.service', '--property=LoadState,ActiveState,SubState,UnitFileState']
        states = {
            'absent': ['not-found', 'inactive', 'dead', ''],
            'dormant': ['masked', 'inactive', 'dead', 'masked'],
            'active': ['loaded', 'active', 'running', 'enabled'],
            'failed': ['loaded', 'failed', 'failed', 'disabled'],
            'unmasked': ['loaded', 'inactive', 'dead', 'disabled'],
        }
        output = ''.join(f'{key}={value}\n' for key, value in zip(
            ['LoadState', 'ActiveState', 'SubState', 'UnitFileState'], states[scenario['service']]))
        return subprocess.CompletedProcess(command, 4 if scenario['service'] == 'absent' else 0, output, '')
    assert command[0].endswith('platform-pki-host-local-lifecycle') and command[1] == 'zot-custody', command
    return subprocess.CompletedProcess(command, 0, json.dumps(dict(custody='dormant', request_id='none')), '')
subprocess.run = run
sys.argv = ['-c', *args]
exec(compile(code, '<production-target-probe>', 'exec'), {'__name__': '__main__'})
'''


@pytest.fixture
def preflight(repo_root, isolated_test_dir, namespace_root_runner):
    root = isolated_test_dir
    project = root / "project"
    plays = project / "playbooks"
    plays.mkdir(parents=True)
    for name in ("registry-operation-preflight.yml", "registry-pki-preflight.yml"):
        shutil.copy(repo_root / "playbooks" / name, plays / name)
    for role in ("pki_host_local_certificate", "zot_registry", "storage_volume"):
        shutil.copytree(repo_root / "roles" / role, project / "roles" / role,
                        ignore=shutil.ignore_patterns("__pycache__"))
    maintenance = plays / "maintenance"
    (maintenance / "tasks").mkdir(parents=True)
    shutil.copy(repo_root / "playbooks/maintenance/storage-volumes-verify.yml", maintenance)
    shutil.copy(repo_root / "playbooks/maintenance/tasks/storage-volumes-verify-mount.yml", maintenance / "tasks")
    # Use the actual controller descriptor validator and its repository boundary.
    (project / "plugins").symlink_to(repo_root / "plugins", target_is_directory=True)
    storage_plugins = root / "storage_plugins"
    storage_plugins.mkdir()
    (storage_plugins / "registry_storage_probe.py").write_text('''
import json
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        if 'path' in args:
            return dict(changed=False, stat=dict(exists=True, isdir=True, islnk=False, isblk=True))
        argv = args['argv']
        if argv[0] == 'lsblk':
            return dict(changed=False, rc=0, stdout='253:1')
        assert argv[0] == 'findmnt', argv
        rows = [dict(options='rw,nosuid,nodev,relatime')] if argv[-1] == 'OPTIONS' else [
            dict(target=argv[argv.index('--mountpoint') + 1], source='/dev/mapper/registry-data',
                 fstype='xfs', fsroot='/', **{'maj:min': '253:1'})]
        return dict(changed=False, rc=0, stdout=json.dumps(dict(filesystems=rows)))
''')
    for path in (maintenance / "tasks/storage-volumes-verify-mount.yml",
                 project / "roles/storage_volume/tasks/verify_mountpoint.yml"):
        tasks = yaml.safe_load(path.read_text())
        for task in tasks:
            for module in ("ansible.builtin.command", "ansible.builtin.stat"):
                if module in task:
                    task["registry_storage_probe"] = task.pop(module)
        path.write_text(yaml.safe_dump(tasks, sort_keys=False))
    wrapper = root / "target.py"
    wrapper.write_text(TARGET)
    for path in (project / "roles/pki_host_local_certificate/tasks").glob("*.yml"):
        tasks = yaml.safe_load(path.read_text())
        for task in tasks:
            if path.name == "filesystem_preflight.yml" and "ansible.builtin.stat" in task:
                # Keep native stat and metadata checks; relocate only the target path.
                task["ansible.builtin.stat"]["path"] = "{{ fixture_target }}{{ item }}"
            if "ansible.builtin.command" in task and task.get("delegate_to") != "localhost":
                original = task["ansible.builtin.command"]["argv"]
                prefix = ["python3", str(wrapper), str(root)]
                task["ansible.builtin.command"]["argv"] = (
                    prefix + original if isinstance(original, list)
                    else "{{ " + repr(prefix) + " + (" + original.strip()[2:-2] + ") }}"
                )
        path.write_text(yaml.safe_dump(tasks, sort_keys=False))
    target = root / "target"
    for directory in ("etc/zot", "etc/ssh", "etc/containers/systemd", "var/lib/exchange-parent", "usr/local/libexec"):
        (target / directory).mkdir(parents=True, exist_ok=True)
    helper = target / "usr/local/libexec/platform-pki-host-local-lifecycle"
    shutil.copy(repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle", helper)
    helper.chmod(0o755)
    signing = target / "etc/ssh/ssh_host_ed25519_key"
    signing.write_text("synthetic key metadata only\n")
    signing.chmod(0o600)
    source = root / "sources"
    source.mkdir(mode=0o700)
    digests = {}
    for name in [*NAMES, "ca.crt"]:
        path = source / name
        path.write_text(f"reviewed synthetic public {name}\n")
        path.chmod(0o600)
        digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    values = {
        "fixture_target": str(target),
        PKI + "transport": "filesystem", PKI + "operation": "issue",
        PKI + "service": "registry-test", PKI + "target": "registry-a",
        PKI + "requester_principal": "registry-a", PKI + "response_principal": "response.test",
        PKI + "inventory_sha256": "a" * 64, PKI + "current_cert_sha256": "none",
        PKI + "common_name": "registry.example.invalid",
        PKI + "dns_sans": ["registry.example.invalid"],
        PKI + "trust_id": "reviewed-v1",
        PKI + "trust_paths": {name: f"/var/lib/registry-pki/trust/reviewed-v1/{name}" for name in NAMES},
        PKI + "trust_sources": {name: str(source / name) for name in NAMES},
        PKI + "trust_sha256": {name: digests[name] for name in NAMES},
        PKI + "state_root": "/var/lib/registry-pki",
        PKI + "pending_root": "/etc/zot/tls-pending",
        PKI + "versions_root": "/etc/zot/tls-versions",
        PKI + "filesystem_exchange_root": "/var/lib/exchange-parent/exchange",
        PKI + "filesystem_owner_uid": 1000,
        PKI + "minimum_remaining_lifetime_seconds": 60,
        PKI + "reviewed_ca_source": str(source / "ca.crt"),
        PKI + "reviewed_ca_sha256": digests["ca.crt"],
        PKI + "reviewed_ca_target_path": "/etc/zot/validation-ca.crt",
        PKI + "reviewed_ca_mode": "0644", PKI + "rollback_seconds": 1209600,
        PKI + "endpoint": "https://registry.example.invalid/v2/",
        "zot_registry_tls_host_local_service": "registry-test",
        "zot_registry_tls_host_local_state_root": "/var/lib/registry-pki",
        "storage_volumes": [{"mountpoint": "/var/lib/zot", "vg_name": "registry", "lv_name": "data"}],
    }
    # Render the real template with the same defaults and inventory before staging.
    defaults = yaml.safe_load((repo_root / "roles/zot_registry/defaults/main.yml").read_text())
    render = root / "render.yml"
    render.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "connection": "local",
        "vars": {**defaults, **values,
                 "zot_registry_tls_effective_cert_path": "{{ zot_registry_tls_cert_path }}",
                 "zot_registry_tls_effective_key_path": "{{ zot_registry_tls_key_path }}"},
        "tasks": [{"ansible.builtin.template": {
            "src": str(repo_root / "roles/zot_registry/templates" / template),
            "dest": str(target / destination), "mode": "0644"}}
            for template, destination in (("config.json.j2", "etc/zot/config.json"),
                                          ("zot.container.j2", "etc/containers/systemd/zot.container"))],
    }]))
    namespace_root_runner.run(["ansible-playbook", "-i", "localhost,", render]).assert_success()

    def run(action="stage", *, service="dormant", overrides=None, groups=None, limit=None,
            pki=False, status=("request-pending", "await-response"), check=False):
        (root / "scenario.json").write_text(json.dumps(dict(service=service, status=status)))
        host_values = {**values, **(overrides or {})}
        children = {
            "registry": {"hosts": {"registry-a": host_values}},
            "registry_clients": {"hosts": {"client-a": {}, "client-b": {}}},
            **{group: {"hosts": {"registry-a": {}}} for group in
               ("rocky", "container_hosts", "storage_volume_hosts")},
            "unrelated": {"hosts": {"other": {}}},
        }
        children.update(groups or {})
        inv = root / "inventory.yml"
        inv.write_text(yaml.safe_dump({"all": {
            "vars": {"ansible_connection": "local", "ansible_become": False}, "children": children,
        }}))
        selected = limit if limit is not None else (
            "client-a,client-b" if action == "clients" else
            "registry-a,client-a,client-b" if action == "smoke" else "registry-a")
        play = "registry-pki-preflight.yml" if pki else "registry-operation-preflight.yml"
        extra = ({"registry_pki_preflight_action": action} if pki and action != "request"
                 else {} if pki else {"registry_operation_action": action})
        before = {str(p.relative_to(target)): p.read_bytes() for p in target.rglob("*") if p.is_file()}
        result = namespace_root_runner.run([
            "ansible-playbook", "-i", inv, plays / play, "--limit", selected,
            "--extra-vars", json.dumps(extra), *(["--check"] if check else []),
        ], timeout=90, environment={"ANSIBLE_ACTION_PLUGINS": str(storage_plugins) + os.pathsep + str(repo_root / "plugins/action")})
        assert {str(p.relative_to(target)): p.read_bytes() for p in target.rglob("*") if p.is_file()} == before
        assert "changed=0" in result.stdout, result.diagnostics()
        return result

    return run, target, source, root


@pytest.mark.parametrize("action,service,check", [
    ("host", "absent", False), ("storage", "absent", True),
    ("stage", "dormant", False), ("stage", "dormant", True),
    ("clients", "active", False), ("smoke", "active", False),
])
def test_general_preflight_fresh_replay_and_active_client_scopes(preflight, action, service, check):
    run, target, _, _ = preflight
    if service == "absent":
        (target / "etc/zot/config.json").unlink()
        (target / "usr/local/libexec/platform-pki-host-local-lifecycle").unlink()
    result = run(action, service=service, check=check, overrides={
        "storage_volumes": [{"mountpoint": "/var/lib/zot", "vg_name": "registry", "lv_name": "data"}],
        PKI + "reviewed_ca_source": "/not/available/yet",
    })
    result.assert_success()


def test_host_preflight_does_not_require_future_storage_declarations(preflight):
    run, target, _, _ = preflight
    (target / "etc/zot/config.json").unlink()
    run("host", service="absent", groups={"registry": {"hosts": {"registry-a": {
        PKI + "transport": "filesystem", PKI + "operation": "issue",
    }}}}).assert_success()


@pytest.mark.parametrize("action", ["host", "storage", "stage"])
def test_general_preflight_rejects_active_before_mutation(preflight, action):
    run, *_ = preflight
    result = run(action, service="active")
    result.assert_failure()
    assert "requires inactive Zot" in result.stdout


@pytest.mark.parametrize("action", ["storage", "stage"])
def test_general_preflight_rejects_storage_unrelated_to_default_zot_data(preflight, action):
    run, _, _, root = preflight
    result = run(action, overrides={
        "storage_volumes": [{"mountpoint": "/srv/data", "vg_name": "registry", "lv_name": "data"}],
    })
    result.assert_failure()
    assert "Registry data must bind exactly one declared volume" in result.stdout
    assert not (root / "calls").exists()


@pytest.mark.parametrize("case", ["state", "managed-key", "data", "config", "unmasked", "failed"])
def test_general_preflight_rejects_nonfresh_or_drifted_state(preflight, case):
    run, target, *_ = preflight
    if case == "state":
        (target / "var/lib/registry-pki").mkdir()
    elif case == "managed-key":
        (target / "etc/zot/tls").mkdir()
        (target / "etc/zot/tls/tls.key").symlink_to("missing")
    elif case == "data":
        data = target / "var/lib/zot/data"
        data.mkdir(parents=True)
        (data / "blob").touch()
    elif case == "config":
        (target / "etc/zot/config.json").write_text("{}")
    run(service=case if case in {"unmasked", "failed"} else "dormant").assert_failure()


@pytest.mark.parametrize("case", ["partial-clients", "extra", "multiple", "disjoint", "transport", "renew", "tls-source"])
def test_general_preflight_scope_and_inventory_rejections(preflight, case):
    run, *_ = preflight
    args = {
        "partial-clients": dict(action="clients", limit="client-a"),
        "extra": dict(limit="registry-a,other"),
        "multiple": dict(groups={"registry": {"hosts": {"registry-a": {}, "other": {}}}}),
        "disjoint": dict(groups={"rke2_servers": {"hosts": {"registry-a": {}}}}),
        "transport": dict(overrides={PKI + "transport": "gitlab"}),
        "renew": dict(overrides={PKI + "operation": "renew"}),
        "tls-source": dict(overrides={"zot_registry_tls_key_src": "/controller/key"}),
    }[case]
    run(**args).assert_failure()


@pytest.mark.parametrize("case", ["fresh", "pending", "active", "missing-helper", "unsafe-helper", "missing-quadlet", "missing-source", "unsafe-source", "digest", "identity", "overlap"])
def test_request_preflight_readiness_and_pending_replay(preflight, case):
    run, target, source, _ = preflight
    overrides = {}
    if case in {"pending", "active"}:
        state = target / "var/lib/registry-pki"
        state.mkdir(mode=0o700)
        if case == "active":
            (state / "active").write_text("active predecessor")
        else:
            (target / "etc/zot/tls-pending").mkdir(mode=0o700)
    if case == "missing-helper":
        (target / "usr/local/libexec/platform-pki-host-local-lifecycle").unlink()
    if case == "unsafe-helper":
        (target / "usr/local/libexec/platform-pki-host-local-lifecycle").chmod(0o777)
    if case == "missing-quadlet":
        (target / "etc/containers/systemd/zot.container").unlink()
    if case == "missing-source":
        (source / "policy").unlink()
    if case == "unsafe-source":
        (source / "policy").chmod(0o644)
    if case == "digest":
        (source / "policy").write_text("changed public source")
    if case == "identity":
        overrides[PKI + "state_root"] = "/var/lib/other"
    if case == "overlap":
        overrides[PKI + "filesystem_exchange_root"] = "/var/lib/registry-pki/exchange"
    result = run("request", pki=True, overrides=overrides)
    if case in {"fresh", "pending"}:
        result.assert_success()
    else:
        result.assert_failure()


@pytest.mark.parametrize("case", ["absent", "existing", "writable-ancestor", "unsafe-parent", "symlink"])
def test_request_uses_shared_read_only_filesystem_guards(preflight, case):
    run, target, *_ = preflight
    parent = target / "var/lib/exchange-parent"
    exchange = parent / "exchange"
    if case == "existing":
        exchange.mkdir(mode=0o755)
    elif case == "writable-ancestor":
        parent.chmod(0o777)
    elif case == "unsafe-parent":
        exchange.mkdir(mode=0o777)
        exchange.chmod(0o777)
    elif case == "symlink":
        exchange.symlink_to(parent, target_is_directory=True)
    result = run("request", pki=True)
    if case in {"absent", "existing"}:
        result.assert_success()
        assert exchange.exists() == (case == "existing")
        assert not (exchange / "registry-test").exists()
    else:
        result.assert_failure()
        assert {
            "writable-ancestor": "existing root-owned directories",
            "unsafe-parent": "Existing filesystem exchange parent metadata is unsafe",
            "symlink": "Filesystem exchange root is noncanonical",
        }[case] in result.stdout


@pytest.mark.parametrize("status", [
    ("request-pending", "await-response"), ("response-ready", "install-response"),
    ("response-ready", "activate-response"), ("activating", "complete-local-validation"),
    ("recovery-required", "recover"), ("not-activated", "recover"),
    ("rolled-back", "recover"), ("complete", "none"),
    ("absent", "create-request"), ("request-expired", "reset-required"),
    ("not-activated", "none"), ("rolled-back", "none"),
])
def test_activation_preflight_preserves_status_contract_without_import(preflight, status):
    run, _, source, root = preflight
    # Completed replay and interrupted recovery are source-independent. Other
    # actionable states will need the CA, but never need controller trust files.
    for name in NAMES:
        (source / name).unlink()
    if status[0] in {"complete", "recovery-required", "not-activated", "rolled-back"}:
        (source / "ca.crt").unlink()
    result = run("activate", pki=True, service="active", status=status)
    if status[0] in {"absent", "request-expired", "not-activated", "rolled-back"}:
        result.assert_failure()
    else:
        result.assert_success()
    if status[0] == "recovery-required":
        assert "still end in terminal failure" in " ".join(result.stdout.split())
    calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
    assert [call[1] for call in calls if call[0].endswith("platform-pki-host-local-lifecycle")] == ["target-status"]


@pytest.mark.parametrize("case,status", [
    ("missing", ("request-pending", "await-response")),
    ("missing", ("response-ready", "install-response")),
    ("missing", ("response-ready", "activate-response")),
    ("missing", ("activating", "complete-local-validation")),
    *[(case, ("request-pending", "await-response")) for case in ("mode", "symlink", "digest")],
])
def test_actionable_activation_preflight_rejects_unusable_ca(preflight, case, status):
    run, _, source, root = preflight
    ca = source / "ca.crt"
    if case == "missing":
        ca.unlink()
    elif case == "mode":
        ca.chmod(0o644)
    elif case == "symlink":
        ca.rename(source / "real-ca")
        ca.symlink_to(source / "real-ca")
    else:
        ca.write_text("changed reviewed bytes\n")
    result = run("activate", pki=True, status=status)
    result.assert_failure()
    assert "Validate reviewed CA before actionable registry activation" in result.stdout
    calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
    assert [call[1] for call in calls if call[0].endswith("platform-pki-host-local-lifecycle")] == ["target-status"]


@pytest.mark.parametrize("terminal", ["not-activated", "rolled-back"])
def test_activation_route_still_fails_after_terminalizing_recovery(
    repo_root, isolated_test_dir, command_runner, terminal,
):
    root = isolated_test_dir
    status = dict(schema="2", kind="platform-config-target-local-certificate-status",
                  service="registry-test", target="registry-a", request_id="1" * 32,
                  status="recovery-required", required_action="recover")
    tasks = yaml.safe_load((repo_root / "roles/pki_host_local_certificate/tasks/response_activate.yml").read_text())
    start = next(i for i, task in enumerate(tasks) if task["name"] == "Recover target-local activation journal without operator coordinates")
    end = next(i for i, task in enumerate(tasks) if task["name"] == "Require an actionable target-local response")
    tasks = tasks[start:end + 1]
    for task in tasks:
        if "ansible.builtin.command" in task:
            task["recovery_target"] = task.pop("ansible.builtin.command")
    plugins = root / "action_plugins"
    plugins.mkdir()
    log = root / "calls"
    (plugins / "recovery_target.py").write_text('''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        command = self._task.args['argv'][1]
        with Path(task_vars['test_log']).open('a') as stream:
            stream.write(command + '\\n')
        initial = json.loads(task_vars['pki_host_local_certificate_initial_status_result']['stdout'])
        if command == 'target-recover':
            result = dict(status=task_vars['test_terminal'], request_id=initial['request_id'])
        else:
            assert command == 'target-status'
            result = dict(initial, status=task_vars['test_terminal'], required_action='none')
        return dict(changed=False, rc=0, stderr='', stdout=json.dumps(result))
''')
    play = root / "recover.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "vars": {PKI + "initial_status_result": dict(stdout=json.dumps(status)),
                 PKI + "lifecycle_helper_path": "/synthetic/lifecycle",
                 PKI + "lifecycle_common_argv": [], PKI + "lifecycle_config_argv": [],
                 PKI + "lifecycle_candidate_argv": [], PKI + "service": "registry-test",
                 PKI + "target": "registry-a", "test_terminal": terminal, "test_log": str(log)},
        "tasks": tasks,
    }]))
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", play],
                                environment={"ANSIBLE_ACTION_PLUGINS": str(plugins)})
    result.assert_failure()
    assert "Recovery reached a terminal failure" in result.stdout
    assert log.read_text().splitlines() == ["target-recover", "target-status"]


def test_pki_preflight_requires_literal_hostname(preflight):
    run, *_ = preflight
    run("request", pki=True, limit="registry").assert_failure()


@pytest.mark.parametrize("valid", [True, False])
def test_general_preflight_checks_selected_ca_without_installation(preflight, valid):
    run, _, source, _ = preflight
    ca = source / "ca.crt"
    result = run(overrides={
        "registry_ca_trust_source": str(ca),
        "registry_ca_trust_sha256": hashlib.sha256(ca.read_bytes()).hexdigest() if valid else "0" * 64,
    })
    if valid:
        result.assert_success()
    else:
        result.assert_failure()


def test_real_stage_launcher_stops_before_zot_writes_on_unmounted_bound_volume(
    preflight, repo_root, namespace_root_runner,
):
    run, target, _, root = preflight
    mount = target / "registry-volume"
    mount.mkdir()
    quadlet = target / "etc/containers/systemd/zot.container"
    quadlet.write_text(quadlet.read_text().replace("/var/lib/zot/data:", str(mount / "data") + ":"))
    # Storage preparation permits an unmounted target, but its declaration must
    # already bind the effective (inventory-overridden) Zot data directory.
    run("storage", overrides={
        "zot_registry_data_dir": str(mount / "data"),
        "storage_volumes": [{"mountpoint": str(mount), "vg_name": "registry", "lv_name": "data"}],
    }).assert_success()
    project = root / "project"
    # Restore native stat/findmnt/lsblk tasks: this is a real empty directory,
    # not a mounted-filesystem double. Only Zot/systemd readiness remains doubled.
    for path in ("playbooks/maintenance/tasks/storage-volumes-verify-mount.yml",
                 "roles/storage_volume/tasks/verify_mountpoint.yml"):
        shutil.copy(repo_root / path, project / path)
    scripts = project / "scripts"
    scripts.mkdir()
    for name in ("platform-config-operation", "platform-config-operation-summary"):
        shutil.copy(repo_root / "scripts" / name, scripts / name)
    shutil.copy(repo_root / "ansible.cfg", project)
    shutil.copy(repo_root / "playbooks/registry.yml", project / "playbooks")
    marker = root / "zot-write"
    # The real stage play/launcher can only reach these fixture role writes after
    # preflight evidence succeeds. Real packages/services are never touched.
    for role in ("firewalld", "podman_host", "zot_registry", "registry_ca_trust", "registry_client_tools"):
        tasks = project / "roles" / role / "tasks"
        tasks.mkdir(parents=True, exist_ok=True)
        (tasks / "main.yml").write_text(yaml.safe_dump([{"ansible.builtin.copy": {
            "dest": str(marker), "content": "stage reached", "mode": "0600",
        }}]))
    controller = root / "controller.json"
    controller.write_text("{}")
    controller.chmod(0o600)
    result = namespace_root_runner.run([
        scripts / "platform-config-operation", "registry-stage-apply",
        "--inventory", root / "inventory.yml", "--controller-vars", controller,
    ], timeout=60, environment={"ANSIBLE_ROLES_PATH": str(project / "roles")})
    result.assert_failure()
    assert "must be actively mounted after apply" in result.stdout, result.diagnostics()
    assert "PLAY [Configure OCI registry hosts]" not in result.stdout
    assert "Overall: FAIL" in result.stdout
    assert not marker.exists()
    assert list(mount.iterdir()) == []
