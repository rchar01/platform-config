from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def preflight(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    project = root / "project"
    plays = project / "playbooks"
    plays.mkdir(parents=True)
    shutil.copy(repo_root / "playbooks/openbao-operation-preflight.yml", plays)
    for name in ("openbao", "pki_host_local_certificate", "openbao_haproxy", "keepalived_vip", "rocky_repository_policy", "podman_host"):
        shutil.copytree(repo_root / "roles" / name, project / "roles" / name)
    (project / "plugins").symlink_to(repo_root / "plugins", target_is_directory=True)
    target = root / "target"
    for name in ("var/lib/openbao", "var/log/openbao/audit-1", "var/log/openbao/audit-2", "var/lib/openbao-backup-staging",
                 "etc/openbao", "usr/local/libexec"):
        (target / name).mkdir(parents=True, exist_ok=True)
    helper = target / "usr/local/libexec/platform-pki-host-local-lifecycle"
    source = repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    actions = root / "actions"
    actions.mkdir()
    support = repo_root / "tests/fixtures/openbao-preparation/target_io.py"
    (actions / "target_probe.py").write_text('''
import importlib.util, json, pathlib
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        argv = self._task.args['argv']
        assert argv[:2] == ['/usr/bin/python3', '-c'], argv
        spec = importlib.util.spec_from_file_location('target_io', task_vars['fixture_support'])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            result = module.execute(argv[2], json.loads(argv[3]), task_vars['fixture_target'], task_vars['fixture_scenario'])
            return dict(changed=False, rc=0, stdout=json.dumps(result))
        except (ValueError, OSError) as error:
            return dict(failed=True, msg=str(error))
''')
    (actions / "lifecycle_io.py").write_text('''
import json, pathlib
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        if 'path' in args:
            args = dict(args, path=task_vars['fixture_target'] + args['path'])
            result = self._execute_module(module_name='ansible.builtin.stat', module_args=args, task_vars=task_vars)
            if result.get('stat', {}).get('exists'):
                result['stat'].update(uid=0, gid=0, pw_name='root', gr_name='root')
            return result
        argv = args['argv']
        assert argv[1] == 'openbao-staging-preflight', argv
        assert '--trust-id' in argv and '--service-adapter' in argv
        scenario = task_vars['fixture_scenario']
        return dict(changed=False, failed=bool(scenario.get('authentication_failed')), rc=0, stderr='',
                    stdout=json.dumps(dict(schema='1', kind='platform-config-openbao-staging-preflight',
                    status=scenario.get('lifecycle_status', 'absent'),
                    service=argv[argv.index('--service') + 1], target=argv[argv.index('--target') + 1])))
''')
    for name in ('lifecycle_preflight.yml', 'staging_lifecycle_preflight.yml'):
        path = project / 'roles/openbao/tasks' / name
        path.write_text(path.read_text().replace('ansible.builtin.stat:', 'lifecycle_io:')
                        .replace('ansible.builtin.command:', 'lifecycle_io:'))
    # Only replace target transport for this command. All shipped validation,
    # default resolution, source pinning and task selection remain executable.
    path = project / "roles/openbao/tasks/preparation_target.yml"
    path.write_text(path.read_text().replace('ansible.builtin.command:', 'target_probe:'))
    ca = root / "config/openbao/validation-ca.pem"
    ca.parent.mkdir(parents=True)
    ca.write_text("reviewed public fixture CA\n")
    ca.chmod(0o600)
    group = yaml.safe_load((repo_root / "inventories/dev/group_vars/openbao.yml.example").read_text())
    group.update({
        "openbao_orchestration_ready": True, "openbao_enabled": True,
        "openbao_haproxy_enabled": True, "keepalived_vip_enabled": True,
        "openbao_haproxy_package_nevra": "haproxy-0:3.0.5-1.el10.x86_64",
        "keepalived_vip_package_nevra": "keepalived-0:2.2.8-1.el10.x86_64",
        "openbao_haproxy_client_allowed_sources": ["192.0.2.0/24"],
        "root_lvm_enabled": False, "openbao_tls_ca_src": str(ca),
        "podman_host_package_nevra": "podman-5:5.6.0-1.el10.x86_64",
        "firewalld_service_enabled": False, "firewalld_service_state": "stopped",
        "openbao_tls_ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
        "ansible_connection": "local", "ansible_become": False,
        "fixture_target": str(target), "fixture_support": str(support), "fixture_scenario": {},
    })
    hosts = {}
    for i in range(1, 4):
        name = f"openbao-example-0{i}"
        hosts[name] = yaml.safe_load((repo_root / f"inventories/dev/host_vars/{name}.yml.example").read_text())
    inv = root / "hosts.yml"
    variables = root / "vars.json"

    def run(*, overrides=None, scenario=None, action="host", check=False, limit="openbao", extra_groups=None, host_overrides=None):
        values = {**group, **(overrides or {}), "fixture_scenario": scenario or {}}
        inv.write_text(yaml.safe_dump({"all": {"vars": values, "children": {
            "openbao": {"hosts": {name: {**values, **(host_overrides or {}).get(name, {})}
                                    for name, values in hosts.items()}},
            "rocky": {"hosts": dict.fromkeys(hosts, {})},
            "storage_volume_hosts": {"hosts": dict.fromkeys(hosts, {})},
            **(extra_groups or {}),
        }}}))
        variables.write_text(json.dumps({"openbao_preparation_action": action}))
        return command_runner.run([
            "ansible-playbook", "-i", inv, plays / "openbao-operation-preflight.yml", "--limit", limit,
            "--extra-vars", f"@{variables}", *(["--check"] if check else []),
        ], environment={"CI": "true", "ANSIBLE_ROLES_PATH": str(project / "roles"),
                        "ANSIBLE_ACTION_PLUGINS": f"{actions}:{repo_root / 'plugins/action'}",
                        "PLATFORM_INFRASTRUCTURE_CONFIG_DIR": str(ca.parent.parent)}, timeout=90)
    return run, target, helper, source, group


def test_real_fresh_preflight_and_check_mode(preflight):
    run, target, helper, _, _ = preflight
    for check in (False, True):
        result = run(check=check)
        result.assert_success()
        assert "changed=0" in result.stdout
        assert not helper.exists()
        assert not (target / "var/lib/platform-config").exists()


@pytest.mark.parametrize("overrides", [
    {"root_lvm_enabled": True}, {"root_lvm_enabled": "false"},
    {"platform_common_directories": ["/var/lib/openbao"]},
    {"openbao_orchestration_ready": False}, {"openbao_service_enabled": True},
    {"openbao_service_state": "started"}, {"openbao_haproxy_service_enabled": "false"},
    {"keepalived_vip_service_state": "started"}, {"openbao_bootstrap_ready": True},
    {"openbao_haproxy_activation_ready": True}, {"openbao_keepalived_activation_ready": True},
    {"openbao_lifecycle_preflight_mode": "active-maintenance"},
])
def test_real_intent_rejections(preflight, overrides):
    run, *_ = preflight
    result = run(overrides=overrides)
    result.assert_failure()
    assert "Inspect inactive OpenBao paths" not in result.stdout


def test_partial_play_rejected(preflight):
    run, *_ = preflight
    result = run(limit="openbao-example-01")
    result.assert_failure()


@pytest.mark.parametrize("action", ["host", "stage"])
def test_real_preflight_rejects_storage_only_scope(preflight, action):
    run, *_ = preflight
    result = run(action=action, extra_groups={
        "openbao_storage": {"children": {"storage_only_nodes": {"hosts": {"openbao-example-03": {}}}}},
    })
    result.assert_failure()
    assert result.returncode == 2
    assert "Preparation requires the complete disjoint canonical Rocky cluster" in result.stdout
    assert "Resolve OpenBao preparation defaults" not in result.stdout
    assert "Inspect inactive OpenBao paths" not in result.stdout


def test_one_unsafe_target_stops_all_host_preflight(preflight):
    run, target, _, source, _ = preflight
    unsafe_target = target.parent / 'unsafe-target'
    shutil.copytree(target, unsafe_target)
    helper = unsafe_target / 'usr/local/libexec/platform-pki-host-local-lifecycle'
    helper.symlink_to(source)
    result = run(host_overrides={"openbao-example-03": {"fixture_target": str(unsafe_target)}})
    result.assert_failure()
    assert result.returncode == 2
    assert "fatal: [openbao-example-03]" in result.stdout
    assert "symlink in preparation path" in result.stdout
    assert "Record authenticated helper availability" not in result.stdout
    assert "Validate runtime inputs without invoking Podman dependencies" not in result.stdout
    assert helper.is_symlink()


@pytest.mark.parametrize("scenario", [{"service": state} for state in ("active", "enabled", "failed")]
                         + [{"unmounted": True}, {"incomplete": True}])
def test_real_target_probe_rejections(preflight, scenario):
    run, *_ = preflight
    result = run(scenario=scenario)
    result.assert_failure()
    assert "Inspect inactive OpenBao paths" in result.stdout


@pytest.mark.parametrize("path", ["var/lib/openbao/raft.db", "var/lib/platform-config/openbao-bootstrap.json",
                                  "var/lib/platform-config/openbao-edge-guard/consumed/old",
                                  "var/lib/platform-config/openbao-rolling-transaction/record",
                                  "var/lib/platform-config/pki/openbao/active",
                                  "var/lib/platform-config/pki/openbao/target-terminal",
                                  "etc/openbao/tls-versions/current", "etc/openbao/tls-pending/request"])
def test_retained_state_preserved(preflight, path):
    run, target, *_ = preflight
    retained = target / path
    retained.parent.mkdir(parents=True, exist_ok=True)
    retained.write_text("retained\n")
    result = run()
    result.assert_failure()
    assert retained.read_text() == "retained\n"


def test_stage_requires_preinstalled_helper(preflight):
    run, *_ = preflight
    result = run(action="stage")
    result.assert_failure()
    assert "requires the installed lifecycle helper" in result.stdout


def test_directory_cannot_be_used_as_managed_artifact(preflight):
    run, target, *_ = preflight
    (target / 'etc/openbao/openbao.hcl').mkdir()
    result = run()
    result.assert_failure()
    assert 'preparation artifact is not a regular file' in result.stdout


def test_unsafe_paths_and_helper_bytes(preflight):
    run, target, helper, source, _ = preflight
    helper.symlink_to(source)
    result = run()
    result.assert_failure()
    assert "symlink in preparation path" in result.stdout
    helper.unlink()
    helper.write_text("not shipped")
    helper.chmod(0o755)
    result = run()
    result.assert_failure()
    assert "installed lifecycle helper is not exact" in result.stdout


def test_stage_reuses_real_lifecycle_include_and_source_validator(preflight):
    run, target, helper, source, _ = preflight
    shutil.copy(source, helper)
    helper.chmod(0o755)
    result = run(action="stage", check=True)
    result.assert_success()
    assert "Require authenticated OpenBao staging lifecycle state" in result.stdout
    assert "Validate pinned controller CA bytes" in result.stdout
    assert not (target / 'etc/openbao/tls/ca.crt').exists()
    state = target / 'var/lib/platform-config/pki/openbao'
    (state / 'trust').mkdir(parents=True)
    (state / 'lock').touch(mode=0o600)
    result = run(action="stage", scenario={"lifecycle_status": "trust-only"})
    result.assert_success()
    assert {entry.name for entry in state.iterdir()} == {'lock', 'trust'}


@pytest.mark.parametrize("failure", ['path', 'digest', 'authentication', 'schema'])
def test_stage_ca_and_lifecycle_rejections(preflight, failure):
    run, _, helper, source, group = preflight
    shutil.copy(source, helper)
    helper.chmod(0o755)
    overrides, scenario = {}, {}
    if failure == 'path': overrides['openbao_tls_ca_src'] = '/tmp/other-ca.pem'
    if failure == 'digest': overrides['openbao_tls_ca_sha256'] = '0' * 64
    if failure == 'authentication': scenario['authentication_failed'] = True
    if failure == 'schema': scenario['lifecycle_status'] = 'active'
    result = run(action='stage', overrides=overrides, scenario=scenario)
    result.assert_failure()
    if failure == 'digest': assert 'digest mismatch' in result.stdout
