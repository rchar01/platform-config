from __future__ import annotations

import json
import shutil

import pytest
import yaml


@pytest.mark.parametrize("override", ["base", "directory", "file"])
def test_native_registry_defaults_preserve_inventory_and_dependents(
    repo_root, isolated_test_dir, command_runner, override,
):
    root = isolated_test_dir
    plays = root / "playbooks"
    plays.mkdir()
    (root / "roles").symlink_to(repo_root / "roles", target_is_directory=True)
    values = {
        "ansible_connection": "local", "ansible_become": False,
        "pki_host_local_certificate_transport": "filesystem",
        "pki_host_local_certificate_operation": "issue",
        "podman_host_quadlet_dir": "/reviewed/base",
        "zot_registry_host_port": 5443,
        "zot_registry_data_dir": "/reviewed/data",
    }
    if override in {"directory", "file"}:
        values["zot_registry_quadlet_dir"] = "/reviewed/override"
    if override == "file":
        values["zot_registry_quadlet_path"] = "/reviewed/explicit/zot.container"
    directory = "/reviewed/base" if override == "base" else "/reviewed/override"
    expected = "/reviewed/explicit/zot.container" if override == "file" else directory + "/zot.container"
    inventory = root / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"hosts": {"registry-a": values}}}))
    play = plays / "defaults.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "all", "gather_facts": False, "tasks": [
            {"ansible.builtin.include_tasks": "../roles/pki_host_local_certificate/tasks/registry_defaults.yml"},
            {"ansible.builtin.assert": {"that": [
                f"zot_registry_quadlet_dir == '{directory}'",
                f"zot_registry_quadlet_path == '{expected}'",
                "zot_registry_data_dir == '/reviewed/data'",
                "zot_registry_host_port == 5443",
                "zot_registry_firewalld_port == '5443/tcp'",
                "zot_registry_smoke_url == 'https://registry-a:5443/v2/'",
                "registry_zot_defaults.zot_registry_host_port == 443",
                "registry_pki_defaults.pki_host_local_certificate_transport == 'gitlab'",
                "pki_host_local_certificate_transport == 'filesystem'",
            ]}},
        ],
    }]))
    result = command_runner.run(["ansible-playbook", "-i", inventory, play])
    result.assert_success()
    assert "changed=0" in result.stdout


@pytest.mark.parametrize("runtime_present", [False, True])
def test_empty_host_stage_check_uses_native_file_copy_and_template_modules(
    repo_root, isolated_test_dir, command_runner, runtime_present,
):
    root = isolated_test_dir
    role = root / "roles/zot_registry"
    shutil.copytree(repo_root / "roles/zot_registry", role)
    pki = root / "roles/pki_host_local_certificate/files"
    pki.mkdir(parents=True)
    shutil.copy(repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle", pki)
    target = root / "empty-target"
    target.mkdir()
    replacements = {
        "/etc/zot": str(target / "etc/zot"),
        "/var/lib/zot/data": str(target / "var/lib/zot/data"),
        "/var/lib/platform-config/pki/host-local/registry-dev": str(target / "var/lib/registry-pki"),
        "/usr/local/libexec/platform-pki-host-local-lifecycle": str(target / "usr/local/libexec/platform-pki-host-local-lifecycle"),
        "/etc/containers/systemd": str(target / "etc/containers/systemd"),
    }
    # Only fixed target paths are relocated. Filesystem modules, templates,
    # custody validation, conditionals, and handler selection remain production.
    for path in role.rglob("*.yml"):
        text = path.read_text()
        for old, new in replacements.items():
            text = text.replace(old, new)
        path.write_text(text)
    plugins = root / "action_plugins"
    plugins.mkdir()
    log = root / "target-operations.jsonl"
    (plugins / "stage_target.py").write_text('''
import json
from pathlib import Path
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        with Path(task_vars['test_log']).open('a') as stream:
            stream.write(json.dumps(dict(args=args, check=self._task.check_mode)) + '\\n')
        if 'name' in args:
            assert args == dict(name='python3-cryptography', state='present'), args
            return dict(changed=not task_vars['test_runtime_present'])
        assert args == dict(daemon_reload=True), args
        assert self._task.check_mode
        return dict(changed=False)
''')
    for path in [role / "tasks/resolve_tls_custody.yml", role / "handlers/main.yml"]:
        tasks = yaml.safe_load(path.read_text())
        for task in tasks:
            for module in ("ansible.builtin.package", "ansible.builtin.systemd_service"):
                if module in task:
                    task["stage_target"] = task.pop(module)
        path.write_text(yaml.safe_dump(tasks, sort_keys=False))
    play = root / "stage.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"zot_registry_firewalld_manage": False,
                 "zot_registry_allow_insecure_anonymous_access": True,
                 "pki_host_local_certificate_operation": "issue",
                 "test_runtime_present": runtime_present, "test_log": str(log)},
        "roles": [str(role)],
        "post_tasks": [{"ansible.builtin.assert": {"that": [
            "zot_registry_tls_effective_custody == 'dormant'",
            "zot_registry_config_result is changed",
            "zot_registry_quadlet_result is changed",
        ]}}],
    }]))
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", play, "--check", "--diff"],
                                environment={"ANSIBLE_ACTION_PLUGINS": str(plugins)})
    result.assert_success()
    assert list(target.iterdir()) == []
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls == [
        {"args": {"name": "python3-cryptography", "state": "present"}, "check": True},
        {"args": {"daemon_reload": True}, "check": True},
    ]
