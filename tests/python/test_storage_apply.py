from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from test_storage_check import inventory, openbao_inventory


# Sanitized output shape from platform-ci/templates/storage-apply.yml (variables).
CI_CONTROLLER_VARS = {
    "ansible_become_password": None, "ansible_become_pass": None,
    "ansible_sudo_pass": None, "ansible_su_pass": None,
    "ansible_private_key": None, "ansible_password": None, "ansible_ssh_pass": None,
    "ansible_ssh_password_mechanism": "disable", "ansible_ssh_pkcs11_provider": "",
    "ansible_ssh_executable": "/usr/bin/ssh", "ansible_ssh_common_args": "", "ansible_ssh_extra_args": "",
    "ansible_ssh_args": (
        "-F /dev/null -o BatchMode=yes -o PreferredAuthentications=publickey "
        "-o PubkeyAuthentication=yes -o PasswordAuthentication=no "
        "-o KbdInteractiveAuthentication=no -o HostbasedAuthentication=no "
        "-o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
        "-o UserKnownHostsFile=/synthetic/known_hosts -o GlobalKnownHostsFile=/dev/null"
    ),
    "platform_ci_ssh_private_key_files": {"server-a": "/synthetic/identity-0"},
    "ansible_ssh_private_key_file": "{{ platform_ci_ssh_private_key_files[inventory_hostname] }}",
}


@pytest.fixture
def launcher(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    root.chmod(0o700)
    inv = root / "inventory.json"
    inv.write_text(json.dumps(inventory()))
    inv.chmod(0o600)
    variables = root / "vars.json"
    variables.write_text("{}")
    variables.chmod(0o600)
    log = root / "commands.jsonl"
    bin_dir = root / "bin"
    bin_dir.mkdir()
    code = '''#!/usr/bin/env python3
import json, os, pathlib, signal, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["FAKE_LOG"], "a") as out:
    out.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
controller = pathlib.Path(sys.argv[sys.argv.index("--extra-vars") + 1][1:])
with open(os.environ["CONTROLLER_LOG"], "a") as out:
    out.write(json.dumps(json.loads(controller.read_text())) + "\\n")
if name == "ansible-inventory":
    if os.environ.get("TAMPER_CONTROLLER") == "1":
        pathlib.Path(os.environ["ORIGINAL_CONTROLLER"]).write_text('{"storage_volumes": []}')
    print(pathlib.Path(os.environ["FAKE_INVENTORY"]).read_text())
    raise SystemExit(0)
phase = os.environ["PLATFORM_CONFIG_OPERATION_PHASE"]
fault = os.environ.get("FAULT", "") if phase == os.environ.get("FAULT_PHASE") else ""
if fault == "interrupt":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    os.kill(os.getppid(), signal.SIGTERM)
    signal.pause()
if os.environ.get("NATIVE") == "1":
    args = [os.environ["REAL_PLAYBOOK"], "-i", os.environ["LOCAL_INVENTORY"],
            os.environ["LOCAL_PLAYBOOK"], "--limit", os.environ["NODE"]]
    if "--check" in sys.argv:
        args += ["--check", "--diff"]
    os.execv(args[0], args)
counters = dict(ok=1, changed=int(phase in ("storage-check", "storage-apply")),
                failures=0, unreachable=0, skipped=0, rescued=0, ignored=0)
if fault in counters:
    counters[fault] = 1
if fault != "missing":
    with open(os.environ["PLATFORM_CONFIG_OPERATION_SUMMARY_PATH"], "a") as out:
        out.write(json.dumps(dict(schema=1, kind="recap", phase=phase,
                   host=os.environ["NODE"], counters=counters)) + "\\n")
        if fault == "extra-host":
            out.write(json.dumps(dict(schema=1, kind="recap", phase=phase,
                       host="runner", counters=counters)) + "\\n")
raise SystemExit(7 if fault == "exit" else 0)
'''
    for name in ("ansible-inventory", "ansible", "ansible-playbook"):
        path = bin_dir / name
        path.write_text(code)
        path.chmod(0o755)

    def run(node=None, phase="", fault="", native=False, controller=None,
            hostvars=None, tamper=False, operation="storage-apply", inventory_data=None):
        node = node or ("vault-a" if operation == "openbao-storage-apply" else "server-a")
        if controller is not None:
            variables.write_text(controller if isinstance(controller, str) else json.dumps(controller))
        data = inventory_data if inventory_data is not None else (
            openbao_inventory() if operation == "openbao-storage-apply" else inventory())
        if hostvars is not None:
            data["_meta"]["hostvars"][node].update(hostvars)
        inv.write_text(json.dumps(data))
        environment = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_LOG": str(log),
            "FAKE_INVENTORY": str(inv), "FAULT_PHASE": phase, "FAULT": fault, "NODE": node,
            "CONTROLLER_LOG": str(root / "controller-inputs.jsonl"),
            "ORIGINAL_CONTROLLER": str(variables), "TAMPER_CONTROLLER": str(int(tamper)),
        }
        if native:
            local_inv = root / "local.yml"
            local_inv.write_text(yaml.safe_dump({"all": {"hosts": {node: {"ansible_connection": "local"}}}}))
            play = root / "local-play.yml"
            play.write_text(yaml.safe_dump([{
                "hosts": "all", "gather_facts": False,
                "tasks": [{
                    "name": "Observe native check versus real apply",
                    "ansible.builtin.assert": {"that": [
                        "ansible_check_mode == (lookup('env', 'PLATFORM_CONFIG_OPERATION_PHASE') == 'storage-check')"
                    ]},
                    "changed_when": "lookup('env', 'PLATFORM_CONFIG_OPERATION_PHASE') in ['storage-check', 'storage-apply'] or "
                                    "(lookup('env', 'PLATFORM_CONFIG_OPERATION_PHASE') == 'storage-idempotence' and lookup('env', 'FAULT') == 'changed')",
                }],
            }]))
            real_playbook = shutil.which("ansible-playbook")
            assert real_playbook is not None
            environment.update(NATIVE="1", REAL_PLAYBOOK=real_playbook,
                               LOCAL_INVENTORY=str(local_inv), LOCAL_PLAYBOOK=str(play))
        result = command_runner.run([
            repo_root / "scripts/platform-config-operation", operation,
            "--inventory", inv, "--controller-vars", variables, "--node", node,
        ], environment=environment, timeout=60)
        commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        used_variables = Path(commands[0][-1][1:]) if commands else variables
        return result, commands, inv, used_variables

    return run


@pytest.mark.parametrize("operation,node", [("storage-apply", "server-a"), ("storage-apply", "agent-a"),
                                           ("openbao-storage-apply", "vault-a")])
def test_storage_apply_fixed_single_node_calls(repo_root, launcher, operation, node):
    result, commands, inv, variables = launcher(node=node, operation=operation)
    result.assert_success()
    assert "Overall: PASS" in result.stdout
    common = ["--extra-vars", f"@{variables}"]
    play = ["ansible-playbook", "-i", str(inv), str(repo_root / "playbooks/storage-volumes.yml"), "--limit", node]
    assert commands == [
        ["ansible-inventory", "-i", str(inv), "--list", *common],
        ["ansible", "-i", str(inv), node, "-m", "ansible.builtin.ping", *common],
        [*play, "--check", "--diff", *common],
        [*play, *common],
        [*play, *common],
        ["ansible-playbook", "-i", str(inv), str(repo_root / "playbooks/maintenance/storage-volumes-verify.yml"),
         "--limit", node, *common],
    ]


@pytest.mark.parametrize("controller", [CI_CONTROLLER_VARS, {
    "platform_ci_ssh_private_key_files": {"server-a": "/synthetic/server-a", "agent-a": "/synthetic/agent-a"},
}])
def test_storage_apply_accepts_generated_transport_and_direct_key_map(launcher, isolated_test_dir, controller):
    result, commands, _, used = launcher(controller=controller)
    result.assert_success()
    assert len(commands) == 6
    assert used != isolated_test_dir / "vars.json"
    assert not used.exists()  # private snapshot was cleaned up
    assert [json.loads(line) for line in (isolated_test_dir / "controller-inputs.jsonl").read_text().splitlines()] == [controller] * 6


@pytest.mark.parametrize("key", [
    "storage_volumes", "storage_volume_layouts", "storage_volume_device", "storage_volume_initialize",
    "storage_volume_require_stable_device", "storage_volume_default_mount_state", "initialize",
    "ansible_host", "ansible_connection", "ansible_become", "arbitrary_variable",
])
def test_storage_apply_rejects_nontransport_controller_vars_before_inventory(launcher, key):
    result, commands, _, _ = launcher(controller={**CI_CONTROLLER_VARS, key: "rejected-secret-value"})
    assert result.returncode == 2
    assert "controller-vars must be transport-only JSON" in result.stderr
    assert "rejected-secret-value" not in result.stdout + result.stderr
    assert commands == []


@pytest.mark.parametrize("controller", [
    "storage_volumes: []\n", "{", "[]", "null",
    '{"ansible_ssh_args":"first","ansible_ssh_args":"second"}',
    '{"platform_ci_ssh_private_key_files":{"server-a":"/a","server-a":"/b"}}',
    {"platform_ci_ssh_private_key_files": []},
    {"platform_ci_ssh_private_key_files": {}},
    {"platform_ci_ssh_private_key_files": {"server-a": {"initialize": True}}},
    {"platform_ci_ssh_private_key_files": {"server-a": "relative"}},
    {"platform_ci_ssh_private_key_files": {"server-a": "/{{ lookup('pipe', 'id') }}"}},
    {"ansible_ssh_args": ["-F", "/dev/null"]},
    {"ansible_ssh_args": "{{ lookup('pipe', 'id') }}"},
    {"ansible_ssh_executable": "ssh"},
    {"ansible_ssh_private_key_file": "/synthetic/key"},
    {"ansible_ssh_private_key_file": CI_CONTROLLER_VARS["ansible_ssh_private_key_file"]},
    {"ansible_password": "not-null"},
    {"ansible_ssh_password_mechanism": "sshpass"},
])
def test_storage_apply_rejects_malformed_controller_schema_before_inventory(launcher, controller):
    result, commands, _, _ = launcher(controller=controller)
    assert result.returncode == 2
    assert "controller-vars must be transport-only JSON" in result.stderr
    assert commands == []


def test_storage_apply_uses_validated_snapshot_after_input_changes(launcher, isolated_test_dir):
    result, commands, _, _ = launcher(controller=CI_CONTROLLER_VARS, tamper=True)
    result.assert_success()
    assert len(commands) == 6
    assert json.loads((isolated_test_dir / "vars.json").read_text()) == {"storage_volumes": []}
    observed = [json.loads(line) for line in (isolated_test_dir / "controller-inputs.jsonl").read_text().splitlines()]
    assert observed == [CI_CONTROLLER_VARS] * 6


@pytest.mark.parametrize("state", ["unmounted", "present", "absent", "ephemeral", "remounted", "", None, False, {}, "{{ mount_state }}"])
@pytest.mark.parametrize("source", ["volume", "default"])
def test_storage_apply_rejects_nonmounted_inventory_before_ping(launcher, state, source):
    values = {"storage_volume_default_mount_state": state} if source == "default" else {
        "storage_volumes": [{"lv_name": "data", "state": state}],
    }
    result, commands, _, _ = launcher(hostvars=values)
    assert result.returncode == 2
    assert [call[0] for call in commands] == ["ansible-inventory"]


def test_storage_apply_requires_every_volume_mounted(launcher):
    result, commands, _, _ = launcher(hostvars={"storage_volumes": [
        {"lv_name": "data", "state": "mounted"}, {"lv_name": "other", "state": "absent"},
    ]})
    assert result.returncode == 2
    assert len(commands) == 1


def test_storage_apply_honors_explicit_mounted_override_of_inventory_default(launcher):
    result, commands, _, _ = launcher(hostvars={
        "storage_volume_default_mount_state": "unmounted",
        "storage_volumes": [{"lv_name": "data", "state": "mounted"}],
    })
    result.assert_success()
    assert len(commands) == 6


def test_storage_check_retains_unrestricted_controller_vars_and_state_preview(launcher, isolated_test_dir):
    result, commands, _, used = launcher(operation="storage-check", controller={"storage_volume_initialize": True},
                                        hostvars={"storage_volumes": [{"lv_name": "data", "state": "unmounted"}]})
    result.assert_success()
    assert len(commands) == 3
    assert used == isolated_test_dir / "vars.json"


def test_storage_apply_preflight_mount_default_matches_role(repo_root):
    defaults = yaml.safe_load((repo_root / "roles/storage_volume/defaults/main.yml").read_text())
    assert defaults["storage_volume_default_mount_state"] == "mounted"


@pytest.mark.parametrize("node", ["all", "rke2_cluster", "storage_volume_hosts", "rke2_servers", "rke2_agents",
                                  "192.0.2.1", "runner", "vault-a", "server-a,agent-a"])
def test_storage_apply_invalid_scope_never_pings(launcher, node):
    result, commands, _, _ = launcher(node=node)
    result.assert_failure()
    assert [call[0] for call in commands] == ([] if node in {"all", "server-a,agent-a"} else ["ansible-inventory"])


@pytest.mark.parametrize("phase,count", [("connectivity", 2), ("storage-check", 3), ("storage-apply", 4),
                                         ("storage-idempotence", 5), ("storage-verify", 6)])
@pytest.mark.parametrize("fault", ["exit", "missing", "failures", "unreachable", "ignored", "rescued", "extra-host"])
@pytest.mark.parametrize("operation", ["storage-apply", "openbao-storage-apply"])
def test_storage_apply_stops_on_failed_or_incomplete_phase(launcher, phase, count, fault, operation):
    result, commands, _, _ = launcher(phase=phase, fault=fault, operation=operation)
    result.assert_failure()
    assert result.returncode == (7 if fault == "exit" else 2)
    assert "Overall: FAIL" in result.stdout
    assert len(commands) == count


@pytest.mark.parametrize("operation", ["storage-apply", "openbao-storage-apply"])
def test_storage_apply_forwards_interruption_without_retry(launcher, operation):
    result, commands, _, _ = launcher(phase="storage-apply", fault="interrupt", operation=operation)
    assert result.returncode == 143
    assert "Overall: FAIL" in result.stdout
    assert len(commands) == 4


def test_storage_verifier_is_read_only_and_reuses_identity_guard(repo_root):
    play = yaml.safe_load((repo_root / "playbooks/maintenance/storage-volumes-verify.yml").read_text())[0]
    tasks = yaml.safe_load((repo_root / "playbooks/maintenance/tasks/storage-volumes-verify-mount.yml").read_text())
    assert "roles" not in play
    assert tasks[0]["ansible.builtin.include_tasks"] == "../../../roles/storage_volume/tasks/verify_mountpoint.yml"
    tasks += yaml.safe_load((repo_root / "roles/storage_volume/tasks/verify_mountpoint.yml").read_text())
    for task in play["tasks"] + tasks:
        modules = [key for key in task if key.startswith("ansible.")]
        assert len(modules) == 1
        assert modules[0] in {"ansible.builtin.assert", "ansible.builtin.include_tasks", "ansible.builtin.include_vars",
                              "ansible.builtin.stat", "ansible.builtin.set_fact", "ansible.builtin.command"}
        if modules[0] == "ansible.builtin.command":
            assert task[modules[0]]["argv"][0] in {"findmnt", "lsblk", "find"}
            assert task["changed_when"] is False
            assert task["check_mode"] is False


def test_storage_verifier_real_includes_reject_unmounted_local_directory(repo_root, isolated_test_dir, command_runner):
    mountpoint = isolated_test_dir / "empty"
    mountpoint.mkdir()
    inv = isolated_test_dir / "local.yml"
    inv.write_text(yaml.safe_dump({"all": {"children": {
        "rke2_cluster": {"children": {"rke2_servers": {"hosts": {"server-a": {
            "ansible_connection": "local", "ansible_become": False,
            "storage_volumes": [{"vg_name": "missing", "lv_name": "missing", "mountpoint": str(mountpoint)}],
        }}}}},
        "storage_volume_hosts": {"hosts": {"server-a": {}}},
    }}}))
    result = command_runner.run([
        "ansible-playbook", "-i", inv, repo_root / "playbooks/maintenance/storage-volumes-verify.yml",
        "--limit", "server-a",
    ])
    result.assert_failure()
    assert "must be actively mounted after apply" in result.stdout, result.diagnostics()
    assert "changed=0" in result.stdout
    assert list(mountpoint.iterdir()) == []


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("operation", ["storage-apply", "openbao-storage-apply"])
def test_storage_apply_native_callback_requires_real_second_apply_unchanged(launcher, changed, operation):
    result, commands, _, _ = launcher(phase="storage-idempotence", fault="changed" if changed else "", native=True,
                                     operation=operation)
    assert result.returncode == (2 if changed else 0), result.diagnostics()
    assert f"Overall: {'FAIL' if changed else 'PASS'}" in result.stdout
    assert len(commands) == (5 if changed else 6)
    host, role = ("vault-a", "openbao-storage") if operation == "openbao-storage-apply" else ("server-a", "server")
    assert any(line.split()[:4] == [host, role, "storage-idempotence", "FAIL" if changed else "PASS"]
                for line in result.stdout.splitlines())


def test_openbao_apply_uses_validated_transport_snapshot(launcher, isolated_test_dir):
    controller = {**CI_CONTROLLER_VARS, "platform_ci_ssh_private_key_files": {"vault-a": "/synthetic/vault-a"}}
    result, commands, _, used = launcher(operation="openbao-storage-apply", controller=controller, tamper=True)
    result.assert_success()
    assert used != isolated_test_dir / "vars.json" and not used.exists()
    observed = [json.loads(line) for line in (isolated_test_dir / "controller-inputs.jsonl").read_text().splitlines()]
    assert observed == [controller] * 6


def test_openbao_apply_refuses_nonmounted_peer_before_ping(launcher):
    data = openbao_inventory()
    data["_meta"]["hostvars"]["vault-c"]["storage_volumes"][0]["state"] = "absent"
    result, commands, _, _ = launcher(operation="openbao-storage-apply", inventory_data=data)
    result.assert_failure()
    assert [call[0] for call in commands] == ["ansible-inventory"]


def test_openbao_apply_rejects_intent_override_before_inventory(launcher):
    result, commands, _, _ = launcher(operation="openbao-storage-apply", controller={"storage_volumes": []})
    result.assert_failure()
    assert "transport-only JSON" in result.stderr
    assert commands == []


@pytest.mark.parametrize("scenario", ["valid", "options", "wrong-device", "bind", "fstype", "absent", "exec", "override"])
def test_storage_post_apply_mount_verification(repo_root, isolated_test_dir, command_runner, scenario):
    """Execute shipped assertions/variable resolution with only target probes doubled."""
    root = isolated_test_dir
    plugins = root / "action_plugins"
    plugins.mkdir()
    (plugins / "storage_probe.py").write_text('''
import json
from ansible.plugins.action import ActionBase

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        scenario = task_vars["test_scenario"]
        args = self._task.args
        if "path" in args:
            if args["path"].startswith("/dev/"):
                assert args["path"] == "/dev/data/primary"
                return dict(changed=False, stat=dict(exists=True, isblk=True))
            return dict(changed=False, stat=dict(exists=True, isdir=True, islnk=False))
        argv = args["argv"]
        if argv[0] == "lsblk":
            assert argv[-1] == "/dev/data/primary"
            return dict(changed=False, rc=0, stdout="253:1")
        if argv[0] == "find":
            return dict(changed=False, rc=0, stdout="")
        assert argv[0] == "findmnt"
        if argv[-1] == "OPTIONS":
            options = "rw,nosuid,nodev,relatime,attr2,inode64"
            if scenario == "options":
                options = "rw,nodev,relatime"
            if scenario in ("exec", "override"):
                options += ",noexec"
            rows = [dict(options=options)]
        else:
            assert argv[-1] == "TARGET,SOURCE,FSTYPE,FSROOT,MAJ:MIN"
            if scenario == "absent":
                return dict(changed=False, rc=1, stdout="")
            rows = [dict(target=argv[argv.index("--mountpoint") + 1], source="/dev/mapper/data-primary",
                         fstype="ext4" if scenario == "fstype" else "xfs",
                         fsroot="/subdir" if scenario == "bind" else "/",
                         **{"maj:min": "253:2" if scenario == "wrong-device" else "253:1"})]
        return dict(changed=False, rc=0, stdout=json.dumps(dict(filesystems=rows)))
''')

    def stage_probes(source, target):
        tasks = yaml.safe_load(source.read_text())
        for task in tasks:
            for module in ("ansible.builtin.command", "ansible.builtin.stat"):
                if module in task:
                    task["ansible.legacy.storage_probe"] = task.pop(module)
        target.write_text(yaml.safe_dump(tasks))
        return tasks

    identity = root / "identity.yml"
    stage_probes(repo_root / "roles/storage_volume/tasks/verify_mountpoint.yml", identity)
    mounts = root / "mounts.yml"
    tasks = stage_probes(repo_root / "playbooks/maintenance/tasks/storage-volumes-verify-mount.yml", mounts)
    tasks[0]["ansible.builtin.include_tasks"] = str(identity)
    mounts.write_text(yaml.safe_dump(tasks))
    play = yaml.safe_load((repo_root / "playbooks/maintenance/storage-volumes-verify.yml").read_text())
    play[0]["tasks"][1]["ansible.builtin.include_vars"]["file"] = str(repo_root / "roles/storage_volume/defaults/main.yml")
    play[0]["tasks"][2]["ansible.builtin.include_tasks"] = str(mounts)
    playbook = root / "verify.yml"
    playbook.write_text(yaml.safe_dump(play))
    values = {
        "ansible_connection": "local", "ansible_become": False, "test_scenario": scenario,
        "storage_volume_layouts": [{"name": "data", "vg_name": "data"}],
        "storage_volumes": [{"layout": "data", "lv_name": "primary", "mountpoint": "/srv/data"}],
    }
    if scenario == "exec":
        values["storage_volumes"][0]["mount_options"] = "rw,exec"
    elif scenario == "override":
        values["storage_volume_default_mount_options"] = "rw,noexec"
        values["storage_volumes"] = [{"vg_name": "data", "lv_name": "primary", "mountpoint": "/srv/data"}]
    inv = root / "hosts.yml"
    inv.write_text(yaml.safe_dump({"all": {"children": {
        "rke2_cluster": {"children": {"rke2_servers": {"hosts": {"server-a": values}}}},
        "storage_volume_hosts": {"hosts": {"server-a": {}}},
    }}}))
    result = command_runner.run(["ansible-playbook", "-i", inv, playbook, "--limit", "server-a"],
                                environment={"ANSIBLE_ACTION_PLUGINS": str(plugins)})
    if scenario in {"valid", "override"}:
        result.assert_success()
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
        messages = {
            "options": "Active storage mount options do not match",
            "exec": "Active storage mount options do not match",
            "wrong-device": "a different filesystem root or block device",
            "bind": "a different filesystem root or block device",
            "fstype": "must be actively mounted after apply",
            "absent": "must be actively mounted after apply",
        }
        assert messages[scenario] in result.stdout, result.diagnostics()
