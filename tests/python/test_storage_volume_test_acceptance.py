from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

import pytest
import yaml

from ansible_test_helpers import run_playbook
from conftest import CommandRunner


def _load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _mock_environment(test_dir: Path, scenario: str = "valid") -> tuple[Path, Path, dict[str, str]]:
    bin_dir = test_dir / "bin"
    bin_dir.mkdir()
    env_file = test_dir / "config-test.env"
    inventory = test_dir / "inventory.yml"
    log = test_dir / "playbook.log"
    env_file.write_text(
        "export ANSIBLE_INVENTORY=ansible-inventory\n"
        "export ANSIBLE=ansible\n"
        "export ANSIBLE_PLAYBOOK=ansible-playbook\n",
        encoding="utf-8",
    )
    inventory.write_text("---\nall: {}\n", encoding="utf-8")
    _write_executable(
        bin_dir / "ansible-inventory",
        """#!/usr/bin/env python3
import json, os
scenario = os.environ.get("STORAGE_TEST_SCENARIO", "valid")
hosts = ["storage-volume-test-example"]
if scenario == "group-zero": hosts = []
if scenario == "group-multi": hosts.append("storage-volume-test-other")
device = "/dev/sdb" if scenario == "wrong-path" else "/dev/disk/by-id/mock-storage-fixture"
hostvars = {host: {"storage_volume_test_device": device} for host in hosts}
ssh_name = os.environ.get("STORAGE_TEST_HOSTVAR_NAME", "")
if ssh_name:
    hostvars[hosts[0]][ssh_name] = os.environ["STORAGE_TEST_SSH_VALUE"]
print(json.dumps({"storage_volume_test_hosts": {"hosts": hosts}, "_meta": {"hostvars": hostvars}}))
""",
    )
    _write_executable(
        bin_dir / "ansible",
        """#!/usr/bin/env python3
import os
scenario = os.environ.get("STORAGE_TEST_SCENARIO", "valid")
print("  hosts (1):")
if scenario == "limit-zero": pass
elif scenario == "limit-multi":
    print("    storage-volume-test-example")
    print("    storage-volume-test-other")
elif scenario == "limit-unrelated": print("    unrelated-host")
else: print("    storage-volume-test-example")
""",
    )
    _write_executable(
        bin_dir / "ansible-config",
        """#!/usr/bin/env python3
import json, os, sys
configured = os.environ.get("STORAGE_TEST_CONFIG_HOST_KEY_CHECKING", os.environ.get("ANSIBLE_HOST_KEY_CHECKING", "true"))
value = configured.lower() in ("true", "yes", "on", "1")
if "--type" in sys.argv:
    ssh_value = os.environ.get("STORAGE_TEST_CONFIG_SSH_VALUE", "")
    plugin_host_key = os.environ.get("STORAGE_TEST_PLUGIN_HOST_KEY_CHECKING", "true").lower() in ("true", "yes", "on", "1")
    print(json.dumps([{"ssh": [
        {"name": "host_key_checking", "origin": "mock", "value": plugin_host_key},
        {"name": "ssh_args", "origin": "mock", "value": ssh_value},
        {"name": "ssh_common_args", "origin": "mock", "value": ""},
        {"name": "ssh_extra_args", "origin": "mock", "value": ""}
    ]}]))
else:
    print(json.dumps([{"name": "HOST_KEY_CHECKING", "origin": "mock", "value": value}]))
""",
    )
    _write_executable(
        bin_dir / "ssh",
        """#!/usr/bin/env python3
import os
strict = os.environ.get("STORAGE_TEST_OPENSSH_STRICT", "ask")
known_hosts = os.environ.get("STORAGE_TEST_OPENSSH_KNOWN_HOSTS", "~/.ssh/known_hosts")
print(f"stricthostkeychecking {strict}")
print(f"userknownhostsfile {known_hosts}")
""",
    )
    _write_executable(
        bin_dir / "ansible-playbook",
        """#!/usr/bin/env python3
import os, pathlib, sys
pathlib.Path(os.environ["STORAGE_TEST_LOG"]).write_text("\\n".join(sys.argv[1:]), encoding="utf-8")
scenario = os.environ.get("STORAGE_TEST_SCENARIO", "valid")
counters = {"changed": 0, "unreachable": 0, "failed": 0, "rescued": 0, "ignored": 0}
if scenario.startswith("recap-"):
    counters[scenario.removeprefix("recap-")] = 1
print("PLAY RECAP")
print("storage-volume-test-example : ok=1 changed={changed} unreachable={unreachable} failed={failed} skipped=0 rescued={rescued} ignored={ignored}".format(**counters))
if scenario == "recap-duplicate":
    print("storage-volume-test-example : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0")
if scenario == "recap-duplicate-counter":
    print("storage-volume-test-example : ok=1 changed=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0")
if scenario == "recap-nonnumeric-counter":
    print("storage-volume-test-example : ok=1 changed=no unreachable=0 failed=0 skipped=0 rescued=0 ignored=0")
""",
    )
    environment = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "STORAGE_TEST_LOG": str(log),
        "STORAGE_TEST_SCENARIO": scenario,
    }
    return env_file, inventory, environment


def _run_helper(
    repo_root: Path,
    command_runner: CommandRunner,
    test_dir: Path,
    *,
    operation: str = "check",
    scenario: str = "valid",
    limit: str = "storage-volume-test-example",
):
    env_file, inventory, environment = _mock_environment(test_dir, scenario)
    return command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            operation,
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            limit,
        ],
        environment=environment,
    )


def test_storage_test_inventory_is_isolated_and_sanitized(repo_root: Path) -> None:
    root = repo_root / "inventories/config-test"
    inventory = _load_yaml(root / "hosts.yml.example")
    hostvars = _load_yaml(root / "host_vars/storage-volume-test-example.yml.example")
    text = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*") if path.is_file())
    children = inventory["all"]["children"]

    assert set(children) == {"rocky", "storage_volume_test_hosts"}
    assert list(children["rocky"]["hosts"]) == ["storage-volume-test-example"]
    assert list(children["storage_volume_test_hosts"]["hosts"]) == [
        "storage-volume-test-example"
    ]
    assert "storage_volume_hosts" not in text
    assert "approval" not in text.lower()
    assert hostvars["storage_volume_test_device"].startswith("/dev/disk/by-id/")
    assert hostvars["storage_volume_test_pv_device"] == (
        "{{ storage_volume_test_device }}-part1"
    )


def test_storage_test_playbook_syntax_and_site_absence(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/storage-volume-test.yml",
        inventory=repo_root / "inventories/config-test/hosts.yml.example",
        syntax_check=True,
    ).assert_success()
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    assert "storage-volume-test" not in site


@pytest.mark.parametrize(
    ("scenario", "limit", "message"),
    [
        ("group-zero", "storage-volume-test-example", "exactly one member"),
        ("group-multi", "storage-volume-test-example", "exactly one member"),
        ("limit-zero", "storage-volume-test-example", "resolve exactly one"),
        ("limit-multi", "storage-volume-test-example", "resolve exactly one"),
        ("valid", "unrelated-host", "literal fixture host"),
        ("wrong-path", "storage-volume-test-example", "exact by-id or by-path"),
    ],
)
def test_storage_test_helper_rejects_unsafe_target_resolution(
    scenario: str,
    limit: str,
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    result = _run_helper(
        repo_root,
        command_runner,
        isolated_test_dir,
        scenario=scenario,
        limit=limit,
    )
    result.assert_failure()
    assert message in result.stderr


def test_storage_test_helper_requires_all_explicit_arguments(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    helper = repo_root / "scripts/storage-volume-test"
    for argv, message in (
        ([helper, "check"], "--env-file"),
        ([helper, "check", "--env-file", "/missing"], "--inventory"),
        (
            [helper, "check", "--env-file", "/missing", "--inventory", "/missing"],
            "--limit",
        ),
    ):
        result = command_runner.run(argv)
        result.assert_failure()
        assert message in result.stderr


def test_storage_test_helper_check_uses_check_diff_and_exact_reserved_vars(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    result = _run_helper(repo_root, command_runner, isolated_test_dir)
    result.assert_success()
    log = (isolated_test_dir / "playbook.log").read_text(encoding="utf-8").splitlines()
    assert "--check" in log
    assert "--diff" in log
    assert "storage_volume_test_operation=check" in log
    assert "storage_volume_test_target_host=storage-volume-test-example" in log
    assert "storage_volume_test_target_device=/dev/disk/by-id/mock-storage-fixture" in log
    assert "storage_volume_test_supported_boundary=storage-volume-test-helper-v1" in log
    assert not any("approval" in argument for argument in log)


def test_storage_test_helper_runs_from_outside_repository(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    outside = isolated_test_dir / "outside"
    outside.mkdir()
    relative_env = os.path.relpath(env_file, outside)
    relative_inventory = os.path.relpath(inventory, outside)
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            relative_env,
            "--inventory",
            relative_inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        cwd=outside,
        environment=environment,
    )
    result.assert_success()
    log = (isolated_test_dir / "playbook.log").read_text(encoding="utf-8").splitlines()
    assert str(repo_root / "playbooks/maintenance/storage-volume-test.yml") in log
    inventory_index = log.index("-i") + 1
    assert log[inventory_index] == str(inventory.resolve())


def test_storage_test_playbook_owns_exact_separate_approvals(repo_root: Path) -> None:
    helper = (repo_root / "scripts/storage-volume-test").read_text(encoding="utf-8")
    playbook = (repo_root / "playbooks/maintenance/storage-volume-test.yml").read_text(
        encoding="utf-8"
    )
    initialize = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-initialize.yml").read_text(
        encoding="utf-8"
    )
    reboot = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-reboot.yml").read_text(
        encoding="utf-8"
    )
    assert playbook.count("ansible.builtin.pause:") == 1
    assert "{{ storage_volume_test_operation }}-storage-test-fixture|{{ inventory_hostname }}|{{ storage_volume_test_device }}" in playbook
    assert playbook.index("Prompt for exact destructive storage fixture approval") < playbook.index(
        "Read effective Ansible SSH connection plugin configuration"
    )
    assert playbook.index("Prompt for exact destructive storage fixture approval") < playbook.index(
        "Read effective OpenSSH storage acceptance policy"
    )
    assert "ansible.builtin.pause:" not in initialize
    assert "ansible.builtin.pause:" not in reboot
    assert "approval" not in helper
    assert "storage_volume_test_reboot_nonce=$nonce" in helper


def test_storage_test_direct_playbook_rejects_wrong_tty_approval_before_contact(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    bin_dir = isolated_test_dir / "bin"
    bin_dir.mkdir()
    ssh_marker = isolated_test_dir / "ssh-g-ran"
    _write_executable(
        bin_dir / "ssh",
        """#!/usr/bin/env bash
set -euo pipefail
: >"$STORAGE_TEST_SSH_MARKER"
exit 99
""",
    )
    playbook_argv = [
        "ansible-playbook",
        "-i",
        repo_root / "inventories/config-test/hosts.yml.example",
        repo_root / "playbooks/maintenance/storage-volume-test.yml",
        "--limit",
        "storage-volume-test-example",
        "--extra-vars",
        "storage_volume_test_supported_boundary=storage-volume-test-helper-v1",
        "--extra-vars",
        "storage_volume_test_operation=initialize",
        "--extra-vars",
        "storage_volume_test_target_host=storage-volume-test-example",
        "--extra-vars",
        "storage_volume_test_target_device=/dev/disk/by-id/scsi-0QEMU_CONFIG_TEST_FIXTURE",
        "--extra-vars",
        "storage_volume_test_device=/dev/disk/by-id/scsi-0QEMU_CONFIG_TEST_FIXTURE",
    ]
    pty_driver = r"""
import os
import pty
import sys
import time

seen = bytearray()
sent = False

def read_master(fd):
    global sent
    data = os.read(fd, 4096)
    seen.extend(data)
    if not sent and b"Type exactly initialize-storage-test-fixture|" in seen:
        time.sleep(0.2)
        os.write(fd, b"wrong-approval\n")
        sent = True
    return data

status = pty.spawn(sys.argv[1:], read_master)
raise SystemExit(os.waitstatus_to_exitcode(status))
"""
    result = command_runner.run(
        ["python", "-c", pty_driver, *playbook_argv],
        environment={
            "PATH": f"{bin_dir}{os.pathsep}{command_runner.environment['PATH']}",
            "STORAGE_TEST_SSH_MARKER": str(ssh_marker),
        },
        timeout=60,
    )
    result.assert_failure()
    output = result.stdout + result.stderr
    assert "initialize-storage-test-fixture|storage-volume-test-example|/dev/disk/by-id/" in output
    assert "Exact destructive storage fixture approval did not match" in output
    assert "UNREACHABLE" not in output
    assert not ssh_marker.exists()


def test_storage_test_direct_playbook_rejects_unsafe_plugin_before_ssh(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    bin_dir = isolated_test_dir / "bin"
    bin_dir.mkdir()
    config_cmd = bin_dir / "ansible-config-storage-test"
    ssh_marker = isolated_test_dir / "ssh-g-ran"
    _write_executable(
        config_cmd,
        """#!/usr/bin/env python3
import json
print(json.dumps([{"ssh": [
    {"name": "host_key_checking", "value": True},
    {"name": "ssh_args", "value": "-o StrictHostKeyChecking=no"},
    {"name": "ssh_common_args", "value": ""},
    {"name": "ssh_extra_args", "value": ""}
]}]))
""",
    )
    _write_executable(
        bin_dir / "ssh",
        """#!/usr/bin/env bash
set -euo pipefail
: >"$STORAGE_TEST_SSH_MARKER"
exit 99
""",
    )
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/storage-volume-test.yml",
        inventory=repo_root / "inventories/config-test/hosts.yml.example",
        limit="storage-volume-test-example",
        extra_vars=(
            {
                "storage_volume_test_supported_boundary": "storage-volume-test-helper-v1",
                "storage_volume_test_operation": "preflight",
                "storage_volume_test_target_host": "storage-volume-test-example",
                "storage_volume_test_target_device": "/dev/disk/by-id/scsi-0QEMU_CONFIG_TEST_FIXTURE",
                "storage_volume_test_device": "/dev/disk/by-id/scsi-0QEMU_CONFIG_TEST_FIXTURE",
            },
        ),
        environment={
            "ANSIBLE_CONFIG_CMD": str(config_cmd),
            "PATH": f"{bin_dir}{os.pathsep}{command_runner.environment['PATH']}",
            "STORAGE_TEST_SSH_MARKER": str(ssh_marker),
        },
    )
    result.assert_failure()
    output = result.stdout + result.stderr
    assert "disables strict host-key trust" in output
    assert "UNREACHABLE" not in output
    assert not ssh_marker.exists()


@pytest.mark.parametrize(
    "source",
    [
        "ansible_ssh_args",
        "ansible_ssh_common_args",
        "ansible_ssh_extra_args",
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_SSH_COMMON_ARGS",
        "ANSIBLE_SSH_EXTRA_ARGS",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "-o StrictHostKeyChecking=no",
        "-o stricthostkeychecking FALSE",
        "-o STRICTHOSTKEYCHECKING = Off",
        "-o StrictHostKeyChecking 0",
        "-o UserKnownHostsFile=/dev/null",
        "-o userknownhostsfile /dev/null",
    ],
)
def test_storage_test_helper_rejects_ssh_bypasses_from_every_source(
    source: str,
    value: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    if source.startswith("ANSIBLE_"):
        env_file.write_text(f"export {source}={shlex.quote(value)}\n", encoding="utf-8")
    else:
        environment["STORAGE_TEST_HOSTVAR_NAME"] = source
        environment["STORAGE_TEST_SSH_VALUE"] = value
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert "unsafe SSH host-key option" in result.stderr


def test_storage_test_helper_rejects_effective_ansible_config(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    environment["STORAGE_TEST_CONFIG_HOST_KEY_CHECKING"] = "false"
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert "effective Ansible HOST_KEY_CHECKING must be true" in result.stderr


def test_storage_test_helper_rejects_effective_config_ssh_bypass(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    environment["STORAGE_TEST_CONFIG_SSH_VALUE"] = "-o StrictHostKeyChecking=OFF"
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert "unsafe effective Ansible SSH option" in result.stderr


def test_storage_test_helper_rejects_plugin_host_key_override(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    environment["STORAGE_TEST_PLUGIN_HOST_KEY_CHECKING"] = "false"
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert "effective Ansible SSH host_key_checking must be true" in result.stderr


@pytest.mark.parametrize(
    ("environment_name", "value"),
    [
        ("STORAGE_TEST_OPENSSH_STRICT", "no"),
        ("STORAGE_TEST_OPENSSH_STRICT", "off"),
        ("STORAGE_TEST_OPENSSH_KNOWN_HOSTS", "/dev/null"),
        ("STORAGE_TEST_OPENSSH_KNOWN_HOSTS", "none"),
    ],
)
def test_storage_test_helper_rejects_unsafe_effective_openssh(
    environment_name: str,
    value: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    environment[environment_name] = value
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert "effective OpenSSH" in result.stderr


@pytest.mark.parametrize(
    "scenario",
    [
        "recap-changed",
        "recap-failed",
        "recap-unreachable",
        "recap-ignored",
        "recap-rescued",
        "recap-duplicate",
        "recap-duplicate-counter",
        "recap-nonnumeric-counter",
    ],
)
def test_storage_test_helper_rejects_unclean_or_duplicate_recap(
    scenario: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    result = _run_helper(
        repo_root,
        command_runner,
        isolated_test_dir,
        operation="converge",
        scenario=scenario,
    )
    result.assert_failure()
    assert "exactly one clean row" in result.stderr


def test_storage_test_private_example_and_wrapper_path_contract(repo_root: Path) -> None:
    example = (repo_root / "examples/private-config/config-test.ansible.env.example").read_text(
        encoding="utf-8"
    )
    wrapper = (repo_root / "scripts/in-container").read_text(encoding="utf-8")
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    assert 'PLATFORM_PRIVATE_CONFIG_ROOT="$HOME/Projects/public/platform-private/config"' in example
    assert 'PLATFORM_CONFIG_INVENTORY="$PLATFORM_PRIVATE_CONFIG_ROOT/inventories/config-test/hosts.yml"' in example
    assert "PRIVATE_CONFIG_ROOT ?= ../platform-private/config" in makefile
    assert "storage-test-preflight: _guard-storage-test\n" in makefile
    assert '--env-file "$(ENV_FILE)" --inventory "$(INVENTORY)"' in makefile
    assert 'podman_args+=(--volume "$private_root:/platform-private:ro")' in wrapper
    assert 'podman_args+=(--volume "$private_root:/tmp/platform-home/Projects/public/platform-private:ro")' in wrapper


def test_storage_test_playbook_rejects_all_ssh_option_surfaces(repo_root: Path) -> None:
    playbook = (repo_root / "playbooks/maintenance/storage-volume-test.yml").read_text(
        encoding="utf-8"
    )
    for source in (
        "ansible_ssh_args",
        "ansible_ssh_common_args",
        "ansible_ssh_extra_args",
        "ansible_ssh_host_key_checking",
        "ANSIBLE_SSH_ARGS",
        "ANSIBLE_SSH_COMMON_ARGS",
        "ANSIBLE_SSH_EXTRA_ARGS",
        "ANSIBLE_SSH_HOST_KEY_CHECKING",
    ):
        assert source in playbook
    assert "lookup('ansible.builtin.config', 'HOST_KEY_CHECKING')" in playbook
    assert "ansible-config', true) }}" in playbook
    assert "--type\n          - connection" in playbook
    assert "storage_volume_test_plugin_host_key_checking is sameas true" in playbook
    assert "stricthostkeychecking" in playbook.lower()
    assert "userknownhostsfile" in playbook.lower()
    assert "no|false|off|0" in playbook
    assert "/dev/null" in playbook


def test_storage_test_controller_commands_never_inherit_become(repo_root: Path) -> None:
    playbook = _load_yaml(
        repo_root / "playbooks/maintenance/storage-volume-test.yml"
    )
    controller_tasks = [
        task
        for task in playbook[1]["pre_tasks"]
        if task.get("delegate_to") == "localhost"
    ]

    assert len(controller_tasks) == 2
    for task in controller_tasks:
        assert task["become"] is False
        assert task["vars"]["ansible_become"] is False


def test_storage_test_helper_rejects_disabled_host_key_checking(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    env_file, inventory, environment = _mock_environment(isolated_test_dir)
    env_file.write_text("export ANSIBLE_HOST_KEY_CHECKING=False\n", encoding="utf-8")
    result = command_runner.run(
        [
            repo_root / "scripts/storage-volume-test",
            "check",
            "--env-file",
            env_file,
            "--inventory",
            inventory,
            "--limit",
            "storage-volume-test-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert "effective Ansible HOST_KEY_CHECKING must be true" in result.stderr


def test_storage_test_helper_initialize_does_not_own_approval(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    result = _run_helper(
        repo_root,
        command_runner,
        isolated_test_dir,
        operation="initialize",
    )
    result.assert_success()
    log = (isolated_test_dir / "playbook.log").read_text(encoding="utf-8")
    assert "storage_volume_test_operation=initialize" in log
    assert "approval" not in log


def test_storage_test_preflight_is_read_only_ordered_and_fail_closed(repo_root: Path) -> None:
    path = repo_root / "playbooks/maintenance/tasks/storage-volume-test-preflight.yml"
    tasks = _load_yaml(path)
    text = path.read_text(encoding="utf-8")
    names = [task["name"] for task in tasks]
    assert names.index("Read complete root block-device ancestry") < names.index(
        "Require completely pristine storage fixture state"
    )
    assert names.index("Inspect pristine storage fixture wipefs signatures") < names.index(
        "Require completely pristine storage fixture state"
    )
    for task in tasks:
        if "ansible.builtin.command" in task:
            assert task["changed_when"] is False
            assert task["check_mode"] is False
    for required in (
        "findmnt",
        "lsblk",
        "root_ancestry",
        "children",
        "mountpoints",
        "pristine_blkid.rc == 2",
        "pristine_wipefs.stdout",
        "--no-act",
        "expected_partition.stat.exists",
        "pristine_vg.rc == 5",
        "32 * 1073741824",
        "storage_volume_test_expected_serial",
    ):
        assert required in text
    assert "ansible.builtin.package" not in text


def test_storage_test_initialize_and_final_reuse_contracts(repo_root: Path) -> None:
    initialize = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-initialize.yml").read_text(
        encoding="utf-8"
    )
    hostvars = _load_yaml(
        repo_root
        / "inventories/config-test/host_vars/storage-volume-test-example.yml.example"
    )
    layout = hostvars["storage_volume_layouts"][0]
    volumes = hostvars["storage_volumes"]
    assert "not ansible_check_mode" in initialize
    assert "ansible.builtin.pause:" not in initialize
    assert initialize.index("Rerun pristine checks immediately before initialization") < initialize.index(
        "Create only the baseline storage fixture"
    )
    assert "initialize: true" in initialize
    assert "reuse_existing_vg: false" in initialize
    assert "size_gib: 8" in initialize
    assert layout["capacity_gib"] == 32
    assert layout["initialize"] is False
    assert layout["reuse_existing_vg"] is True
    assert layout["required_free_gib"] == 12
    assert [(volume["lv_name"], volume["size_gib"]) for volume in volumes] == [
        ("baseline", 8),
        ("added", 4),
    ]


def test_storage_test_check_snapshot_equality_contract(repo_root: Path) -> None:
    check = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-check.yml").read_text(
        encoding="utf-8"
    )
    snapshot = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-snapshot.yml").read_text(
        encoding="utf-8"
    )
    assert check.count("storage-volume-test-snapshot.yml") == 2
    assert "storage_volume_test_snapshot == storage_volume_test_snapshot_before" in check
    for state in (
        "lsblk",
        "pvs",
        "vgs",
        "lvs",
        "mounts",
        "fstab",
        "fstab_lines_sha256",
        "baseline_sentinel",
    ):
        assert f"'{state}'" in snapshot
    assert '"vg_name={{ storage_volume_test_vg_name }}"' in snapshot
    assert snapshot.count("storage_volume_test_snapshot_mountpoint") >= 4
    assert "/etc/fstab" in snapshot
    assert "checksum_algorithm: sha256" in snapshot


def test_storage_test_verification_and_reboot_contract(repo_root: Path) -> None:
    verify = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-verify.yml").read_text(
        encoding="utf-8"
    )
    reboot = (repo_root / "playbooks/maintenance/tasks/storage-volume-test-reboot.yml").read_text(
        encoding="utf-8"
    )
    for required in (
        "vg_extent_size",
        "12 * 1073741824",
        "ftype=1",
        "source == 'UUID='",
        "unique | length == storage_volumes | length",
        "storage-volume-test-baseline",
        "root_ancestry",
    ):
        assert required in verify
    for required in (
        "storage_volume_test_reboot_nonce",
        "/proc/sys/kernel/random/boot_id",
        "ansible.builtin.reboot",
        "reboot_timeout: 300",
        "storage_volume_test_boot_id_after.stdout | trim != storage_volume_test_boot_id_before.stdout | trim",
        "storage-volume-test-verify.yml",
        "b64decode == storage_volume_test_reboot_nonce ~ '\\n'",
    ):
        assert required in reboot
    assert "ansible.builtin.pause:" not in reboot


def test_storage_test_has_no_destructive_cleanup_interface(repo_root: Path) -> None:
    helper = (repo_root / "scripts/storage-volume-test").read_text(encoding="utf-8")
    playbook_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (repo_root / "playbooks/maintenance").glob("storage-volume-test*.yml")
    )
    task_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (repo_root / "playbooks/maintenance/tasks").glob("storage-volume-test*.yml")
    )
    assert "preflight|initialize|check|converge|reboot" in helper
    assert not re.search(r"\b(reset|cleanup|wipe)\)", helper)
    for command in ("pvremove", "vgremove", "lvremove", "wipefs --all", "sgdisk"):
        assert command not in helper + playbook_text + task_text


def test_storage_test_make_targets_are_guarded_and_not_in_verify(repo_root: Path) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    for operation in ("preflight", "initialize", "check", "converge", "reboot"):
        target = f"storage-test-{operation}"
        assert re.search(rf"^{target}: _guard-storage-test", makefile, re.MULTILINE)
        assert f"./scripts/storage-volume-test {operation}" in makefile
    assert 'test "$(ENV)" = config-test' in makefile
    assert 'test -n "$(strip $(LIMIT))"' in makefile
    verify_lines = [line for line in makefile.splitlines() if line.startswith("verify:")]
    assert all("storage-test" not in line for line in verify_lines)


@pytest.mark.parametrize(
    ("variables", "message"),
    [
        ({"ENV": "dev", "LIMIT": "storage-volume-test-example"}, "ENV=config-test"),
        ({"ENV": "config-test", "LIMIT": ""}, "nonempty LIMIT"),
    ],
)
def test_storage_test_make_guard_failures(
    variables: dict[str, str],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    argv = ["make", "storage-test-preflight", "IN_CONTAINER=/bin/true"]
    argv.extend(f"{key}={value}" for key, value in variables.items())
    result = command_runner.run(argv)
    result.assert_failure()
    assert message in result.stderr
