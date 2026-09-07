from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner, NamespaceRootRunner


def _render(
    repo_root: Path,
    command_runner: CommandRunner,
    output_dir: Path,
    extra_vars: dict[str, Any] | None = None,
) -> None:
    output_dir.mkdir()
    variables = {"keepalived_vip_test_output_dir": str(output_dir)}
    variables.update(extra_vars or {})
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/keepalived-vip/render.yml",
        extra_vars=(variables,),
    ).assert_success()


@pytest.fixture
def rendered_keepalived(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> dict[str, str]:
    output = isolated_test_dir / "rendered"
    _render(repo_root, command_runner, output)
    return {
        name: (output / filename).read_text(encoding="utf-8")
        for name, filename in {
            "config": "keepalived.conf",
            "script": "check-service",
            "drop_in": "platform.conf",
        }.items()
    }


def test_keepalived_vip_role_staging_defaults(repo_root: Path) -> None:
    defaults = (repo_root / "roles/keepalived_vip/defaults/main.yml").read_text(encoding="utf-8")
    for line in (
        "keepalived_vip_enabled: false",
        "keepalived_vip_service_enabled: false",
        "keepalived_vip_service_state: stopped",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)


def test_keepalived_vip_rendered_fail_closed_contract(
    rendered_keepalived: dict[str, str]
) -> None:
    config = rendered_keepalived["config"]
    for pattern in (
        r"^[ \t]+state BACKUP$",
        r"^[ \t]+preempt_delay 300$",
        r"^[ \t]+unicast_src_ip 192[.]0[.]2[.]10$",
        r"^[ \t]+weight 0$",
        r"^[ \t]+init_fail$",
        r"^[ \t]+check_unicast_src$",
        r"^[ \t]+unicast_fault_no_peer$",
    ):
        assert re.search(pattern, config, re.MULTILINE), pattern
    assert not re.search(r"^[ \t]+nopreempt$", config, re.MULTILINE)
    assert not re.search(r"^[ \t]+state MASTER$", config, re.MULTILINE)


def test_keepalived_vip_tracking_script_contract(
    rendered_keepalived: dict[str, str]
) -> None:
    script = rendered_keepalived["script"]
    assert re.search(r"^#!/bin/bash$", script, re.MULTILINE)
    assert "systemctl is-active --quiet haproxy.service" in script
    assert "ip link show up dev vrrp-test >/dev/null 2>&1" in script
    assert 'sport = :8200" 2>/dev/null' in script
    assert not re.search(r"openbao|grafana|loki|mimir|postgres", script)


def test_keepalived_vip_systemd_ordering_contract(
    rendered_keepalived: dict[str, str]
) -> None:
    assert re.search(
        r"^After=network-online[.]target haproxy[.]service$",
        rendered_keepalived["drop_in"],
        re.MULTILINE,
    )


def test_keepalived_vip_behavior_harness_contract(repo_root: Path) -> None:
    fixture = (repo_root / "tests/fixtures/keepalived-vip/behavior.yml").read_text(
        encoding="utf-8"
    )
    harness = (
        repo_root / "tests/integration/test-keepalived-vip-behavior.sh"
    ).read_text(encoding="utf-8")
    for required in (
        "keepalived-0:2.2.8-9.el10.x86_64",
        "keepalived_vip_preempt_delay: 60",
        "platform-test-listeners.service",
        "platform_external_probe_vip_ownership:",
        "endpoint: monitoring_vip",
    ):
        assert required in fixture
    for required in (
        "podman network create",
        "--internal",
        "Repeated preferred-node failure",
        "All-fault state retained a VIP owner",
        "platform_vip_ownership_collection_success",
        "podman network exists",
    ):
        assert required in harness
    assert "192.0.2." not in fixture
    assert "192.0.2." not in harness


@pytest.mark.parametrize("priority", [1, 254])
def test_keepalived_vip_accepts_priority_boundaries(
    priority: int,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    _render(
        repo_root,
        command_runner,
        isolated_test_dir / f"priority-{priority}",
        {
            "keepalived_vip_test_priority": priority,
            "keepalived_vip_test_canonical_priority": priority,
        },
    )


@pytest.mark.parametrize("delay", [60, 1000])
def test_keepalived_vip_accepts_preempt_delay_boundaries(
    delay: int,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    _render(
        repo_root,
        command_runner,
        isolated_test_dir / f"delay-{delay}",
        {"keepalived_vip_preempt_delay": delay},
    )


@pytest.mark.parametrize(
    ("case_id", "extra_vars"),
    [
        ("priority-255", {"keepalived_vip_test_priority": 255, "keepalived_vip_test_canonical_priority": 255}),
        ("delay-59", {"keepalived_vip_preempt_delay": 59}),
        ("delay-1001", {"keepalived_vip_preempt_delay": 1001}),
        ("string-delay", {"keepalived_vip_preempt_delay": "300"}),
        ("unpinned-package", {"keepalived_vip_test_package_nevra": ""}),
        ("duplicate-router", {"keepalived_vip_test_peer_2_router_id": "test-node-01"}),
        ("duplicate-priority", {"keepalived_vip_test_peer_2_priority": 150}),
        ("extra-instance", {"keepalived_vip_test_peer_2_extra_instances": {"EXTRA_VIP": {"source_address": "192.0.2.21", "priority": 120}}}),
        ("remote-priority-255", {"keepalived_vip_test_peer_2_priority": 255}),
        ("decimal-priority", {"keepalived_vip_test_canonical_priority": "150.9"}),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_keepalived_vip_rejects_unsafe_inputs(
    case_id: str,
    extra_vars: dict[str, Any],
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    output = isolated_test_dir / case_id
    output.mkdir()
    variables = {"keepalived_vip_test_output_dir": str(output), **extra_vars}
    expected = {
        "priority-255": "requires a safe name/interface",
        "duplicate-priority": "must use its inventory-host assignment",
        "extra-instance": "Keepalived cluster members require",
        "remote-priority-255": "must use its inventory-host assignment",
        "decimal-priority": "cluster priorities must be integers without coercion",
    }.get(case_id, "Keepalived VIP requires")
    assert_failed_with(
        run_playbook(
            command_runner,
            repo_root / "tests/fixtures/keepalived-vip/render.yml",
            extra_vars=(variables,),
        ),
        expected,
    )


@pytest.mark.parametrize(
    "variables",
    [
        {"keepalived_vip_enabled": "false"},
        {"keepalived_vip_service_enabled": "false"},
        {"keepalived_vip_firewalld_manage": "true"},
        {"keepalived_vip_service_state": "restarted"},
        {"keepalived_vip_service_state": "reloaded"},
        {"keepalived_vip_service_state": "started"},
        {"keepalived_vip_service_enabled": True},
        {"keepalived_vip_service_enabled": True, "keepalived_vip_service_state": "started"},
        {"keepalived_vip_enabled": True, "keepalived_vip_service_enabled": True,
         "keepalived_vip_service_state": "started", "firewalld_service_state": "stopped"},
    ],
)
def test_keepalived_lifecycle_rejected_before_disabled_short_circuit(
    variables: dict[str, Any], command_runner: CommandRunner, isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "lifecycle.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": variables,
        "tasks": [{"ansible.builtin.include_role": {"name": "keepalived_vip"}}],
    }]), encoding="utf-8")
    result = run_playbook(command_runner, playbook)
    assert_failed_with(result, "Keepalived VIP requires strict lifecycle booleans")
    assert "Install exact Keepalived package" not in result.stdout


@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("legacy", [None, False, True])
def test_keepalived_lifecycle_accepts_coherent_active_inputs(
    managed: bool, legacy: bool | None, command_runner: CommandRunner, isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "active-lifecycle.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "vars": {
            "keepalived_vip_enabled": True, "keepalived_vip_service_enabled": True,
            "keepalived_vip_service_state": "started", "keepalived_vip_firewalld_manage": managed,
            **({"firewalld_enabled": legacy} if legacy is not None else {}),
            "firewalld_service_enabled": True,
            "firewalld_service_state": "started",
        },
        "tasks": [{"ansible.builtin.include_role": {
            "name": "keepalived_vip", "tasks_from": "validate_lifecycle.yml",
        }}],
    }]), encoding="utf-8")
    run_playbook(command_runner, playbook).assert_success()


def test_keepalived_preflight_has_no_mutating_tasks_or_dependencies(repo_root: Path) -> None:
    role = repo_root / "roles/keepalived_vip"
    assert yaml.safe_load((role / "meta/main.yml").read_text())["dependencies"] == []
    pending = ["activation_preflight.yml"]
    visited = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        tasks = yaml.safe_load((role / "tasks" / name).read_text())
        while tasks:
            task = tasks.pop()
            if "block" in task:
                assert task["ignore_errors"] is False
                assert task["ignore_unreachable"] is False
                tasks.extend(task["block"])
                continue
            actions = [key for key in task if key.startswith("ansible.")]
            assert len(actions) == 1
            action = actions[0]
            assert action in {
                "ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.include_tasks",
                "ansible.builtin.stat", "ansible.builtin.slurp", "ansible.builtin.command",
            }
            if action == "ansible.builtin.include_tasks":
                pending.append(task[action])
            if action == "ansible.builtin.command":
                assert task["changed_when"] is False
                assert task["check_mode"] is False


@pytest.mark.parametrize("override", [
    {}, {"keepalived_vip_package_name": "other"}, {"keepalived_vip_service_name": "other.service"},
    {"keepalived_vip_binary_path": "/tmp/keepalived"}, {"keepalived_vip_config_path": "/tmp/keepalived.conf"},
    {"keepalived_vip_service_drop_in_dir": "/tmp/keepalived.service.d"},
    {"keepalived_vip_service_drop_in_path": "/etc/systemd/system/other.service.d/platform.conf"},
])
def test_keepalived_activation_rejects_noncanonical_paths(
    override: dict[str, str], command_runner: CommandRunner, isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "canonical.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False, "vars": override,
        "tasks": [_activation_include("activation_paths.yml")],
    }]), encoding="utf-8")
    result = run_playbook(command_runner, playbook)
    if override:
        assert_failed_with(result, "Keepalived activation requires the canonical native service")
    else:
        result.assert_success()


# These command doubles exercise the real Ansible task chain, templates, stat,
# SHA-256 comparisons, and JSON parsing without systemd, RPM, or host networking.
_ACTIVATION_COMMAND = r'''
import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
case = os.environ.get("KEEPALIVED_CASE", "ready")
with open(os.environ["KEEPALIVED_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")

def result(text="", rc=0):
    print(text)
    sys.exit(rc)

if name == "rpm":
    if "-V" in args:
        assert "--noscripts" in args and "--noconfig" in args
        result("modified package file" if case == "package-files" else "",
               1 if case == "package-files" else 0)
    if "%{SHA256HEADER}" in args:
        result("(none)" if case == "package-digest" else "a" * 64)
    result("wrong-package" if case == "package" else "keepalived-0:2.2.8-9.el10.x86_64")
if name == "keepalived":
    assert args == ["-t", "-f", os.environ["KEEPALIVED_CONFIG"]]
    result("native validation failed" if case == "native" else "", 1 if case == "native" else 0)
if name == "runuser":
    assert args == ["-u", "keepalived_script", "-g", "keepalived_script", "--", os.environ["KEEPALIVED_SCRIPT"]]
    result("script not ready" if case == "script-unready" else "", 1 if case == "script-unready" else 0)
if name == "systemctl":
    if args[0] == "show":
        prop = args[2].removeprefix("--property=")
        binary = os.environ["KEEPALIVED_BINARY"]
        expected = {
            "FragmentPath": os.environ["KEEPALIVED_UNIT"],
            "DropInPaths": os.environ["KEEPALIVED_DROP_IN"],
            "NeedDaemonReload": "no",
            "EnvironmentFiles": os.environ["KEEPALIVED_SYSCONFIG"] + " (ignore_errors=yes)",
            "Environment": "", "PassEnvironment": "", "UnsetEnvironment": "",
            "ExecStart": "{ path=" + binary + " ; argv[]=" + binary + " --dont-fork $KEEPALIVED_OPTIONS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
        }[prop]
        if case == "systemd-" + prop:
            expected = "wrong " + expected
        if case == "systemd-extra-drop-in" and prop == "DropInPaths":
            expected += " /etc/systemd/system/service.d/override.conf"
        if case == "systemd-alternate-config" and prop == "ExecStart":
            expected = expected.replace("--dont-fork", "--dont-fork -f /tmp/other.conf")
        result(expected)
    operation, service = args
    if service == "keepalived.service":
        active = case == "keepalived-active"
        enabled = case == "keepalived-enabled"
    else:
        active = case != ("haproxy-inactive" if service == "haproxy.service" else "firewall-inactive")
        enabled = case != "haproxy-disabled"
    if operation == "is-active":
        result("active" if active else "inactive", 0 if active else 3)
    assert operation == "is-enabled"
    result("enabled" if enabled else "disabled", 0 if enabled else 1)
if name == "firewall-cmd":
    assert any(arg.startswith("--query-rich-rule=") for arg in args)
    result("no" if case == "firewall-rule" else "yes", 1 if case == "firewall-rule" else 0)
if name == "ip":
    assert args[:2] == ["-j", "-4"]
    if "route" in args:
        assert args == ["-j", "-4", "route", "get", "192.0.2.100", "from", "192.0.2.10"]
        result(json.dumps([{"dev": "wrong0" if case == "route" else "vrrp-test"}]))
    interface = {"ifname": "vrrp-test", "flags": [] if case == "link-down" else ["UP"],
                 "addr_info": [{"local": "192.0.2.110" if case == "source" else "192.0.2.10"}]}
    addresses = [interface]
    if "dev" not in args:
        if case == "address-error":
            result("ip failed", 2)
        if case == "address-malformed":
            result("not json")
        addresses.append({"ifname": "unrelated0", "addr_info": [{"local":
            "192.0.2.100" if case == "vip-other-interface" else "192.0.2.1000"}]})
    result(json.dumps(addresses))
raise AssertionError((name, args))
'''


_TEST_COMMAND_ACTION = '''
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._templar.template(self._task.args)
        if (self._task.name == task_vars.get("unreachable_task")
                and (not task_vars.get("unreachable_operation")
                     or args["argv"][1] == task_vars["unreachable_operation"])):
            return {"unreachable": True, "msg": "Injected transient connection loss"}
        return self._execute_module(module_name="ansible.builtin.command", module_args=args, task_vars=task_vars)
'''


@pytest.fixture
def activation_fixture(
    repo_root: Path, isolated_test_dir: Path,
) -> tuple[Path, dict[str, Any]]:
    root = isolated_test_dir
    binaries = root / "bin"
    binaries.mkdir()
    for name in ("rpm", "keepalived", "runuser", "systemctl", "ip", "firewall-cmd"):
        path = binaries / name
        path.write_text(f"#!{sys.executable}\n" + _ACTIVATION_COMMAND, encoding="utf-8")
        path.chmod(0o755)
    output = root / "artifacts"
    output.mkdir()
    for name, content in {
        "sysconfig": 'KEEPALIVED_OPTIONS="-D"\n',
        "keepalived.service": "[Service]\nExecStart=/usr/sbin/keepalived --dont-fork $KEEPALIVED_OPTIONS\n",
    }.items():
        path = output / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o644)
    # Relocate fixed paths only in a scratch role, never add a production bypass.
    # Separate tests below exercise the original canonical-path guards unchanged.
    role = root / "roles/keepalived_vip"
    shutil.copytree(repo_root / "roles/keepalived_vip", role)
    replacements = {
        "/etc/systemd/system/keepalived.service.d/platform.conf": str(output / "platform.conf"),
        "/etc/systemd/system/keepalived.service.d": str(output),
        "/usr/lib/systemd/system/keepalived.service": str(output / "keepalived.service"),
        "/etc/sysconfig/keepalived": str(output / "sysconfig"),
        "/etc/keepalived/keepalived.conf": str(output / "keepalived.conf"),
        "/usr/sbin/keepalived": str(binaries / "keepalived"),
        "ansible.builtin.command:": "keepalived_test_command:",
    }
    for path in role.rglob("*.yml"):
        source = path.read_text()
        for old, new in replacements.items():
            source = source.replace(old, new)
        path.write_text(source, encoding="utf-8")
    plugins = root / "action_plugins"
    plugins.mkdir()
    (plugins / "keepalived_test_command.py").write_text(_TEST_COMMAND_ACTION, encoding="utf-8")
    fixture = yaml.safe_load((repo_root / "tests/fixtures/keepalived-vip/render.yml").read_text())[0]
    fixture["vars"].update({
        "keepalived_vip_role_dir": str(role),
        "keepalived_vip_test_role": str(role),
        "keepalived_vip_test_output_dir": str(output),
    })
    # Load defaults and canonical fixture inputs, then render exactly as staging does.
    fixture["tasks"] = fixture["tasks"][1:]
    fixture["tasks"].insert(2, {"ansible.builtin.set_fact": {
        "keepalived_vip_enabled": True,
        "keepalived_vip_config_path": str(output / "keepalived.conf"),
        "keepalived_vip_script_path": str(output / "check-service"),
        "keepalived_vip_service_drop_in_path": str(output / "platform.conf"),
        "keepalived_vip_binary_path": str(binaries / "keepalived"),
        "keepalived_vip_firewalld_manifest_path": str(output / "firewall.yml"),
    }})
    fixture["tasks"].append({"ansible.builtin.copy": {
        "dest": str(output / "firewall.yml"), "mode": "0644",
        "content": yaml.safe_dump({"rich_rules": [
            f'rule family="ipv4" source address="192.0.2.{peer}/32" protocol value="112" accept'
            for peer in (11, 12)
        ]}),
    }})
    fixture["environment"] = {
        "PATH": f"{binaries}:/usr/sbin:/usr/bin:/sbin:/bin",
        "KEEPALIVED_CASE": "{{ test_case | default('ready') }}",
        "KEEPALIVED_LOG": str(root / "commands.jsonl"),
        "KEEPALIVED_CONFIG": str(output / "keepalived.conf"),
        "KEEPALIVED_SCRIPT": str(output / "check-service"),
        "KEEPALIVED_BINARY": str(binaries / "keepalived"),
        "KEEPALIVED_UNIT": str(output / "keepalived.service"),
        "KEEPALIVED_DROP_IN": str(output / "platform.conf"),
        "KEEPALIVED_SYSCONFIG": str(output / "sysconfig"),
    }
    return root, fixture


def _activation_include(entry: str = "activation_preflight.yml") -> dict[str, Any]:
    return {"ansible.builtin.include_role": {
        "name": "{{ keepalived_vip_test_role | default('keepalived_vip') }}", "tasks_from": entry,
    }}


@pytest.mark.parametrize("managed", [False, True])
def test_keepalived_activation_preflight_is_repeatable_and_read_only(
    managed: bool,
    activation_fixture: tuple[Path, dict[str, Any]], namespace_root_runner: NamespaceRootRunner,
) -> None:
    root, play = activation_fixture
    # Invalid repository-policy inputs must not run a dependency or stage helpers.
    play["vars"]["rocky_repository_policy_enabled"] = True
    play["tasks"] += [
        {"ansible.builtin.set_fact": {"keepalived_vip_firewalld_manage": managed}},
        _activation_include(),
        {"ansible.builtin.set_fact": {"before_approval": "{{ keepalived_vip_activation_observation }}"}},
        _activation_include(),
        {"ansible.builtin.assert": {"that": [
            "before_approval == keepalived_vip_activation_observation",
            "keepalived_vip_activation_observation.inventory_host == 'localhost'",
            "keepalived_vip_activation_observation.instances == keepalived_vip_instances",
            "keepalived_vip_activation_observation.cluster_members == keepalived_vip_cluster_members",
            "keepalived_vip_activation_observation.package_checksum == 'a' * 64",
            "keepalived_vip_activation_observation.binary_checksum | length == 64",
            "(keepalived_vip_activation_observation.firewalld_manifest_checksum != 'unmanaged') == keepalived_vip_firewalld_manage",
        ]}},
    ]
    playbook = root / "preflight.yml"
    playbook.write_text(yaml.safe_dump([play]), encoding="utf-8")
    result = namespace_root_runner.run(["ansible-playbook", playbook], timeout=120).assert_success()
    assert "rocky_repository_policy :" not in result.stdout
    preflight_output = result.stdout.split(" : Invalidate previous Keepalived activation observation]", 1)[1]
    assert "changed: [localhost]" not in preflight_output
    commands = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
    assert commands.count(["ip", "-j", "-4", "address", "show"]) == 2
    assert ["systemctl", "is-enabled", "haproxy.service"] in commands
    assert any(command[0] == "runuser" for command in commands)
    assert any(command[0] == "firewall-cmd" for command in commands) is managed


@pytest.mark.parametrize("case", [
    "package", "package-digest", "package-files", "native", "script-unready",
    "haproxy-inactive", "haproxy-disabled", "keepalived-active", "keepalived-enabled",
    "firewall-inactive", "firewall-rule", "link-down", "source", "route",
    "vip-other-interface", "address-error", "address-malformed",
    "config-drift", "script-drift", "drop-in-drift", "metadata", "symlink", "inventory-drift",
    "manifest-drift", "manifest-mode", "missing-config",
    "systemd-FragmentPath", "systemd-DropInPaths", "systemd-NeedDaemonReload",
    "systemd-EnvironmentFiles", "systemd-Environment", "systemd-PassEnvironment",
    "systemd-UnsetEnvironment", "systemd-ExecStart", "systemd-extra-drop-in", "systemd-alternate-config",
    "sysconfig-alternate-config", "sysconfig-lifecycle", "sysconfig-extra-assignment",
])
def test_keepalived_activation_preflight_rejects_unready_or_stale_state(
    case: str, activation_fixture: tuple[Path, dict[str, Any]], namespace_root_runner: NamespaceRootRunner,
) -> None:
    root, play = activation_fixture
    paths = {"config-drift": "keepalived.conf", "script-drift": "check-service", "drop-in-drift": "platform.conf"}
    if case in paths:
        play["tasks"].append({"ansible.builtin.lineinfile": {
            "path": str(root / "artifacts" / paths[case]), "line": "# stale content",
        }})
    if case == "metadata":
        play["tasks"].append({"ansible.builtin.file": {
            "path": str(root / "artifacts/keepalived.conf"), "mode": "0644",
        }})
    if case == "symlink":
        play["tasks"] += [
            {"ansible.builtin.copy": {"src": str(root / "artifacts/keepalived.conf"),
                                      "dest": str(root / "artifacts/real.conf"), "mode": "0600"}},
            {"ansible.builtin.file": {"path": str(root / "artifacts/keepalived.conf"), "state": "absent"}},
            {"ansible.builtin.file": {"path": str(root / "artifacts/keepalived.conf"), "state": "link",
                                      "src": str(root / "artifacts/real.conf")}},
        ]
    if case == "inventory-drift":
        play["tasks"].append({"ansible.builtin.set_fact": {"keepalived_vip_preempt_delay": 301}})
    if case == "manifest-drift":
        play["tasks"].append({"ansible.builtin.copy": {
            "dest": str(root / "artifacts/firewall.yml"), "content": "rich_rules: []\n", "mode": "0644",
        }})
    if case == "manifest-mode":
        play["tasks"].append({"ansible.builtin.file": {
            "path": str(root / "artifacts/firewall.yml"), "mode": "0666",
        }})
    if case == "missing-config":
        play["tasks"].append({"ansible.builtin.file": {
            "path": str(root / "artifacts/keepalived.conf"), "state": "absent",
        }})
    if case.startswith("sysconfig-"):
        content = {
            "sysconfig-alternate-config": 'KEEPALIVED_OPTIONS="-D -f /tmp/other.conf"\n',
            "sysconfig-lifecycle": 'KEEPALIVED_OPTIONS="-D --dont-release-vrrp"\n',
            "sysconfig-extra-assignment": 'KEEPALIVED_OPTIONS="-D"\nOTHER_OPTIONS="bad"\n',
        }[case]
        (root / "artifacts/sysconfig").write_text(content, encoding="utf-8")
    play["tasks"] += [
        {"ansible.builtin.set_fact": {"keepalived_vip_activation_observation": {"stale": True}}},
        {"block": [_activation_include()], "rescue": [
            {"ansible.builtin.assert": {"that": "keepalived_vip_activation_observation == {}"}},
            {"ansible.builtin.fail": {"msg": "Preflight rejected and invalidated stale observation"}},
        ]},
    ]
    playbook = root / "reject.yml"
    playbook.write_text(yaml.safe_dump([play]), encoding="utf-8")
    result = namespace_root_runner.run([
        "ansible-playbook", playbook, "-e", json.dumps({"test_case": case}),
    ], timeout=120)
    assert_failed_with(result, "Preflight rejected and invalidated stale observation")


@pytest.mark.parametrize("unreachable_task", [
    "Inspect exact staged Keepalived package identity",
    "Verify staged Keepalived non-configuration package files without scripts",
    "Validate staged Keepalived configuration natively",
    "Check staged Keepalived readiness as the configured script identity",
    "Inspect loaded Keepalived unit configuration",
    "Observe Keepalived activation service states",
    "Verify staged Keepalived peer rules in runtime and permanent firewall policy",
])
def test_keepalived_preflight_cannot_inherit_ignored_unreachable_reads(
    unreachable_task: str, activation_fixture: tuple[Path, dict[str, Any]],
    namespace_root_runner: NamespaceRootRunner,
) -> None:
    root, play = activation_fixture
    play["ignore_unreachable"] = True
    play["vars"]["unreachable_task"] = unreachable_task
    preflight = _activation_include()
    preflight["ansible.builtin.include_role"]["apply"] = {"ignore_unreachable": True, "ignore_errors": True}
    play["tasks"] += [preflight, {"ansible.builtin.fail": {"msg": "Unexpected preflight continuation"}}]
    playbook = root / "unreachable.yml"
    playbook.write_text(yaml.safe_dump([play]), encoding="utf-8")
    result = namespace_root_runner.run(["ansible-playbook", playbook], timeout=120)
    assert_failed_with(result, "Injected transient connection loss")
    assert "Publish verified staged Keepalived activation observation]" not in result.stdout
    assert "Unexpected preflight continuation" not in result.stdout


def test_keepalived_active_convergence_requires_actual_managed_firewall(
    activation_fixture: tuple[Path, dict[str, Any]], namespace_root_runner: NamespaceRootRunner,
) -> None:
    root, play = activation_fixture
    play["tasks"] += [
        {"ansible.builtin.set_fact": {
            "keepalived_vip_service_enabled": True, "keepalived_vip_service_state": "started",
            "firewalld_enabled": True, "firewalld_service_enabled": True,
            "firewalld_service_state": "started",
        }},
        _activation_include("main.yml"),
    ]
    playbook = root / "active-firewall.yml"
    playbook.write_text(yaml.safe_dump([play]), encoding="utf-8")
    result = namespace_root_runner.run([
        "ansible-playbook", playbook, "-e", json.dumps({"test_case": "firewall-inactive"}),
    ], timeout=120)
    assert_failed_with(result, "Require running managed firewalld before active Keepalived convergence")
    assert "Install exact Keepalived package" not in result.stdout


@pytest.mark.parametrize("boundary", ["management", "reload"])
@pytest.mark.parametrize("loss", ["ready", "firewall-inactive", "firewall-rule", "unreachable"])
def test_keepalived_rechecks_firewall_at_each_service_boundary(
    boundary: str, loss: str, activation_fixture: tuple[Path, dict[str, Any]],
    namespace_root_runner: NamespaceRootRunner,
) -> None:
    root, play = activation_fixture
    role = root / "roles/keepalived_vip"
    main = yaml.safe_load((role / "tasks/main.yml").read_text())[1]["block"]
    assert main[-2]["ansible.builtin.include_tasks"] == "runtime_firewall_guard.yml"
    assert "ansible.builtin.systemd_service" in main[-1]
    early_guard = next(task for task in main if task["name"].startswith("Require running managed firewalld"))
    transitions = root / "service-transitions"
    (root / "action_plugins/keepalived_test_systemd.py").write_text('''
from pathlib import Path
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._templar.template(self._task.args)
        assert args["name"] == "keepalived.service"
        Path(task_vars["test_transitions"]).write_text(args["state"])
        return {"changed": False}
''', encoding="utf-8")
    transition_tasks = [early_guard, {"ansible.builtin.set_fact": {"test_case": loss}}]
    if boundary == "management":
        main[-1]["keepalived_test_systemd"] = main[-1].pop("ansible.builtin.systemd_service")
        transition_tasks += main[-2:]
    else:
        reload_path = role / "tasks/reload.yml"
        reload_path.write_text(reload_path.read_text().replace(
            "ansible.builtin.systemd_service:", "keepalived_test_systemd:",
        ), encoding="utf-8")
        transition_tasks.append({
            "ansible.builtin.debug": {"msg": "Schedule the actual reload handler"},
            "changed_when": True, "notify": "Reload shared Keepalived VIP",
        })
    (role / "tasks/test_transition.yml").write_text(yaml.safe_dump(transition_tasks), encoding="utf-8")
    play["vars"]["test_transitions"] = str(transitions)
    if loss == "unreachable":
        play["vars"]["unreachable_task"] = "Require active firewalld at the Keepalived service boundary"
    play["ignore_unreachable"] = True
    play["tasks"] += [
        {"ansible.builtin.set_fact": {
            "keepalived_vip_service_enabled": True, "keepalived_vip_service_state": "started",
            "keepalived_vip_dependencies_ready": True,
        }},
        _activation_include("test_transition.yml"),
    ]
    playbook = root / "service-boundary.yml"
    playbook.write_text(yaml.safe_dump([play]), encoding="utf-8")
    result = namespace_root_runner.run(["ansible-playbook", playbook], timeout=120)
    if loss == "ready":
        result.assert_success()
        assert transitions.read_text() == ("started" if boundary == "management" else "reloaded")
    else:
        result.assert_failure()
        assert not transitions.exists(), result.diagnostics()
    assert "Require running managed firewalld before active Keepalived convergence]" in result.stdout


@pytest.mark.parametrize("case,confirmed", [
    ("ready", True), ("keepalived-active", False), ("keepalived-enabled", False),
    ("vip-other-interface", False), ("address-error", False), ("address-malformed", False),
    ("stop-error", False), ("stop-unreachable", False), ("check-mode", False),
    ("vip-normalized", False), ("vip-second-instance", False),
    ("observation-active-unreachable", False), ("observation-enabled-unreachable", False),
    ("address-unreachable", False),
])
def test_keepalived_activation_rollback_never_confirms_failed_evidence(
    case: str, confirmed: bool, activation_fixture: tuple[Path, dict[str, Any]],
    namespace_root_runner: NamespaceRootRunner, repo_root: Path,
) -> None:
    root, play = activation_fixture
    plugins = root / "action_plugins"
    (plugins / "keepalived_test_systemd.py").write_text('''
from ansible.plugins.action import ActionBase
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        assert self._templar.template(self._task.args) == {"name": "keepalived.service", "enabled": False, "state": "stopped"}
        case = task_vars["test_case"]
        return {"changed": False, "failed": case == "stop-error", "unreachable": case == "stop-unreachable"}
''', encoding="utf-8")
    # FQCN builtins cannot be shadowed via ANSIBLE_ACTION_PLUGINS. Substitute only
    # the stop module in a scratch copy; all control flow and assertions stay real.
    role = root / "roles/keepalived_vip"
    rollback_path = role / "tasks/activation_rollback.yml"
    rollback_tasks = yaml.safe_load(rollback_path.read_text())
    for task in rollback_tasks[1]["block"]:
        if "ansible.builtin.systemd_service" in task:
            task["keepalived_test_systemd"] = task.pop("ansible.builtin.systemd_service")
    rollback_path.write_text(yaml.safe_dump(rollback_tasks), encoding="utf-8")
    play["ignore_unreachable"] = True
    if case.startswith("observation-"):
        play["vars"].update({
            "unreachable_task": "Observe Keepalived rollback service states",
            "unreachable_operation": "is-active" if "-active-" in case else "is-enabled",
        })
    if case == "address-unreachable":
        play["vars"]["unreachable_task"] = "Read IPv4 addresses on ALL local interfaces"
    rollback = _activation_include("activation_rollback.yml")
    rollback["ansible.builtin.include_role"]["apply"] = {"ignore_errors": True}
    if case in {"vip-normalized", "vip-second-instance"}:
        instances = [{"vip": "192.000.002.100/24"}] if case == "vip-normalized" else [
            {"vip": "192.0.2.200/24"}, {"vip": "192.0.2.100/24"},
        ]
        play["tasks"].append({"ansible.builtin.set_fact": {"keepalived_vip_instances": instances}})
        play["environment"]["KEEPALIVED_CASE"] = "vip-other-interface"
    if case == "check-mode":
        play["tasks"] = [{"block": play["tasks"], "check_mode": False}]
    play["tasks"] += [
        {"ansible.builtin.set_fact": {"keepalived_vip_activation_rollback_confirmed": True}},
        rollback,
        {"ansible.builtin.assert": {"that":
            f"keepalived_vip_activation_rollback_confirmed is sameas {'true' if confirmed else 'false'}"},
         "ignore_errors": False},
    ]
    playbook = root / "rollback.yml"
    playbook.write_text(yaml.safe_dump([play]), encoding="utf-8")
    namespace_root_runner.run([
        "ansible-playbook", playbook, "-e", json.dumps({"test_case": case}),
        *(["--check"] if case == "check-mode" else []),
    ], environment={
        "ANSIBLE_ACTION_PLUGINS": str(plugins),
        "ANSIBLE_ROLES_PATH": f"{root / 'roles'}:{repo_root / 'roles'}",
    }, timeout=120).assert_success()
