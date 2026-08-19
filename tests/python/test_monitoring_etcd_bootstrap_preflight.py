from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


PLAYBOOK = "playbooks/maintenance/monitoring-etcd-bootstrap-preflight.yml"
FIXTURE = "tests/fixtures/monitoring-etcd-orchestration/inventory.yml"


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [
                str(repo_root / "tests/fixtures/monitoring-etcd-orchestration/roles"),
                str(repo_root / "roles"),
            ]
        )
    }


def _run_preflight(
    repo_root: Path,
    command_runner: CommandRunner,
    *,
    extra_vars: dict[str, object] | None = None,
    limit: str | None = None,
    inventory: str = FIXTURE,
):
    variables: dict[str, object] = {
        "monitoring_etcd_bootstrap_preflight_ready": True,
        "monitoring_etcd_data_fstype": "xfs",
        "monitoring_etcd_data_mount_source": "/dev/mapper/synthetic-etcd",
        "monitoring_etcd_bootstrap_require_selinux_enforcing": True,
    }
    variables.update(extra_vars or {})
    return run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / inventory,
        extra_vars=(variables,),
        limit=limit,
        environment=_roles_environment(repo_root),
    )


def test_monitoring_etcd_bootstrap_preflight_source_is_read_only(
    repo_root: Path,
) -> None:
    playbook = (repo_root / PLAYBOOK).read_text(encoding="utf-8")
    tasks_path = repo_root / "roles/monitoring_etcd/tasks/bootstrap_preflight.yml"
    tasks_text = tasks_path.read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")

    for fragment in (
        "monitoring_etcd_bootstrap_preflight_ready",
        "Inspect every monitoring etcd bootstrap member",
        "Compare monitoring etcd bootstrap observations",
        "Require pristine monitoring etcd bootstrap data",
        "Require inactive generated monitoring etcd service",
        "Require exact monitoring etcd bootstrap image",
        "Publish monitoring etcd bootstrap observation",
        "'log_level': monitoring_etcd_log_level",
    ):
        assert fragment in playbook + tasks_text
    assert "monitoring-etcd-bootstrap-preflight.yml" not in site
    assert not re.search(
        r"ansible[.]builtin[.](?:file|copy|template|dnf|package|service|systemd_service|mount):",
        playbook + tasks_text,
    )
    assert not re.search(
        r"\b(?:start|stop|restart|enable|disable|pull|rm|mv|write)\b",
        tasks_text,
        re.IGNORECASE,
    )

    allowed_actions = {
        "ansible.builtin.assert",
        "ansible.builtin.command",
        "ansible.builtin.find",
        "ansible.builtin.include_tasks",
        "ansible.builtin.set_fact",
        "ansible.builtin.slurp",
        "ansible.builtin.stat",
    }
    task_keywords = {
        "name",
        "loop",
        "loop_control",
        "no_log",
        "register",
        "when",
        "become",
        "delegate_to",
    }
    tasks = yaml.safe_load(tasks_text)
    for task in tasks:
        actions = set(task) - task_keywords - {"changed_when", "check_mode", "failed_when"}
        assert len(actions) == 1, (task.get("name"), actions)
        assert actions.pop() in allowed_actions

    allowed_commands = {
        "findmnt",
        "systemctl",
        "/usr/bin/podman",
        "/usr/bin/firewall-cmd",
        "ss",
        "matchpathcon",
    }
    for task in tasks:
        command = task.get("ansible.builtin.command")
        if command is not None:
            argv = command["argv"]
            assert argv[0] in allowed_commands
            assert task.get("changed_when") is False
            assert task.get("check_mode") is False
            if argv[0] == "systemctl":
                assert argv[1] in {"show", "is-active", "is-enabled"}
            elif argv[0] == "/usr/bin/podman":
                assert argv[1:3] in (
                    ["container", "exists"],
                    ["image", "inspect"],
                )


def test_monitoring_etcd_bootstrap_preflight_accepts_consistent_cluster(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    _run_preflight(repo_root, command_runner).assert_success()


@pytest.mark.parametrize(
    ("case_id", "kwargs", "message"),
    (
        (
            "partial-limit",
            {"limit": "monitoring-stage-1"},
            "requires all three monitoring inventory hosts",
        ),
        (
            "unrelated-limit",
            {"limit": "unrelated-stage"},
            "did not select the monitoring service group",
        ),
        (
            "two-members",
            {
                "inventory": (
                    "tests/fixtures/monitoring-etcd-orchestration/inventory-two.yml"
                )
            },
            "requires exactly three monitoring inventory members",
        ),
        (
            "not-ready",
            {"extra_vars": {"monitoring_etcd_bootstrap_preflight_ready": False}},
            "requires explicit readiness",
        ),
        (
            "invalid-host-observation",
            {
                "extra_vars": {
                    "monitoring_etcd_bootstrap_test_invalid_host": "monitoring-stage-3"
                }
            },
            "Mocked monitoring etcd bootstrap host observation is invalid",
        ),
        (
            "cross-host-drift",
            {
                "extra_vars": {
                    "monitoring_etcd_bootstrap_test_drift_host": "monitoring-stage-2"
                }
            },
            "requires one consistent cluster contract",
        ),
        (
            "cross-host-ca-drift",
            {
                "extra_vars": {
                    "monitoring_etcd_bootstrap_test_ca_drift_host": "monitoring-stage-3"
                }
            },
            "requires one consistent cluster contract",
        ),
    ),
)
def test_monitoring_etcd_bootstrap_preflight_rejects_unsafe_cluster(
    case_id: str,
    kwargs: dict[str, Any],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    del case_id
    result = _run_preflight(repo_root, command_runner, **kwargs)
    assert_failed_with(result, message)


def test_monitoring_etcd_bootstrap_preflight_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / PLAYBOOK,
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()
