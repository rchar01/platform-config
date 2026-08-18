from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@dataclass(frozen=True)
class Rejection:
    case_id: str
    inventory: str
    extra_vars: dict[str, Any]
    message: str
    limit: str | None = None


REJECTIONS = (
    Rejection(
        "partial-limit",
        "inventory.yml",
        {},
        "requires all three monitoring inventory hosts",
        "monitoring-stage-1",
    ),
    Rejection(
        "localhost-limit",
        "inventory.yml",
        {},
        "requires all three monitoring inventory hosts",
        "localhost",
    ),
    Rejection(
        "two-members",
        "inventory-two.yml",
        {},
        "requires exactly three monitoring inventory members",
    ),
    Rejection(
        "empty-inventory",
        "empty-inventory.yml",
        {},
        "requires exactly three monitoring inventory members",
    ),
    Rejection(
        "unready",
        "inventory.yml",
        {"monitoring_etcd_orchestration_ready": False},
        "requires explicit ready inactive ownership",
    ),
    Rejection(
        "contract-unready",
        "inventory.yml",
        {"monitoring_etcd_contract_ready": False},
        "requires explicit ready inactive ownership",
    ),
    Rejection(
        "role-disabled",
        "inventory.yml",
        {"monitoring_etcd_enabled": False},
        "requires explicit ready inactive ownership",
    ),
    Rejection(
        "convergence-disabled",
        "inventory.yml",
        {"monitoring_etcd_converge": False},
        "requires explicit ready inactive ownership",
    ),
    Rejection(
        "active-service",
        "inventory.yml",
        {"monitoring_etcd_test_active_host": "monitoring-stage-2"},
        "requires explicit ready inactive ownership",
    ),
    Rejection(
        "firewall-disabled",
        "inventory.yml",
        {"firewalld_enabled": False},
        "requires managed firewalld and SELinux",
    ),
    Rejection(
        "firewall-service-disabled",
        "inventory.yml",
        {"firewalld_service_enabled": False},
        "requires managed firewalld and SELinux",
    ),
    Rejection(
        "firewall-stopped",
        "inventory.yml",
        {"firewalld_service_state": "stopped"},
        "requires managed firewalld and SELinux",
    ),
    Rejection(
        "etcd-firewall-unmanaged",
        "inventory.yml",
        {"monitoring_etcd_firewalld_manage": False},
        "requires managed firewalld and SELinux",
    ),
    Rejection(
        "selinux-unmanaged",
        "inventory.yml",
        {"monitoring_etcd_selinux_manage": False},
        "requires managed firewalld and SELinux",
    ),
    Rejection(
        "invalid-contract-second-host",
        "inventory.yml",
        {"monitoring_etcd_test_invalid_host": "monitoring-stage-2"},
        "Mocked monitoring etcd contract is invalid",
    ),
    Rejection(
        "missing-pki",
        "inventory.yml",
        {"monitoring_etcd_tls_cert_src": "/missing/tls.crt"},
        "requires every controller PKI input",
    ),
    Rejection(
        "directory-pki",
        "inventory.yml",
        {"monitoring_etcd_tls_cert_src": "__DIRECTORY__"},
        "requires every controller PKI input",
    ),
    Rejection(
        "symlink-pki",
        "inventory.yml",
        {"monitoring_etcd_tls_cert_src": "__SYMLINK__"},
        "requires every controller PKI input",
    ),
    Rejection(
        "unrelated-limit",
        "inventory.yml",
        {},
        "did not select the monitoring service group",
        "unrelated-stage",
    ),
)


def _fixture_root(repo_root: Path) -> Path:
    return repo_root / "tests/fixtures/monitoring-etcd-orchestration"


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [str(_fixture_root(repo_root) / "roles"), str(repo_root / "roles")]
        )
    }


def test_monitoring_etcd_orchestration_source_contract(repo_root: Path) -> None:
    playbook = (repo_root / "playbooks/monitoring-etcd.yml").read_text(
        encoding="utf-8"
    )
    quiesce = (repo_root / "roles/monitoring_etcd/tasks/quiesce.yml").read_text(
        encoding="utf-8"
    )
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    for fragment in (
        "monitoring_etcd_orchestration_ready",
        "ansible_play_hosts_all",
        "Validate monitoring etcd contract before staging",
        "Require safe monitoring etcd controller PKI inputs",
        "Quiesce the validated monitoring etcd cluster",
        "Stage the inactive monitoring etcd foundation",
    ):
        assert fragment in playbook
    plays = yaml.safe_load(playbook)
    assert [play["name"] for play in plays[1:4]] == [
        "Validate the monitoring etcd staging contract",
        "Quiesce the validated monitoring etcd cluster",
        "Stage the inactive monitoring etcd foundation",
    ]
    assert "Disable existing monitoring etcd service before staging" in quiesce
    assert "Stop existing monitoring etcd service before staging" in quiesce
    role_order = re.findall(r"^    - (firewalld|podman_host|monitoring_etcd)$", playbook, re.MULTILINE)
    assert role_order == ["firewalld", "podman_host", "monitoring_etcd"]
    assert not re.search(
        r"state: started|initialize|restore|member (?:add|remove)|snapshot",
        playbook,
        re.IGNORECASE,
    )
    assert "monitoring-etcd.yml" not in site


def test_monitoring_etcd_orchestration_runs_exact_mocked_role_order(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    quiesce_marker = isolated_test_dir / "quiesced"
    run_playbook(
        command_runner,
        repo_root / "playbooks/monitoring-etcd.yml",
        inventory=_fixture_root(repo_root) / "inventory.yml",
        extra_vars=(
            {
                "monitoring_etcd_test_marker_path": str(marker),
                "monitoring_etcd_test_quiesce_marker_path": str(quiesce_marker),
            },
        ),
        environment=_roles_environment(repo_root),
    ).assert_success()
    assert quiesce_marker.read_text(encoding="utf-8") == "quiesced"
    assert marker.read_text(encoding="utf-8") == "complete"


@pytest.mark.parametrize("case", REJECTIONS, ids=lambda case: case.case_id)
def test_monitoring_etcd_orchestration_rejects_before_convergence(
    case: Rejection,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    quiesce_marker = isolated_test_dir / "quiesced"
    extra_vars = dict(case.extra_vars)
    if extra_vars.get("monitoring_etcd_tls_cert_src") == "__DIRECTORY__":
        extra_vars["monitoring_etcd_tls_cert_src"] = str(
            _fixture_root(repo_root) / "roles"
        )
    elif extra_vars.get("monitoring_etcd_tls_cert_src") == "__SYMLINK__":
        symlink = isolated_test_dir / "tls-symlink.crt"
        symlink.symlink_to(_fixture_root(repo_root) / "pki-input.txt")
        extra_vars["monitoring_etcd_tls_cert_src"] = str(symlink)
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/monitoring-etcd.yml",
        inventory=_fixture_root(repo_root) / case.inventory,
        extra_vars=(
            {
                "monitoring_etcd_test_marker_path": str(marker),
                "monitoring_etcd_test_quiesce_marker_path": str(quiesce_marker),
                **extra_vars,
            },
        ),
        limit=case.limit,
        environment=_roles_environment(repo_root),
    )
    assert_failed_with(result, case.message)
    assert not quiesce_marker.exists()
    assert not marker.exists()


def test_monitoring_etcd_staging_playbook_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/monitoring-etcd.yml",
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()
