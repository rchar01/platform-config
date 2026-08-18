from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

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
        "unready",
        "inventory.yml",
        {"monitoring_haproxy_orchestration_ready": False},
        "requires an explicit ready contract",
    ),
    Rejection(
        "contract-unready",
        "inventory.yml",
        {"monitoring_haproxy_contract_ready": False},
        "requires an explicit ready contract",
    ),
    Rejection(
        "role-disabled",
        "inventory.yml",
        {"monitoring_haproxy_enabled": False},
        "requires an explicit ready contract",
    ),
    Rejection(
        "active-service",
        "inventory.yml",
        {"monitoring_haproxy_test_active_host": "monitoring-stage-2"},
        "stopped/disabled HAProxy",
    ),
    Rejection(
        "firewall-disabled",
        "inventory.yml",
        {"firewalld_enabled": False},
        "declared enabled firewalld contract",
    ),
    Rejection(
        "firewall-service-disabled",
        "inventory.yml",
        {"firewalld_service_enabled": False},
        "declared enabled firewalld contract",
    ),
    Rejection(
        "firewall-stopped",
        "inventory.yml",
        {"firewalld_service_state": "stopped"},
        "declared enabled firewalld contract",
    ),
    Rejection(
        "haproxy-firewall-unmanaged",
        "inventory.yml",
        {"monitoring_haproxy_firewalld_manage": False},
        "declared enabled firewalld contract",
    ),
    Rejection(
        "selinux-unmanaged",
        "inventory.yml",
        {"monitoring_haproxy_selinux_manage": False},
        "managed SELinux",
    ),
    Rejection(
        "invalid-policy",
        "inventory.yml",
        {"monitoring_haproxy_test_invalid_component": "policy"},
        "Mocked monitoring HAProxy policy inputs are invalid",
    ),
    Rejection(
        "invalid-operations",
        "inventory.yml",
        {"monitoring_haproxy_test_invalid_component": "operations"},
        "Mocked monitoring HAProxy operational inputs are invalid",
    ),
    Rejection(
        "missing-pki",
        "inventory.yml",
        {"monitoring_haproxy_frontend_pem_src": "/missing/frontend.pem"},
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


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [
                str(
                    repo_root
                    / "tests/fixtures/monitoring-haproxy-orchestration/roles"
                ),
                str(repo_root / "roles"),
            ]
        )
    }


def test_monitoring_haproxy_orchestration_source_contract(
    repo_root: Path,
) -> None:
    playbook = (repo_root / "playbooks/monitoring-haproxy.yml").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "monitoring_haproxy_orchestration_ready",
        "ansible_play_hosts_all",
        "Validate monitoring HAProxy policy before staging",
        "Validate monitoring HAProxy operations before staging",
        "Disable and stop existing monitoring HAProxy before staging",
    ):
        assert fragment in playbook
    assert playbook.index(
        "Require safe monitoring HAProxy controller PKI inputs"
    ) < playbook.index("Disable and stop existing monitoring HAProxy before staging")
    assert playbook.index(
        "Disable and stop existing monitoring HAProxy before staging"
    ) < playbook.index("Stage the disabled monitoring HAProxy foundation")
    assert re.search(r"^    - firewalld$", playbook, re.MULTILINE)
    assert re.search(r"^    - monitoring_haproxy$", playbook, re.MULTILINE)
    assert not re.search(
        r"monitoring_stack|grafana_alloy|keepalived_vip|initialize|restore",
        playbook,
    )


def test_monitoring_haproxy_orchestration_runs_exact_mocked_role_order(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    run_playbook(
        command_runner,
        repo_root / "playbooks/monitoring-haproxy.yml",
        inventory=(
            repo_root
            / "tests/fixtures/monitoring-haproxy-orchestration/inventory.yml"
        ),
        extra_vars=({"monitoring_haproxy_test_marker_path": str(marker)},),
        environment=_roles_environment(repo_root),
    ).assert_success()
    assert marker.read_text(encoding="utf-8") == "complete"


@pytest.mark.parametrize("case", REJECTIONS, ids=lambda case: case.case_id)
def test_monitoring_haproxy_orchestration_rejects_before_convergence(
    case: Rejection,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    variables = {
        "monitoring_haproxy_test_marker_path": str(marker),
        **case.extra_vars,
    }
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/monitoring-haproxy.yml",
        inventory=(
            repo_root
            / "tests/fixtures/monitoring-haproxy-orchestration"
            / case.inventory
        ),
        extra_vars=(variables,),
        limit=case.limit,
        environment=_roles_environment(repo_root),
    )
    assert_failed_with(result, case.message)
    assert not marker.exists()


def test_monitoring_haproxy_orchestration_allows_unaffected_homelab_inventory(
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/monitoring-haproxy.yml",
        inventory=repo_root / "inventories/homelab/hosts.yml.example",
    ).assert_success()
