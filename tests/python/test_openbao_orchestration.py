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
    Rejection("partial-limit", "inventory.yml", {}, "requires all three OpenBao inventory hosts", "bao-stage-1"),
    Rejection("two-members", "inventory-two.yml", {}, "requires exactly three inventory members"),
    Rejection("unready", "inventory.yml", {"openbao_orchestration_ready": False}, "requires an explicit ready contract"),
    Rejection("openbao-disabled", "inventory.yml", {"openbao_enabled": False}, "requires an explicit ready contract"),
    Rejection("haproxy-disabled", "inventory.yml", {"openbao_haproxy_enabled": False}, "requires an explicit ready contract"),
    Rejection("keepalived-disabled", "inventory.yml", {"keepalived_vip_enabled": False}, "requires an explicit ready contract"),
    Rejection("invalid-openbao", "inventory.yml", {"openbao_test_invalid_component": "openbao"}, "Mocked OpenBao inputs are invalid"),
    Rejection("invalid-haproxy", "inventory.yml", {"openbao_test_invalid_component": "haproxy"}, "Mocked OpenBao HAProxy inputs are invalid"),
    Rejection("invalid-keepalived", "inventory.yml", {"openbao_test_invalid_component": "keepalived"}, "Mocked Keepalived inputs are invalid"),
    Rejection("active-openbao", "inventory.yml", {"openbao_test_active_openbao": "bao-stage-2"}, "stopped/disabled OpenBao, HAProxy, and Keepalived"),
    Rejection("active-haproxy", "inventory.yml", {"openbao_test_active_haproxy": "bao-stage-2"}, "stopped/disabled OpenBao, HAProxy, and Keepalived"),
    Rejection("active-keepalived", "inventory.yml", {"openbao_test_active_keepalived": "bao-stage-2"}, "stopped/disabled OpenBao, HAProxy, and Keepalived"),
    Rejection(
        "active-maintenance-mode",
        "inventory.yml",
        {"openbao_lifecycle_preflight_mode": "active-maintenance"},
        "inactive custody preflight",
    ),
    Rejection("unrelated-limit", "inventory.yml", {}, "did not select the replacement service group", "unrelated-stage"),
)


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [str(repo_root / "tests/fixtures/openbao-orchestration/roles"), str(repo_root / "roles")]
        ),
        "PATH": os.pathsep.join(
            [
                str(repo_root / "tests/fixtures/openbao-orchestration/bin"),
                os.environ["PATH"],
            ]
        ),
    }


def _registry_remaps_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [
                str(repo_root / "tests/fixtures/openbao-registry-remaps/roles"),
                str(repo_root / "roles"),
            ]
        )
    }


def test_openbao_orchestration_source_contract(repo_root: Path) -> None:
    playbook = (repo_root / "playbooks/openbao.yml").read_text(encoding="utf-8")
    role = (repo_root / "roles/openbao/tasks/main.yml").read_text(encoding="utf-8")
    defaults = (repo_root / "roles/openbao/defaults/main.yml").read_text(encoding="utf-8")
    validation = (repo_root / "roles/openbao/tasks/validate.yml").read_text(encoding="utf-8")
    lifecycle = (repo_root / "roles/openbao/tasks/lifecycle_preflight.yml").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "openbao_orchestration_ready",
        "ansible_play_hosts_all",
        "Inspect existing OpenBao HA services",
        "Disable and stop existing OpenBao HA edge services",
        "Mask and stop an existing OpenBao service before staging",
        "Mask the successfully staged disabled OpenBao service",
    ):
        assert fragment in playbook
    assert re.search(r"^    - firewalld$", playbook, re.MULTILINE)
    assert re.search(r"^    - keepalived_vip$", playbook, re.MULTILINE)
    assert not re.search(r"platform_external_probe|grafana_alloy|operator init|operator unseal", playbook)
    assert "include_tasks: custody.yml" in role
    assert "Stage exact dormant OpenBao listener" in role
    assert "Install OpenBao node certificate" not in role
    assert "Install OpenBao node private key" not in role
    assert "openbao_lifecycle_preflight_mode: inactive-custody" in defaults
    assert "in ['inactive-custody', 'active-maintenance']" in validation
    assert "include_tasks: staging_lifecycle_preflight.yml" in lifecycle
    assert "not openbao_listener_staging_stats.results[0].stat.exists" in lifecycle
    assert "include_tasks: custody.yml" in lifecycle
    assert "openbao_lifecycle_preflight_mode == 'inactive-custody'" in lifecycle
    assert "include_tasks: active_preflight.yml" in lifecycle
    assert "openbao_lifecycle_preflight_mode == 'active-maintenance'" in lifecycle
    assert "openbao_lifecycle_preflight_mode | default('inactive-custody')" in playbook
    assert "== 'inactive-custody'" in playbook


def test_openbao_lifecycle_preflight_mode_branches_are_exact(repo_root: Path) -> None:
    tasks = yaml.safe_load(
        (repo_root / "roles/openbao/tasks/lifecycle_preflight.yml").read_text(
            encoding="utf-8"
        )
    )
    staging, custody, active = tasks[1:]
    assert staging["ansible.builtin.include_tasks"] == "staging_lifecycle_preflight.yml"
    assert staging["when"] == [
        "openbao_lifecycle_preflight_mode == 'inactive-custody'",
        "not openbao_listener_staging_stats.results[0].stat.exists",
    ]
    assert custody["ansible.builtin.include_tasks"] == "custody.yml"
    assert custody["when"] == [
        "openbao_lifecycle_preflight_mode == 'inactive-custody'",
        "openbao_listener_staging_stats.results[0].stat.exists",
    ]
    assert active["ansible.builtin.include_tasks"] == "active_preflight.yml"
    assert active["when"] == [
        "openbao_lifecycle_preflight_mode == 'active-maintenance'",
    ]


def test_openbao_active_maintenance_with_absent_listener_never_stages(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/openbao-lifecycle-preflight/validate.yml",
        extra_vars=({"openbao_lifecycle_test_root": str(isolated_test_dir)},),
    )
    assert_failed_with(result, "private completion marker")


def test_openbao_orchestration_runs_exact_mocked_role_order(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    marker = isolated_test_dir / "converged"
    run_playbook(
        command_runner,
        repo_root / "playbooks/openbao.yml",
        inventory=repo_root / "tests/fixtures/openbao-orchestration/inventory.yml",
        extra_vars=({"openbao_test_marker_path": str(marker)},),
        environment=_roles_environment(repo_root),
    ).assert_success()
    assert marker.read_text(encoding="utf-8") == "complete"


def test_openbao_orchestration_accepts_absent_pristine_data_directory(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    marker = isolated_test_dir / "converged"
    run_playbook(
        command_runner,
        repo_root / "playbooks/openbao.yml",
        inventory=repo_root / "tests/fixtures/openbao-orchestration/inventory.yml",
        extra_vars=(
            {
                "openbao_test_marker_path": str(marker),
                "openbao_test_leave_data_dir_absent": True,
            },
        ),
        environment=_roles_environment(repo_root),
    ).assert_success()
    assert marker.read_text(encoding="utf-8") == "complete"
    assert not (isolated_test_dir / "data").exists()


@pytest.mark.parametrize("case", REJECTIONS, ids=lambda case: case.case_id)
def test_openbao_orchestration_rejects_before_convergence(
    case: Rejection,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    variables = {"openbao_test_marker_path": str(marker), **case.extra_vars}
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/openbao.yml",
        inventory=repo_root / f"tests/fixtures/openbao-orchestration/{case.inventory}",
        extra_vars=(variables,),
        limit=case.limit,
        environment=_roles_environment(repo_root),
    )
    assert_failed_with(result, case.message)
    assert not marker.exists()


def test_openbao_orchestration_allows_unaffected_homelab_inventory(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/openbao.yml",
        inventory=repo_root / "inventories/homelab/hosts.yml.example",
    ).assert_success()


def test_openbao_registry_remap_maintenance_requires_complete_active_scope(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    inventory = repo_root / "tests/fixtures/openbao-orchestration/inventory.yml"
    playbook = repo_root / "playbooks/maintenance/openbao-registry-remaps.yml"
    marker = isolated_test_dir / "registry-remaps"
    variables = {
        "openbao_registry_remaps_test_marker": str(marker),
        "podman_host_registry_remaps": {
            "ghcr.io/openbao/openbao": "registry.example.test/openbao/openbao"
        },
    }

    run_playbook(
        command_runner,
        playbook,
        inventory=inventory,
        extra_vars=(variables,),
        limit="openbao",
        environment=_registry_remaps_environment(repo_root),
    ).assert_success()
    assert marker.read_text(encoding="utf-8") == "complete"

    for case_id, extra_vars, limit, message in (
        (
            "missing-limit",
            {},
            None,
            "requires an explicit limit selecting exactly all three OpenBao hosts",
        ),
        (
            "partial",
            {},
            "bao-stage-1",
            "requires an explicit limit selecting exactly all three OpenBao hosts",
        ),
        (
            "inactive",
            {"openbao_registry_remaps_test_inactive_host": "bao-stage-3"},
            "openbao",
            "Mocked active OpenBao lifecycle preflight failed",
        ),
        (
            "mismatched-cluster",
            {"openbao_registry_remaps_test_mismatched_host": "bao-stage-3"},
            "openbao",
            "requires one exact active OpenBao cluster",
        ),
        (
            "unrelated",
            {},
            "unrelated-stage",
            "requires an explicit limit selecting exactly all three OpenBao hosts",
        ),
    ):
        marker.unlink(missing_ok=True)
        result = run_playbook(
            command_runner,
            playbook,
            inventory=inventory,
            extra_vars=({**variables, **extra_vars},),
            limit=limit,
            environment=_registry_remaps_environment(repo_root),
        )
        assert_failed_with(result, message)
        assert not marker.exists(), case_id
