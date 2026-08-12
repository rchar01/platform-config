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
    Rejection("partial-limit", "inventory.yml", {}, "requires all three OpenBao inventory hosts", "observer-1"),
    Rejection("two-members", "inventory-two.yml", {}, "requires exactly three inventory members"),
    Rejection(
        "unready",
        "inventory.yml",
        {"openbao_observers_orchestration_ready": False},
        "requires an explicit ready contract",
    ),
    Rejection(
        "second-host-unready",
        "inventory.yml",
        {"openbao_observers_test_unready_host": "observer-2"},
        "requires an explicit ready contract",
    ),
    Rejection(
        "probe-disabled",
        "inventory.yml",
        {"platform_external_probe_enabled": False},
        "requires an explicit ready contract",
    ),
    Rejection(
        "second-host-probe-disabled",
        "inventory.yml",
        {"openbao_observers_test_probe_disabled_host": "observer-2"},
        "requires an explicit ready contract",
    ),
    Rejection(
        "alloy-disabled",
        "inventory.yml",
        {"grafana_alloy_enabled": False},
        "requires an explicit ready contract",
    ),
    Rejection(
        "second-host-alloy-disabled",
        "inventory.yml",
        {"openbao_observers_test_alloy_disabled_host": "observer-2"},
        "requires an explicit ready contract",
    ),
    Rejection(
        "invalid-activation",
        "inventory.yml",
        {"openbao_observers_activate": "yes"},
        "requires an explicit ready contract",
    ),
    Rejection(
        "second-host-invalid-activation",
        "inventory.yml",
        {"openbao_observers_test_invalid_activation_host": "observer-2"},
        "requires an explicit ready contract",
    ),
    Rejection(
        "second-host-invalid-probe-input",
        "inventory.yml",
        {"openbao_observers_test_invalid_probe_host": "observer-2"},
        "Mocked external probe inputs are invalid",
    ),
    Rejection(
        "second-host-invalid-alloy-input",
        "inventory.yml",
        {"openbao_observers_test_invalid_alloy_host": "observer-2"},
        "Mocked Grafana Alloy inputs are invalid",
    ),
    Rejection(
        "unrelated-limit",
        "inventory.yml",
        {},
        "did not select the observer group",
        "unrelated-observer",
    ),
)


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [
                str(repo_root / "tests/fixtures/openbao-observer-orchestration/roles"),
                str(repo_root / "roles"),
            ]
        )
    }


@pytest.mark.parametrize("activate", [False, True], ids=["staged", "active"])
def test_openbao_observers_derive_complete_lifecycle(
    activate: bool,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    run_playbook(
        command_runner,
        repo_root / "playbooks/openbao-observers.yml",
        inventory=repo_root / "tests/fixtures/openbao-observer-orchestration/inventory.yml",
        extra_vars=(
            {
                "openbao_observers_test_activate": activate,
                "openbao_observers_test_marker_path": str(marker),
            },
        ),
        environment=_roles_environment(repo_root),
    ).assert_success()
    assert marker.read_text(encoding="utf-8") == ("active" if activate else "staged")


@pytest.mark.parametrize("case", REJECTIONS, ids=lambda case: case.case_id)
def test_openbao_observers_reject_before_convergence(
    case: Rejection,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    marker = isolated_test_dir / "converged"
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/openbao-observers.yml",
        inventory=repo_root / f"tests/fixtures/openbao-observer-orchestration/{case.inventory}",
        extra_vars=(
            {
                "openbao_observers_test_marker_path": str(marker),
                **case.extra_vars,
            },
        ),
        limit=case.limit,
        environment=_roles_environment(repo_root),
    )
    assert_failed_with(result, case.message)
    assert not marker.exists()


def test_openbao_observer_playbooks_source_contract(repo_root: Path) -> None:
    deployment = (repo_root / "playbooks/openbao-observers.yml").read_text(encoding="utf-8")
    smoke = (repo_root / "playbooks/openbao-observers-smoke.yml").read_text(encoding="utf-8")
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")

    assert deployment.index("name: platform_external_probe") < deployment.index("name: grafana_alloy")
    assert "ansible_play_hosts_all" in deployment
    assert "openbao_observers_activate" in deployment
    assert "tasks_from: preflight.yml" in deployment
    assert not re.search(r"initialize|unseal|restore|migrat", deployment)
    for fragment in (
        "/usr/bin/alloy",
        "alloy-0:1.18.1-1.x86_64",
        "/-/ready",
        "probe_success",
        "platform_postgresql_primary_query_success",
        "platform_garage_canary_ambiguity",
        "platform_vip_ownership_observation_timestamp_seconds",
        "platform_postgresql_primary_observation_timestamp_seconds",
        "platform_garage_canary_observation_timestamp_seconds",
        "openbao_observers_smoke_max_evidence_age == 90",
        "openbao_observers_smoke_ownership_now.stdout",
        "openbao_observers_smoke_postgresql_now.stdout",
        "openbao_observers_smoke_garage_now.stdout",
        "future-dated",
        "ansible_play_hosts_all",
    ):
        assert fragment in smoke
    assert "openbao_status" not in smoke
    assert "ansible_date_time.epoch" not in smoke
    assert "openbao-observers" not in site
    assert re.search(r"^deploy-openbao-observers:", makefile, re.MULTILINE)
    assert re.search(r"^smoke-openbao-observers:", makefile, re.MULTILINE)
    assert "legacy check is blocked" in makefile


def test_observer_roles_preflight_before_lifecycle(repo_root: Path) -> None:
    for role in ("platform_external_probe", "grafana_alloy"):
        tasks = (repo_root / f"roles/{role}/tasks/main.yml").read_text(encoding="utf-8")
        preflight = (repo_root / f"roles/{role}/tasks/preflight.yml").read_text(encoding="utf-8")
        assert tasks.index("include_tasks: preflight.yml") < tasks.index("ansible.builtin.stat:")
        assert "ansible.builtin.assert:" in preflight
        assert not re.search(
            r"ansible[.]builtin[.](?:file|copy|template|dnf|systemd_service|command|uri):",
            preflight,
        )


def test_openbao_observer_playbooks_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    inventory = repo_root / "inventories/dev/hosts.yml.example"
    for name in ("openbao-observers.yml", "openbao-observers-smoke.yml"):
        run_playbook(
            command_runner,
            repo_root / f"playbooks/{name}",
            inventory=inventory,
            syntax_check=True,
        ).assert_success()


@pytest.mark.parametrize(
    ("extra_vars", "message"),
    [
        ({"openbao_observers_activate": False}, "explicitly active"),
        ({"openbao_observers_orchestration_ready": False}, "explicitly active"),
        ({"openbao_observers_test_unready_host": "observer-2", "openbao_observers_test_activate": True}, "explicitly active"),
        ({"openbao_observers_test_invalid_activation_host": "observer-2", "openbao_observers_test_activate": True}, "explicitly active"),
        ({"openbao_observers_test_probe_disabled_host": "observer-2", "openbao_observers_test_activate": True}, "explicitly active"),
        ({"openbao_observers_test_alloy_disabled_host": "observer-2", "openbao_observers_test_activate": True}, "explicitly active"),
    ],
)
def test_openbao_observer_smoke_rejects_inactive_contract_before_runtime(
    extra_vars: dict[str, Any],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/openbao-observers-smoke.yml",
        inventory=repo_root / "tests/fixtures/openbao-observer-orchestration/inventory.yml",
        extra_vars=(extra_vars,),
    )
    assert_failed_with(result, message)
