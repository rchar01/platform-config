from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@dataclass(frozen=True)
class BlockedPlaybook:
    case_id: str
    inventory: str
    playbook: str
    limit: str | None = None


BLOCKED_PLAYBOOKS = (
    BlockedPlaybook("empty-openbao", "tests/fixtures/ha-handoff/empty-inventory.yml", "playbooks/openbao.yml"),
    BlockedPlaybook("empty-status", "tests/fixtures/ha-handoff/empty-inventory.yml", "playbooks/maintenance/openbao-status.yml"),
    BlockedPlaybook("empty-monitoring", "tests/fixtures/ha-handoff/empty-inventory.yml", "playbooks/monitoring.yml"),
    BlockedPlaybook("empty-monitoring-smoke", "tests/fixtures/ha-handoff/empty-inventory.yml", "playbooks/monitoring-smoke.yml"),
    BlockedPlaybook("dev-openbao", "inventories/dev/hosts.yml.example", "playbooks/openbao.yml", "openbao-example-01"),
    BlockedPlaybook("dev-status", "inventories/dev/hosts.yml.example", "playbooks/maintenance/openbao-status.yml", "openbao-example-01"),
    BlockedPlaybook("dev-monitoring", "inventories/dev/hosts.yml.example", "playbooks/monitoring.yml", "monitoring-example-01"),
    BlockedPlaybook("dev-monitoring-smoke", "inventories/dev/hosts.yml.example", "playbooks/monitoring-smoke.yml", "monitoring-example-01"),
    BlockedPlaybook("unrelated-openbao", "inventories/dev/hosts.yml.example", "playbooks/openbao.yml", "k8s-bastion-example"),
    BlockedPlaybook("unrelated-status", "inventories/dev/hosts.yml.example", "playbooks/maintenance/openbao-status.yml", "k8s-bastion-example"),
    BlockedPlaybook("unrelated-monitoring", "inventories/dev/hosts.yml.example", "playbooks/monitoring.yml", "k8s-bastion-example"),
    BlockedPlaybook("unrelated-monitoring-smoke", "inventories/dev/hosts.yml.example", "playbooks/monitoring-smoke.yml", "k8s-bastion-example"),
    BlockedPlaybook("legacy-openbao", "tests/fixtures/ha-handoff/legacy-openbao-inventory.yml", "playbooks/openbao.yml", "legacy-openbao-example"),
    BlockedPlaybook("legacy-status", "tests/fixtures/ha-handoff/legacy-openbao-inventory.yml", "playbooks/maintenance/openbao-status.yml", "legacy-openbao-example"),
)


def test_ha_transition_sources_fail_closed(repo_root: Path) -> None:
    openbao = (repo_root / "playbooks/openbao.yml").read_text(encoding="utf-8")
    status = (repo_root / "playbooks/maintenance/openbao-status.yml").read_text(encoding="utf-8")
    monitoring = (repo_root / "playbooks/monitoring.yml").read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")

    assert re.search(r"^  hosts: openbao$", openbao, re.MULTILINE)
    assert "openbao_orchestration_ready" in openbao
    assert "ansible_play_hosts_all" in openbao
    assert not re.search(r"hosts: vault|initialize|unseal", openbao)
    assert "ansible.builtin.fail:" in monitoring
    assert not re.search(r"monitoring_stack|grafana_alloy|node_exporter", monitoring)
    assert not re.search(r"initialize|reset|restore|failure", site)
    assert not re.search(r"validate_certs: false|initialize|unseal", status)
    assert "legacy check is blocked" in makefile


@pytest.mark.parametrize("case", BLOCKED_PLAYBOOKS, ids=lambda case: case.case_id)
def test_managed_playbooks_reject_unsafe_inventory_or_limit(
    case: BlockedPlaybook, repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / case.playbook,
        inventory=repo_root / case.inventory,
        limit=case.limit,
    )
    result.assert_failure()
    assert re.search(
        r"OpenBao staging|Strict OpenBao HA status requires|"
        r"HA implementation is unavailable|HA smoke checks are not implemented",
        result.stdout + result.stderr,
    ), result.diagnostics()


@pytest.mark.parametrize("playbook", ["playbooks/openbao.yml", "playbooks/monitoring.yml"])
def test_homelab_transition_playbooks_are_noops(
    playbook: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / playbook,
        inventory=repo_root / "inventories/homelab/hosts.yml.example",
    ).assert_success()


def test_public_ha_inventory_contract(repo_root: Path, command_runner: CommandRunner) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/validate-public-inventory.yml",
        inventory=repo_root / "inventories/dev/hosts.yml.example",
    ).assert_success()


def test_storage_layout_within_capacity(repo_root: Path, command_runner: CommandRunner) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/validate-storage-layout.yml",
    ).assert_success()


def test_storage_layout_overallocation_is_rejected(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/validate-storage-layout.yml",
        extra_vars=({"test_capacity_gib": 13},),
    )
    assert_failed_with(result, "allocations and required free space")


def test_mixed_storage_vg_lv_collision_is_rejected(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/validate-storage-mixed-duplicate.yml",
    )
    assert_failed_with(result, "unique VG/LV pairs")


def test_public_ha_examples_are_sanitized(repo_root: Path) -> None:
    dev_inventory = (repo_root / "inventories/dev/hosts.yml.example").read_text(encoding="utf-8")
    assert "vault:" not in dev_inventory
    examples = [
        repo_root / "inventories/dev/group_vars/openbao.yml.example",
        repo_root / "inventories/dev/group_vars/monitoring.yml.example",
        *sorted((repo_root / "inventories/dev/host_vars").glob("openbao-example-*.yml.example")),
        *sorted((repo_root / "inventories/dev/host_vars").glob("monitoring-example-*.yml.example")),
    ]
    assert len(examples) == 8
    secret_pattern = re.compile(
        r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|client-certificate-data:|"
        r"token: [A-Za-z0-9]"
    )
    for example in examples:
        assert not secret_pattern.search(example.read_text(encoding="utf-8")), example


def test_public_example_sanitizer_is_mutation_sensitive() -> None:
    secret_pattern = re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|token: [A-Za-z0-9]")
    assert secret_pattern.search("token: fixture-secret")
