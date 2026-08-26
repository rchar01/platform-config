from __future__ import annotations

from pathlib import Path

import yaml


PLAYBOOK = "playbooks/maintenance/openbao-audit-migrate.yml"
PREFLIGHT = "roles/openbao/tasks/audit_migration_preflight.yml"
APPLY = "roles/openbao/tasks/audit_migration_apply.yml"


def test_openbao_audit_migration_has_attended_fail_closed_boundary(
    repo_root: Path,
) -> None:
    source = (repo_root / PLAYBOOK).read_text(encoding="utf-8")

    for fragment in (
        "ansible_limit is defined",
        "audit_migration_preflight.yml",
        "no-api-audit-devices",
        "ansible.builtin.pause:",
        "audit_migration_apply.yml",
        "openbao_audit_migration_approved_observations",
    ):
        assert fragment in source

    for forbidden in ("root_token", "operator init", "operator unseal", "restart"):
        assert forbidden not in source


def test_openbao_audit_migration_preflight_requires_pending_unsealed_state(
    repo_root: Path,
) -> None:
    source = (repo_root / PREFLIGHT).read_text(encoding="utf-8")

    for fragment in (
        "openbao_audit_migration_ready",
        "state == 'awaiting-manual-custody'",
        "audit_config_checksum",
        "openbao_audit_migration_expected_checksum",
        "certificate_checksum",
        "key_checksum",
        "openbao_audit_migration_container_exists.rc == 0",
        "get('initialized')",
        "get('sealed')",
    ):
        assert fragment in source


def test_openbao_audit_migration_reloads_without_restart_and_updates_marker(
    repo_root: Path,
) -> None:
    tasks = yaml.safe_load((repo_root / APPLY).read_text(encoding="utf-8"))
    source = (repo_root / APPLY).read_text(encoding="utf-8")
    reload_task = next(
        task
        for task in tasks
        if task["name"] == "Reload declarative OpenBao configuration without restart"
    )

    assert reload_task["ansible.builtin.command"]["argv"] == [
        "/usr/bin/podman",
        "kill",
        "--signal",
        "HUP",
        "{{ openbao_container_name }}",
    ]
    assert "ansible.builtin.service:" not in source
    assert "ansible.builtin.systemd_service:" not in source
    assert "openbao_audit_1_dir" in source
    assert "openbao_audit_2_dir" in source
    assert "item.1.stat.isreg" in source
    assert "item.1.stat.mode == '0600'" in source
    assert "item.1.stat.size > (item.0.stat.size | default(0))" in source
    assert "or item.1.stat.mtime" not in source
    assert "not item.0.stat.exists" not in source
    assert "combine({'audit_config_checksum'" in source
    assert "root_token" not in source


def test_openbao_audit_migration_has_public_entry_point(repo_root: Path) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    runbook = (repo_root / "docs/operator-runbook.md").read_text(encoding="utf-8")

    assert "migrate-openbao-audit:" in makefile
    assert "PLAYBOOK=playbooks/maintenance/openbao-audit-migrate.yml" in makefile
    assert "make migrate-openbao-audit ENV=dev LIMIT=openbao" in runbook


def test_openbao_audit_migration_readiness_is_strict_boolean(repo_root: Path) -> None:
    validation = (repo_root / "roles/openbao/tasks/validate.yml").read_text(
        encoding="utf-8"
    )

    assert "openbao_audit_migration_ready is boolean" in validation
