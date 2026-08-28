from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


FORBIDDEN_ACTIONS = {
    "ansible.builtin.command",
    "ansible.builtin.copy",
    "ansible.builtin.file",
    "ansible.builtin.service",
    "ansible.builtin.shell",
    "ansible.builtin.systemd_service",
    "ansible.builtin.template",
}


def _assert_no_mutating_actions(node: Any) -> None:
    if isinstance(node, dict):
        assert not FORBIDDEN_ACTIONS.intersection(node)
        for value in node.values():
            _assert_no_mutating_actions(value)
    elif isinstance(node, list):
        for value in node:
            _assert_no_mutating_actions(value)


def test_openbao_status_source_security_contract(repo_root: Path) -> None:
    main = (repo_root / "roles/openbao_status/tasks/main.yml").read_text(encoding="utf-8")
    raft = (repo_root / "roles/openbao_status/tasks/observe_raft.yml").read_text(encoding="utf-8")
    playbook = (repo_root / "playbooks/maintenance/openbao-status.yml").read_text(encoding="utf-8")
    assert "mode is match('^0?[46]00$')" in main
    assert "validate_certs: true" in main
    assert "follow_redirects: none" in main
    assert "X-Vault-Token:" in raft
    assert "no_log: true" in raft
    assert "follow_redirects: none" in raft
    assert "run_once: true" in playbook


def test_openbao_status_role_contains_no_explicit_mutating_modules(repo_root: Path) -> None:
    task_root = repo_root / "roles/openbao_status/tasks"
    for path in sorted((*task_root.rglob("*.yml"), *task_root.rglob("*.yaml"))):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        _assert_no_mutating_actions(data)


def test_openbao_status_mutation_scanner_rejects_nested_shell() -> None:
    with pytest.raises(AssertionError):
        _assert_no_mutating_actions(
            [{"block": [{"ansible.builtin.shell": "touch /tmp/unsafe"}]}]
        )


def test_healthy_openbao_status_fixture_succeeds(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner, repo_root / "tests/fixtures/openbao-status/validate.yml"
    ).assert_success()


def test_fresh_zero_index_openbao_status_fixture_succeeds(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/openbao-status/validate.yml",
        extra_vars=({"openbao_status_test_mode": "zero-index"},),
    ).assert_success()


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("sealed", "all initialized, unsealed"),
        ("split-cluster", "all initialized, unsealed"),
        ("empty-cluster-id", "all initialized, unsealed"),
        ("numeric-health", "all initialized, unsealed"),
        ("nonvoter", "three expected unique voters"),
        ("leader-mismatch", "three expected unique voters"),
        ("malformed-index", "three expected unique voters"),
        ("numeric-raft", "three expected unique voters"),
        ("swapped-address", "three expected unique voters"),
        ("unstable", "changed between strict status observations"),
    ],
)
def test_invalid_openbao_status_fixture_is_rejected(
    mode: str, message: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/openbao-status/validate.yml",
        extra_vars=({"openbao_status_test_mode": mode},),
    )
    assert_failed_with(result, message)
