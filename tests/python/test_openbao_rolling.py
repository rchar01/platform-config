from __future__ import annotations

import os
import re
from pathlib import Path

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [str(repo_root / "tests/fixtures/openbao-rolling/roles"), str(repo_root / "roles")]
        )
    }


def test_openbao_rolling_source_contract(repo_root: Path) -> None:
    playbook = (repo_root / "playbooks/maintenance/openbao-rolling-restart.yml").read_text(encoding="utf-8")
    role = (repo_root / "roles/openbao/tasks/main.yml").read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    for pattern in (
        r"openbao_rolling_restart_confirm",
        r"not ansible_check_mode",
        r"ansible_play_hosts_all.*groups[.]get",
        r"^  order: inventory$",
        r"^  serial: 1$",
        r"openbao_rolling_expected_state: standby",
        r"openbao_rolling_expected_state: active",
        r"leadership changed after the rolling order",
        r"ansible[.]builtin[.]pause:",
        r"when: openbao_restart_required \| bool",
    ):
        assert re.search(pattern, playbook, re.MULTILINE), pattern
    assert not re.search(r"^  strategy: free$", playbook, re.MULTILINE)
    assert "openbao_restart_required:" in role
    assert "openbao_service_state == 'started'" in role
    assert re.search(r"^roll-openbao:", makefile, re.MULTILINE)
    assert "openbao-rolling-restart" not in site
    assert playbook.count("name: openbao_status") >= 3


def test_openbao_rolling_playbook_syntax(repo_root: Path, command_runner: CommandRunner) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-rolling-restart.yml",
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()


def test_openbao_rolling_rejects_missing_confirmation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-rolling-restart.yml",
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        limit="openbao-example-01",
    )
    assert_failed_with(result, "requires explicit confirmation")


def _run_mocked(
    repo_root: Path,
    command_runner: CommandRunner,
    order: Path,
    extra_vars: dict[str, object] | None = None,
    limit: str | None = None,
):
    variables: dict[str, object] = {
        "openbao_rolling_restart_confirm": True,
        "openbao_test_order_path": str(order),
    }
    variables.update(extra_vars or {})
    return run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-rolling-restart.yml",
        inventory=repo_root / "tests/fixtures/openbao-rolling/inventory.yml",
        extra_vars=(variables,),
        limit=limit,
        environment=_roles_environment(repo_root),
    )


def test_openbao_rolling_runs_standbys_before_active(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    _run_mocked(repo_root, command_runner, order).assert_success()
    assert order.read_text(encoding="utf-8").splitlines() == [
        "bao-test-2",
        "bao-test-3",
        "bao-test-1",
    ]


def test_openbao_rolling_rejects_disabled_voter_before_convergence(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root, command_runner, order, {"openbao_test_disabled_host": "bao-test-3"}
    )
    assert_failed_with(result, "enabled and started service contract on this node")
    assert not order.exists()


def test_openbao_rolling_rejects_confirmed_partial_limit(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(repo_root, command_runner, order, limit="bao-test-2")
    assert_failed_with(result, "all three OpenBao inventory hosts")
    assert not order.exists()


def test_openbao_rolling_stops_after_leadership_drift(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {"openbao_test_drift_after": "bao-test-2", "openbao_test_drift_to": "bao-test-2"},
    )
    assert_failed_with(result, "leadership changed after the rolling order")
    assert order.read_text(encoding="utf-8").splitlines() == ["bao-test-2"]
