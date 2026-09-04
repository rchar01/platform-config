from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


_TRANSACTION_ARTIFACTS = {
    "active-marker.json": "mock active marker",
    "openbao.container": "mock Quadlet",
    "openbao.hcl": "mock base config",
    "listener.hcl": "mock active listener",
    "audit.hcl": "mock audit config",
    "ca.crt": "mock CA certificate",
    "fullchain.crt": "mock leaf certificate",
    "tls.key": "mock TLS private key",
}


def _roles_environment(repo_root: Path) -> dict[str, str]:
    return {
        "ANSIBLE_ROLES_PATH": os.pathsep.join(
            [str(repo_root / "tests/fixtures/openbao-rolling/roles"), str(repo_root / "roles")]
        )
    }


def test_openbao_rolling_source_contract(repo_root: Path) -> None:
    playbook = (repo_root / "playbooks/maintenance/openbao-rolling-restart.yml").read_text(encoding="utf-8")
    role = (repo_root / "roles/openbao/tasks/main.yml").read_text(encoding="utf-8")
    defaults = (repo_root / "roles/openbao/defaults/main.yml").read_text(encoding="utf-8")
    unseal = (repo_root / "roles/openbao/tasks/rolling_unseal_wait.yml").read_text(encoding="utf-8")
    transaction = (repo_root / "roles/openbao/tasks/rolling_transaction_create.yml").read_text(encoding="utf-8")
    transaction_remove = (
        repo_root / "roles/openbao/tasks/rolling_transaction_remove.yml"
    ).read_text(encoding="utf-8")
    mocked_unseal = (
        repo_root / "tests/fixtures/openbao-rolling/roles/openbao/tasks/rolling_unseal_wait.yml"
    ).read_text(encoding="utf-8")
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
        r"tasks_from: rolling_transaction_create[.]yml",
        r"tasks_from: rolling_unseal_wait[.]yml",
        r"tasks_from: refresh_active_marker[.]yml",
        r"tasks_from: rolling_transaction_remove[.]yml",
    ):
        assert re.search(pattern, playbook, re.MULTILINE), pattern
    assert "ansible.builtin.pause" not in playbook
    assert "ansible.builtin.pause" not in unseal
    assert not re.search(r"^  strategy: free$", playbook, re.MULTILINE)
    assert "openbao_restart_required:" in role
    assert "openbao_service_state == 'started'" in role
    assert re.search(r"^roll-openbao:", makefile, re.MULTILINE)
    assert "openbao-rolling-restart" not in site
    assert playbook.count("name: openbao_status") >= 3
    for line in (
        "openbao_rolling_force_restart: false",
        "openbao_rolling_unseal_retries: 60",
        "openbao_rolling_unseal_delay: 20",
        "openbao_rolling_unseal_request_timeout: 5",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)
    for fragment in (
        "ansible.builtin.uri:",
        "https://{{ openbao_node_dns }}:{{ openbao_backend_port }}/v1/sys/health",
        "validate_certs: true",
        "follow_redirects: none",
        'retries: "{{ openbao_rolling_unseal_retries }}"',
        'delay: "{{ openbao_rolling_unseal_delay }}"',
        "get('initialized') == true",
        "get('sealed') == false",
    ):
        assert fragment in unseal
    assert "--mode=0700" in transaction
    assert "active-marker.json" in transaction
    assert "tls.key" in transaction
    assert "no_log: true" in transaction
    assert "openbao_rolling_force_restart in ['true', 'false']" in playbook
    fixed_transaction_path = "/var/lib/platform-config/openbao-rolling-transaction"
    assert f"openbao_rolling_transaction_dir: {fixed_transaction_path}" in defaults
    assert "{{ openbao_state_dir }}/openbao-rolling-transaction" not in defaults
    assert f"== '{fixed_transaction_path}'" in playbook
    assert f"== '{fixed_transaction_path}'" in transaction
    assert f"== '{fixed_transaction_path}'" in transaction_remove
    for status in (200, 429, 472, 473, 501, 503):
        assert f"- {status}" in unseal
    for bound in (
        "openbao_rolling_unseal_retries <= 120",
        "openbao_rolling_unseal_delay >= 5",
        "openbao_rolling_unseal_delay <= 60",
        "openbao_rolling_unseal_request_timeout <= 10",
    ):
        assert bound in playbook
    assert "(openbao_rolling_unseal_retries + 1)" in playbook
    assert re.search(
        r"3\s+[*]\s+[(].*"
        r"[(]openbao_rolling_unseal_retries [+] 1[)]\s+"
        r"[*] openbao_rolling_unseal_request_timeout.*"
        r"openbao_rolling_unseal_retries\s+"
        r"[*] openbao_rolling_unseal_delay.*[)]\s+<= 6600",
        playbook,
        re.DOTALL,
    )
    assert "retries: 2" in mocked_unseal
    assert "delay: 0" in mocked_unseal


def test_openbao_rolling_playbook_syntax(repo_root: Path, command_runner: CommandRunner) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-rolling-restart.yml",
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()


def test_openbao_active_check_playbook_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-active-check.yml",
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
    extra_var_strings: tuple[str, ...] = (),
):
    variables: dict[str, object] = {
        "openbao_rolling_restart_confirm": True,
        "openbao_test_order_path": str(order),
        "openbao_test_state_root": str(order.parent / "state"),
        "openbao_test_restart_path": str(order.parent / "restarts"),
        "openbao_test_unseal_path": str(order.parent / "unseal-waits"),
        "openbao_test_unseal_attempt_dir": str(order.parent / "unseal-attempts"),
    }
    variables.update(extra_vars or {})
    return run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-rolling-restart.yml",
        inventory=repo_root / "tests/fixtures/openbao-rolling/inventory.yml",
        extra_vars=(variables, *extra_var_strings),
        limit=limit,
        environment=_roles_environment(repo_root),
    )


def _assert_transaction_artifacts(transaction: Path, host: str) -> None:
    assert stat.S_IMODE(transaction.stat().st_mode) == 0o700
    assert {path.name for path in transaction.iterdir()} == set(_TRANSACTION_ARTIFACTS)
    for name, content in _TRANSACTION_ARTIFACTS.items():
        artifact = transaction / name
        assert artifact.read_text(encoding="utf-8") == f"{content} for {host}\n"
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


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
    for host in ("bao-test-1", "bao-test-2", "bao-test-3"):
        assert not (
            isolated_test_dir / f"state/{host}/openbao-rolling-transaction"
        ).exists()


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


def test_openbao_rolling_accepts_exact_unseal_duration_boundary(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    _run_mocked(
        repo_root,
        command_runner,
        order,
        {
            "openbao_rolling_unseal_retries": 73,
            "openbao_rolling_unseal_delay": 20,
            "openbao_rolling_unseal_request_timeout": 10,
        },
    ).assert_success()
    assert order.read_text(encoding="utf-8").splitlines() == [
        "bao-test-2",
        "bao-test-3",
        "bao-test-1",
    ]


def test_openbao_rolling_rejects_duration_old_formula_would_accept(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {
            "openbao_rolling_unseal_retries": 110,
            "openbao_rolling_unseal_delay": 10,
            "openbao_rolling_unseal_request_timeout": 10,
        },
    )
    assert_failed_with(result, "polling bounded to at most 110 minutes")
    assert not order.exists()
    assert not (isolated_test_dir / "state").exists()


@pytest.mark.parametrize(
    "transaction_path",
    [
        "/var/lib/platform-config/../openbao-rolling-transaction",
        "/tmp/openbao-rolling-transaction",
        "//var/lib/platform-config/openbao-rolling-transaction",
        "/var/lib/platform-config/openbao-rolling-transaction/..",
    ],
)
def test_openbao_rolling_rejects_noncanonical_transaction_path_before_mutation(
    transaction_path: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {"openbao_rolling_transaction_dir": transaction_path},
    )
    assert_failed_with(result, "fixed host-local transaction path")
    assert not order.exists()
    assert not (isolated_test_dir / "state").exists()


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


def test_openbao_rolling_forces_each_unchanged_voter_exactly_once(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    _run_mocked(
        repo_root,
        command_runner,
        order,
        extra_var_strings=("openbao_rolling_force_restart=true",),
    ).assert_success()
    expected = ["bao-test-2", "bao-test-3", "bao-test-1"]
    assert (isolated_test_dir / "restarts").read_text(encoding="utf-8").splitlines() == expected
    assert (isolated_test_dir / "unseal-waits").read_text(encoding="utf-8").splitlines() == expected
    for host in expected:
        assert (isolated_test_dir / f"unseal-attempts/{host}").read_text(
            encoding="utf-8"
        ) == "1\n"


def test_openbao_rolling_mocked_unseal_retries_until_success(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    _run_mocked(
        repo_root,
        command_runner,
        order,
        {
            "openbao_test_convergence_changed_hosts": ["bao-test-2"],
            "openbao_test_unseal_sealed_attempts": {"bao-test-2": 2},
        },
    ).assert_success()
    assert (isolated_test_dir / "unseal-attempts/bao-test-2").read_text(
        encoding="utf-8"
    ) == "3\n"
    assert (isolated_test_dir / "unseal-waits").read_text(
        encoding="utf-8"
    ).splitlines() == ["bao-test-2"]


def test_openbao_rolling_mocked_unseal_exhaustion_retains_and_stops(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {
            "openbao_test_convergence_changed_hosts": ["bao-test-2"],
            "openbao_test_unseal_sealed_attempts": {"bao-test-2": 99},
        },
    )
    assert_failed_with(result, "Mocked OpenBao voter remains sealed")
    assert (isolated_test_dir / "unseal-attempts/bao-test-2").read_text(
        encoding="utf-8"
    ) == "3\n"
    assert order.read_text(encoding="utf-8").splitlines() == ["bao-test-2"]
    _assert_transaction_artifacts(
        isolated_test_dir / "state/bao-test-2/openbao-rolling-transaction",
        "bao-test-2",
    )
    assert not (
        isolated_test_dir / "state/bao-test-3/openbao-rolling-transaction"
    ).exists()


def test_openbao_rolling_does_not_double_restart_changed_voters(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    _run_mocked(
        repo_root,
        command_runner,
        order,
        {
            "openbao_rolling_force_restart": True,
            "openbao_test_convergence_changed_hosts": [
                "bao-test-1",
                "bao-test-2",
                "bao-test-3",
            ],
        },
    ).assert_success()
    restarts = (isolated_test_dir / "restarts").read_text(encoding="utf-8").splitlines()
    assert restarts == ["bao-test-2", "bao-test-3", "bao-test-1"]
    assert all(restarts.count(host) == 1 for host in restarts)


def test_openbao_rolling_rejects_and_retains_pending_transaction(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    pending = isolated_test_dir / "state/bao-test-3/openbao-rolling-transaction"
    pending.mkdir(parents=True)

    result = _run_mocked(repo_root, command_runner, order)

    assert_failed_with(result, "found a pending transaction")
    assert pending.is_dir()
    assert not order.exists()


def test_openbao_rolling_snapshot_creation_failure_retains_partial_transaction(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {"openbao_test_snapshot_failure_host": "bao-test-2"},
    )
    assert_failed_with(result, "Mocked OpenBao transaction snapshot creation failed")
    transaction = isolated_test_dir / "state/bao-test-2/openbao-rolling-transaction"
    assert stat.S_IMODE(transaction.stat().st_mode) == 0o700
    assert {path.name for path in transaction.iterdir()} == {"active-marker.json"}
    marker = transaction / "active-marker.json"
    assert marker.read_text(encoding="utf-8") == "mock active marker for bao-test-2\n"
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert not order.exists()
    assert not (
        isolated_test_dir / "state/bao-test-3/openbao-rolling-transaction"
    ).exists()


def test_openbao_rolling_retains_transaction_after_recovery_failure(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {"openbao_test_refresh_failure_host": "bao-test-3"},
    )

    assert_failed_with(result, "Mocked OpenBao marker refresh failed")
    assert not (
        isolated_test_dir / "state/bao-test-2/openbao-rolling-transaction"
    ).exists()
    assert (isolated_test_dir / "state/bao-test-3/openbao-rolling-transaction").is_dir()
    _assert_transaction_artifacts(
        isolated_test_dir / "state/bao-test-3/openbao-rolling-transaction",
        "bao-test-3",
    )
    assert order.read_text(encoding="utf-8").splitlines() == [
        "bao-test-2",
        "bao-test-3",
    ]


@pytest.mark.parametrize(
    ("variable", "message"),
    [
        ("openbao_test_image_mismatch_host", "rejects an image transition"),
        ("openbao_test_ca_mismatch_host", "rejects a controller CA transition"),
    ],
)
def test_openbao_rolling_rejects_image_or_ca_transition_before_mutation(
    variable: str,
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    order = isolated_test_dir / "order"
    result = _run_mocked(
        repo_root,
        command_runner,
        order,
        {variable: "bao-test-3"},
    )

    assert_failed_with(result, message)
    assert not order.exists()
    assert not (isolated_test_dir / "state").exists()


def test_openbao_marker_refresh_follows_strict_recovery_and_precedes_cleanup(
    repo_root: Path,
) -> None:
    playbook = (repo_root / "playbooks/maintenance/openbao-rolling-restart.yml").read_text(
        encoding="utf-8"
    )
    refresh = (repo_root / "roles/openbao/tasks/refresh_active_marker.yml").read_text(
        encoding="utf-8"
    )
    recovery = playbook.index("Require strict voter recovery before advancing")
    marker_refresh = playbook.index("Refresh marker from verified current OpenBao artifacts")
    lifecycle_recheck = playbook.index("Recheck exact active OpenBao lifecycle after recovery")
    cleanup = playbook.index("Remove successful host-local OpenBao rolling transaction")
    final_status = playbook.index("Confirm strict OpenBao state after rolling maintenance")
    assert recovery < marker_refresh < lifecycle_recheck < cleanup
    assert cleanup < final_status
    assert playbook.count("tasks_from: rolling_transaction_remove.yml") == 1
    assert "openbao_active_marker.cluster_signature" in refresh
    assert "openbao_active_marker.cluster_id" in refresh
    assert "openbao_active_marker.node_id" in refresh
    assert "ansible.builtin.copy:" in refresh
    assert "when: >-" in refresh
    assert "openbao_active_marker.config_checksum" in refresh
    assert "force: true" not in refresh
    role_readme = (repo_root / "roles/openbao/README.md").read_text(encoding="utf-8")
    maintenance_readme = (
        repo_root / "playbooks/maintenance/README.md"
    ).read_text(encoding="utf-8")
    assert "stops before the next voter" in role_readme
    assert "does not\nrecreate prior snapshots" in role_readme
    assert "avoids retaining root-only copies of\nTLS key material" in role_readme
    assert "real systemd restart semantics remain a live" in role_readme
    assert "later failures do not recreate prior voter\n  snapshots" in maintenance_readme


def test_openbao_marker_refresh_uses_only_active_lifecycle_facts(repo_root: Path) -> None:
    refresh = (repo_root / "roles/openbao/tasks/refresh_active_marker.yml").read_text(
        encoding="utf-8"
    )
    assert "openbao_tls_custody" not in refresh
    assert "lookup('ansible.builtin.template', 'listener.hcl.j2')" in refresh
    assert "openbao_active_marker.certificate_checksum" in refresh
    assert "openbao_active_marker.key_checksum" in refresh
    assert "openbao_active_request_ids | first" in refresh
    assert "'/openbao/config/tls/tls.crt'" in refresh
    assert "'/openbao/config/tls/tls.key'" in refresh
    assert "~ '/fullchain.crt'" in refresh
    assert "~ '/tls.key'" in refresh


def test_openbao_active_preflight_drift_override_is_narrow(repo_root: Path) -> None:
    variable = "openbao_active_preflight_allow_desired_config_drift"
    defaults = (repo_root / "roles/openbao/defaults/main.yml").read_text(encoding="utf-8")
    preflight = (repo_root / "roles/openbao/tasks/active_preflight.yml").read_text(
        encoding="utf-8"
    )
    rolling = (repo_root / "playbooks/maintenance/openbao-rolling-restart.yml").read_text(
        encoding="utf-8"
    )
    active_check = (repo_root / "playbooks/maintenance/openbao-active-check.yml").read_text(
        encoding="utf-8"
    )
    status = (repo_root / "playbooks/maintenance/openbao-status.yml").read_text(
        encoding="utf-8"
    )
    assert f"{variable}: false" in defaults
    assert f"{variable} is boolean" in preflight
    assert f"{variable}\n        or openbao_active_audit_config_stat.stat.checksum" in preflight
    assert "openbao_active_marker.audit_config_checksum" in preflight
    assert "== openbao_active_audit_config_stat.stat.checksum" in preflight
    assert rolling.count(f"{variable}: true") == 3
    assert active_check.count(f"{variable}: true") == 2
    rolling_convergence = rolling[
        rolling.index("Converge this OpenBao voter") : rolling.index(
            "Apply any explicit unchanged-voter restart"
        )
    ]
    final_validation = rolling[
        rolling.index("Recheck exact active OpenBao lifecycle after recovery") : rolling.index(
            "Remove successful host-local OpenBao rolling transaction"
        )
    ]
    active_check_convergence = active_check[
        active_check.index("Check OpenBao role convergence") :
    ]
    assert f"{variable}: true" in rolling_convergence
    assert f"{variable}: true" in active_check_convergence
    assert variable not in final_validation
    assert variable not in status


def test_openbao_active_maintenance_mode_and_fresh_voter_preflight(
    repo_root: Path,
) -> None:
    mode = "openbao_lifecycle_preflight_mode: active-maintenance"
    rolling = (repo_root / "playbooks/maintenance/openbao-rolling-restart.yml").read_text(
        encoding="utf-8"
    )
    active_check = (repo_root / "playbooks/maintenance/openbao-active-check.yml").read_text(
        encoding="utf-8"
    )
    assert rolling.count(mode) == 1
    assert active_check.count(mode) == 1
    rolling_convergence = rolling[
        rolling.index("Converge this OpenBao voter") : rolling.index(
            "Apply any explicit unchanged-voter restart"
        )
    ]
    active_check_convergence = active_check[
        active_check.index("Check OpenBao role convergence") :
    ]
    assert mode in rolling_convergence
    assert mode in active_check_convergence
    leadership = rolling.index("Stop if OpenBao leadership changed across the planned order")
    fresh_preflight = rolling.index(
        "Refresh active OpenBao lifecycle proof before voter mutation"
    )
    transaction = rolling.index("Create host-local OpenBao rolling transaction")
    assert leadership < fresh_preflight < transaction
    fresh_preflight_block = rolling[fresh_preflight:transaction]
    assert "tasks_from: active_preflight.yml" in fresh_preflight_block
    assert "openbao_active_preflight_allow_desired_config_drift: true" in (
        fresh_preflight_block
    )
    final_validation = rolling[
        rolling.index("Recheck exact active OpenBao lifecycle after recovery") : rolling.index(
            "Remove successful host-local OpenBao rolling transaction"
        )
    ]
    assert "openbao_lifecycle_preflight_mode" not in final_validation


def test_openbao_active_check_source_contract(repo_root: Path) -> None:
    active_check = (repo_root / "playbooks/maintenance/openbao-active-check.yml").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "ansible_limit is defined",
        "inventory_hostnames",
        "ansible_check_mode",
        "ansible_play_hosts_all",
        "tasks_from: active_preflight.yml",
        "name: openbao_status",
        "Check OpenBao role convergence",
    ):
        assert fragment in active_check
    assert "openbao-rolling-restart.yml" not in active_check
    assert "rolling_transaction" not in active_check


def test_openbao_active_check_runs_mocked_role_in_check_mode(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    variables = {
        "ansible_become": False,
        "openbao_test_desired_audit_drift_host": "bao-test-2",
        "openbao_test_order_path": str(isolated_test_dir / "order"),
        "openbao_test_restart_path": str(isolated_test_dir / "restarts"),
        "openbao_test_state_root": str(isolated_test_dir / "state"),
    }
    result = command_runner.run(
        [
            "ansible-playbook",
            "-i",
            repo_root / "tests/fixtures/openbao-rolling/inventory.yml",
            repo_root / "playbooks/maintenance/openbao-active-check.yml",
            "--limit",
            "openbao",
            "--check",
            "--extra-vars",
            json.dumps(variables, separators=(",", ":"), sort_keys=True),
        ],
        environment=_roles_environment(repo_root),
    )
    result.assert_success()
    assert not (isolated_test_dir / "order").exists()
    assert not (isolated_test_dir / "restarts").exists()


def test_openbao_rolling_allows_marker_authenticated_desired_audit_drift(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    order = isolated_test_dir / "order"
    _run_mocked(
        repo_root,
        command_runner,
        order,
        {"openbao_test_desired_audit_drift_host": "bao-test-2"},
    ).assert_success()
    assert order.read_text(encoding="utf-8").splitlines() == [
        "bao-test-2",
        "bao-test-3",
        "bao-test-1",
    ]


def test_openbao_status_rejects_desired_audit_drift(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "playbooks/maintenance/openbao-status.yml",
        inventory=repo_root / "tests/fixtures/openbao-rolling/inventory.yml",
        extra_vars=(
            {
                "ansible_become": False,
                "openbao_test_desired_audit_drift_host": "bao-test-2",
                "openbao_test_state_root": str(isolated_test_dir / "state"),
            },
        ),
        limit="openbao",
        environment=_roles_environment(repo_root),
    )
    assert_failed_with(
        result,
        "Active OpenBao lifecycle requires its exact desired audit configuration",
    )
