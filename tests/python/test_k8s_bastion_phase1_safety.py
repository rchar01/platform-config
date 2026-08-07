from __future__ import annotations

import re
from pathlib import Path

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@pytest.fixture(scope="module")
def phase1_sources(repo_root: Path) -> dict[str, str]:
    role = repo_root / "roles/k8s_bastion_access"
    paths = {
        "defaults": role / "defaults/main.yml",
        "preflight": role / "tasks/preflight.yml",
        "validate": role / "tasks/validate_bootstrap.yml",
        "host_config": role / "tasks/host_config.yml",
        "users": role / "tasks/users.yml",
        "select_users": role / "tasks/select_bootstrap_users.yml",
        "login": role / "templates/bastion-login.sh.j2",
        "systemd": role / "tasks/systemd.yml",
        "runtime": role / "tasks/runtime.yml",
        "bootstrapd": role / "templates/bastion-bootstrapd.service.j2",
        "example": repo_root
        / "inventories/dev/group_vars/k8s_bastion_user_access.yml.example",
        "docs": repo_root / "docs/k8s-bastion.md",
    }
    return {name: path.read_text(encoding="utf-8") for name, path in paths.items()}


def test_bootstrapd_write_allowlist_is_narrow(phase1_sources: dict[str, str]) -> None:
    unit = phase1_sources["bootstrapd"]
    assert re.search(r"^ProtectSystem=strict$", unit, re.MULTILINE)
    assert re.search(r"^ProtectHome=false$", unit, re.MULTILINE)
    assert re.search(
        r"^ReadWritePaths=/run/bastion-bootstrapd /home "
        r"/var/lib/bastion/bootstrap-tokens$",
        unit,
        re.MULTILINE,
    )
    assert not re.search(r"^ReadWritePaths=.* /var/lib/bastion($| )", unit, re.MULTILINE)
    assert "/var/lib/bastion/bootstrap-tokens" in phase1_sources["host_config"]
    assert 'mode: "0700"' in phase1_sources["host_config"]


def test_bootstrap_modes_are_safe_by_default(phase1_sources: dict[str, str]) -> None:
    defaults = phase1_sources["defaults"]
    validation = phase1_sources["validate"]
    assert re.search(
        r"^k8s_bastion_initial_user_bootstrap_mode: disabled$", defaults, re.MULTILINE
    )
    assert re.search(
        r"^k8s_bastion_enable_automatic_user_bootstrap: false$",
        defaults,
        re.MULTILINE,
    )
    assert "validate_bootstrap.yml" in phase1_sources["preflight"]
    assert "['disabled', 'online', 'offline']" in validation
    assert "k8s_bastion_enable_bootstrapd is not defined" in validation
    assert validation.count("k8s_bastion_enable_automatic_user_bootstrap | bool") >= 2
    assert "k8s_bastion_initial_user_bootstrap_mode == 'disabled'" in validation
    assert "Block automatic login bootstrap pending runtime admin exclusion" in validation
    assert "k8s_bastion_enable_automatic_user_bootstrap | bool" in phase1_sources["login"]
    assert "k8s_bastion_enable_automatic_user_bootstrap | bool" in phase1_sources["systemd"]


@pytest.mark.parametrize("mode", ["disabled", "online", "offline"])
@pytest.mark.parametrize("value", ["false", "no", "off", "0"])
def test_false_automatic_bootstrap_values_are_accepted(
    mode: str, value: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/k8s-bastion-phase1/validate-bootstrap.yml",
        extra_vars=(
            {
                "phase1_initial_mode": mode,
                "phase1_automatic_bootstrap": value,
            },
        ),
    ).assert_success()


def test_default_initial_mode_with_native_false_is_accepted(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/k8s-bastion-phase1/validate-bootstrap.yml",
        extra_vars=({"phase1_automatic_bootstrap": False},),
    ).assert_success()


@pytest.mark.parametrize("value", ["invalid", "maybe", "2", ""])
def test_invalid_automatic_bootstrap_strings_are_rejected(
    value: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/k8s-bastion-phase1/validate-bootstrap.yml",
        extra_vars=({"phase1_automatic_bootstrap": value},),
    )
    assert_failed_with(result, "must be a boolean or a boolean-compatible")


@pytest.mark.parametrize("value", ["true", "yes", "on", "1", True])
def test_truthy_automatic_bootstrap_is_blocked_by_runtime_gate(
    value: str | bool, repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/k8s-bastion-phase1/validate-bootstrap.yml",
        extra_vars=({"phase1_automatic_bootstrap": value},),
    )
    assert_failed_with(result, "login recovery does not exclude policy admins")


def test_quoted_false_render_behavior(repo_root: Path, command_runner: CommandRunner) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/k8s-bastion-phase1/render-behavior.yml",
    ).assert_success()


def test_initial_bootstrap_selects_only_eligible_non_admin_users(
    phase1_sources: dict[str, str], repo_root: Path, command_runner: CommandRunner
) -> None:
    users = phase1_sources["users"]
    selector = phase1_sources["select_users"]
    assert "import_tasks: select_bootstrap_users.yml" in users
    assert "k8s_bastion_admin_group not in" in selector
    assert "lookup('template', 'select-bootstrap-users.sh.j2')" in selector
    assert "--user {{ item }}" in users
    assert "--all" not in users
    assert "k8s_bastion_initial_user_bootstrap_mode == 'offline'" in users
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/k8s-bastion-phase1/select-users.yml",
    ).assert_success()


def test_future_phase_interfaces_are_inert_and_sanitized(
    phase1_sources: dict[str, str]
) -> None:
    variables = (
        "k8s_bastion_enable_issuer_convergence",
        "k8s_bastion_enable_controller_staging",
        "k8s_bastion_enable_controller_convergence",
        "k8s_bastion_enable_controller_cutover",
        "k8s_bastion_enable_automatic_user_bootstrap",
    )
    for variable in variables:
        pattern = rf"^{variable}: false$"
        assert re.search(pattern, phase1_sources["defaults"], re.MULTILINE)
        assert re.search(pattern, phase1_sources["example"], re.MULTILINE)
    example = phase1_sources["example"]
    assert ".invalid" in example
    assert "192.0.2.10/32" in example
    assert re.search(r"^k8s_bastion_controller_policy_config_map:$", example, re.MULTILINE)
    assert re.search(r"^k8s_bastion_controller_signing_secret:$", example, re.MULTILINE)
    assert not re.search(
        r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|client-certificate-data:|"
        r"token: [A-Za-z0-9]",
        example,
    )


def test_public_rbac_and_runtime_ownership_boundaries(
    phase1_sources: dict[str, str]
) -> None:
    docs = phase1_sources["docs"]
    defaults = phase1_sources["defaults"]
    runtime = phase1_sources["runtime"]
    assert re.search(r"Issuer.*Secret verbs.*exactly `create` and `delete`", docs)
    assert re.search(r"approver.*Secret `get`", docs)
    assert "vendor/platform-k8s-bastion/runtime" in defaults
    assert re.search(r"src:.*k8s_bastion_runtime_src", runtime)
    assert "src: files/" not in runtime


def test_bootstrap_source_checks_are_mutation_sensitive(
    phase1_sources: dict[str, str]
) -> None:
    widened = phase1_sources["bootstrapd"].replace(
        " /var/lib/bastion/bootstrap-tokens", " /var/lib/bastion", 1
    )
    assert re.search(r"^ReadWritePaths=.* /var/lib/bastion($| )", widened, re.MULTILINE)
