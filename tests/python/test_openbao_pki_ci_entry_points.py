from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


PLAYBOOKS = ("openbao-pki-request.yml", "openbao-pki-activate.yml")


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def make_target(makefile: str, name: str) -> tuple[list[str], str]:
    match = re.search(
        rf"^{re.escape(name)}:([^\n]*)\n((?:\t[^\n]*\n?)*)",
        makefile,
        re.MULTILINE,
    )
    assert match is not None
    return match.group(1).split(), match.group(2).strip()


def task_named(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(task for task in tasks if task.get("name") == name)


def nested_action(
    tasks: list[dict[str, Any]], container_name: str, action_name: str
) -> dict[str, Any]:
    return task_named(task_named(tasks, container_name)["block"], action_name)


def test_make_exposes_two_coordinate_free_openbao_pki_routes(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    declarations = set(
        re.findall(r"^(openbao-pki-[A-Za-z0-9_.-]+):", makefile, re.MULTILINE)
    )

    assert declarations == {
        "openbao-pki-request-publish",
        "openbao-pki-response-activate",
    }
    request_prerequisites, request_recipe = make_target(
        makefile, "openbao-pki-request-publish"
    )
    assert request_prerequisites == [
        "_guard-pki-env",
        "_guard-pki-limit",
        "_guard-pki-request-ttl",
    ]
    assert "PLAYBOOK=playbooks/openbao-pki-request.yml" in request_recipe
    assert "openbao_pki_request_ttl_seconds=$(REQUEST_TTL_SECONDS)" in request_recipe
    assert "$(EXTRA_ARGS)" not in request_recipe

    activation_prerequisites, activation_recipe = make_target(
        makefile, "openbao-pki-response-activate"
    )
    assert activation_prerequisites == ["_guard-pki-env", "_guard-pki-limit"]
    assert "PLAYBOOK=playbooks/openbao-pki-activate.yml" in activation_recipe
    assert "$(EXTRA_ARGS)" not in activation_recipe
    assert activation_recipe.endswith("EXTRA_ARGS=")

    guard = make_target(makefile, "_guard-pki-limit")[1]
    assert "canonical lowercase inventory host" in guard
    assert "registry inventory host" not in guard


@pytest.mark.parametrize(("playbook_name", "tasks_from"), (
    ("openbao-pki-request.yml", "request_publish"),
    ("openbao-pki-activate.yml", "response_activate"),
))
def test_playbooks_require_one_literal_openbao_host_and_fixed_role_route(
    repo_root: Path, playbook_name: str, tasks_from: str
) -> None:
    plays = load_yaml(repo_root / "playbooks" / playbook_name)

    assert len(plays) == 2
    admission, action = plays
    assert admission["hosts"] == "all"
    assert admission["gather_facts"] is False
    assert admission["any_errors_fatal"] is True
    gate = task_named(
        admission["tasks"], "Require an explicit one-host OpenBao limit"
    )
    checks = gate["ansible.builtin.assert"]["that"]
    assert "ansible_limit is defined" in checks
    assert "openbao_pki_selected_hosts == [ansible_limit | default('')]" in checks
    assert any("difference(groups.get('openbao', []))" in check for check in checks)
    assert "inventory_hostnames" in gate["vars"]["openbao_pki_selected_hosts"]
    assert gate["run_once"] is True

    assert action["hosts"] == "openbao"
    assert action["become"] is True
    assert action["gather_facts"] is False
    selection = action["tasks"][0]["ansible.builtin.assert"]["that"]
    assert "ansible_play_hosts_all == [inventory_hostname]" in selection
    assert "inventory_hostname in groups.get('openbao', [])" in selection

    dumped = yaml.safe_dump(action["tasks"])
    expected_include_count = 1 if tasks_from == "request_publish" else 2
    assert dumped.count("ansible.builtin.include_role:") == expected_include_count
    assert "name: pki_host_local_certificate" in dumped
    assert f"tasks_from: {tasks_from}" in dumped
    if tasks_from == "response_activate":
        assert "tasks_from: response_preflight" in dumped


def test_request_ttl_is_the_only_operator_value_forwarded(repo_root: Path) -> None:
    plays = load_yaml(repo_root / "playbooks/openbao-pki-request.yml")
    action = plays[1]

    assert action["vars"] == {
        "openbao_pki_request_ttl_seconds": 3600,
        "pki_host_local_certificate_request_ttl_seconds": (
            "{{ openbao_pki_request_ttl_seconds | int }}"
        ),
        "pki_host_local_certificate_rollback_seconds": 0,
    }
    assert action["tasks"][-1]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_certificate",
        "tasks_from": "request_publish",
    }


def test_request_route_prepares_only_the_fixed_openbao_parent(repo_root: Path) -> None:
    tasks = load_yaml(
        repo_root
        / "roles/pki_host_local_certificate/tasks/request_publish.yml"
    )
    prepare = task_named(tasks, "Prepare fixed OpenBao PKI parent directory")

    assert prepare["ansible.builtin.file"] == {
        "path": "/etc/openbao",
        "state": "directory",
        "owner": "root",
        "group": "1000",
        "mode": "0750",
    }
    assert prepare["when"] == (
        "pki_host_local_certificate_service_adapter == 'openbao-pristine-v1'"
    )


def test_activation_has_no_manual_coordinates_or_overrides(repo_root: Path) -> None:
    source = (repo_root / "playbooks/openbao-pki-activate.yml").read_text(
        encoding="utf-8"
    )
    action = load_yaml(repo_root / "playbooks/openbao-pki-activate.yml")[1]

    assert "vars" not in action
    for forbidden in (
        "request_id",
        "artifact_sha256",
        "package_version",
        "response_directory",
        "service_adapter",
        "endpoint",
        "extra_args",
    ):
        assert forbidden not in source.lower()


def test_activation_is_an_inactive_masked_transaction(repo_root: Path) -> None:
    action = load_yaml(repo_root / "playbooks/openbao-pki-activate.yml")[1]
    tasks = action["tasks"]
    assert [task["name"] for task in tasks].index(
        "Authenticate target-local response before service mutation"
    ) < [task["name"] for task in tasks].index(
        "Inspect the staged OpenBao unit before activation"
    )
    initial = task_named(tasks, "Inspect the staged OpenBao unit before activation")
    assert initial["ansible.builtin.systemd_service"] == {"name": "openbao.service"}

    precondition = task_named(tasks, "Require stopped and masked OpenBao staging")
    assert precondition["ansible.builtin.assert"]["that"] == [
        "openbao_pki_activation_initial_unit.status.ActiveState == 'inactive'",
        "openbao_pki_activation_initial_unit.status.UnitFileState == 'masked'",
    ]

    transaction = task_named(
        tasks, "Run the fail-closed OpenBao response activation transaction"
    )
    unmask = nested_action(
        transaction["block"],
        "Temporarily unmask stopped OpenBao for fixed activation",
        "Unmask stopped OpenBao for local certificate validation",
    )
    assert unmask["ansible.builtin.systemd_service"] == {
        "name": "openbao.service",
        "masked": False,
        "state": "stopped",
    }
    activate = nested_action(
        transaction["block"],
        "Run structurally fixed target-local response activation",
        "Activate the authenticated OpenBao response",
    )
    assert activate["ansible.builtin.include_role"] == {
        "name": "pki_host_local_certificate",
        "tasks_from": "response_activate",
    }

    always = transaction["always"]
    stop = nested_action(
        always,
        "Stop OpenBao after local certificate validation",
        "Stop the temporarily unmasked OpenBao unit",
    )
    assert stop["ansible.builtin.systemd_service"] == {
        "name": "openbao.service",
        "state": "stopped",
    }
    mask = nested_action(
        always,
        "Restore the fail-closed OpenBao staging mask",
        "Mask the stopped OpenBao unit",
    )
    assert mask["ansible.builtin.systemd_service"] == {
        "name": "openbao.service",
        "masked": True,
    }
    final = task_named(always, "Require inactive masked OpenBao after activation")
    final_checks = final["ansible.builtin.assert"]["that"]
    assert "openbao_pki_activation_failures | length == 0" in final_checks
    assert any("ActiveState" in check and "inactive" in check for check in final_checks)
    assert any("UnitFileState" in check and "masked" in check for check in final_checks)
    assert "enabled" not in yaml.safe_dump(action)


def test_openbao_pki_playbooks_are_not_imported_by_site(repo_root: Path) -> None:
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    for playbook in PLAYBOOKS:
        assert playbook not in site


@pytest.mark.parametrize("playbook_name", PLAYBOOKS)
def test_openbao_pki_playbook_syntax(
    repo_root: Path, command_runner: CommandRunner, playbook_name: str
) -> None:
    run_playbook(
        command_runner,
        repo_root / "playbooks" / playbook_name,
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        syntax_check=True,
    ).assert_success()


@pytest.mark.parametrize("playbook_name", PLAYBOOKS)
@pytest.mark.parametrize(
    "limit",
    (None, "registry-example", "openbao-example-01,registry-example"),
    ids=("omitted", "unrelated", "openbao-plus-unrelated"),
)
def test_openbao_pki_rejects_noncanonical_or_unrelated_selection(
    repo_root: Path,
    command_runner: CommandRunner,
    playbook_name: str,
    limit: str | None,
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "playbooks" / playbook_name,
        inventory=repo_root / "inventories/dev/hosts.yml.example",
        limit=limit,
    )
    assert_failed_with(result, "exactly one canonical OpenBao inventory host")


def test_openbao_pki_help_distinguishes_node_and_cluster_limits(
    command_runner: CommandRunner,
) -> None:
    result = command_runner.run(["make", "help"]).assert_success()

    assert "openbao-pki-request-publish" in result.stdout
    assert "one-host LIMIT" in result.stdout
    assert "openbao-pki-response-activate" in result.stdout
    assert "restore its staging mask" in result.stdout
    assert "start-openbao-bootstrap" in result.stdout
    assert "full-cluster LIMIT" in result.stdout


@pytest.mark.parametrize("ttl", ("0", "01", "604801", "invalid"))
def test_openbao_request_make_target_rejects_unbounded_ttl(
    command_runner: CommandRunner, ttl: str
) -> None:
    result = command_runner.run(
        [
            "make",
            "openbao-pki-request-publish",
            "ENV=dev",
            "LIMIT=openbao-example-01",
            f"REQUEST_TTL_SECONDS={ttl}",
        ]
    )
    assert_failed_with(
        result,
        "REQUEST_TTL_SECONDS must be a canonical integer from 1 through 604800",
    )


def test_public_openbao_pki_example_is_default_deny(repo_root: Path) -> None:
    variables = load_yaml(
        repo_root / "inventories/dev/group_vars/openbao.yml.example"
    )

    assert variables["pki_host_local_certificate_service_adapter"] == (
        "openbao-pristine-v1"
    )
    assert variables["pki_host_local_certificate_service_unit"] == "openbao.service"
    assert variables["pki_host_local_certificate_endpoint"] == ""
    assert variables["pki_host_local_certificate_reviewed_ca_target_path"] == (
        "/etc/platform-config/openbao-validation-ca.crt"
    )
    assert variables["pki_host_local_certificate_reviewed_ca_target_path"] != (
        "/etc/openbao/tls/ca.crt"
    )
    assert variables["pki_host_local_certificate_trust_paths"] == {}
    assert variables["pki_host_local_certificate_trust_sha256"] == {}
    for name, value in variables.items():
        if name.startswith("pki_host_local_certificate_") and name.endswith("sha256"):
            assert value in ("", {}, "none")
    assert "token" not in yaml.safe_dump(
        {
            key: value
            for key, value in variables.items()
            if key.startswith("pki_host_local_certificate_")
        }
    ).lower()
