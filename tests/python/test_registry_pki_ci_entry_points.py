from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _make_target(makefile: str, name: str) -> str:
    return makefile.split(f"{name}:", 1)[1].split("\n\n", 1)[0]


def _task_names(tasks: list[dict[str, Any]]) -> list[str]:
    return [task["name"] for task in tasks]


def _fixed_cleanup_ci(workflow: str) -> dict[str, Any]:
    section = workflow.split("## Fixed Cleanup\n", 1)[1].split(
        "\n## Expected Status Transitions", 1
    )[0]
    assert section.count("```yaml\n") == 1
    yaml_text = section.split("```yaml\n", 1)[1].split("\n```", 1)[0]
    return yaml.safe_load(yaml_text)


def test_bootstrap_readiness_is_check_mode_exact_and_transport_free(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    target = _make_target(makefile, "registry-pki-bootstrap-readiness")
    tasks = _load(
        repo_root
        / "roles/pki_host_local_certificate/tasks/bootstrap_readiness.yml"
    )
    play = _load(repo_root / "playbooks/registry-pki-bootstrap-readiness.yml")[0]

    assert play["hosts"] == "registry"
    assert play["tasks"][0]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_certificate",
        "tasks_from": "bootstrap_readiness",
    }
    assert "_guard-pki-limit" in target
    assert "_guard-pki-runner" in target
    assert "$(MAKE) check" in target
    assert "PLAYBOOK=playbooks/registry-pki-bootstrap-readiness.yml" in target
    assert target.index("$(EXTRA_ARGS)") < target.index(
        "-e pki_host_local_certificate_remote_validator=$(RUNNER_LIMIT)"
    )
    assert tasks[0]["ansible.builtin.assert"]["that"][0] == "ansible_check_mode"
    topology = tasks[0]["ansible.builtin.assert"]["that"]
    assert "ansible_play_hosts_all == [inventory_hostname]" in topology
    assert "pki_host_local_certificate_remote_validator != inventory_hostname" in topology
    assert "Run existing request helper in non-mutating preflight mode" in _task_names(
        tasks
    )
    assert "Load host-local certificate lifecycle helper preflight" in _task_names(tasks)
    assert "Load reviewed runner validator helper preflight" in _task_names(tasks)
    names = _task_names(tasks)
    assert names.index("Load host-local certificate lifecycle helper preflight") < (
        names.index("Run existing request helper in non-mutating preflight mode")
    )
    assert names.index("Load reviewed runner validator helper preflight") < (
        names.index("Run existing request helper in non-mutating preflight mode")
    )
    text = yaml.safe_dump(tasks)
    for forbidden in (
        "platform_pki_request_collection",
        "platform_pki_response_ingress",
        "platform_pki_evidence_collection",
        "exchange_helper.yml",
        "ansible.builtin.pause",
    ):
        assert forbidden not in text


def test_readiness_authenticates_all_helpers_against_fixed_role_sources(
    repo_root: Path,
) -> None:
    cases = (
        (
            "request_apply.yml",
            "Inspect shipped host-local certificate request helper source",
            "Inspect installed host-local certificate request helper",
            "Require installed helper for non-mutating request preflight",
            "Create or validate the target-local certificate request",
            "platform-pki-host-local-request",
            None,
        ),
        (
            "lifecycle_helper.yml",
            "Inspect shipped host-local certificate lifecycle helper source",
            "Inspect installed host-local certificate lifecycle helper",
            "Require installed lifecycle helper for read-only preflight",
            None,
            "platform-pki-host-local-lifecycle",
            None,
        ),
        (
            "validator_helper.yml",
            "Inspect shipped host-local certificate validator helper source",
            "Inspect installed host-local certificate validator helper",
            "Require installed validator helper for read-only preflight",
            None,
            "platform-pki-zot-read-only-validate",
            "{{ pki_host_local_certificate_remote_validator }}",
        ),
    )
    root = repo_root / "roles/pki_host_local_certificate/tasks"
    for (
        filename,
        source_name,
        installed_name,
        assertion_name,
        execution_name,
        source_filename,
        installed_delegate,
    ) in cases:
        tasks = _load(root / filename)
        source = next(task for task in tasks if task["name"] == source_name)
        installed = next(task for task in tasks if task["name"] == installed_name)
        assertion = next(task for task in tasks if task["name"] == assertion_name)
        source_stat = source["ansible.builtin.stat"]
        installed_stat = installed["ansible.builtin.stat"]

        assert source_stat["path"] == f"{{{{ role_path }}}}/files/{source_filename}"
        assert source_stat["get_checksum"] is True
        assert source_stat["checksum_algorithm"] == "sha256"
        assert source["delegate_to"] == "localhost"
        assert source["become"] is False
        assert source["vars"] == {"ansible_become": False}
        assert installed_stat["get_checksum"] is True
        assert installed_stat["checksum_algorithm"] == "sha256"
        assert installed.get("delegate_to") == installed_delegate
        checks = assertion["ansible.builtin.assert"]["that"]
        assert any("source.stat.checksum" in check for check in checks)
        assert any("installed" in check and "source.stat.checksum" in check for check in checks)
        assert tasks.index(source) < tasks.index(installed) < tasks.index(assertion)
        if execution_name is not None:
            execution = next(task for task in tasks if task["name"] == execution_name)
            assert tasks.index(assertion) < tasks.index(execution)


def test_controller_local_pki_tasks_override_inventory_become(repo_root: Path) -> None:
    root = repo_root / "roles/pki_host_local_certificate/tasks"
    task_files = sorted(
        path for path in root.rglob("*") if path.suffix in {".yml", ".yaml"}
    )
    for path in task_files:
        pending = list(_load(path))
        while pending:
            task = pending.pop()
            if task.get("delegate_to") == "localhost":
                assert task.get("become") is False
                assert task.get("vars") == {"ansible_become": False}
            for section in ("block", "rescue", "always"):
                pending.extend(task.get(section, []))


def test_terminal_verification_requires_all_exact_coordinates_and_final_state(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    target = _make_target(makefile, "registry-pki-terminal-verification")
    tasks = _load(
        repo_root
        / "roles/pki_host_local_certificate/tasks/terminal_verification.yml"
    )
    play = _load(repo_root / "playbooks/registry-pki-terminal-verification.yml")[0]

    assert play["hosts"] == "registry"
    assert play["tasks"][0]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_certificate",
        "tasks_from": "terminal_verification",
    }
    for guard in (
        "_guard-pki-service",
        "_guard-pki-limit",
        "_guard-pki-request-id",
        "_guard-pki-artifact",
        "_guard-pki-deployment",
        "_guard-pki-outcome",
        "_guard-pki-runner",
    ):
        assert guard in target
    forced = (
        '\"pki_host_local_certificate_helper_read_only\":true',
        "pki_host_local_certificate_service=$(SERVICE)",
        "pki_host_local_certificate_request_id=$(REQUEST_ID)",
        "pki_host_local_certificate_artifact_manifest_sha256=$(ARTIFACT_SHA256)",
        "pki_host_local_certificate_deployment_sha256=$(DEPLOYMENT_SHA256)",
        "pki_host_local_certificate_outcome_sha256=$(OUTCOME_SHA256)",
        "pki_host_local_certificate_remote_validator=$(RUNNER_LIMIT)",
    )
    assert all(value in target for value in forced)
    assert all(target.index("$(EXTRA_ARGS)") < target.index(value) for value in forced)
    assert tasks[1]["ansible.builtin.import_tasks"] == "decision_preflight.yml"
    terminal = tasks[2]["ansible.builtin.assert"]["that"]
    assert "pki_host_local_certificate_terminal_status.status == 'complete'" in terminal
    assert (
        "pki_host_local_certificate_terminal_status.signer_outcome_state == 'finalized'"
        in terminal
    )
    assert "pki_host_local_certificate_terminal_status.required_action == 'none'" in terminal
    assert (
        "pki_host_local_certificate_terminal_status.recovery_required is sameas false"
        in terminal
    )
    assert "ansible.builtin.pause" not in yaml.safe_dump(tasks)
    for relative_path in (
        "roles/pki_host_local_certificate/tasks/terminal_verification.yml",
        "roles/pki_host_local_certificate/tasks/decision_preflight.yml",
        "roles/pki_host_local_certificate/tasks/status.yml",
        "roles/pki_host_local_certificate/tasks/validator_helper.yml",
        "roles/pki_host_local_certificate/tasks/lifecycle_helper.yml",
    ):
        assert "ansible.builtin.pause" not in (
            repo_root / relative_path
        ).read_text(encoding="utf-8")


def test_status_binds_terminal_outcome_inside_authenticated_status_protocol(
    repo_root: Path,
) -> None:
    status_tasks = _load(
        repo_root / "roles/pki_host_local_certificate/tasks/status.yml"
    )
    command = next(
        task
        for task in status_tasks
        if task["name"] == "Read authenticated host-local certificate lifecycle status"
    )
    argv = command["ansible.builtin.command"]["argv"]
    helper = (
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    ).read_text(encoding="utf-8")

    assert "--outcome-sha256" in argv
    assert "pki_host_local_certificate_outcome_sha256" in argv
    assert 'status_parser.add_argument("--outcome-sha256")' in helper
    assert 'pointer["outcome_sha256"] != args.outcome_sha256' in helper


def test_ci_entry_points_have_syntax_coverage_and_do_not_invoke_transport_clis(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    syntax = _make_target(makefile, "syntax-registry-pki-ci")
    for playbook in (
        "playbooks/registry-pki-bootstrap-readiness.yml",
        "playbooks/registry-pki-exchange-access-revoke.yml",
        "playbooks/registry-pki-terminal-verification.yml",
    ):
        assert f"PLAYBOOK={playbook}" in syntax
    assert "platform-pki direct-exchange" not in makefile
    assert "platform-pki gitlab-package" not in makefile

    ansible_sources = [
        *repo_root.glob("playbooks/**/*.yml"),
        *repo_root.glob("roles/*/tasks/**/*.yml"),
        *repo_root.glob("roles/*/handlers/**/*.yml"),
    ]
    for path in ansible_sources:
        data = _load(path)
        for task in _walk_tasks(data):
            for action in (
                "ansible.builtin.command",
                "ansible.builtin.shell",
                "ansible.builtin.raw",
            ):
                if action in task:
                    invocation = str(task[action])
                    assert "platform-pki direct-exchange" not in invocation
                    assert "platform-pki gitlab-package" not in invocation


def test_fixed_cleanup_ci_example_is_protected_required_and_ordered(
    repo_root: Path,
) -> None:
    workflow = (
        repo_root / "docs/registry-host-local-pki-workflow.md"
    ).read_text(encoding="utf-8")
    config = _fixed_cleanup_ci(workflow)
    command = (
        'make registry-pki-exchange-access-revoke '
        'ENV="$PKI_ENVIRONMENT" LIMIT="$PKI_TARGET"'
    )

    assert config["stages"] == ["pki-online", "pki-cleanup", "pki-gate"]
    assert config["variables"] == {
        "PKI_ENVIRONMENT": "dev",
        "PKI_TARGET": "dev-registry-01",
    }
    protected = config[".pki-protected-job"]
    assert protected["tags"] == ["pki-protected"]
    assert protected["rules"] == [
        {"if": '$CI_COMMIT_REF_PROTECTED == "true"'}
    ]

    cleanup = config["pki-fixed-cleanup"]
    assert cleanup["extends"] == ".pki-protected-job"
    assert cleanup["stage"] == "pki-cleanup"
    assert cleanup["needs"] == [
        {"job": "pki-online-stage", "artifacts": False}
    ]
    assert cleanup["when"] == "always"
    assert cleanup["allow_failure"] is False
    assert cleanup["script"] == [command]
    assert 0 < cleanup["retry"]["max"] <= 2
    assert set(cleanup["retry"]["when"]) == {
        "runner_system_failure",
        "stuck_or_timeout_failure",
        "script_failure",
    }

    gate = config["pki-next-gate"]
    assert gate["extends"] == ".pki-protected-job"
    assert gate["stage"] == "pki-gate"
    assert gate["needs"] == [
        {"job": "pki-fixed-cleanup", "artifacts": False}
    ]
    assert gate["when"] == "on_success"
    assert gate["allow_failure"] is False
    assert gate["script"][0] == command


def test_fixed_cleanup_ci_documentation_states_failure_boundaries(
    repo_root: Path,
) -> None:
    workflow = (
        repo_root / "docs/registry-host-local-pki-workflow.md"
    ).read_text(encoding="utf-8")
    section = workflow.split("## Fixed Cleanup\n", 1)[1].split(
        "\n## Expected Status Transitions", 1
    )[0]
    normalized = " ".join(section.split())

    for required in (
        "GitLab cannot guarantee",
        "pipeline cancellation",
        "runner loss",
        "next gate or job must independently run fixed revocation and verify absence",
        "administrator must",
        "out-of-band revocation and absence verification",
        "terminal-acceptance job must likewise `need` `pki-fixed-cleanup`",
    ):
        assert required in normalized


def test_fixed_revoke_playbook_dispatches_revoke_and_verifies_absence(
    repo_root: Path,
) -> None:
    play = _load(repo_root / "playbooks/registry-pki-exchange-access-revoke.yml")[0]
    tasks = play["tasks"]
    dispatch = tasks[1]["ansible.builtin.include_role"]

    assert dispatch == {
        "name": "pki_host_local_exchange_access",
        "tasks_from": "revoke",
    }
    assert "vars" not in play
    postcondition = tasks[-1]["ansible.builtin.assert"]["that"]
    assert any("revoked_paths" in condition for condition in postcondition)
    assert "registry_pki_exchange_revoked_user.rc == 2" in postcondition
    assert "registry_pki_exchange_revoked_group.rc == 2" in postcondition
    assert tasks.index(tasks[1]) < tasks.index(tasks[-1])


def _walk_tasks(value: Any):
    if isinstance(value, list):
        for child in value:
            yield from _walk_tasks(child)
    elif isinstance(value, dict):
        if "name" in value:
            yield value
        for child in value.values():
            yield from _walk_tasks(child)


def test_activation_make_route_forces_direct_mode_after_caller_arguments(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    target = _make_target(makefile, "registry-pki-activate")
    forced = (
        "pki_host_local_certificate_exchange_mode=direct",
        "pki_host_local_certificate_request_id=$(REQUEST_ID)",
        "pki_host_local_certificate_artifact_manifest_sha256=$(ARTIFACT_SHA256)",
        "pki_host_local_certificate_remote_validator=$(RUNNER_LIMIT)",
    )

    assert all(value in target for value in forced)
    assert all(target.index("$(EXTRA_ARGS)") < target.index(value) for value in forced)
    assert "registry-pki-activate-controller-local" not in makefile
    assert "registry-pki-activate-unattended" not in makefile
    for compatibility_target in (
        "registry-pki-request-controller-local",
        "registry-pki-evidence-export-controller-local",
        "registry-pki-outcome-import-controller-local",
    ):
        compatibility_route = _make_target(makefile, compatibility_target)
        assert "pki_host_local_certificate_exchange_mode=controller-local" in (
            compatibility_route
        )
