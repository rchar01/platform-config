from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import run_playbook
from conftest import CommandRunner


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


def test_make_exposes_only_two_coordinate_free_registry_pki_routes(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    declarations = set(
        re.findall(r"^(registry-pki-[A-Za-z0-9_.-]+):", makefile, re.MULTILINE)
    )

    assert declarations == {
        "registry-pki-request-publish",
        "registry-pki-response-activate",
    }
    request_prerequisites, request_recipe = make_target(
        makefile, "registry-pki-request-publish"
    )
    assert request_prerequisites == [
        "_guard-pki-env",
        "_guard-pki-limit",
        "_guard-pki-request-ttl",
    ]
    assert "PLAYBOOK=playbooks/registry-pki-request.yml" in request_recipe
    assert "registry_pki_request_ttl_seconds=$(REQUEST_TTL_SECONDS)" in request_recipe
    assert "$(EXTRA_ARGS)" not in request_recipe

    activation_prerequisites, activation_recipe = make_target(
        makefile, "registry-pki-response-activate"
    )
    assert activation_prerequisites == ["_guard-pki-env", "_guard-pki-limit"]
    assert "PLAYBOOK=playbooks/registry-pki-activate.yml" in activation_recipe
    assert "$(EXTRA_ARGS)" not in activation_recipe

    for removed in (
        "REQUEST_ID",
        "ARTIFACT_SHA256",
        "DEPLOYMENT_SHA256",
        "OUTCOME_SHA256",
        "RUNNER_LIMIT",
        "ENDPOINT_RECORD",
        "TRANSFER_DIR",
        "OPERATION_TOKEN",
        "_guard-pki-runner",
        "_guard-pki-request-id",
        "_guard-pki-artifact",
    ):
        assert removed not in makefile

    _, syntax_recipe = make_target(makefile, "syntax-registry-pki-ci")
    assert syntax_recipe.count("$(MAKE) syntax") == 2
    assert "PLAYBOOK=playbooks/registry-pki-request.yml" in syntax_recipe
    assert "PLAYBOOK=playbooks/registry-pki-activate.yml" in syntax_recipe


@pytest.mark.parametrize(
    ("playbook_name", "tasks_from"),
    (
        ("registry-pki-request.yml", "request_publish"),
        ("registry-pki-activate.yml", "response_activate"),
    ),
)
def test_playbooks_dispatch_only_target_local_role_routes(
    repo_root: Path, playbook_name: str, tasks_from: str
) -> None:
    plays = load_yaml(repo_root / "playbooks" / playbook_name)

    assert len(plays) == 1
    play = plays[0]
    assert play["hosts"] == "registry"
    assert play["become"] is True
    assert play["gather_facts"] is False
    assert len(play["tasks"]) == 1
    assert play["tasks"][0]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_certificate",
        "tasks_from": tasks_from,
    }


def test_target_local_task_chains_use_facades_and_recover_before_download(
    repo_root: Path,
) -> None:
    root = repo_root / "roles/pki_host_local_certificate/tasks"
    request = load_yaml(root / "request_publish.yml")
    activation = load_yaml(root / "response_activate.yml")

    assert [
        task["ansible.builtin.import_tasks"]
        for task in request
        if "ansible.builtin.import_tasks" in task
    ] == ["validate_target_local.yml", "trust.yml", "gitlab_setup.yml"]
    publish = task_named(
        request, "Create and publish the target-local schema-2 request"
    )
    assert publish["ansible.builtin.command"]["argv"] == [
        "{{ pki_host_local_certificate_gitlab_helper_path }}",
        "request-publish",
        "--config",
        "{{ pki_host_local_certificate_gitlab_config_path }}",
    ]
    assert publish["no_log"] is True
    validation = task_named(
        request, "Validate target-local request publication result"
    )
    checks = validation["ansible.builtin.assert"]["that"]
    assert (
        "pki_host_local_certificate_request_publish.keys() | list | sort "
        "== ['command', 'kind', 'request_id', 'schema', 'status']"
    ) in checks
    assert (
        "pki_host_local_certificate_request_publish.request_id "
        "is match('^[0-9a-f]{32}$')"
    ) in checks
    report = task_named(request, "Report authenticated target-local request ID")
    assert report["ansible.builtin.debug"] == {
        "msg": {
            "request_id": "{{ (pki_host_local_certificate_request_publish_result.stdout | from_json).request_id }}"
        }
    }

    names = [task["name"] for task in activation]
    assert names.index("Read initial authenticated target-local status") < names.index(
        "Recover target-local activation journal without operator coordinates"
    )
    assert names.index(
        "Recover target-local activation journal without operator coordinates"
    ) < names.index(
        "Install target-local GitLab certificate components when transport is required"
    )
    assert names.index(
        "Install target-local GitLab certificate components when transport is required"
    ) < names.index("Download and install the authenticated schema-2 response")
    assert names.index("Read post-download target-local status") < names.index(
        "Install reviewed local Zot validation CA"
    )
    assert names.index("Install reviewed local Zot validation CA") < names.index(
        "Start and locally validate target-local certificate activation"
    )
    download = task_named(
        activation, "Download and install the authenticated schema-2 response"
    )
    assert download["ansible.builtin.command"]["argv"] == [
        "{{ pki_host_local_certificate_gitlab_helper_path }}",
        "response-download",
        "--config",
        "{{ pki_host_local_certificate_gitlab_config_path }}",
    ]
    assert download["no_log"] is True

    install_ca = task_named(
        activation, "Install reviewed local Zot validation CA"
    )
    assert install_ca["platform_pki_reviewed_ca"] == {
        "source": "{{ pki_host_local_certificate_reviewed_ca_source }}",
        "sha256": "{{ pki_host_local_certificate_reviewed_ca_sha256 }}",
        "dest": "{{ pki_host_local_certificate_reviewed_ca_target_path }}",
        "mode": "{{ pki_host_local_certificate_reviewed_ca_mode }}",
    }
    assert "['response-ready', 'activate-response']" in install_ca["when"]
    assert "['activating', 'complete-local-validation']" in install_ca["when"]


def test_activation_validates_reviewed_ca_source_and_digest(repo_root: Path) -> None:
    tasks = load_yaml(
        repo_root / "roles/pki_host_local_certificate/tasks/response_activate.yml"
    )
    validation = task_named(tasks, "Validate local activation inputs")
    checks = validation["ansible.builtin.assert"]["that"]

    assert (
        "pki_host_local_certificate_reviewed_ca_source is "
        "match(pki_host_local_certificate_absolute_path_pattern)"
    ) in checks
    assert (
        "pki_host_local_certificate_reviewed_ca_sha256 is "
        "match('^[0-9a-f]{64}$')"
    ) in checks
    assert validation["vars"]["pki_host_local_certificate_absolute_path_pattern"] == (
        "^/[A-Za-z0-9_@%+=:,.-]+(/[A-Za-z0-9_@%+=:,.-]+)*$"
    )


def test_gitlab_token_is_validated_by_metadata_without_entering_ansible(
    repo_root: Path,
) -> None:
    tasks = load_yaml(
        repo_root / "roles/pki_host_local_certificate/tasks/gitlab_setup.yml"
    )
    token_stat = task_named(tasks, "Inspect pre-provisioned GitLab token metadata")
    assert token_stat["ansible.builtin.stat"] == {
        "path": "{{ pki_host_local_certificate_gitlab_token_path }}",
        "follow": False,
        "get_checksum": False,
        "get_mime": False,
    }
    assert token_stat["no_log"] is True

    token_contract = task_named(
        tasks, "Require protected pre-provisioned GitLab token metadata"
    )
    checks = token_contract["ansible.builtin.assert"]["that"]
    for expected in (
        "pki_host_local_certificate_gitlab_token.stat.uid == 0",
        "pki_host_local_certificate_gitlab_token.stat.gid == 0",
        "pki_host_local_certificate_gitlab_token.stat.nlink == 1",
        "pki_host_local_certificate_gitlab_token.stat.mode == '0600'",
        "pki_host_local_certificate_gitlab_token.stat.size <= 4096",
    ):
        assert expected in checks
    assert token_contract["no_log"] is True

    dumped = yaml.safe_dump(tasks)
    assert "ansible.builtin.slurp" not in dumped
    assert "ansible.builtin.fetch" not in dumped
    config = task_named(
        tasks, "Install target-local GitLab facade configuration"
    )["vars"]["pki_host_local_certificate_gitlab_config"]
    assert config["token_file"] == "{{ pki_host_local_certificate_gitlab_token_path }}"
    assert not any("lookup(" in str(value) or "query(" in str(value) for value in config.values())
    for field, variable in (
        ("request_ttl_seconds", "pki_host_local_certificate_request_ttl_seconds"),
        (
            "minimum_remaining_lifetime_seconds",
            "pki_host_local_certificate_minimum_remaining_lifetime_seconds",
        ),
        ("timeout", "pki_host_local_certificate_gitlab_timeout"),
        (
            "processing_attempts",
            "pki_host_local_certificate_gitlab_processing_attempts",
        ),
        (
            "processing_interval",
            "pki_host_local_certificate_gitlab_processing_interval",
        ),
    ):
        assert config[field] == "{{ " + variable + " | int }}"


def test_transport_client_installation_uses_reviewed_digest(
    repo_root: Path,
) -> None:
    tasks = load_yaml(
        repo_root / "roles/pki_host_local_certificate/tasks/gitlab_setup.yml"
    )
    install = task_named(tasks, "Install platform-pki transport client")

    assert install["platform_pki_transport_client"] == {
        "source": "{{ pki_host_local_certificate_platform_pki_source }}",
        "sha256": "{{ pki_host_local_certificate_platform_pki_sha256 }}",
        "dest": "{{ pki_host_local_certificate_platform_pki_path }}",
    }


def test_gitlab_facade_config_renders_typed_json(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    tasks = load_yaml(
        repo_root / "roles/pki_host_local_certificate/tasks/gitlab_setup.yml"
    )
    config_task = task_named(
        tasks, "Install target-local GitLab facade configuration"
    )
    variables = load_yaml(
        repo_root / "roles/pki_host_local_certificate/defaults/main.yml"
    )
    variables.update(
        pki_host_local_certificate_service="registry-test",
        pki_host_local_certificate_target="target.test",
        pki_host_local_certificate_operation="issue",
        pki_host_local_certificate_inventory_sha256="a" * 64,
        pki_host_local_certificate_common_name="registry.test",
        pki_host_local_certificate_dns_sans=["registry.test", "target.test"],
        pki_host_local_certificate_ip_sans=["192.0.2.61"],
        pki_host_local_certificate_response_principal="response.test",
        pki_host_local_certificate_minimum_remaining_lifetime_seconds=60,
    )
    output = isolated_test_dir / "gitlab-config.json"
    playbook = isolated_test_dir / "render-gitlab-config.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Render focused target-local GitLab configuration",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": [
                        {
                            "name": "Render target-local GitLab configuration",
                            "ansible.builtin.copy": {
                                "content": config_task["ansible.builtin.copy"]["content"],
                                "dest": str(output),
                                "mode": "0600",
                            },
                            "vars": config_task["vars"],
                        }
                    ],
                }
            ],
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    run_playbook(command_runner, playbook).assert_success()
    rendered = json.loads(output.read_text(encoding="utf-8"))

    assert rendered["schema"] == 2
    assert rendered["dns_sans"] == ["registry.test", "target.test"]
    for field, expected in (
        ("request_ttl_seconds", 3600),
        ("minimum_remaining_lifetime_seconds", 60),
        ("timeout", 30),
        ("processing_attempts", 5),
        ("processing_interval", 2),
    ):
        assert type(rendered[field]) is int
        assert rendered[field] == expected
