from __future__ import annotations

import hashlib
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml


TRUST_NAMES = {
    "approvers.allowed_signers",
    "policy",
    "requesters.allowed_signers",
    "responses.allowed_signers",
}


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def task_named(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(task for task in tasks if task.get("name") == name)


def load_script(path: Path) -> ModuleType:
    name = path.name.replace("-", "_")
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_schema2_target_local_contract_uses_exact_four_file_trust(
    repo_root: Path,
) -> None:
    role = repo_root / "roles/pki_host_local_certificate"
    defaults = load_yaml(role / "defaults/main.yml")
    validation = load_yaml(role / "tasks/validate_target_local.yml")
    trust_validation = load_yaml(role / "tasks/validate_trust.yml")
    contract = task_named(
        validation, "Validate target-local certificate contract"
    )
    checks = contract["ansible.builtin.assert"]["that"]

    assert defaults["pki_host_local_certificate_request_namespace"] == (
        "platform-pki-csr-request-v2"
    )
    assert "not ansible_check_mode" in checks
    assert "pki_host_local_certificate_operation in ['issue', 'renew']" in checks
    assert (
        "pki_host_local_certificate_request_namespace == "
        "'platform-pki-csr-request-v2'"
    ) in checks
    assert defaults["pki_host_local_certificate_platform_pki_sha256"] == ""
    assert any(
        "pki_host_local_certificate_platform_pki_sha256 is "
        "match('^[0-9a-f]{64}$')" in check
        for check in checks
    )
    assert defaults["pki_host_local_certificate_reviewed_ca_source"] == ""
    assert defaults["pki_host_local_certificate_reviewed_ca_sha256"] == ""
    destinations = contract["vars"][
        "pki_host_local_certificate_file_destinations"
    ]
    for required in (
        "pki_host_local_certificate_request_signing_key_path",
        "pki_host_local_certificate_trust_paths['approvers.allowed_signers']",
        "pki_host_local_certificate_trust_paths['policy']",
        "pki_host_local_certificate_trust_paths['requesters.allowed_signers']",
        "pki_host_local_certificate_trust_paths['responses.allowed_signers']",
        "pki_host_local_certificate_reviewed_ca_target_path",
        "pki_host_local_certificate_service_config_path",
    ):
        assert required in destinations
    assert (
        set(contract["vars"]["pki_host_local_certificate_required_trust_names"])
        == TRUST_NAMES
    )
    trust_contract = task_named(
        trust_validation, "Validate host-local certificate trust bootstrap contract"
    )
    assert set(trust_contract["vars"]["pki_host_local_certificate_required_trust_names"]) == TRUST_NAMES

    plugin = load_script(repo_root / "plugins/action/platform_pki_trust_ingress.py")
    assert set(plugin.TRUST_NAMES) == TRUST_NAMES


def test_fixed_service_adapter_defaults_and_validation_are_closed(
    repo_root: Path,
) -> None:
    role = repo_root / "roles/pki_host_local_certificate"
    defaults = load_yaml(role / "defaults/main.yml")
    validation = load_yaml(role / "tasks/validate_target_local.yml")
    contract = task_named(
        validation, "Validate target-local certificate contract"
    )
    checks = contract["ansible.builtin.assert"]["that"]
    adapter_contract = next(
        check for check in checks
        if isinstance(check, str)
        and "pki_host_local_certificate_service_adapter == 'zot-v1'" in check
        and "openbao-pristine-v1" in check
    )

    assert defaults["pki_host_local_certificate_service_adapter"] == "zot-v1"
    assert defaults["pki_host_local_certificate_service_unit"] == "zot.service"
    assert defaults["pki_host_local_certificate_service_config_path"] == (
        "/etc/zot/config.json"
    )
    assert defaults["pki_host_local_certificate_openbao_backend_port"] == 18200
    assert defaults["pki_host_local_certificate_openbao_cluster_port"] == 8201
    assert "pki_host_local_certificate_operation == 'issue'" in adapter_contract
    assert "pki_host_local_certificate_service is match('^openbao-" in adapter_contract
    assert "pki_host_local_certificate_service_unit == 'openbao.service'" in (
        adapter_contract
    )
    assert (
        "pki_host_local_certificate_reviewed_ca_target_path == "
        "'/etc/platform-config/openbao-validation-ca.crt'"
    ) in adapter_contract
    assert "'/etc/openbao/listener.hcl'" in adapter_contract
    assert "pki_host_local_certificate_endpoint | length == 0" in adapter_contract
    assert "pki_host_local_certificate_openbao_backend_port == 18200" in (
        adapter_contract
    )
    assert "pki_host_local_certificate_openbao_cluster_port == 8201" in (
        adapter_contract
    )
    assert "pki_host_local_certificate_service_adapter in ['zot-v1', 'openbao-pristine-v1']" in checks


def test_legacy_zot_facade_argv_and_bounded_output_remain_exact(
    repo_root: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    facade = load_script(
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-gitlab"
    )
    config = {
        "schema": 2,
        "state_root": "/state",
        "pending_root": "/tls-pending",
        "versions_root": "/tls-versions",
        "service": "registry",
        "target": "registry.test",
        "zot_config": "/etc/zot/config.json",
    }

    assert facade.common_lifecycle(config) == [
        "--state-root", "/state",
        "--pending-root", "/tls-pending",
        "--versions-root", "/tls-versions",
        "--service", "registry",
        "--target", "registry.test",
    ]
    assert facade.service_config_arguments(config) == [
        "--zot-config", "/etc/zot/config.json",
    ]
    facade.status("response-download", "installed")
    assert json.loads(capsys.readouterr().out) == {
        "schema": 2,
        "kind": "platform-config-target-local-gitlab-status",
        "command": "response-download",
        "status": "installed",
    }


def test_only_target_local_registry_pki_entry_points_remain(repo_root: Path) -> None:
    assert {
        path.name for path in (repo_root / "playbooks").glob("registry-pki-*.yml")
    } == {"registry-pki-request.yml", "registry-pki-activate.yml"}

    role_tasks = repo_root / "roles/pki_host_local_certificate/tasks"
    assert {path.name for path in role_tasks.glob("*.yml")} == {
        "filesystem_request.yml",
        "filesystem_response.yml",
        "gitlab_setup.yml",
        "lifecycle_helper.yml",
        "main.yml",
        "request_helper.yml",
        "request_publish.yml",
        "response_activate.yml",
        "response_preflight.yml",
        "trust.yml",
        "validate_target_local.yml",
        "validate_trust.yml",
    }
    assert {path.name for path in (repo_root / "plugins/action").glob("platform_pki_*.py")} == {
        "platform_pki_reviewed_ca.py",
        "platform_pki_transport_client.py",
        "platform_pki_trust_ingress.py",
    }
    for relative in (
        "scripts/registry-pki-direct-exchange",
        "roles/pki_host_local_certificate/files/platform-pki-host-local-exchange",
        "roles/pki_host_local_certificate/files/platform-pki-zot-read-only-validate",
        "roles/pki_host_local_validation_material/tasks/main.yml",
        "roles/pki_host_local_exchange_access/tasks/main.yml",
    ):
        assert not (repo_root / relative).exists()


def test_transport_client_source_is_descriptor_pinned(
    repo_root: Path, tmp_path: Path
) -> None:
    plugin = load_script(
        repo_root / "plugins/action/platform_pki_transport_client.py"
    )
    source = tmp_path / "platform-pki"
    source.write_bytes(b"#!/bin/sh\nexit 0\n")
    source.chmod(0o600)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    pinned = plugin.pin_source(str(source), digest)
    try:
        assert pinned.data == source.read_bytes()
        pinned.recheck()
    finally:
        pinned.close()

    with pytest.raises(plugin.AnsibleActionFail, match="digest mismatch"):
        plugin.pin_source(str(source), "0" * 64)


def test_reviewed_ca_source_is_descriptor_pinned(
    repo_root: Path, tmp_path: Path
) -> None:
    plugin = load_script(repo_root / "plugins/action/platform_pki_reviewed_ca.py")
    source = tmp_path / "reviewed-ca.crt"
    source.write_bytes(b"reviewed CA bytes\n")
    source.chmod(0o600)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    pinned = plugin.pin_source(str(source), digest)
    try:
        assert pinned.data == source.read_bytes()
        pinned.recheck()
    finally:
        pinned.close()

    with pytest.raises(plugin.AnsibleActionFail, match="digest mismatch"):
        plugin.pin_source(str(source), "0" * 64)


def test_public_execution_surface_has_no_legacy_transport_or_runner(
    repo_root: Path,
) -> None:
    role = repo_root / "roles/pki_host_local_certificate"
    sources = [
        repo_root / "Makefile",
        repo_root / "scripts/in-container",
        repo_root / "playbooks/registry.yml",
        *sorted((repo_root / "playbooks").glob("registry-pki-*.yml")),
        *sorted((role / "tasks").glob("*.yml")),
        *sorted((role / "files").glob("platform-pki-host-local-*")),
    ]
    surface = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    for forbidden in (
        "controller-local",
        "direct-exchange",
        "exchange-access",
        "remote_validator",
        "remote-validator",
        "validation_boundary",
        "validation-boundary",
        "abandon-expired-request",
        "cancel-pending-request",
        "candidate_state",
        "deployment_state",
        "RUNNER_LIMIT",
        "PLATFORM_CONFIG_PKI_EXCHANGE_ROOT",
        "PLATFORM_CONFIG_PKI_OUTCOME_DIR",
        "platform_pki_request_collection",
        "platform_pki_response_ingress",
        "platform_pki_evidence_collection",
        "platform_pki_outcome_import",
        "platform_pki_validation_material",
    ):
        assert forbidden not in surface

    defaults = load_yaml(role / "defaults/main.yml")
    legacy_defaults = {
        "pki_host_local_certificate_controller_exchange_root",
        "pki_host_local_certificate_exchange_mode",
        "pki_host_local_certificate_request_id",
        "pki_host_local_certificate_artifact_manifest_sha256",
        "pki_host_local_certificate_exchange_helper_path",
        "pki_host_local_certificate_validator_helper_path",
        "pki_host_local_certificate_remote_validator",
        "pki_host_local_certificate_deployment_sha256",
        "pki_host_local_certificate_outcome_sha256",
    }
    assert legacy_defaults.isdisjoint(defaults)
    assert defaults["pki_host_local_certificate_transport"] == "gitlab"
    assert defaults["pki_host_local_certificate_filesystem_exchange_root"] == ""
    assert defaults["pki_host_local_certificate_filesystem_owner_uid"] is None


def test_target_local_facades_reject_migration(repo_root: Path) -> None:
    request = load_script(
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-request"
    )
    gitlab = load_script(
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-gitlab"
    )
    lifecycle = load_script(
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    )

    request_parser = request.build_parser()
    request_args = request_parser.parse_args(
        [
            "request",
            "--service", "registry",
            "--target", "registry.test",
            "--requester-principal", "registry.test",
            "--operation", "migrate",
            "--profile", "server-p384-sha384-v1",
            "--inventory-sha256", "a" * 64,
            "--current-cert-sha256", "b" * 64,
            "--predecessor-request-id", "none",
            "--current-cert-path", "/tmp/current.crt",
            "--common-name", "registry.test",
            "--dns-san", "registry.test",
            "--response-principal", "issuer.test",
            "--request-ttl-seconds", "3600",
            "--request-signing-key", "/tmp/key",
            "--request-namespace", "platform-pki-csr-request-v2",
            "--state-root", "/state",
            "--pending-root", "/pending",
            "--trust-binding", "policy", "/trust/policy", "c" * 64,
        ]
    )
    with pytest.raises(request.RequestError, match="operation must be issue or renew"):
        request.validate_arguments(request_args)

    config: dict[str, object] = {
        field: "value" for field in gitlab.CONFIG_FIELDS
    }
    config.update({"schema": 2, "kind": "platform-config-target-local-gitlab", "operation": "migrate"})
    with pytest.raises(gitlab.FacadeError):
        gitlab.validate_config(config)

    custody = lifecycle.build_parser()._subparsers._group_actions[0].choices[
        "zot-custody"
    ]
    operation = next(action for action in custody._actions if action.dest == "operation")
    assert tuple(operation.choices) == ("issue", "renew")
