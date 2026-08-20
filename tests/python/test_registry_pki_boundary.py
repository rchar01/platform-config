from __future__ import annotations

import ast
import copy
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import CommandRunner
from plugins.action import platform_pki_evidence_collection as evidence_collection_action
from plugins.action import platform_pki_evidence_intake as evidence_intake_action
from plugins.action import platform_pki_evidence_status as evidence_status_action
from plugins.action import platform_pki_outcome_import as outcome_import_action
from plugins.action import platform_pki_request_collection as request_collection_action
from plugins.action import platform_pki_request_intake as request_intake_action
from plugins.action import platform_pki_response_ingress as response_ingress_action
from plugins.action import platform_pki_response_intake as response_intake_action
from plugins.module_utils.platform_pki_exchange import (
    EVIDENCE_NAMES,
    OUTCOME_NAMES,
    REQUEST_REMOTE_NAMES,
    RESPONSE_NAMES,
)


ALLOWED_ACTIONS = {
    "ansible.builtin.assert",
    "ansible.builtin.command",
    "ansible.builtin.copy",
    "ansible.builtin.fail",
    "ansible.builtin.file",
    "ansible.builtin.import_tasks",
    "ansible.builtin.package",
    "ansible.builtin.pause",
    "ansible.builtin.stat",
    "platform_pki_evidence_collection",
    "platform_pki_evidence_intake",
    "platform_pki_evidence_status",
    "platform_pki_outcome_import",
    "platform_pki_request_collection",
    "platform_pki_request_intake",
    "platform_pki_response_ingress",
    "platform_pki_response_intake",
    "platform_pki_trust_ingress",
}
TASK_METADATA = {
    "name",
    "vars",
    "loop",
    "loop_control",
    "when",
    "become",
    "delegate_to",
    "register",
    "changed_when",
    "failed_when",
    "check_mode",
    "no_log",
}
METADATA_BY_ACTION = {
    "ansible.builtin.assert": {"name", "vars", "loop", "loop_control", "when"},
    "ansible.builtin.command": {
        "name",
        "register",
        "changed_when",
        "failed_when",
        "check_mode",
        "when",
        "delegate_to",
    },
    "ansible.builtin.copy": {
        "name",
        "vars",
        "loop",
        "loop_control",
        "when",
        "delegate_to",
    },
    "ansible.builtin.fail": {"name"},
    "ansible.builtin.file": {
        "name",
        "loop",
        "loop_control",
        "when",
        "delegate_to",
    },
    "ansible.builtin.import_tasks": {"name", "vars", "when"},
    "ansible.builtin.package": {"name", "when"},
    "ansible.builtin.pause": {"name", "register", "when"},
    "ansible.builtin.stat": {
        "name",
        "vars",
        "loop",
        "loop_control",
        "become",
        "delegate_to",
        "register",
        "when",
    },
    "platform_pki_evidence_collection": {"name", "register", "when"},
    "platform_pki_evidence_intake": {
        "name",
        "vars",
        "delegate_to",
        "become",
        "register",
    },
    "platform_pki_evidence_status": {
        "name",
        "vars",
        "delegate_to",
        "become",
        "register",
        "when",
    },
    "platform_pki_outcome_import": {"name", "register", "no_log", "when"},
    "platform_pki_request_collection": {"name", "register", "when"},
    "platform_pki_request_intake": {
        "name",
        "vars",
        "delegate_to",
        "become",
        "register",
    },
    "platform_pki_response_ingress": {"name", "register", "when"},
    "platform_pki_response_intake": {
        "name",
        "vars",
        "delegate_to",
        "become",
        "register",
    },
    "platform_pki_trust_ingress": {"name", "when"},
}
ALLOWED_CONDITIONS = {
    (
        "ansible.builtin.stat",
        "Inspect shipped host-local certificate request helper source",
    ): "ansible_check_mode",
    (
        "ansible.builtin.stat",
        "Inspect shipped host-local certificate lifecycle helper source",
    ): "ansible_check_mode or pki_host_local_certificate_helper_read_only",
    (
        "ansible.builtin.stat",
        "Inspect shipped host-local certificate validator helper source",
    ): "ansible_check_mode or pki_host_local_certificate_helper_read_only",
    (
        "ansible.builtin.assert",
        "Require installed helper for non-mutating request preflight",
    ): "ansible_check_mode",
    (
        "ansible.builtin.assert",
        "Require installed trust helper for non-mutating bootstrap preflight",
    ): "ansible_check_mode",
    (
        "ansible.builtin.copy",
        "Install host-local certificate request helper",
    ): "not ansible_check_mode",
    (
        "ansible.builtin.copy",
        "Install host-local certificate trust helper",
    ): "not ansible_check_mode",
    (
        "ansible.builtin.file",
        "Create absent host-local certificate helper directory",
    ): "not pki_host_local_certificate_helper_directory.stat.exists",
    (
        "ansible.builtin.file",
        "Create absent host-local certificate trust helper directory",
    ): (
        "not ansible_check_mode and not "
        "pki_host_local_certificate_trust_helper_directory.stat.exists"
    ),
    (
        "ansible.builtin.file",
        "Create absent host-local certificate lifecycle helper directory",
    ): [
        "not ansible_check_mode",
        "not pki_host_local_certificate_helper_read_only",
        "not pki_host_local_certificate_lifecycle_helper_directory.stat.exists",
    ],
    (
        "ansible.builtin.file",
        "Create absent host-local certificate validator helper directory",
    ): [
        "not ansible_check_mode",
        "not pki_host_local_certificate_helper_read_only",
        "not pki_host_local_certificate_validator_helper_directory.stat.exists",
    ],
    (
        "ansible.builtin.file",
        "Remove only transient host-local certificate observation",
    ): "not ansible_check_mode",
    (
        "ansible.builtin.command",
        "Prepare protected target trust ingress",
    ): (
        "not ansible_check_mode and not "
        "pki_host_local_certificate_target_trust.stat.exists"
    ),
    (
        "platform_pki_trust_ingress",
        "Transfer pinned reviewed public trust into protected target ingress",
    ): (
        "not ansible_check_mode and not "
        "pki_host_local_certificate_target_trust.stat.exists"
    ),
    (
        "ansible.builtin.command",
        "Probe host-local certificate lifecycle Python runtime",
    ): [
        "not ansible_check_mode",
        "not pki_host_local_certificate_helper_read_only",
    ],
    (
        "ansible.builtin.package",
        "Install host-local certificate lifecycle Python runtime",
    ): [
        "not ansible_check_mode",
        "not pki_host_local_certificate_helper_read_only",
        "pki_host_local_certificate_lifecycle_python_runtime.rc != 0",
    ],
    (
        "ansible.builtin.copy",
        "Install host-local certificate lifecycle helper",
    ): [
        "not ansible_check_mode",
        "not pki_host_local_certificate_helper_read_only",
    ],
    (
        "ansible.builtin.copy",
        "Install host-local certificate validator helper on reviewed runner",
    ): [
        "not ansible_check_mode",
        "not pki_host_local_certificate_helper_read_only",
    ],
    (
        "platform_pki_request_collection",
        "Collect exact public host-local certificate request",
    ): [
        "pki_host_local_certificate_exchange_mode == 'controller-local'",
        "not ansible_check_mode",
    ],
    (
        "ansible.builtin.assert",
        "Validate public request collection metadata",
    ): [
        "pki_host_local_certificate_exchange_mode == 'controller-local'",
        "not ansible_check_mode",
    ],
    (
        "ansible.builtin.import_tasks",
        "Install fixed direct exchange facade",
    ): [
        "pki_host_local_certificate_exchange_mode == 'direct'",
        "not ansible_check_mode",
    ],
    (
        "ansible.builtin.assert",
        "Publish exact direct request transfer coordinates",
    ): [
        "pki_host_local_certificate_exchange_mode == 'direct'",
        "not ansible_check_mode",
    ],
    (
        "platform_pki_response_ingress",
        "Transfer exact controller response into protected target ingress",
    ): [
        "pki_host_local_certificate_exchange_mode == 'controller-local'",
        "not ansible_check_mode",
        "(pki_host_local_certificate_response_prepare_result.stdout | from_json).status != 'installed'",
    ],
    (
        "ansible.builtin.assert",
        "Validate exact response ingress metadata",
    ): [
        "pki_host_local_certificate_exchange_mode == 'controller-local'",
        "not ansible_check_mode",
        "(pki_host_local_certificate_response_prepare_result.stdout | from_json).status != 'installed'",
    ],
    (
        "ansible.builtin.assert",
        "Validate derived exact response ingress digests",
    ): [
        "pki_host_local_certificate_exchange_mode == 'controller-local'",
        "not ansible_check_mode",
        "(pki_host_local_certificate_response_prepare_result.stdout | from_json).status != 'installed'",
    ],
    (
        "ansible.builtin.command",
        "Install or preflight exact immutable certificate version",
    ): "(pki_host_local_certificate_response_prepare_result.stdout | from_json).status != 'installed'",
    (
        "ansible.builtin.assert",
        "Validate exact response installation metadata",
    ): "(pki_host_local_certificate_response_prepare_result.stdout | from_json).status != 'installed'",
    (
        "ansible.builtin.pause",
        "Confirm exact host-local certificate activation mutation",
    ): [
        "not ansible_check_mode",
        "pki_host_local_certificate_interactive_confirmation",
    ],
    (
        "ansible.builtin.assert",
        "Require exact host-local certificate activation confirmation",
    ): [
        "not ansible_check_mode",
        "pki_host_local_certificate_interactive_confirmation",
    ],
    (
        "ansible.builtin.pause",
        "Wait bounded interval before external Zot validation",
    ): "pki_host_local_certificate_validation_wait_seconds > 0",
    (
        "platform_pki_evidence_status",
        "Authenticate exact controller evidence publication",
    ): "pki_host_local_certificate_deployment_sha256 | length > 0",
    (
        "ansible.builtin.assert",
        "Validate exact controller evidence status metadata",
    ): "pki_host_local_certificate_deployment_sha256 | length > 0",
    (
        "ansible.builtin.assert",
        "Require installed lifecycle helper for read-only preflight",
    ): "ansible_check_mode or pki_host_local_certificate_helper_read_only",
    (
        "ansible.builtin.assert",
        "Require installed validator helper for read-only preflight",
    ): "ansible_check_mode or pki_host_local_certificate_helper_read_only",
    (
        "platform_pki_evidence_collection",
        "Collect exact authenticated host-local deployment evidence",
    ): "pki_host_local_certificate_exchange_mode == 'controller-local'",
    (
        "ansible.builtin.assert",
        "Validate exact evidence collection metadata",
    ): "pki_host_local_certificate_exchange_mode == 'controller-local'",
    (
        "ansible.builtin.assert",
        "Publish exact direct evidence transfer coordinates",
    ): "pki_host_local_certificate_exchange_mode == 'direct'",
    (
        "platform_pki_outcome_import",
        "Authenticate, transfer, and import exact signer outcome",
    ): "pki_host_local_certificate_exchange_mode == 'controller-local'",
    (
        "ansible.builtin.assert",
        "Validate exact signer-outcome import metadata",
    ): "pki_host_local_certificate_exchange_mode == 'controller-local'",
    (
        "ansible.builtin.command",
        "Authenticate and import exact directly staged signer outcome",
    ): "pki_host_local_certificate_exchange_mode == 'direct'",
    (
        "ansible.builtin.assert",
        "Validate exact direct signer-outcome import metadata",
    ): "pki_host_local_certificate_exchange_mode == 'direct'",
    (
        "ansible.builtin.command",
        "Remove only the accepted direct outcome stage",
    ): [
        "pki_host_local_certificate_exchange_mode == 'direct'",
        "not ansible_check_mode",
        "(pki_host_local_certificate_direct_outcome_import_command.stdout | from_json).status in ['imported', 'existing']",
    ],
    (
        "ansible.builtin.assert",
        "Validate exact direct outcome cleanup metadata",
    ): [
        "pki_host_local_certificate_exchange_mode == 'direct'",
        "not ansible_check_mode",
        "(pki_host_local_certificate_direct_outcome_import_command.stdout | from_json).status in ['imported', 'existing']",
    ],
}
EXPECTED_COPIES = {
    "Install host-local certificate request helper": {
        "src": "platform-pki-host-local-request",
        "dest": "{{ pki_host_local_certificate_request_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Install host-local certificate trust helper": {
        "src": "platform-pki-host-local-trust",
        "dest": "{{ pki_host_local_certificate_trust_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Install host-local certificate lifecycle helper": {
        "src": "platform-pki-host-local-lifecycle",
        "dest": "{{ pki_host_local_certificate_lifecycle_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Install host-local certificate exchange facade": {
        "src": "platform-pki-host-local-exchange",
        "dest": "{{ pki_host_local_certificate_exchange_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Install fixed host-local certificate exchange config": {
        "content": "{{ pki_host_local_certificate_exchange_config | to_json(sort_keys=true, separators=[',', ':']) }}\n",
        "dest": "{{ pki_host_local_certificate_exchange_config_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0600",
    },
    "Install host-local certificate validator helper on reviewed runner": {
        "src": "platform-pki-zot-read-only-validate",
        "dest": "{{ pki_host_local_certificate_validator_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Copy only canonical public runner observation to target": {
        "content": "{{ pki_host_local_certificate_validator_result.stdout }}\n",
        "dest": "/run/platform-pki-host-local/{{ pki_host_local_certificate_request_id }}.observation",
        "owner": "root",
        "group": "root",
        "mode": "0600",
    },
}
EXPECTED_COPY_VARS = {
    "Install fixed host-local certificate exchange config": {
        "pki_host_local_certificate_exchange_config": {
            "lifecycle_helper": "{{ pki_host_local_certificate_lifecycle_helper_path }}",
            "pending_root": "{{ pki_host_local_certificate_pending_root }}",
            "schema": 1,
            "service": "{{ pki_host_local_certificate_service }}",
            "spool_root": "{{ pki_host_local_certificate_exchange_spool_root }}",
            "state_root": "{{ pki_host_local_certificate_state_root }}",
            "target": "{{ pki_host_local_certificate_target }}",
            "trust_id": "{{ pki_host_local_certificate_trust_id }}",
            "versions_root": "{{ pki_host_local_certificate_versions_root }}",
            "zot_config": "{{ pki_host_local_certificate_zot_config_path }}",
        }
    }
}
EXPECTED_FILES = {
    "Create absent host-local certificate helper directory": {
        "path": "{{ pki_host_local_certificate_request_helper_path | dirname }}",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Create absent host-local certificate trust helper directory": {
        "path": "{{ pki_host_local_certificate_trust_helper_path | dirname }}",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Create absent host-local certificate lifecycle helper directory": {
        "path": "{{ pki_host_local_certificate_lifecycle_helper_path | dirname }}",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Create fixed host-local certificate exchange directories": {
        "path": "{{ item.path }}",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "{{ item.mode }}",
    },
    "Create absent host-local certificate validator helper directory": {
        "path": "{{ pki_host_local_certificate_validator_helper_path | dirname }}",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Create private transient observation directory": {
        "path": "/run/platform-pki-host-local",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0700",
    },
    "Remove only transient host-local certificate observation": {
        "path": "/run/platform-pki-host-local/{{ pki_host_local_certificate_request_id }}.observation",
        "state": "absent",
    },
}
ACTION_OPTION_SETS = {
    "platform_pki_trust_ingress": {"sources", "sha256", "ingress_root"},
    "platform_pki_request_collection": {
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "trust_id",
        "request_id",
        "exchange_root",
        "service",
        "target",
        "transport",
        "transport_host_key_sha256",
        "inventory_sha256",
        "profile",
        "requester_principal",
        "response_principal",
        "common_name",
        "dns_sans",
        "ip_sans",
        "trust_paths",
        "trust_sha256",
        "expected_request_sha256",
        "expected_csr_sha256",
        "expected_csr_spki_sha256",
    },
    "platform_pki_request_intake": {
        "request_dir",
        "exchange_root",
        "service",
        "target",
        "transport_host_key_sha256",
        "inventory_sha256",
        "profile",
        "requester_principal",
        "response_principal",
        "common_name",
        "dns_sans",
        "ip_sans",
        "trust_paths",
        "trust_sha256",
        "expected_request_sha256",
        "expected_csr_sha256",
        "expected_csr_spki_sha256",
        "request_id",
    },
    "platform_pki_response_intake": {
        "response_dir",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "inventory_sha256",
        "expected_artifact_sha256",
        "response_principal",
        "trust_paths",
        "trust_sha256",
        "common_name",
        "dns_sans",
        "ip_sans",
        "minimum_remaining_lifetime_seconds",
    },
    "platform_pki_response_ingress": {
        "exchange_root",
        "service",
        "request_id",
        "ingress_root",
        "artifact_sha256",
    },
    "platform_pki_evidence_collection": {
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "trust_id",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    },
    "platform_pki_evidence_intake": {
        "evidence_dir",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    },
    "platform_pki_evidence_status": {
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    },
    "platform_pki_outcome_import": {
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "zot_config_path",
        "trust_id",
        "exchange_root",
        "outcome_dir",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
        "outcome_sha256",
        "response_principal",
    },
}
CUSTOM_ACTIONS = {
    "Transfer pinned reviewed public trust into protected target ingress": (
        "platform_pki_trust_ingress",
        ACTION_OPTION_SETS["platform_pki_trust_ingress"],
    ),
    "Collect exact public host-local certificate request": (
        "platform_pki_request_collection",
        ACTION_OPTION_SETS["platform_pki_request_collection"],
    ),
    "Authenticate and publish exact direct request intake": (
        "platform_pki_request_intake",
        ACTION_OPTION_SETS["platform_pki_request_intake"],
    ),
    "Authenticate and snapshot exact controller-side certificate response": (
        "platform_pki_response_intake",
        ACTION_OPTION_SETS["platform_pki_response_intake"],
    ),
    "Transfer exact controller response into protected target ingress": (
        "platform_pki_response_ingress",
        ACTION_OPTION_SETS["platform_pki_response_ingress"],
    ),
    "Collect exact authenticated host-local deployment evidence": (
        "platform_pki_evidence_collection",
        ACTION_OPTION_SETS["platform_pki_evidence_collection"],
    ),
    "Authenticate and publish exact direct evidence intake": (
        "platform_pki_evidence_intake",
        ACTION_OPTION_SETS["platform_pki_evidence_intake"],
    ),
    "Authenticate exact controller evidence publication": (
        "platform_pki_evidence_status",
        ACTION_OPTION_SETS["platform_pki_evidence_status"],
    ),
    "Authenticate, transfer, and import exact signer outcome": (
        "platform_pki_outcome_import",
        ACTION_OPTION_SETS["platform_pki_outcome_import"],
    ),
}
COMMAND_DISPATCHES = {
    "Create or validate the target-local certificate request": (
        "pki_host_local_certificate_request_helper_path",
        "request",
    ),
    "Abandon exact expired host-local certificate request": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "abandon-expired-request",
    ),
    "Cancel exact pending host-local certificate request": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "cancel-pending-request",
    ),
    "Prepare protected target trust ingress": (
        "pki_host_local_certificate_trust_helper_path",
        "prepare",
    ),
    "Install or validate complete host-local certificate trust tree": (
        "pki_host_local_certificate_trust_helper_path",
        "install",
    ),
    "Prepare exact target response ingress": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "response-prepare",
    ),
    "Authenticate and import exact directly staged signer outcome": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "outcome-import",
    ),
    "Remove only the accepted direct outcome stage": (
        "pki_host_local_certificate_exchange_helper_path",
        "cleanup-outcome",
    ),
    "Install or preflight exact immutable certificate version": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "response-install",
    ),
    "Preflight exact host-local certificate activation candidate": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "activate-start",
    ),
    "Start exact host-local certificate activation": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "activate-start",
    ),
    "Validate exact active Zot endpoint from reviewed runner": (
        "pki_host_local_certificate_validator_helper_path",
        "--service",
    ),
    "Finalize exact activated host-local certificate evidence": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "activate-finish",
    ),
    "Strictly validate restored predecessor on registry target": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "activate-finish",
    ),
    "Validate exact restored Zot endpoint from reviewed runner": (
        "pki_host_local_certificate_validator_helper_path",
        "--service",
    ),
    "Publish exact rolled-back host-local certificate evidence": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "activate-finish",
    ),
    "Recover exact interrupted host-local certificate activation": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "recover",
    ),
    "Recover exact host-local certificate lifecycle journal": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "recover",
    ),
    "Read authenticated host-local certificate lifecycle status": (
        "pki_host_local_certificate_lifecycle_helper_path",
        "status",
    ),
    "Revalidate exact exported active Zot endpoint from reviewed runner": (
        "pki_host_local_certificate_validator_helper_path",
        "--service",
    ),
}


class BoundaryViolation(AssertionError):
    pass


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _task_named(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    matches = [task for task in tasks if task.get("name") == name]
    if len(matches) != 1:
        raise BoundaryViolation(f"expected exactly one task named {name!r}")
    return matches[0]


def _actions_in(tasks: list[dict[str, Any]]) -> set[str]:
    actions: set[str] = set()
    for task in tasks:
        for section in ("block", "rescue", "always"):
            actions.update(_actions_in(task.get(section, [])))
        actions.update(
            set(task).difference(TASK_METADATA).difference({"block", "rescue", "always"})
        )
    return actions


def _fetch_file_sources(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        ast.unparse(node.args[0])
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fetch_file"
        and node.args
    ]


def _reject_controller_templating(value: Any, source: str | Path) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_controller_templating(key, source)
            _reject_controller_templating(child, source)
    elif isinstance(value, list):
        for child in value:
            _reject_controller_templating(child, source)
    elif isinstance(value, str) and re.search(r"\b(?:lookup|query|q)\b", value):
        raise BoundaryViolation(
            f"controller-side lookup or query is forbidden in {source}"
        )


def _validate_task(task: Any, source: str | Path) -> None:
    if not isinstance(task, dict):
        raise BoundaryViolation(f"non-mapping task in {source}")
    if "action" in task or "local_action" in task:
        raise BoundaryViolation(f"dynamic action syntax is forbidden in {source}")
    _reject_controller_templating(task, source)

    nested = any(section in task for section in ("block", "rescue", "always"))
    for section in ("block", "rescue", "always"):
        for child in task.get(section, []):
            _validate_task(child, source)
    actions = (
        set(task).difference(TASK_METADATA).difference({"block", "rescue", "always"})
    )
    if nested and not actions:
        valid_activation_block = (
            set(task) == {"name", "when", "block", "rescue", "always"}
            and task.get("name")
            == "Activate, validate, and finalize exact host-local certificate"
            and task.get("when") == "not ansible_check_mode"
            and bool(task.get("block"))
            and [child.get("name") for child in task.get("rescue", [])]
            == [
                "Recover exact interrupted host-local certificate activation",
                "Validate exact activation recovery metadata",
                "Fail activation after exact recovery",
            ]
            and [child.get("name") for child in task.get("always", [])]
            == ["Remove only transient host-local certificate observation"]
        )
        valid_rollback_publication_block = (
            set(task) == {"name", "block", "always"}
            and task.get("name")
            == "Validate restored predecessor and publish rolled-back evidence"
            and bool(task.get("block"))
            and [child.get("name") for child in task.get("always", [])]
            == ["Remove only transient host-local certificate observation"]
        )
        if not valid_activation_block and not valid_rollback_publication_block:
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected block shape in {source}"
            )
        return
    if len(actions) != 1 or not actions.issubset(ALLOWED_ACTIONS):
        raise BoundaryViolation(
            "host-local boundary contains a non-allowlisted action in "
            f"{source}: {sorted(actions)}"
        )
    action = next(iter(actions))
    metadata = set(task).difference(actions)
    if not metadata.issubset(METADATA_BY_ACTION[action]):
        raise BoundaryViolation(
            "host-local boundary contains fail-neutralizing or unexpected metadata "
            f"in {source}"
        )
    task_name = str(task.get("name", ""))
    if action == "ansible.builtin.stat":
        controller_source_tasks = {
            "Inspect shipped host-local certificate request helper source",
            "Inspect shipped host-local certificate lifecycle helper source",
            "Inspect shipped host-local certificate validator helper source",
        }
        if task_name in controller_source_tasks:
            valid_controller_source = (
                task.get("delegate_to") == "localhost"
                and task.get("become") is False
                and task.get("vars") == {"ansible_become": False}
            )
        else:
            valid_controller_source = "vars" not in task
        if not valid_controller_source:
            raise BoundaryViolation(
                f"host-local boundary stat has unexpected execution bindings in {source}"
            )
    condition_key = (action, task_name)
    if condition_key in ALLOWED_CONDITIONS:
        if task.get("when") != ALLOWED_CONDITIONS[condition_key]:
            raise BoundaryViolation(
                f"host-local boundary omits or changes a required conditional in {source}"
            )
    elif "when" in task:
        raise BoundaryViolation(
            f"host-local boundary contains an unexpected conditional in {source}"
        )
    if action == "ansible.builtin.import_tasks" and task[action] not in {
        "decision_preflight.yml",
        "lifecycle_helper.yml",
        "exchange_helper.yml",
        "status.yml",
        "validate.yml",
        "validate_trust.yml",
        "validate_validator_result.yml",
        "validator_helper.yml",
        "request_apply.yml",
    }:
        raise BoundaryViolation(
            f"host-local boundary imports an unexpected task file in {source}"
        )
    if action == "ansible.builtin.command" and set(task[action]) != {"argv"}:
        raise BoundaryViolation(
            f"host-local boundary command must use argv only in {source}"
        )
    if action == "ansible.builtin.package" and task[action] != {
        "name": "python3-cryptography",
        "state": "present",
    }:
        raise BoundaryViolation(
            f"host-local boundary contains an unexpected package in {source}"
        )
    if action == "ansible.builtin.command":
        if task_name == "Probe host-local certificate lifecycle Python runtime":
            if task[action] != {
                "argv": ["/usr/bin/env", "python3", "-c", "import cryptography"]
            } or any(
                task.get(name) is not False
                for name in ("changed_when", "failed_when", "check_mode")
            ):
                raise BoundaryViolation(
                    f"host-local lifecycle runtime probe is not fixed in {source}"
                )
            return
        dispatch = COMMAND_DISPATCHES.get(task_name)
        if dispatch is None:
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected command dispatch in {source}"
            )
        helper, subcommand = dispatch
        argv = task[action]["argv"]
        if isinstance(argv, list):
            if argv[0] != "{{ " + helper + " }}" or subcommand not in argv[1:]:
                raise BoundaryViolation(
                    f"host-local boundary command dispatch is not fixed in {source}"
                )
        elif not (
            isinstance(argv, str)
            and helper in argv
            and f"'{subcommand}'" in argv
        ):
            raise BoundaryViolation(
                f"host-local boundary command dispatch is not fixed in {source}"
            )
        if re.search(r"(?<![A-Za-z0-9_])(?:newest|latest)(?![A-Za-z0-9_])", str(argv)):
            raise BoundaryViolation(
                f"host-local boundary command selects a moving version in {source}"
            )
        expected_delegate = (
            "{{ pki_host_local_certificate_remote_validator }}"
            if task_name
            in {
                "Validate exact active Zot endpoint from reviewed runner",
                "Validate exact restored Zot endpoint from reviewed runner",
                "Revalidate exact exported active Zot endpoint from reviewed runner",
            }
            else None
        )
        if task.get("delegate_to") != expected_delegate:
            raise BoundaryViolation(
                f"host-local boundary command has an unexpected execution host in {source}"
            )
    if action == "ansible.builtin.copy":
        expected_copy = EXPECTED_COPIES.get(task_name)
        if expected_copy is None:
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected copy transfer in {source}"
            )
        if task[action] != expected_copy:
            raise BoundaryViolation(
                f"host-local boundary contains an unpinned copy transfer in {source}"
            )
        if task.get("vars") != EXPECTED_COPY_VARS.get(task_name):
            raise BoundaryViolation(
                f"host-local boundary copy has unexpected variable bindings in {source}"
            )
        expected_delegate = (
            "{{ pki_host_local_certificate_remote_validator }}"
            if task_name
            == "Install host-local certificate validator helper on reviewed runner"
            else None
        )
        if task.get("delegate_to") != expected_delegate:
            raise BoundaryViolation(
                f"host-local boundary copy has an unexpected execution host in {source}"
            )
    if action.startswith("platform_pki_"):
        custom_action = CUSTOM_ACTIONS.get(task_name)
        if custom_action is None or action != custom_action[0]:
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected custom action dispatch in {source}"
            )
        if set(task[action]) != custom_action[1]:
            raise BoundaryViolation(
                f"host-local custom action has unexpected options in {source}"
            )
        if action in {
            "platform_pki_evidence_intake",
            "platform_pki_evidence_status",
            "platform_pki_request_intake",
            "platform_pki_response_intake",
        }:
            if (
                task.get("delegate_to") != "localhost"
                or task.get("become") is not False
                or task.get("vars") != {"ansible_become": False}
            ):
                raise BoundaryViolation(
                    f"controller-only custom action escaped localhost in {source}"
                )
    if action == "ansible.builtin.file":
        if task[action] != EXPECTED_FILES.get(task_name):
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected file mutation in {source}"
            )
        expected_delegate = (
            "{{ pki_host_local_certificate_remote_validator }}"
            if task_name
            == "Create absent host-local certificate validator helper directory"
            else None
        )
        if task.get("delegate_to") != expected_delegate:
            raise BoundaryViolation(
                f"host-local boundary file task has an unexpected execution host in {source}"
            )
    if action == "ansible.builtin.pause":
        expected_pause = {
            "Confirm exact host-local certificate activation mutation": {
                "prompt": (
                    "Candidate certificate SHA-256 is "
                    "{{ (pki_host_local_certificate_activation_preflight_result.stdout | from_json).certificate_sha256 }}; "
                    "rollback deadline is "
                    "{{ (pki_host_local_certificate_activation_preflight_result.stdout | from_json).rollback_deadline_epoch }}. "
                    "Type exactly activate {{ pki_host_local_certificate_service }} "
                    "{{ pki_host_local_certificate_request_id }} "
                    "{{ pki_host_local_certificate_artifact_manifest_sha256 }}"
                )
            },
            "Wait bounded interval before external Zot validation": {
                "seconds": "{{ pki_host_local_certificate_validation_wait_seconds }}"
            },
        }.get(task_name)
        if task[action] != expected_pause:
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected pause in {source}"
            )


def _validate_operator_playbook(
    plays: Any, expected_tasks_from: str, source: str | Path
) -> None:
    _reject_controller_templating(plays, source)
    if not isinstance(plays, list) or len(plays) != 1:
        raise BoundaryViolation(f"{source} must contain exactly one play")
    play = plays[0]
    required_play_keys = {"name", "hosts", "become", "gather_facts", "tasks"}
    if expected_tasks_from in {
        "request",
        "abandon_expired_request",
        "cancel_pending_request",
        "activate",
        "publish_rolled_back_evidence",
    }:
        required_play_keys.add("vars")
    if set(play) != required_play_keys:
        raise BoundaryViolation(
            f"{source} contains imports, roles, handlers, or another executable section"
        )
    if (
        play.get("hosts") != "registry"
        or play.get("become") is not True
        or play.get("gather_facts") is not False
    ):
        raise BoundaryViolation(f"{source} is not constrained to the registry boundary")
    if expected_tasks_from == "request":
        expected_vars = {
            "registry_pki_request_ttl_seconds": 3600,
            "pki_host_local_certificate_request_ttl_seconds": (
                "{{ registry_pki_request_ttl_seconds | int }}"
            ),
            "pki_host_local_certificate_validation_boundary_sha256": "",
            "pki_host_local_certificate_rollback_seconds": 0,
        }
        if play["vars"] != expected_vars:
            raise BoundaryViolation(f"{source} does not pin exact request-phase values")
    if expected_tasks_from == "abandon_expired_request" and play["vars"] != {
        "pki_host_local_certificate_request_ttl_seconds": 0,
        "pki_host_local_certificate_validation_boundary_sha256": "",
        "pki_host_local_certificate_rollback_seconds": 0,
    }:
        raise BoundaryViolation(
            f"{source} does not pin exact expired-request abandonment values"
        )
    if expected_tasks_from == "cancel_pending_request" and play["vars"] != {
        "pki_host_local_certificate_request_ttl_seconds": 0,
        "pki_host_local_certificate_validation_boundary_sha256": "",
        "pki_host_local_certificate_rollback_seconds": 0,
    }:
        raise BoundaryViolation(
            f"{source} does not pin exact pending-request cancellation values"
        )
    if expected_tasks_from == "activate" and play["vars"] != {
        "pki_host_local_certificate_activation_action": "finalize",
        "pki_host_local_certificate_activation_result": "activated",
        "pki_host_local_certificate_interactive_confirmation": True,
        "pki_host_local_certificate_unattended_authorized": False,
    }:
        raise BoundaryViolation(
            f"{source} does not pin exact activation-phase values"
        )
    if expected_tasks_from == "publish_rolled_back_evidence" and play["vars"] != {
        "pki_host_local_certificate_activation_action": "abandon",
        "pki_host_local_certificate_activation_result": "rolled-back",
        "pki_host_local_certificate_interactive_confirmation": False,
        "pki_host_local_certificate_unattended_authorized": False,
    }:
        raise BoundaryViolation(
            f"{source} does not pin exact rolled-back evidence values"
        )
    play_tasks = play.get("tasks", [])
    if len(play_tasks) != 1:
        raise BoundaryViolation(
            f"{source} must contain exactly one structural role dispatch"
        )
    task = play_tasks[0]
    if set(task) != {"name", "ansible.builtin.include_role"}:
        raise BoundaryViolation(f"{source} contains an unexpected playbook action")
    if task["ansible.builtin.include_role"] != {
        "name": "pki_host_local_certificate",
        "tasks_from": expected_tasks_from,
    }:
        raise BoundaryViolation(
            f"{source} does not structurally pin {expected_tasks_from}"
        )


def assert_registry_pki_boundary(repo_root: Path) -> None:
    role_dir = repo_root / "roles/pki_host_local_certificate"
    in_container = (repo_root / "scripts/in-container").read_text(encoding="utf-8")
    if "--env PYTHONPATH=/workspace" not in in_container:
        raise BoundaryViolation("controller cannot import shared PKI utilities")
    for outcome_mount_contract in (
        "PLATFORM_CONFIG_PKI_OUTCOME_DIR=/platform-pki-outcome",
        '$outcome_dir:/platform-pki-outcome:ro,Z',
    ):
        if outcome_mount_contract not in in_container:
            raise BoundaryViolation(
                "controller does not mount the exact signer outcome read-only"
            )
    private_home_permissions = in_container[
        in_container.index("chmod 0700") : in_container.index('case "$profile"')
    ]
    if '"$tmp_home/.config"' not in private_home_permissions:
        raise BoundaryViolation(
            "controller private-source mount ancestry is not owner-only"
        )
    defaults = _load_yaml(role_dir / "defaults/main.yml")
    tasks = _load_yaml(role_dir / "tasks/main.yml")
    validation_tasks = _load_yaml(role_dir / "tasks/validate.yml")

    assert defaults["pki_host_local_certificate_profile"] == "server-p384-sha384-v1"
    assert (
        defaults["pki_host_local_certificate_request_namespace"]
        == "platform-pki-csr-request-v1"
    )
    assert (
        defaults["pki_host_local_certificate_deployment_namespace"]
        == "platform-pki-csr-deployment-v1"
    )
    assert (
        defaults["pki_host_local_certificate_outcome_namespace"]
        == "platform-pki-csr-outcome-v1"
    )
    assert defaults["pki_host_local_certificate_helper_read_only"] is False
    assert defaults["pki_host_local_certificate_unattended_authorized"] is False
    assert (
        defaults["pki_host_local_certificate_lifecycle_helper_path"]
        == "/usr/local/libexec/platform-pki-host-local-lifecycle"
    )
    assert (
        defaults["pki_host_local_certificate_validator_helper_path"]
        == "/usr/local/libexec/platform-pki-zot-read-only-validate"
    )

    common = next(
        task
        for task in validation_tasks
        if task.get("name") == "Validate host-local certificate common contract"
    )
    common_assertions = common["ansible.builtin.assert"]["that"]
    required = {
        "pki_host_local_certificate_target == inventory_hostname",
        (
            "pki_host_local_certificate_requester_principal == "
            "pki_host_local_certificate_target"
        ),
        "pki_host_local_certificate_profile == 'server-p384-sha384-v1'",
        (
            "pki_host_local_certificate_deployment_signing_key_path == "
            "'/etc/ssh/ssh_host_ed25519_key'"
        ),
        "pki_host_local_certificate_trust_id not in ['latest', 'current']",
        "pki_host_local_certificate_state_root is not search('(^|/)(latest|current)(/|$)')",
        "pki_host_local_certificate_pending_root is not search('(^|/)(latest|current)(/|$)')",
        "pki_host_local_certificate_versions_root is not search('(^|/)(latest|current)(/|$)')",
        "pki_host_local_certificate_controller_exchange_root is not search('(^|/)(latest|current)(/|$)')",
        "pki_host_local_certificate_unattended_authorized is boolean",
    }
    missing = required.difference(common_assertions)
    if missing:
        raise BoundaryViolation(
            f"host-local common contract assertions missing: {sorted(missing)}"
        )
    request_contract = _task_named(
        _load_yaml(role_dir / "tasks/request.yml"),
        "Validate host-local certificate request contract",
    )
    if not any(
        "pki_host_local_certificate_current_cert_path is not search('(^|/)(latest|current)(/|$)')"
        in assertion
        for assertion in request_contract["ansible.builtin.assert"]["that"]
    ):
        raise BoundaryViolation("request current certificate path permits moving selection")
    trust_contract = _task_named(
        _load_yaml(role_dir / "tasks/validate_trust.yml"),
        "Validate host-local certificate trust bootstrap contract",
    )
    if "pki_host_local_certificate_trust_id not in ['latest', 'current']" not in (
        trust_contract["ansible.builtin.assert"]["that"]
    ):
        raise BoundaryViolation("trust bootstrap permits moving trust selection")

    if len(tasks) != 1 or set(tasks[0]) != {"name", "ansible.builtin.fail"}:
        raise BoundaryViolation(
            "implicit host-local role execution is not one unconditional failure"
        )

    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    operator_playbooks = (
        (repo_root / "playbooks/registry-pki-request.yml", "request"),
        (
            repo_root / "playbooks/registry-pki-bootstrap-readiness.yml",
            "bootstrap_readiness",
        ),
        (
            repo_root / "playbooks/registry-pki-request-intake.yml",
            "request_intake",
        ),
        (
            repo_root / "playbooks/registry-pki-abandon-expired-request.yml",
            "abandon_expired_request",
        ),
        (
            repo_root / "playbooks/registry-pki-cancel-request.yml",
            "cancel_pending_request",
        ),
        (repo_root / "playbooks/registry-pki-activate.yml", "activate"),
        (repo_root / "playbooks/registry-pki-trust.yml", "trust"),
        (repo_root / "playbooks/registry-pki-response-check.yml", "response_check"),
        (repo_root / "playbooks/registry-pki-status.yml", "status"),
        (repo_root / "playbooks/registry-pki-recover.yml", "recover"),
        (
            repo_root / "playbooks/registry-pki-publish-rolled-back-evidence.yml",
            "publish_rolled_back_evidence",
        ),
        (repo_root / "playbooks/registry-pki-evidence-export.yml", "evidence_export"),
        (
            repo_root / "playbooks/registry-pki-evidence-intake.yml",
            "evidence_intake",
        ),
        (repo_root / "playbooks/registry-pki-outcome-import.yml", "outcome_import"),
        (
            repo_root / "playbooks/registry-pki-decision-preflight.yml",
            "decision_preflight",
        ),
        (
            repo_root / "playbooks/registry-pki-terminal-verification.yml",
            "terminal_verification",
        ),
    )
    registry = (repo_root / "playbooks/registry.yml").read_text(encoding="utf-8")
    for playbook, _ in operator_playbooks:
        for convergence_source in (site, registry):
            if playbook.name in convergence_source:
                raise BoundaryViolation(
                    f"normal convergence references operator-only playbook {playbook.name}"
                )

    for directory in (role_dir / "tasks", role_dir / "handlers"):
        if not directory.is_dir():
            continue
        for executable in sorted((*directory.rglob("*.yml"), *directory.rglob("*.yaml"))):
            for task in _load_yaml(executable):
                _validate_task(task, executable)

    meta_dir = role_dir / "meta"
    if meta_dir.is_dir():
        for meta_path in sorted((*meta_dir.rglob("*.yml"), *meta_dir.rglob("*.yaml"))):
            if (_load_yaml(meta_path) or {}).get("dependencies"):
                raise BoundaryViolation(
                    f"host-local role dependencies are forbidden: {meta_path}"
                )

    for playbook, tasks_from in operator_playbooks:
        _validate_operator_playbook(_load_yaml(playbook), tasks_from, playbook)

    action_modules = {
        "platform_pki_request_collection": request_collection_action,
        "platform_pki_request_intake": request_intake_action,
        "platform_pki_response_intake": response_intake_action,
        "platform_pki_response_ingress": response_ingress_action,
        "platform_pki_evidence_collection": evidence_collection_action,
        "platform_pki_evidence_intake": evidence_intake_action,
        "platform_pki_evidence_status": evidence_status_action,
        "platform_pki_outcome_import": outcome_import_action,
    }
    for action_name, module in action_modules.items():
        if set(module.ACTION_ARGUMENTS) != ACTION_OPTION_SETS[action_name]:
            raise BoundaryViolation(f"{action_name} argument contract changed")

    if REQUEST_REMOTE_NAMES != ("tls.csr", "request", "request.sig"):
        raise BoundaryViolation("request collection is not exactly three public files")
    if RESPONSE_NAMES != (
        "artifact",
        "tls.crt",
        "ca-chain.crt",
        "fullchain.crt",
        "response",
        "response.sig",
    ):
        raise BoundaryViolation("response intake and ingress are not exactly six files")
    if EVIDENCE_NAMES != (
        "deployment",
        "deployment.sig",
        "validation-boundary",
        "validation-result",
        "validation-result.sig",
    ):
        raise BoundaryViolation("evidence collection is not exactly five files")
    if "tls.key" in {
        *REQUEST_REMOTE_NAMES,
        *RESPONSE_NAMES,
        *EVIDENCE_NAMES,
        *OUTCOME_NAMES,
    }:
        raise BoundaryViolation("a controller transfer allowlist addresses tls.key")

    collection_plugin = repo_root / "plugins/action/platform_pki_request_collection.py"
    evidence_plugin = repo_root / "plugins/action/platform_pki_evidence_collection.py"
    if _fetch_file_sources(collection_plugin) != ["_remote_path(remote_tmp, name)"]:
        raise BoundaryViolation("request fetch_file source is not the guarded fixed path")
    if _fetch_file_sources(evidence_plugin) != ["_remote_path(remote_tmp, name)"]:
        raise BoundaryViolation("evidence fetch_file source is not the guarded fixed path")
    for plugin, allowlist in (
        (collection_plugin, "REQUEST_REMOTE_NAMES"),
        (evidence_plugin, "EVIDENCE_NAMES"),
    ):
        plugin_text = plugin.read_text(encoding="utf-8")
        if (
            f"if name not in {allowlist}:" not in plugin_text
            or "self._connection.fetch_file" not in plugin_text
            or "collection-prepare" not in plugin_text
            and "evidence-collection-prepare" not in plugin_text
        ):
            raise BoundaryViolation(f"fetch allowlist/helper binding is incomplete in {plugin}")

    defaults = _load_yaml(role_dir / "defaults/main.yml")
    if defaults.get("pki_host_local_certificate_exchange_mode") != "direct":
        raise BoundaryViolation("host-local exchange mode does not fail closed to direct")
    for plugin in (
        repo_root / "plugins/action/platform_pki_request_intake.py",
        repo_root / "plugins/action/platform_pki_evidence_intake.py",
    ):
        tree = ast.parse(plugin.read_text(encoding="utf-8"), filename=str(plugin))
        transfer_calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"fetch_file", "_transfer_data", "copy", "slurp"}
        }
        if transfer_calls:
            raise BoundaryViolation(
                f"direct local intake uses Ansible/package transfer calls: {plugin}"
            )

    direct_transfer_tasks = (
        (
            role_dir / "tasks/request.yml",
            "Collect exact public host-local certificate request",
        ),
        (
            role_dir / "tasks/activate.yml",
            "Transfer exact controller response into protected target ingress",
        ),
        (
            role_dir / "tasks/evidence_export.yml",
            "Collect exact authenticated host-local deployment evidence",
        ),
        (
            role_dir / "tasks/outcome_import.yml",
            "Authenticate, transfer, and import exact signer outcome",
        ),
    )
    for task_path, task_name in direct_transfer_tasks:
        conditions = _task_named(_load_yaml(task_path), task_name).get("when")
        if not conditions or (
            "pki_host_local_certificate_exchange_mode == 'controller-local'"
            not in ([conditions] if isinstance(conditions, str) else conditions)
        ):
            raise BoundaryViolation(
                f"direct mode can reach compatibility transfer task: {task_name}"
            )

    activation_tasks = _load_yaml(role_dir / "tasks/activate.yml")
    activation_contract = _task_named(
        activation_tasks,
        "Validate host-local certificate activation contract",
    )["ansible.builtin.assert"]["that"]
    if not {
        "pki_host_local_certificate_activation_action == 'finalize'",
        "pki_host_local_certificate_activation_result == 'activated'",
        "pki_host_local_certificate_interactive_confirmation is boolean",
        "pki_host_local_certificate_unattended_authorized is boolean",
        (
            "(pki_host_local_certificate_interactive_confirmation is sameas true "
            "and pki_host_local_certificate_unattended_authorized is sameas false) "
            "or (pki_host_local_certificate_interactive_confirmation is sameas false "
            "and pki_host_local_certificate_unattended_authorized is sameas true "
            "and pki_host_local_certificate_exchange_mode == 'direct')"
        ),
    }.issubset(activation_contract):
        raise BoundaryViolation("activation decision is overrideable")
    activation_confirmation_conditions = [
        "not ansible_check_mode",
        "pki_host_local_certificate_interactive_confirmation",
    ]
    for task_name in (
        "Confirm exact host-local certificate activation mutation",
        "Require exact host-local certificate activation confirmation",
    ):
        if _task_named(activation_tasks, task_name).get("when") != (
            activation_confirmation_conditions
        ):
            raise BoundaryViolation(
                f"{task_name} is not pinned to the interactive activation route"
            )
    activation_block = _task_named(
        activation_tasks,
        "Activate, validate, and finalize exact host-local certificate",
    )
    _validate_task(activation_block, role_dir / "tasks/activate.yml")
    if "smoke" in (role_dir / "tasks/activate.yml").read_text(encoding="utf-8").lower():
        raise BoundaryViolation("activation references a general registry smoke path")

    rolled_back_tasks = _load_yaml(
        role_dir / "tasks/publish_rolled_back_evidence.yml"
    )
    rolled_back_contract = _task_named(
        rolled_back_tasks,
        "Validate rolled-back evidence publication contract",
    )["ansible.builtin.assert"]["that"]
    if not {
        "pki_host_local_certificate_activation_action == 'abandon'",
        "pki_host_local_certificate_activation_result == 'rolled-back'",
        "pki_host_local_certificate_interactive_confirmation is sameas false",
        "pki_host_local_certificate_unattended_authorized is sameas false",
    }.issubset(rolled_back_contract):
        raise BoundaryViolation("rolled-back evidence dispatch is overrideable")

    read_only_phase_tasks = {
        name: _load_yaml(role_dir / f"tasks/{name}.yml")
        for name in ("status", "decision_preflight", "evidence_export")
    }
    forbidden_phase_actions = {"ansible.builtin.copy", "ansible.builtin.file"}
    for phase, phase_tasks in read_only_phase_tasks.items():
        unexpected = _actions_in(phase_tasks).intersection(forbidden_phase_actions)
        if unexpected:
            raise BoundaryViolation(
                f"{phase} directly mutates target files: {sorted(unexpected)}"
            )
    for phase in ("status", "evidence_export"):
        helper_import = _task_named(
            read_only_phase_tasks[phase],
            "Load host-local certificate lifecycle helper preflight",
        )
        if helper_import.get("vars") != {
            "pki_host_local_certificate_helper_read_only": True
        }:
            raise BoundaryViolation(f"{phase} does not require the existing helper")
    for phase, command_name in (
        ("status", "Read authenticated host-local certificate lifecycle status"),
        (
            "decision_preflight",
            "Revalidate exact exported active Zot endpoint from reviewed runner",
        ),
    ):
        read_only_command = _task_named(read_only_phase_tasks[phase], command_name)
        if (
            read_only_command.get("changed_when") is not False
            or read_only_command.get("check_mode") is not False
        ):
            raise BoundaryViolation(f"{phase} command is not pinned read-only")
    decision_status_task = _task_named(
        read_only_phase_tasks["decision_preflight"],
        "Require exact active and exported evidence identity",
    )
    decision_status_contract = "\n".join(
        decision_status_task["ansible.builtin.assert"]["that"]
    )
    for required_state in (
        "status in ['evidence-exported', 'complete']",
        "signer_outcome_state == 'unavailable'",
        "signer_outcome_state == 'finalized'",
    ):
        if required_state not in decision_status_contract:
            raise BoundaryViolation(
                "decision preflight does not preserve pre/post-finalization status"
            )
    validator_import = _task_named(
        read_only_phase_tasks["decision_preflight"],
        "Load reviewed runner validator helper preflight",
    )
    if validator_import.get("vars") != {
        "pki_host_local_certificate_helper_read_only": True
    }:
        raise BoundaryViolation("decision preflight can install its validator helper")

    zot_defaults = _load_yaml(repo_root / "roles/zot_registry/defaults/main.yml")
    if zot_defaults["zot_registry_tls_custody"] != "managed":
        raise BoundaryViolation("managed Zot TLS custody is not the default")
    zot_validation = (
        repo_root / "roles/zot_registry/tasks/validate_tls_custody.yml"
    ).read_text(encoding="utf-8")
    zot_resolution = (
        repo_root / "roles/zot_registry/tasks/resolve_tls_active_paths.yml"
    ).read_text(encoding="utf-8")
    if "zot_registry_tls_custody in ['managed', 'host-local']" not in zot_validation:
        raise BoundaryViolation("Zot host-local custody is not explicit")
    if zot_resolution.count("zot_registry_tls_custody == 'host-local'") != 4:
        raise BoundaryViolation("Zot active-path resolution is not pinned to host-local mode")

    lifecycle_path = role_dir / "files/platform-pki-host-local-lifecycle"
    lifecycle_text = lifecycle_path.read_text(encoding="utf-8")
    lifecycle_tree = ast.parse(lifecycle_text, filename=str(lifecycle_path))
    lifecycle_commands = {
        node.args[0].value
        for node in ast.walk(lifecycle_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_parser"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "commands"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    if lifecycle_commands != {
        "collection-prepare",
        "abandon-expired-request",
        "cancel-pending-request",
        "evidence-collection-prepare",
        "response-prepare",
        "response-install",
        "activate-start",
        "activate-finish",
        "recover",
        "status",
        "active-paths",
        "outcome-import",
        "outcome-preflight",
    }:
        raise BoundaryViolation("lifecycle helper command surface changed")
    lifecycle_functions = {
        node.name: node
        for node in lifecycle_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    reachable = set()
    pending = ["outcome_import", "outcome_preflight"]
    while pending:
        name = pending.pop()
        if name in reachable or name not in lifecycle_functions:
            continue
        reachable.add(name)
        pending.extend(
            call.func.id
            for call in ast.walk(lifecycle_functions[name])
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in lifecycle_functions
        )
    outcome_import_source = "\n".join(
        ast.get_source_segment(lifecycle_text, lifecycle_functions[name]) or ""
        for name in sorted(reachable)
    )
    for forbidden in ('"tls.key"', "'tls.key'", "PENDING_NAMES", "VERSION_NAMES"):
        if forbidden in outcome_import_source:
            raise BoundaryViolation(
                "outcome import call graph references candidate private-key state"
            )
    if "authenticate_active_public" not in reachable:
        raise BoundaryViolation(
            "scalar preflight does not authenticate active public state"
        )
    public_auth_calls = {
        call.func.id
        for call in ast.walk(lifecycle_functions["authenticate_active_public"])
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    if public_auth_calls & {
        "authenticate_active", "open_exact_tree", "scan", "validate_version"
    }:
        raise BoundaryViolation(
            "active public authentication can enumerate or open private version state"
        )
    public_open_calls = {
        call.func.id
        for call in ast.walk(lifecycle_functions["open_public_files"])
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    if public_open_calls & {"open_exact_tree", "scan", "validate_version"}:
        raise BoundaryViolation(
            "public file opener can enumerate private version state"
        )
    status_text = (role_dir / "tasks/status.yml").read_text(encoding="utf-8")
    for required_status in (
        "pki_host_local_certificate_status.signer_outcome_state in ['unavailable', 'finalized', 'abandoned']",
        "[complete, none]",
        "[signer-outcome-abandoned, none]",
    ):
        if required_status not in status_text:
            raise BoundaryViolation("signer-outcome status contract is incomplete")

    executable_sources = [
        *(role_dir / "tasks").glob("*.yml"),
        *(repo_root / "playbooks").glob("registry-pki-*.yml"),
        *(repo_root / "plugins/action").glob("platform_pki_*.py"),
        lifecycle_path,
    ]
    archive_pattern = re.compile(r"\b(?:archive|unarchive|tarfile)\b|\.tar(?:\.|\b)")
    for executable in executable_sources:
        executable_text = executable.read_text(encoding="utf-8")
        if archive_pattern.search(executable_text):
            raise BoundaryViolation(f"archive or tar handling is forbidden in {executable}")
        if executable.parent.name == "action" and "tls.key" in executable_text:
            raise BoundaryViolation(f"action plugin references private-key transfer in {executable}")

    trust_helper = role_dir / "files/platform-pki-host-local-trust"
    action_plugin = repo_root / "plugins/action/platform_pki_trust_ingress.py"
    if not trust_helper.is_file() or not trust_helper.stat().st_mode & 0o111:
        raise BoundaryViolation(
            "dedicated target trust helper is missing or not executable"
        )
    if not action_plugin.is_file():
        raise BoundaryViolation(
            "pinned controller trust ingress action plugin is missing"
        )

    trust_tasks = (role_dir / "tasks/trust.yml").read_text(encoding="utf-8")
    request_tasks = (role_dir / "tasks/request.yml").read_text(encoding="utf-8")
    request_apply_tasks = (role_dir / "tasks/request_apply.yml").read_text(
        encoding="utf-8"
    )
    if "platform-pki-host-local-trust" not in trust_tasks:
        raise BoundaryViolation(
            "trust action does not structurally dispatch the dedicated helper"
        )
    if "platform_pki_trust_ingress" not in trust_tasks:
        raise BoundaryViolation(
            "trust action does not structurally dispatch the pinned ingress action"
        )
    action_plugin_text = action_plugin.read_text(encoding="utf-8")
    secure_source_text = (
        repo_root / "plugins/module_utils/platform_pki_secure_source.py"
    ).read_text(encoding="utf-8")
    for fragment in (
        "source.recheck()",
        "self._transfer_data",
    ):
        if fragment not in action_plugin_text:
            raise BoundaryViolation(
                f"pinned ingress action is missing required boundary logic: {fragment}"
            )
    for fragment in ("O_NOFOLLOW", "REPOSITORY_ROOT", "PinnedSource"):
        if fragment not in secure_source_text:
            raise BoundaryViolation(
                f"shared source pinning is missing required boundary logic: {fragment}"
            )
    if "trust_sources" in request_apply_tasks:
        raise BoundaryViolation(
            "target request helper attempts to source controller trust"
        )
    for forbidden in ("tls.key", "request_signing_key", "private_key"):
        if forbidden in trust_tasks:
            raise BoundaryViolation(
                f"trust action references forbidden private-key material: {forbidden}"
            )


def test_registry_pki_source_boundary(repo_root: Path) -> None:
    assert_registry_pki_boundary(repo_root)


def _fake_podman(fake_bin: Path, log: Path) -> None:
    executable = fake_bin / "podman"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "if sys.argv[1:3] == ['image', 'exists']:\n"
        "    raise SystemExit(0)\n"
        "if sys.argv[1:2] != ['run']:\n"
        "    raise SystemExit(2)\n"
        "Path(os.environ['FAKE_PODMAN_LOG']).write_text(\n"
        "    json.dumps(sys.argv[1:]), encoding='utf-8'\n"
        ")\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)


def _container_wrapper_environment(tmp_path: Path, log: Path) -> dict[str, str]:
    private_root = tmp_path / "platform-private"
    secret_root = tmp_path / "platform-infrastructure"
    runtime_root = tmp_path / "runtime"
    fake_bin = tmp_path / "bin"
    for directory in (private_root, secret_root, runtime_root, fake_bin):
        directory.mkdir(mode=0o700)
    _fake_podman(fake_bin, log)
    return {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_PODMAN_LOG": str(log),
        "TMPDIR": str(runtime_root),
        "PLATFORM_CONFIG_CONTAINER_PROFILE": "development",
        "PLATFORM_CONFIG_DEV_IMAGE": "exchange-root-test",
        "PLATFORM_CONFIG_PRIVATE_ROOT": str(private_root),
        "PLATFORM_CONFIG_SECRET_ROOT": str(secret_root),
    }


def test_container_wrapper_mounts_only_validated_exchange_root_read_write(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    log = isolated_test_dir / "podman.json"
    environment = _container_wrapper_environment(isolated_test_dir, log)
    exchange_root = isolated_test_dir / "platform-infrastructure/pki-exchange"
    exchange_root.mkdir(mode=0o700)
    environment["PLATFORM_CONFIG_PKI_EXCHANGE_ROOT"] = str(exchange_root)

    command_runner.run(
        (repo_root / "scripts/in-container", "true"), environment=environment
    ).assert_success()
    arguments = json.loads(log.read_text(encoding="utf-8"))
    assert "PLATFORM_CONFIG_PKI_EXCHANGE_ROOT=/platform-pki-exchange" in arguments
    assert f"{exchange_root}:/platform-pki-exchange:rw,Z" in arguments
    assert (
        f"{isolated_test_dir}/platform-infrastructure:"
        "/tmp/platform-home/.config/platform-infrastructure:ro"
    ) in arguments


def test_container_wrapper_mounts_only_validated_outcome_directory_read_only(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    log = isolated_test_dir / "podman.json"
    environment = _container_wrapper_environment(isolated_test_dir, log)
    outcome_dir = isolated_test_dir / "outcome"
    outcome_dir.mkdir(mode=0o700)
    environment["PLATFORM_CONFIG_PKI_OUTCOME_DIR"] = str(outcome_dir)

    command_runner.run(
        (repo_root / "scripts/in-container", "true"), environment=environment
    ).assert_success()
    arguments = json.loads(log.read_text(encoding="utf-8"))
    assert "PLATFORM_CONFIG_PKI_OUTCOME_DIR=/platform-pki-outcome" in arguments
    assert f"{outcome_dir}:/platform-pki-outcome:ro,Z" in arguments


@pytest.mark.parametrize("unsafe_kind", ("mode", "symlink"))
def test_container_wrapper_rejects_unsafe_outcome_directory(
    unsafe_kind: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    log = isolated_test_dir / "podman.json"
    environment = _container_wrapper_environment(isolated_test_dir, log)
    actual = isolated_test_dir / "outcome-actual"
    actual.mkdir(mode=0o700)
    if unsafe_kind == "mode":
        actual.chmod(0o755)
        outcome_dir = actual
        expected = "current-user-owned with mode 0700"
    else:
        outcome_dir = isolated_test_dir / "outcome-link"
        outcome_dir.symlink_to(actual, target_is_directory=True)
        expected = "canonical non-symlink directory"
    environment["PLATFORM_CONFIG_PKI_OUTCOME_DIR"] = str(outcome_dir)

    result = command_runner.run(
        (repo_root / "scripts/in-container", "true"), environment=environment
    ).assert_failure()
    assert expected in result.stderr
    assert not log.exists()


@pytest.mark.parametrize("unsafe_kind", ("mode", "symlink"))
def test_container_wrapper_rejects_unsafe_exchange_root(
    unsafe_kind: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    log = isolated_test_dir / "podman.json"
    environment = _container_wrapper_environment(isolated_test_dir, log)
    actual = isolated_test_dir / "exchange-actual"
    actual.mkdir(mode=0o700)
    if unsafe_kind == "mode":
        actual.chmod(0o755)
        exchange_root = actual
        expected = "current-user-owned with mode 0700"
    else:
        exchange_root = isolated_test_dir / "exchange-link"
        exchange_root.symlink_to(actual, target_is_directory=True)
        expected = "canonical non-symlink directory"
    environment["PLATFORM_CONFIG_PKI_EXCHANGE_ROOT"] = str(exchange_root)

    result = command_runner.run(
        (repo_root / "scripts/in-container", "true"), environment=environment
    ).assert_failure()
    assert expected in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    ("unsafe_kind", "expected"),
    (
        ("relative", "canonical absolute path"),
        ("colon", "canonical absolute path"),
        ("control", "canonical absolute path"),
        ("noncanonical", "canonical non-symlink directory"),
        ("file", "canonical non-symlink directory"),
        ("protected-ancestor", "outside public and private repositories"),
    ),
)
def test_container_wrapper_rejects_unsafe_exchange_coordinates(
    unsafe_kind: str,
    expected: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    case_root = isolated_test_dir / unsafe_kind
    case_root.mkdir(mode=0o700)
    log = case_root / "podman.json"
    environment = _container_wrapper_environment(case_root, log)
    actual = case_root / "exchange"
    if unsafe_kind == "file":
        actual.write_text("not a directory\n", encoding="ascii")
        actual.chmod(0o600)
        exchange_root = str(actual)
    else:
        actual.mkdir(mode=0o700)
        if unsafe_kind == "relative":
            exchange_root = "exchange"
        elif unsafe_kind == "colon":
            exchange_root = f"{actual}:option"
        elif unsafe_kind == "control":
            exchange_root = f"{actual}\n"
        elif unsafe_kind == "noncanonical":
            exchange_root = f"{actual.parent}/../{actual.parent.name}/{actual.name}"
        else:
            exchange_root = str(case_root)
    environment["PLATFORM_CONFIG_PKI_EXCHANGE_ROOT"] = exchange_root

    result = command_runner.run(
        (repo_root / "scripts/in-container", "true"), environment=environment
    ).assert_failure()
    assert expected in result.stderr
    assert not log.exists()


def test_test_container_profile_never_exposes_exchange_root(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    log = isolated_test_dir / "podman.json"
    environment = _container_wrapper_environment(isolated_test_dir, log)
    exchange_root = isolated_test_dir / "platform-infrastructure/pki-exchange"
    exchange_root.mkdir(mode=0o700)
    environment.update(
        {
            "PLATFORM_CONFIG_CONTAINER_PROFILE": "test",
            "PLATFORM_CONFIG_PKI_EXCHANGE_ROOT": str(exchange_root),
            "PLATFORM_CONFIG_PKI_OUTCOME_DIR": str(exchange_root),
            "PLATFORM_CONFIG_TEST_SCRATCH_ROOT": str(isolated_test_dir / "runtime"),
        }
    )

    command_runner.run(
        (repo_root / "scripts/in-container", "true"), environment=environment
    ).assert_success()
    arguments = json.loads(log.read_text(encoding="utf-8"))
    assert not any("PLATFORM_CONFIG_PKI_EXCHANGE_ROOT" in value for value in arguments)
    assert not any("/platform-pki-exchange" in value for value in arguments)
    assert not any("PLATFORM_CONFIG_PKI_OUTCOME_DIR" in value for value in arguments)
    assert not any("/platform-pki-outcome" in value for value in arguments)


def test_registry_pki_epoch_conversion_is_timezone_independent(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    normalized_fragment = (
        "( (now(utc=true, fmt='%Y-%m-%d %H:%M:%S') | to_datetime) "
        "- ('1970-01-01 00:00:00' | to_datetime) ).total_seconds() | int"
    )
    for relative_path in (
        "roles/pki_host_local_certificate/tasks/decision_preflight.yml",
        "roles/pki_host_local_certificate/tasks/validate_validator_result.yml",
    ):
        source = (repo_root / relative_path).read_text(encoding="utf-8")
        assert "strftime('%s')" not in source
        assert normalized_fragment in " ".join(source.split())

    started = int(time.time())
    result = command_runner.run(
        (
            "ansible",
            "localhost",
            "-i",
            "localhost,",
            "-c",
            "local",
            "-m",
            "ansible.builtin.debug",
            "-a",
            f"msg={{{{ {normalized_fragment} }}}}",
        ),
        environment={"TZ": "America/New_York"},
    ).assert_success()
    finished = int(time.time())
    match = re.search(r"\bmsg: ([1-9][0-9]*)", result.stdout)
    assert match is not None
    assert started <= int(match.group(1)) <= finished


def test_registry_pki_make_guards_reject_shell_input_without_execution(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    marker = isolated_test_dir / "make-guard-injection"
    result = command_runner.run(
        (
            "make",
            "_guard-pki-limit",
            f"LIMIT=registry`touch {marker}`",
        ),
        cwd=repo_root,
    )

    result.assert_failure()
    assert not marker.exists()
    assert "canonical lowercase registry inventory host" in result.stderr


def test_registry_pki_unattended_activation_is_explicit_and_digest_pinned(
    repo_root: Path,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("registry-pki-activate-unattended:", 1)[1].split(
        "\n\n", 1
    )[0]

    for contract in (
        "_guard-pki-env",
        "_guard-pki-limit",
        "_guard-pki-request-id",
        "_guard-pki-artifact",
        "_guard-pki-runner",
        "pki_host_local_certificate_exchange_mode=direct",
        "@vars/registry-pki-activation-unattended.yml",
        "pki_host_local_certificate_request_id=$(REQUEST_ID)",
        "pki_host_local_certificate_artifact_manifest_sha256=$(ARTIFACT_SHA256)",
        "pki_host_local_certificate_remote_validator=$(RUNNER_LIMIT)",
    ):
        assert contract in target

    for target_name in (
        "registry-pki-activate:",
        "registry-pki-activate-controller-local:",
    ):
        interactive_target = makefile.split(target_name, 1)[1].split("\n\n", 1)[0]
        assert (
            "$(EXTRA_ARGS) -e pki_host_local_certificate_exchange_mode="
            in interactive_target
        )
        assert "@vars/registry-pki-activation-interactive.yml" in interactive_target
        for forced_value in (
            "pki_host_local_certificate_exchange_mode=",
            "@vars/registry-pki-activation-interactive.yml",
        ):
            assert interactive_target.index(
                "$(EXTRA_ARGS)"
            ) < interactive_target.index(forced_value)

    assert target.index("$(EXTRA_ARGS)") < target.index(
        "@vars/registry-pki-activation-unattended.yml"
    )

    interactive_vars = yaml.safe_load(
        (repo_root / "vars/registry-pki-activation-interactive.yml").read_text(
            encoding="utf-8"
        )
    )
    unattended_vars = yaml.safe_load(
        (repo_root / "vars/registry-pki-activation-unattended.yml").read_text(
            encoding="utf-8"
        )
    )
    assert interactive_vars == {
        "pki_host_local_certificate_interactive_confirmation": True,
        "pki_host_local_certificate_unattended_authorized": False,
    }
    assert unattended_vars == {
        "pki_host_local_certificate_interactive_confirmation": False,
        "pki_host_local_certificate_unattended_authorized": True,
    }


def test_registry_pki_wrapper_rejects_shell_env_without_execution(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    marker = isolated_test_dir / "make-env-injection"
    result = command_runner.run(
        (
            "make",
            "registry-pki-request",
            f"ENV=dev`touch {marker}`",
            "LIMIT=registry-one.test",
        ),
        cwd=repo_root,
    )

    result.assert_failure()
    assert not marker.exists()
    assert "canonical lowercase environment name" in result.stderr


def test_registry_pki_make_guards_accept_canonical_coordinates(
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    digest = "a" * 64
    command_runner.run(
        (
            "make",
            "_guard-pki-env",
            "_guard-pki-limit",
            "_guard-pki-request-id",
            "_guard-pki-request-sha256",
            "_guard-pki-request-ttl",
            "_guard-pki-artifact",
            "_guard-pki-deployment",
            "_guard-pki-outcome-dir",
            "_guard-pki-outcome",
            "_guard-pki-response-dir",
            "_guard-pki-runner",
            "LIMIT=registry-one.test",
            "ENV=dev",
            "RUNNER_LIMIT=runner-one.test",
            "REQUEST_ID=0123456789abcdef0123456789abcdef",
            f"REQUEST_SHA256={digest}",
            "REQUEST_TTL_SECONDS=604800",
            f"ARTIFACT_SHA256={digest}",
            f"DEPLOYMENT_SHA256={digest}",
            f"OUTCOME_SHA256={digest}",
            "OUTCOME_DIR=/outside-git/csr-outcomes/request-id",
            "RESPONSE_DIR=/outside-git/pki-response",
        ),
        cwd=repo_root,
    ).assert_success()


@pytest.mark.parametrize(
    "value",
    (
        "",
        "/",
        "relative/outcome",
        "/outside-git/outcome/",
        "/outside-git//outcome",
        "/outside-git/./outcome",
        "/outside-git/../outcome",
        "/outside git/outcome",
    ),
)
def test_registry_pki_outcome_directory_guard_rejects_noncanonical_paths(
    repo_root: Path,
    command_runner: CommandRunner,
    value: str,
) -> None:
    result = command_runner.run(
        ("make", "_guard-pki-outcome-dir", f"OUTCOME_DIR={value}"),
        cwd=repo_root,
    )

    result.assert_failure()
    assert "canonical absolute protected directory" in result.stderr


@pytest.mark.parametrize("value", ("0", "01", "604801", "not-a-number"))
def test_registry_pki_request_ttl_guard_rejects_invalid_values(
    repo_root: Path,
    command_runner: CommandRunner,
    value: str,
) -> None:
    result = command_runner.run(
        ("make", "_guard-pki-request-ttl", f"REQUEST_TTL_SECONDS={value}"),
        cwd=repo_root,
    )

    result.assert_failure()
    assert "canonical integer from 1 through 604800" in result.stderr


def test_one_runner_pty_waits_for_prompt_before_confirmation(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    confirmation = isolated_test_dir / "activation-confirmation"
    confirmation.write_text("activate registry-dev request artifact\n", encoding="ascii")
    confirmation.chmod(0o600)
    driver = (
        repo_root
        / "tests/fixtures/pki-host-local-zot-one-runner/pty_prompt.py"
    )
    child = (
        "import sys,termios,time; "
        "time.sleep(0.1); "
        "print('Type exactly activate ', flush=True); "
        "time.sleep(0.05); "
        "termios.tcflush(sys.stdin, termios.TCIFLUSH); "
        "print(input(), flush=True); "
        "sys.exit(0)"
    )

    result = command_runner.run(
        (
            sys.executable,
            driver,
            "--prompt",
            "Type exactly activate ",
            "--input-file",
            confirmation,
            "--timeout",
            "5",
            "--",
            sys.executable,
            "-c",
            child,
        ),
        cwd=repo_root,
    ).assert_success()

    assert "Type exactly activate" in result.stdout
    assert "activate registry-dev request artifact" in result.stdout


@pytest.mark.parametrize(
    "remote_path",
    [
        request_collection_action._remote_path,
        evidence_collection_action._remote_path,
    ],
)
def test_registry_pki_fetch_allowlists_reject_private_key(remote_path: Any) -> None:
    with pytest.raises(request_collection_action.AnsibleActionFail):
        remote_path("/tmp/action-owned", "tls.key")


@pytest.mark.parametrize(
    "bad_task",
    [
        {"name": "short action", "copy": {"src": "tls.key"}},
        {"name": "fetch private key", "ansible.builtin.fetch": {"src": "tls.key"}},
        {"name": "slurp private key", "ansible.builtin.slurp": {"src": "tls.key"}},
        {"name": "archive intake", "ansible.builtin.unarchive": {"src": "pki.tar"}},
        {"name": "shell command", "ansible.builtin.shell": "id"},
        {"name": "raw command", "ansible.builtin.raw": "id"},
        {"name": "URI download", "ansible.builtin.uri": {"url": "https://example"}},
        {
            "name": "download",
            "ansible.builtin.get_url": {"url": "https://example", "dest": "/tmp/x"},
        },
        {"name": "debug disclosure", "ansible.builtin.debug": {"var": "secret"}},
        {"name": "foreign action", "community.crypto.openssl_privatekey": {}},
        {"name": "dynamic action", "action": "copy src=tls.key dest=/tmp/key"},
        {"name": "dynamic local action", "local_action": "command id"},
        {
            "name": "nested action",
            "block": [{"ansible.builtin.copy": {"src": "tls.key"}}],
        },
        {
            "name": "concealed private transfer",
            "ansible.builtin.copy": {"content": "private", "dest": "/tmp/tls.key"},
        },
        {
            "name": "wildcard transfer",
            "ansible.builtin.copy": {"src": "response/*", "dest": "/tmp"},
        },
        {
            "name": "recursive transfer",
            "ansible.builtin.copy": {"src": "response/", "dest": "/tmp"},
        },
        {
            "name": "Install host-local certificate request helper",
            "ansible.builtin.copy": {
                "content": "{{ pki_host_local_certificate_request_signing_key }}",
                "dest": "{{ pki_host_local_certificate_request_helper_path }}",
                "owner": "root",
                "group": "root",
                "mode": "0755",
            },
            "when": "not ansible_check_mode",
        },
        {
            "name": "foreign argv command",
            "ansible.builtin.command": {"argv": ["/bin/true"]},
        },
        {
            "name": "Read authenticated host-local certificate lifecycle status",
            "ansible.builtin.command": {
                "argv": [
                    "{{ pki_host_local_certificate_lifecycle_helper_path }}",
                    "status",
                    "--newest",
                ]
            },
        },
        {
            "name": "arbitrary file mutation",
            "ansible.builtin.file": {"path": "/tmp/pki", "state": "absent"},
        },
        {"name": "foreign custom action", "unsafe_local_action": {}},
        {
            "name": "misnamed trust ingress",
            "platform_pki_trust_ingress": {
                "sources": {},
                "sha256": {},
                "ingress_root": "/tmp",
            },
        },
        {
            "name": "Transfer exact controller response into protected target ingress",
            "platform_pki_response_ingress": {
                "exchange_root": "/tmp/exchange",
                "service": "registry-dev",
                "request_id": "0" * 32,
                "ingress_root": "/etc/zot/tls-versions/.ingress-" + "0" * 32,
                "artifact_sha256": "0" * 64,
                "private_key": "/etc/zot/tls.key",
            },
            "register": "result",
            "when": [
                "not ansible_check_mode",
                "(pki_host_local_certificate_response_prepare_result.stdout | from_json).status != 'installed'",
            ],
        },
        {"name": "foreign import", "ansible.builtin.import_tasks": "mutate.yml"},
        {
            "name": "controller lookup",
            "ansible.builtin.assert": {"that": ["lookup('pipe', 'id')"]},
        },
        {
            "name": "parenthesized lookup",
            "ansible.builtin.assert": {"that": ["(lookup)('pipe', 'id')"]},
        },
        {
            "name": "parenthesized query",
            "ansible.builtin.assert": {"that": ["(query)('pipe', 'id')"]},
        },
        {
            "name": "parenthesized q",
            "ansible.builtin.assert": {"that": ["(q)('pipe', 'id')"]},
        },
        {
            "name": "ignored failure",
            "ansible.builtin.fail": {"msg": "stop"},
            "ignore_errors": True,
        },
        {
            "name": "diff disclosure",
            "ansible.builtin.assert": {"that": [True]},
            "diff": True,
        },
        {
            "name": "hidden unsafe task",
            "ansible.builtin.assert": {"that": [True]},
            "no_log": True,
        },
        {
            "name": "skipped assertion",
            "ansible.builtin.assert": {"that": [True]},
            "when": False,
        },
        {
            "name": "target stat with controller privilege override",
            "ansible.builtin.stat": {"path": "/tmp/example"},
            "vars": {"ansible_become": False},
        },
    ],
    ids=lambda task: str(task["name"]),
)
def test_registry_pki_task_scanner_rejects_unsafe_examples(
    bad_task: dict[str, Any],
) -> None:
    with pytest.raises(BoundaryViolation):
        _validate_task(bad_task, "scanner self-test")


@pytest.mark.parametrize(
    ("filename", "task_name"),
    [
        (
            "request_apply.yml",
            "Inspect shipped host-local certificate request helper source",
        ),
        (
            "lifecycle_helper.yml",
            "Inspect shipped host-local certificate lifecycle helper source",
        ),
        (
            "validator_helper.yml",
            "Inspect shipped host-local certificate validator helper source",
        ),
        (
            "request_intake.yml",
            "Authenticate and publish exact direct request intake",
        ),
        (
            "evidence_intake.yml",
            "Authenticate and publish exact direct evidence intake",
        ),
        (
            "response_check.yml",
            "Authenticate and snapshot exact controller-side certificate response",
        ),
        ("status.yml", "Authenticate exact controller evidence publication"),
    ],
)
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("delegate_to", None),
        ("delegate_to", "{{ inventory_hostname }}"),
        ("become", True),
        ("vars", {}),
        ("vars", {"ansible_become": True}),
    ],
)
def test_registry_pki_task_scanner_rejects_controller_execution_drift(
    repo_root: Path,
    filename: str,
    task_name: str,
    field: str,
    value: Any,
) -> None:
    tasks = _load_yaml(
        repo_root / "roles/pki_host_local_certificate/tasks" / filename
    )
    task = copy.deepcopy(next(item for item in tasks if item["name"] == task_name))
    if value is None:
        task.pop(field)
    else:
        task[field] = value
    with pytest.raises(BoundaryViolation):
        _validate_task(task, "scanner self-test")


@pytest.mark.parametrize(
    "bad_playbook",
    [
        [{"import_playbook": "mutate.yml"}],
        [{"hosts": "registry", "gather_facts": False, "roles": ["mutating_role"]}],
        [
            {"hosts": "registry", "gather_facts": False, "tasks": []},
            {
                "hosts": "registry",
                "gather_facts": False,
                "roles": ["mutating_role"],
            },
        ],
        [
            {
                "name": "{{ lookup('pipe', 'id') }}",
                "hosts": "registry",
                "become": True,
                "gather_facts": False,
                "tasks": [
                    {
                        "name": "request",
                        "ansible.builtin.include_role": {
                            "name": "pki_host_local_certificate",
                            "tasks_from": "request",
                        },
                    }
                ],
            }
        ],
        [
            {
                "name": "request",
                "hosts": "registry",
                "become": True,
                "gather_facts": False,
                "tasks": [
                    {
                        "name": "{{ query('pipe', 'id') }}",
                        "ansible.builtin.include_role": {
                            "name": "pki_host_local_certificate",
                            "tasks_from": "request",
                        },
                    }
                ],
            }
        ],
    ],
)
def test_registry_pki_playbook_scanner_rejects_unsafe_examples(
    bad_playbook: list[dict[str, Any]],
) -> None:
    with pytest.raises(BoundaryViolation):
        _validate_operator_playbook(bad_playbook, "request", "scanner self-test")


def test_registry_pki_check_mode_boundaries(
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    command_runner.run(
        [
            "ansible-playbook",
            "--check",
            "-i",
            str(repo_root / "tests/fixtures/registry-pki-boundary/inventory.yml"),
            str(repo_root / "tests/fixtures/registry-pki-boundary/integration.yml"),
        ],
        timeout=120,
    ).assert_success()
