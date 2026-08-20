from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


REQUEST_ID = "0123456789abcdef0123456789abcdef"
VERSIONS_ROOT = "/etc/zot/tls-versions"
FULLCHAIN_PATH = f"{VERSIONS_ROOT}/{REQUEST_ID}/fullchain.crt"
KEY_PATH = f"{VERSIONS_ROOT}/{REQUEST_ID}/tls.key"
DIGEST = "a" * 64
V2_HELPER_SHA256 = (
    "3044058c3d4884a3ab1d51f1dc128a5c84407e387d2805fa99087c65d98eb280"
)
V3_HELPER_SHA256 = (
    "9b6c62c6380fb1ab00e0a10dc5905ec4f88af2b57b503c1b44ec4db497b68fb3"
)
MANAGED_RESULT = {
    "schema": "1",
    "kind": "platform-config-zot-tls-custody",
    "custody": "managed",
    "request_id": "none",
    "cert_path": "/etc/zot/tls/tls.crt",
    "key_path": "/etc/zot/tls/tls.key",
    "artifact_sha256": "none",
    "certificate_sha256": "none",
    "spki_sha256": "none",
    "chain_sha256": "none",
    "fullchain_sha256": "none",
    "zot_config_sha256": DIGEST,
}
HOST_LOCAL_RESULT = {
    **MANAGED_RESULT,
    "custody": "host-local",
    "request_id": REQUEST_ID,
    "cert_path": FULLCHAIN_PATH,
    "key_path": KEY_PATH,
    "artifact_sha256": DIGEST,
    "certificate_sha256": DIGEST,
    "spki_sha256": DIGEST,
    "chain_sha256": DIGEST,
    "fullchain_sha256": DIGEST,
}
MANAGED_SOURCES = {
    "zot_registry_tls_cert_src": "/controller/tls.crt",
    "zot_registry_tls_key_src": "/controller/tls.key",
}


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _write_playbook(path: Path, play: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump([play], sort_keys=False), encoding="utf-8")


def _role_tasks_playbook(path: Path, tasks_from: str) -> None:
    _write_playbook(
        path,
        {
            "name": "Exercise focused Zot TLS custody tasks",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "tasks": [
                {
                    "name": "Load focused Zot TLS custody tasks",
                    "ansible.builtin.include_role": {
                        "name": "zot_registry",
                        "tasks_from": tasks_from,
                    },
                }
            ],
        },
    )


def _render_config(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
    case_id: str,
    extra_vars: dict[str, Any],
) -> dict[str, Any]:
    playbook = isolated_test_dir / f"render-{case_id}.yml"
    output = isolated_test_dir / f"config-{case_id}.json"
    role = repo_root / "roles/zot_registry"
    _write_playbook(
        playbook,
        {
            "name": "Render focused Zot configuration",
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": {"zot_registry_test_output": str(output)},
            "tasks": [
                {
                    "name": "Load Zot defaults",
                    "ansible.builtin.include_vars": {
                        "file": str(role / "defaults/main.yml")
                    },
                },
                {
                    "name": "Render Zot configuration",
                    "ansible.builtin.template": {
                        "src": str(role / "templates/config.json.j2"),
                        "dest": "{{ zot_registry_test_output }}",
                        "mode": "0600",
                    },
                },
            ],
        },
    )
    run_playbook(command_runner, playbook, extra_vars=(extra_vars,)).assert_success()
    return json.loads(output.read_text(encoding="utf-8"))


def _command_result(value: Any, *, stderr: str = "") -> dict[str, Any]:
    stdout = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return {"rc": 0, "stdout": stdout, "stderr": stderr}


def _helper_stat(checksum: str, *, mode: str = "0755") -> dict[str, Any]:
    return {
        "exists": True,
        "isreg": True,
        "islnk": False,
        "uid": 0,
        "gid": 0,
        "mode": mode,
        "checksum": checksum,
    }


def _source_stat(checksum: str = V3_HELPER_SHA256) -> dict[str, Any]:
    return {
        "exists": True,
        "isreg": True,
        "islnk": False,
        "checksum": checksum,
    }


def test_zot_tls_defaults_remove_inventory_custody_and_pin_lifecycle_inputs(
    repo_root: Path,
) -> None:
    defaults = _load_yaml(repo_root / "roles/zot_registry/defaults/main.yml")

    assert "zot_registry_tls_custody" not in defaults
    assert defaults["zot_registry_tls_cert_path"] == "{{ zot_registry_tls_dir }}/tls.crt"
    assert defaults["zot_registry_tls_key_path"] == "{{ zot_registry_tls_dir }}/tls.key"
    assert defaults["zot_registry_tls_host_local_lifecycle_helper_path"] == (
        "/usr/local/libexec/platform-pki-host-local-lifecycle"
    )
    assert defaults["zot_registry_tls_host_local_state_root"] == (
        "/var/lib/platform-config/pki/host-local/registry-dev"
    )
    assert defaults["zot_registry_tls_host_local_pending_root"] == (
        "/etc/zot/tls-pending"
    )
    assert defaults["zot_registry_tls_host_local_versions_root"] == VERSIONS_ROOT
    assert defaults["zot_registry_tls_host_local_service"] == "registry-dev"
    assert defaults["zot_registry_tls_host_local_target"] == "{{ inventory_hostname }}"
    assert defaults["zot_registry_tls_host_local_zot_config_path"] == (
        "/etc/zot/config.json"
    )
    helper = (
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    )
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == V3_HELPER_SHA256


def test_zot_tls_tasks_derive_custody_without_error_fallback(repo_root: Path) -> None:
    role = repo_root / "roles/zot_registry"
    main_tasks = _load_yaml(role / "tasks/main.yml")
    resolve_tasks = _load_yaml(role / "tasks/resolve_tls_custody.yml")
    main_by_name = {task["name"]: task for task in main_tasks}
    resolve_by_name = {task["name"]: task for task in resolve_tasks}

    assert main_tasks[0]["ansible.builtin.import_tasks"] == "validate_tls_custody.yml"
    assert main_tasks[1]["ansible.builtin.import_tasks"] == "resolve_tls_custody.yml"
    assert list(main_by_name).index("Resolve Zot TLS custody") < list(main_by_name).index(
        "Preview the authenticated host-local Zot configuration"
    )
    assert main_by_name["Write Zot configuration"]["when"] == (
        "zot_registry_tls_effective_custody == 'managed'"
    )
    for name in ("Copy Zot TLS certificate", "Copy Zot TLS private key"):
        assert main_by_name[name]["when"] == [
            "zot_registry_tls_enabled | bool",
            "zot_registry_tls_effective_custody == 'managed'",
        ]

    command = resolve_by_name[
        "Derive Zot TLS custody from initialized lifecycle state"
    ]
    assert command["ansible.builtin.command"]["argv"] == [
        "{{ zot_registry_tls_host_local_lifecycle_helper_path }}",
        "zot-custody",
        "--state-root",
        "{{ zot_registry_tls_host_local_state_root }}",
        "--pending-root",
        "{{ zot_registry_tls_host_local_pending_root }}",
        "--versions-root",
        "{{ zot_registry_tls_host_local_versions_root }}",
        "--service",
        "{{ zot_registry_tls_host_local_service }}",
        "--target",
        "{{ zot_registry_tls_host_local_target }}",
        "--zot-config",
        "{{ zot_registry_tls_host_local_zot_config_path }}",
        "--managed-cert",
        "{{ zot_registry_tls_cert_path }}",
        "--managed-key",
        "{{ zot_registry_tls_key_path }}",
        "--managed-config-sha256",
        "{{ zot_registry_tls_managed_config_sha256 }}",
    ]
    assert command["changed_when"] is False
    assert command["check_mode"] is False
    assert "failed_when" not in command
    assert command["when"] == [
        "zot_registry_tls_enabled | bool",
        "zot_registry_tls_custody_state.state_root.exists",
    ]
    assert not any("rescue" in task or "ignore_errors" in task for task in resolve_tasks)

    task_names = list(resolve_by_name)
    validate_index = task_names.index(
        "Validate trusted Zot TLS lifecycle helper upgrade state"
    )
    upgrade_index = task_names.index(
        "Upgrade trusted predecessor Zot TLS lifecycle helper"
    )
    refresh_index = task_names.index(
        "Refresh installed Zot TLS lifecycle helper state"
    )
    require_index = task_names.index(
        "Require exact current Zot TLS lifecycle helper before custody selection"
    )
    selector_index = task_names.index(
        "Derive Zot TLS custody from initialized lifecycle state"
    )
    assert (
        validate_index
        < upgrade_index
        < refresh_index
        < require_index
        < selector_index
    )

    upgrade = resolve_by_name[
        "Upgrade trusted predecessor Zot TLS lifecycle helper"
    ]
    assert upgrade["ansible.builtin.copy"] == {
        "src": "{{ role_path }}/../pki_host_local_certificate/files/platform-pki-host-local-lifecycle",
        "dest": "{{ zot_registry_tls_host_local_lifecycle_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    }
    assert upgrade["when"] == [
        "zot_registry_tls_enabled | bool",
        "not ansible_check_mode",
        "zot_registry_tls_custody_state.helper.exists",
        f"zot_registry_tls_custody_state.helper.checksum == '{V2_HELPER_SHA256}'",
    ]

    refreshed = resolve_by_name["Refresh installed Zot TLS lifecycle helper state"]
    assert refreshed["ansible.builtin.stat"]["checksum_algorithm"] == "sha256"
    current = resolve_by_name[
        "Require exact current Zot TLS lifecycle helper before custody selection"
    ]
    current_contract = "\n".join(current["ansible.builtin.assert"]["that"])
    assert "root:root 0755" in current["ansible.builtin.assert"]["fail_msg"]
    assert V3_HELPER_SHA256 in current_contract
    assert current["when"] == [
        "zot_registry_tls_enabled | bool",
        "zot_registry_tls_custody_state.state_root.exists",
    ]

    fresh = resolve_by_name["Require unambiguous fresh Zot TLS bootstrap state"]
    fresh_contract = "\n".join(fresh["ansible.builtin.assert"]["that"])
    assert "pending_root.exists" in fresh_contract
    assert "versions_root.exists" in fresh_contract
    assert "config.checksum" in fresh_contract
    assert "zot_registry_tls_managed_config_sha256" in fresh_contract


def test_zot_tls_custody_result_contract_is_exact(repo_root: Path) -> None:
    task = _load_yaml(
        repo_root / "roles/zot_registry/tasks/validate_tls_custody_result.yml"
    )[0]
    fields = task["vars"]["zot_registry_tls_custody_required_fields"]
    expressions = task["ansible.builtin.assert"]["that"]

    assert fields == sorted(MANAGED_RESULT)
    assert any("stderr == ''" in expression for expression in expressions)
    assert any("custody in ['managed', 'host-local']" in expression for expression in expressions)
    assert any("/fullchain.crt" in expression for expression in expressions)
    assert any("/tls.key" in expression for expression in expressions)


def test_zot_tls_input_validation_accepts_required_bootstrap_sources(
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "validate.yml"
    _role_tasks_playbook(playbook, "validate_tls_custody")

    run_playbook(
        command_runner, playbook, extra_vars=(MANAGED_SOURCES,)
    ).assert_success()


@pytest.mark.parametrize(
    ("case_id", "extra_vars", "message"),
    [
        ("missing-sources", {}, "remain required"),
        (
            "inventory-custody",
            {**MANAGED_SOURCES, "zot_registry_tls_custody": "managed"},
            "no longer an inventory choice",
        ),
        (
            "missing-target",
            {**MANAGED_SOURCES, "zot_registry_tls_host_local_target": ""},
            "canonical custody contract",
        ),
        (
            "wrong-root",
            {
                **MANAGED_SOURCES,
                "zot_registry_tls_host_local_versions_root": "/etc/zot/other",
            },
            "canonical custody contract",
        ),
        (
            "moving-alias",
            {
                **MANAGED_SOURCES,
                "zot_registry_tls_host_local_state_root": "/var/lib/pki/current",
                "zot_registry_tls_host_local_service": "synthetic",
            },
            "canonical custody contract",
        ),
        (
            "wrong-helper",
            {
                **MANAGED_SOURCES,
                "zot_registry_tls_host_local_lifecycle_helper_path": "/tmp/helper",
            },
            "canonical custody contract",
        ),
        (
            "wrong-config",
            {
                **MANAGED_SOURCES,
                "zot_registry_tls_host_local_zot_config_path": "/tmp/config.json",
            },
            "canonical custody contract",
        ),
        (
            "wrong-managed-path",
            {**MANAGED_SOURCES, "zot_registry_tls_cert_path": "/tmp/tls.crt"},
            "canonical custody contract",
        ),
    ],
)
def test_zot_tls_input_validation_fails_closed(
    case_id: str,
    extra_vars: dict[str, Any],
    message: str,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / f"validate-{case_id}.yml"
    _role_tasks_playbook(playbook, "validate_tls_custody")

    result = run_playbook(command_runner, playbook, extra_vars=(extra_vars,))
    assert_failed_with(result, message)


@pytest.mark.parametrize(
    (
        "case_id",
        "state_exists",
        "helper_checksum",
        "helper_mode",
        "source_checksum",
        "valid",
    ),
    [
        ("fresh-absent", False, None, "0755", V3_HELPER_SHA256, True),
        ("initialized-absent", True, None, "0755", V3_HELPER_SHA256, False),
        (
            "unknown-checksum",
            True,
            "b" * 64,
            "0755",
            V3_HELPER_SHA256,
            False,
        ),
        (
            "unsafe-predecessor",
            True,
            V2_HELPER_SHA256,
            "0775",
            V3_HELPER_SHA256,
            False,
        ),
        (
            "initialized-current",
            True,
            V3_HELPER_SHA256,
            "0755",
            V3_HELPER_SHA256,
            True,
        ),
        (
            "initialized-predecessor",
            True,
            V2_HELPER_SHA256,
            "0755",
            V3_HELPER_SHA256,
            True,
        ),
        (
            "source-drift",
            True,
            V2_HELPER_SHA256,
            "0755",
            "c" * 64,
            False,
        ),
    ],
)
def test_zot_tls_helper_absence_and_drift_are_state_sensitive(
    case_id: str,
    state_exists: bool,
    helper_checksum: str | None,
    helper_mode: str,
    source_checksum: str,
    valid: bool,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / f"helper-{case_id}.yml"
    _role_tasks_playbook(playbook, "validate_tls_lifecycle_helper")
    helper = (
        {"exists": False}
        if helper_checksum is None
        else _helper_stat(helper_checksum, mode=helper_mode)
    )
    result = run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {
                "zot_registry_tls_custody_state": {
                    "state_root": {"exists": state_exists},
                    "helper": helper,
                },
                "zot_registry_tls_lifecycle_helper_source": {
                    "stat": _source_stat(source_checksum)
                },
            },
        ),
    )

    if valid:
        result.assert_success()
    else:
        assert_failed_with(result, "fail closed")


@pytest.mark.parametrize(
    ("checksum", "valid"),
    ((V3_HELPER_SHA256, True), (V2_HELPER_SHA256, False)),
    ids=("current", "predecessor"),
)
def test_zot_tls_helper_check_mode_requires_current_without_mutation(
    checksum: str,
    valid: bool,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / f"helper-check-{checksum[:8]}.yml"
    _role_tasks_playbook(playbook, "validate_tls_lifecycle_helper")
    variables = {
        "zot_registry_tls_custody_state": {
            "state_root": {"exists": True},
            "helper": _helper_stat(checksum),
        },
        "zot_registry_tls_lifecycle_helper_source": {
            "stat": _source_stat()
        },
    }
    result = command_runner.run(
        [
            "ansible-playbook",
            playbook,
            "--check",
            "--extra-vars",
            json.dumps(variables, separators=(",", ":"), sort_keys=True),
        ]
    )

    if valid:
        result.assert_success()
    else:
        assert_failed_with(result, "check mode")


def test_zot_read_only_helper_validation_remains_exact(repo_root: Path) -> None:
    tasks = _load_yaml(
        repo_root / "roles/pki_host_local_certificate/tasks/lifecycle_helper.yml"
    )
    read_only = {task["name"]: task for task in tasks}[
        "Require installed lifecycle helper for read-only preflight"
    ]
    contract = "\n".join(read_only["ansible.builtin.assert"]["that"])

    assert "installed_lifecycle_helper.stat.checksum" in contract
    assert "lifecycle_helper_source.stat.checksum" in contract
    assert V2_HELPER_SHA256 not in contract
    assert read_only["when"] == (
        "ansible_check_mode or pki_host_local_certificate_helper_read_only"
    )


@pytest.mark.parametrize("result", (MANAGED_RESULT, HOST_LOCAL_RESULT), ids=("managed", "host-local"))
def test_zot_tls_custody_result_accepts_exact_schemas(
    result: dict[str, Any],
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / f"result-{result['custody']}.yml"
    _role_tasks_playbook(playbook, "validate_tls_custody_result")

    run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {
                "zot_registry_tls_custody_result": _command_result(result),
                "zot_registry_tls_managed_config_sha256": DIGEST,
            },
        ),
    ).assert_success()


@pytest.mark.parametrize(
    "result",
    [
        _command_result({}),
        _command_result("not-json"),
        _command_result({**HOST_LOCAL_RESULT, "cert_path": "/etc/zot/tls-versions/current/fullchain.crt"}),
        _command_result({**MANAGED_RESULT, "unexpected": "field"}),
        _command_result(MANAGED_RESULT, stderr="unexpected diagnostic"),
        _command_result({**MANAGED_RESULT, "custody": "host-local"}),
    ],
    ids=("missing-fields", "malformed-json", "ambiguous-path", "extra-field", "stderr", "mixed-schema"),
)
def test_zot_tls_custody_result_rejects_malformed_or_ambiguous_output(
    result: dict[str, Any],
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "result-invalid.yml"
    _role_tasks_playbook(playbook, "validate_tls_custody_result")

    run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {
                "zot_registry_tls_custody_result": result,
                "zot_registry_tls_managed_config_sha256": DIGEST,
            },
        ),
    ).assert_failure()


@pytest.mark.parametrize(
    ("case_id", "cert_path", "key_path"),
    (
        ("managed", "/etc/zot/tls/tls.crt", "/etc/zot/tls/tls.key"),
        ("host-local", FULLCHAIN_PATH, KEY_PATH),
    ),
)
def test_zot_tls_render_uses_only_derived_exact_paths(
    case_id: str,
    cert_path: str,
    key_path: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    config = _render_config(
        repo_root,
        command_runner,
        isolated_test_dir,
        case_id,
        {
            "zot_registry_tls_effective_cert_path": cert_path,
            "zot_registry_tls_effective_key_path": key_path,
            "zot_registry_extra_config": {
                "http": {"tls": {"cert": "/ambiguous", "key": "/ambiguous"}}
            },
        },
    )

    assert config["http"]["tls"] == {"cert": cert_path, "key": key_path}
