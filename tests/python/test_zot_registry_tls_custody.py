from __future__ import annotations

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
ACTIVE_PATHS = {
    "request_id": REQUEST_ID,
    "cert_path": FULLCHAIN_PATH,
    "key_path": KEY_PATH,
    "artifact_sha256": DIGEST,
    "certificate_sha256": DIGEST,
    "spki_sha256": DIGEST,
    "chain_sha256": DIGEST,
    "fullchain_sha256": DIGEST,
    "zot_config_sha256": DIGEST,
}
HOST_LOCAL_VARS = {
    "zot_registry_tls_custody": "host-local",
    "zot_registry_tls_host_local_target": "localhost",
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


def _active_result(value: Any, *, stderr: str = "") -> dict[str, Any]:
    stdout = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return {"rc": 0, "stdout": stdout, "stderr": stderr}


def test_zot_tls_custody_defaults_to_managed_with_canonical_lookup_inputs(
    repo_root: Path,
) -> None:
    defaults = _load_yaml(repo_root / "roles/zot_registry/defaults/main.yml")

    assert defaults["zot_registry_tls_custody"] == "managed"
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
    assert defaults["zot_registry_tls_host_local_target"] == ""
    assert defaults["zot_registry_tls_host_local_zot_config_path"] == (
        "/etc/zot/config.json"
    )
    assert "zot_registry_tls_host_local_fullchain_path" not in defaults
    assert "zot_registry_tls_host_local_key_path" not in defaults


def test_zot_tls_tasks_use_read_only_authenticated_lookup_only_for_host_local(
    repo_root: Path,
) -> None:
    role = repo_root / "roles/zot_registry"
    main_tasks = _load_yaml(role / "tasks/main.yml")
    resolve_tasks = _load_yaml(role / "tasks/resolve_tls_active_paths.yml")
    main_by_name = {task["name"]: task for task in main_tasks}
    resolve_by_name = {task["name"]: task for task in resolve_tasks}
    host_local_when = [
        "zot_registry_tls_enabled | bool",
        "zot_registry_tls_custody == 'host-local'",
    ]

    assert main_tasks[0]["ansible.builtin.import_tasks"] == (
        "validate_tls_custody.yml"
    )
    assert main_tasks[1]["ansible.builtin.import_tasks"] == (
        "resolve_tls_active_paths.yml"
    )
    assert list(main_by_name).index("Resolve Zot TLS active paths") < list(
        main_by_name
    ).index("Preview the authenticated host-local Zot configuration")

    preview_task = main_by_name["Preview the authenticated host-local Zot configuration"]
    assert preview_task["check_mode"] is True
    assert preview_task["diff"] is False
    assert preview_task["when"] == host_local_when
    assert main_by_name["Refuse host-local Zot configuration drift"]["when"] == (
        host_local_when
    )
    assert list(main_by_name).index("Refuse host-local Zot configuration drift") < list(
        main_by_name
    ).index("Assert Zot htpasswd source file is configured")
    assert main_by_name["Write Zot configuration"]["when"] == (
        "zot_registry_tls_custody == 'managed'"
    )

    command_task = resolve_by_name["Resolve authenticated Zot TLS active paths"]
    assert command_task["ansible.builtin.command"]["argv"] == [
        "{{ zot_registry_tls_host_local_lifecycle_helper_path }}",
        "active-paths",
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
    ]
    assert command_task["check_mode"] is False
    assert command_task["changed_when"] is False
    assert command_task["when"] == host_local_when
    for task in resolve_tasks:
        assert task["when"] == host_local_when

    for name in ("Copy Zot TLS certificate", "Copy Zot TLS private key"):
        assert main_by_name[name]["when"] == [
            "zot_registry_tls_enabled | bool",
            "zot_registry_tls_custody == 'managed'",
        ]


def test_zot_tls_lookup_result_contract_is_exact(repo_root: Path) -> None:
    tasks = _load_yaml(
        repo_root / "roles/zot_registry/tasks/validate_tls_active_paths.yml"
    )
    assertion = tasks[0]["ansible.builtin.assert"]
    expressions = assertion["that"]
    fields = tasks[0]["vars"]["zot_registry_tls_active_paths_required_fields"]

    assert fields == sorted(ACTIVE_PATHS)
    assert any("stderr == ''" in expression for expression in expressions)
    assert sum("is match('^[0-9a-f]{64}$')" in item for item in expressions) == 6
    assert any("/fullchain.crt" in expression for expression in expressions)
    assert any("/tls.key" in expression for expression in expressions)


@pytest.mark.parametrize(
    "extra_vars",
    [
        {
            "zot_registry_tls_custody": "managed",
            "zot_registry_tls_cert_src": "/controller/tls.crt",
            "zot_registry_tls_key_src": "/controller/tls.key",
        },
        HOST_LOCAL_VARS,
    ],
    ids=("managed", "host-local"),
)
def test_zot_tls_custody_validation_accepts_exact_inputs(
    extra_vars: dict[str, Any],
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "validate.yml"
    _role_tasks_playbook(playbook, "validate_tls_custody")

    run_playbook(command_runner, playbook, extra_vars=(extra_vars,)).assert_success()


@pytest.mark.parametrize(
    ("case_id", "extra_vars", "message"),
    [
        (
            "managed-missing-sources",
            {},
            "required when TLS is enabled",
        ),
        (
            "unsupported",
            {"zot_registry_tls_custody": "external"},
            "must be managed or host-local",
        ),
        (
            "missing-target",
            {"zot_registry_tls_custody": "host-local"},
            "canonical lifecycle contract",
        ),
        (
            "host-local-disabled",
            {
                **HOST_LOCAL_VARS,
                "zot_registry_tls_enabled": False,
            },
            "requires Zot TLS to be enabled",
        ),
        (
            "wrong-registry-root",
            {
                **HOST_LOCAL_VARS,
                "zot_registry_tls_host_local_versions_root": "/etc/zot/other",
            },
            "canonical lifecycle contract",
        ),
        (
            "moving-alias",
            {
                **HOST_LOCAL_VARS,
                "zot_registry_tls_host_local_state_root": "/var/lib/pki/current",
                "zot_registry_tls_host_local_service": "synthetic",
            },
            "canonical lifecycle contract",
        ),
        (
            "wrong-helper",
            {
                **HOST_LOCAL_VARS,
                "zot_registry_tls_host_local_lifecycle_helper_path": "/tmp/helper",
            },
            "canonical lifecycle contract",
        ),
        (
            "wrong-config",
            {
                **HOST_LOCAL_VARS,
                "zot_registry_tls_host_local_zot_config_path": "/tmp/config.json",
            },
            "canonical lifecycle contract",
        ),
    ],
)
def test_zot_tls_custody_validation_fails_closed(
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
    "metadata",
    [
        {"exists": False},
        {
            "exists": True,
            "isreg": True,
            "islnk": False,
            "uid": 1000,
            "gid": 0,
            "mode": "0755",
        },
        {
            "exists": True,
            "isreg": True,
            "islnk": False,
            "uid": 0,
            "gid": 0,
            "mode": "0775",
        },
    ],
    ids=("absent", "non-root", "unsafe-mode"),
)
def test_zot_tls_lifecycle_helper_metadata_fails_closed(
    metadata: dict[str, Any],
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "helper.yml"
    _role_tasks_playbook(playbook, "validate_tls_lifecycle_helper")
    result = run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {"zot_registry_tls_lifecycle_helper_stat": {"stat": metadata}},
        ),
    )

    assert_failed_with(result, "must exist as a root:root 0755 regular file")


def test_zot_tls_lifecycle_helper_metadata_accepts_exact_file(
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "helper-valid.yml"
    _role_tasks_playbook(playbook, "validate_tls_lifecycle_helper")
    metadata = {
        "exists": True,
        "isreg": True,
        "islnk": False,
        "uid": 0,
        "gid": 0,
        "mode": "0755",
    }

    run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {"zot_registry_tls_lifecycle_helper_stat": {"stat": metadata}},
        ),
    ).assert_success()


def test_zot_tls_active_result_accepts_exact_authenticated_schema(
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "active-valid.yml"
    _role_tasks_playbook(playbook, "validate_tls_active_paths")

    run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {"zot_registry_tls_active_paths_result": _active_result(ACTIVE_PATHS)},
        ),
    ).assert_success()


@pytest.mark.parametrize(
    "result",
    [
        _active_result({}),
        _active_result("not-json"),
        _active_result({**ACTIVE_PATHS, "cert_path": "/etc/zot/tls-versions/current/fullchain.crt"}),
        _active_result({**ACTIVE_PATHS, "unexpected": "field"}),
        _active_result(ACTIVE_PATHS, stderr="unexpected diagnostic"),
    ],
    ids=("missing-fields", "malformed-json", "ambiguous-path", "extra-field", "stderr"),
)
def test_zot_tls_active_result_rejects_malformed_or_ambiguous_output(
    result: dict[str, Any],
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    playbook = isolated_test_dir / "active-invalid.yml"
    _role_tasks_playbook(playbook, "validate_tls_active_paths")

    run_playbook(
        command_runner,
        playbook,
        extra_vars=({"zot_registry_tls_active_paths_result": result},),
    ).assert_failure()


def test_zot_managed_tls_render_preserves_managed_paths_without_lookup(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    config = _render_config(
        repo_root,
        command_runner,
        isolated_test_dir,
        "managed",
        {"zot_registry_tls_custody": "managed"},
    )

    assert config["http"]["tls"] == {
        "cert": "/etc/zot/tls/tls.crt",
        "key": "/etc/zot/tls/tls.key",
    }


def test_zot_host_local_tls_render_uses_only_authenticated_lookup_paths(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    config = _render_config(
        repo_root,
        command_runner,
        isolated_test_dir,
        "host-local",
        {
            "zot_registry_tls_custody": "host-local",
            "zot_registry_tls_active_paths_result": _active_result(ACTIVE_PATHS),
            "zot_registry_extra_config": {
                "http": {"tls": {"cert": "/ambiguous", "key": "/ambiguous"}}
            },
        },
    )

    assert config["http"]["tls"] == {
        "cert": FULLCHAIN_PATH,
        "key": KEY_PATH,
    }
