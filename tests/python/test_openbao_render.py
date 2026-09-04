from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@pytest.fixture
def rendered_openbao(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> dict[str, str]:
    output = isolated_test_dir / "rendered"
    output.mkdir()
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/openbao/render.yml",
        extra_vars=({"openbao_test_output_dir": str(output)},),
    ).assert_success()
    return {
        name: (output / path).read_text(encoding="utf-8")
        for name, path in {
            "config": "openbao.hcl",
            "listener": "listener.hcl",
            "audit": "audit.hcl",
            "quadlet": "openbao.container",
            "validator": "validate-config",
        }.items()
    }


def test_openbao_defaults_remain_staged(repo_root: Path) -> None:
    defaults = (repo_root / "roles/openbao/defaults/main.yml").read_text(encoding="utf-8")
    for line in (
        "openbao_enabled: false",
        "openbao_service_enabled: false",
        "openbao_service_state: stopped",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)
    assert not re.search(r"^openbao_require_separate_mounts:", defaults, re.MULTILINE)


def test_openbao_egress_matrix_tracks_pinned_inputs(repo_root: Path) -> None:
    matrix = (repo_root / "docs/openbao-egress.md").read_text(encoding="utf-8")
    openbao = yaml.safe_load(
        (repo_root / "roles/openbao/defaults/main.yml").read_text(encoding="utf-8")
    )
    remaps = yaml.safe_load(
        (repo_root / "roles/podman_registry_remaps/defaults/main.yml").read_text(
            encoding="utf-8"
        )
    )
    alloy = yaml.safe_load(
        (repo_root / "roles/grafana_alloy/defaults/main.yml").read_text(
            encoding="utf-8"
        )
    )
    containerfile_base = (repo_root / "Containerfile.dev").read_text(
        encoding="utf-8"
    ).splitlines()[0].removeprefix("FROM ")

    for value in (
        openbao["openbao_version"],
        openbao["openbao_image_registry"],
        openbao["openbao_image_digest"],
        openbao["openbao_image_architecture"],
        alloy["grafana_alloy_version"],
        alloy["grafana_alloy_download_checksum"],
        alloy["grafana_alloy_package_nevra"],
        containerfile_base,
    ):
        assert str(value) in matrix

    for variable in (
        "podman_host_registry_remaps",
        "podman_host_package_nevra",
        "openbao_haproxy_package_nevra",
        "keepalived_vip_package_nevra",
        "openbao_haproxy_selinux_package",
    ):
        assert f"`{variable}`" in matrix

    for package in (
        "python3-dnf-plugin-versionlock",
        "kmod",
        "firewalld",
        "python3-firewall",
        "policycoreutils-python-utils",
    ):
        assert f"`{package}`" in matrix

    assert remaps["podman_host_registry_remaps"] == {}
    assert "90-platform-config-remaps.conf" in matrix
    assert "does not set `Pull=never`" in matrix
    for command in (
        "PLAYBOOK=playbooks/maintenance/openbao-registry-remaps.yml LIMIT=openbao",
        "make status-openbao ENV=dev LIMIT=openbao",
        "make smoke-openbao ENV=dev LIMIT=openbao",
        "make roll-openbao ENV=dev LIMIT=openbao",
    ):
        assert command in matrix

    maintenance = (
        repo_root / "playbooks/maintenance/openbao-registry-remaps.yml"
    ).read_text(encoding="utf-8")
    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    for fragment in (
        "hosts: openbao",
        "ansible_limit is defined",
        "ansible_play_hosts_all",
        "tasks_from: active_preflight.yml",
        "openbao_active_observation",
        "podman_host_registry_remaps",
        "name: podman_registry_remaps",
    ):
        assert fragment in maintenance
    assert "openbao-registry-remaps.yml" not in site


def test_openbao_hcl_render_contract(rendered_openbao: dict[str, str]) -> None:
    config = rendered_openbao["config"]
    for pattern in (
        r'^api_addr = "https://bao[.]example[.]invalid:8200"$',
        r'^cluster_addr = "https://bao-1[.]internal[.]invalid:8201"$',
        r"^  performance_multiplier = 1$",
        r'leader_api_addr = "https://bao-2[.]internal[.]invalid:18200"',
        r'leader_api_addr = "https://bao-3[.]internal[.]invalid:18200"',
        r'leader_ca_cert_file = "/openbao/config/tls/ca[.]crt"',
        r'leader_tls_servername = "bao-2[.]internal[.]invalid"',
        r"^telemetry \{$",
    ):
        assert re.search(pattern, config, re.MULTILINE), pattern
    for pattern in (
        r"^disable_mlock",
        r"^seal ",
        r'leader_api_addr = "https://bao-1[.]internal[.]invalid',
        r'leader_api_addr = "https://bao[.]example[.]invalid',
        r"192[.]0[.]2[.]100",
        r'^listener "tcp"',
    ):
        assert not re.search(pattern, config, re.MULTILINE), pattern


def test_openbao_dormant_listener_is_exact(rendered_openbao: dict[str, str]) -> None:
    assert rendered_openbao["listener"] == (
        'listener "tcp" {\n'
        '  address = "192.0.2.10:18200"\n'
        '  cluster_address = "192.0.2.10:8201"\n'
        '  tls_cert_file = "/openbao/config/tls/tls.crt"\n'
        '  tls_key_file = "/openbao/config/tls/tls.key"\n'
        '  tls_min_version = "tls12"\n'
        '  tls_max_version = "tls13"\n'
        '  tls_disable_client_certs = true\n'
        '  disable_unauthed_rekey_endpoints = true\n'
        '  disable_unauthed_generate_root_endpoints = true\n'
        '}\n'
    )


def test_openbao_declarative_audit_is_exact(rendered_openbao: dict[str, str]) -> None:
    assert rendered_openbao["audit"] == (
        'audit "file" "file-audit-1" {\n'
        "  local = false\n"
        "\n"
        "  options {\n"
        '    file_path = "/openbao/audit-1/audit.log"\n'
        "  }\n"
        "}\n"
        "\n"
        'audit "file" "file-audit-2" {\n'
        "  local = false\n"
        "\n"
        "  options {\n"
        '    file_path = "/openbao/audit-2/audit.log"\n'
        "  }\n"
        "}\n"
    )


def test_openbao_quadlet_render_contract(rendered_openbao: dict[str, str]) -> None:
    quadlet = rendered_openbao["quadlet"]
    for pattern in (
        r"^Image=ghcr[.]io/openbao/openbao@sha256:15e90b",
        r"^User=100:1000$",
        r"^Network=host$",
        r"^Environment=SKIP_CHOWN=true$",
        r"^Volume=/etc/openbao:/openbao/config:ro,Z$",
        r"^Exec=server$",
        r"^MemorySwapMax=0$",
    ):
        assert re.search(pattern, quadlet, re.MULTILINE), pattern
    assert not re.search(r"^PublishPort=|^\[Install\]$|^WantedBy=", quadlet, re.MULTILINE)


def test_openbao_validator_render_contract(rendered_openbao: dict[str, str]) -> None:
    validator = rendered_openbao["validator"]
    for pattern in (
        r"^#!/bin/bash$",
        r'^case "[$]\{kind\}" in$',
        r'^  base\)$',
        r'^  base-dormant\)$',
        r'^  listener\)$',
        r'^  audit\)$',
        r"^  --network none \\$",
        r"^  --pull never \\$",
        r"^  --read-only \\$",
        r"^  --user 0:0 \\$",
        r"^  --security-opt no-new-privileges \\$",
        r"^  operator validate-config -config=/openbao/config$",
    ):
        assert re.search(pattern, validator, re.MULTILINE), pattern


def test_openbao_role_validates_base_with_existing_listener(repo_root: Path) -> None:
    role = (repo_root / "roles/openbao/tasks/main.yml").read_text(
        encoding="utf-8"
    )

    assert role.index("Authenticate OpenBao lifecycle state before role mutation") < (
        role.index("Write validated OpenBao configuration")
    )
    assert role.index("Require pristine stopped state before dormant listener staging") < (
        role.index("Write validated OpenBao configuration")
    )
    first_mutation = role.index("Ensure OpenBao configuration directories exist")
    assert role.index("Require pristine stopped state before dormant listener staging") < (
        first_mutation
    )
    assert role.index("Authenticate OpenBao lifecycle state before role mutation") < (
        first_mutation
    )
    assert role.index("Refuse implicit post-bootstrap audit migration") < (
        role.index("Write validated declarative OpenBao audit configuration")
    )
    assert "openbao_base_config_validate_command" in role
    assert "openbao_dormant_base_config_validate_command" in role
    assert "openbao_config_validate_command" in role
    assert "openbao_audit_config_validate_command" in role


def test_openbao_custody_checks_canonical_ca_chain(repo_root: Path) -> None:
    custody = (repo_root / "roles/openbao/tasks/custody.yml").read_text(
        encoding="utf-8"
    )

    assert "/{{ openbao_tls_custody.request_id }}/ca-chain.crt" in custody
    assert "/{{ openbao_tls_custody.request_id }}/chain.crt" not in custody


def test_openbao_active_preflight_authenticates_selected_tls_version(
    repo_root: Path,
) -> None:
    preflight = (repo_root / "roles/openbao/tasks/active_preflight.yml").read_text(
        encoding="utf-8"
    )
    refresh = (repo_root / "roles/openbao/tasks/refresh_active_marker.yml").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "lookup('ansible.builtin.template', 'listener.hcl.j2')",
        "'/openbao/config/tls/tls.crt'",
        "'/openbao/config/tls/tls.key'",
        "~ '/fullchain.crt'",
        "~ '/tls.key'",
    ):
        assert fragment in preflight
        assert fragment in refresh
    for fragment in (
        "path: /etc/openbao/tls-versions",
        "openbao_active_versions_root_stat.stat.exists",
        "openbao_active_versions_root_stat.stat.isdir",
        "not openbao_active_versions_root_stat.stat.islnk",
        "openbao_active_versions_root_stat.stat.pw_name == 'root'",
        "openbao_active_versions_root_stat.stat.gid == openbao_container_gid | int",
        "openbao_active_versions_root_stat.stat.mode == '0750'",
        "openbao_active_version_directory_stat.stat.isdir",
        "not openbao_active_version_directory_stat.stat.islnk",
        "openbao_active_version_directory_stat.stat.pw_name == 'root'",
        "openbao_active_version_directory_stat.stat.gid == openbao_container_gid | int",
        "openbao_active_version_directory_stat.stat.mode == '0750'",
        "openbao_active_leaf_stats.results[0].stat.isreg",
        "not openbao_active_leaf_stats.results[0].stat.islnk",
        "openbao_active_leaf_stats.results[0].stat.pw_name == 'root'",
        "openbao_active_leaf_stats.results[0].stat.gr_name == 'root'",
        "openbao_active_leaf_stats.results[0].stat.gid == 0",
        "openbao_active_leaf_stats.results[0].stat.mode == '0644'",
        "openbao_active_leaf_stats.results[1].stat.isreg",
        "not openbao_active_leaf_stats.results[1].stat.islnk",
        "openbao_active_leaf_stats.results[1].stat.pw_name == 'root'",
        "openbao_active_leaf_stats.results[1].stat.gid == openbao_container_gid | int",
        "openbao_active_leaf_stats.results[1].stat.mode == '0640'",
    ):
        assert fragment in preflight
    listener_index = "openbao_active_lifecycle_stats.results[4].stat"
    for suffix in (
        "isreg",
        "islnk",
        "pw_name == 'root'",
        "gid == openbao_container_gid | int",
        "mode == '0640'",
    ):
        assert f"{listener_index}.{suffix}" in preflight


def test_openbao_role_has_no_controller_leaf_transfer(repo_root: Path) -> None:
    role_root = repo_root / "roles/openbao"
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in role_root.rglob("*")
        if path.is_file()
    )
    assert "openbao_tls_cert_src" not in sources
    assert "openbao_tls_key_src" not in sources
    assert "ansible.builtin.fetch:" not in sources
    assert not re.search(
        r"ansible[.]builtin[.](?:copy|slurp):[\s\S]{0,240}"
        r"(?:host_key_path|tls[.]key|fullchain[.]crt)",
        sources,
    )


@pytest.mark.parametrize(
    ("case_id", "extra_vars", "message"),
    [
        ("mutable-image", {"openbao_test_image_digest": "latest"}, "approved immutable amd64 2.6.1 image"),
        ("duplicate-node", {"openbao_test_peer_2_node_name": "bao-1"}, "exactly three members with unique"),
        ("shared-dns", {"openbao_test_peer_2_dns": "bao.example.invalid"}, "safe unique inventory"),
        ("port-collision", {"openbao_test_cluster_port": 18200}, "approved immutable amd64 2.6.1 image"),
        ("identity-mismatch", {"openbao_test_local_node_name": "not-bao-1"}, "local node identity must exactly match"),
        ("transit-seal", {"openbao_test_seal_type": "transit"}, "approved immutable amd64 2.6.1 image"),
        ("active-service", {"openbao_service_enabled": True}, "approved immutable amd64 2.6.1 image"),
        ("invalid-lifecycle-mode", {"openbao_lifecycle_preflight_mode": "automatic"}, "approved immutable amd64 2.6.1 image"),
        ("wrong-mounts", {"openbao_required_mounts": ["/tmp/a", "/tmp/b", "/tmp/c", "/tmp/d"]}, "approved immutable amd64 2.6.1 image"),
        ("invalid-source", {"openbao_backend_allowed_sources": ["999.51.100.1/32"]}, "is invalid"),
        ("two-members", {"openbao_test_cluster_members": [{"name": "localhost", "node_id": "bao-1", "address": "192.0.2.10", "dns": "bao-1.internal.invalid"}, {"name": "test-node-02", "node_id": "bao-2", "address": "192.0.2.11", "dns": "bao-2.internal.invalid"}]}, "exactly three members with unique"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_openbao_render_rejects_invalid_input(
    case_id: str,
    extra_vars: dict[str, Any],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    output = isolated_test_dir / case_id
    output.mkdir()
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/openbao/render.yml",
        extra_vars=({"openbao_test_output_dir": str(output), **extra_vars},),
    )
    assert_failed_with(result, message)
