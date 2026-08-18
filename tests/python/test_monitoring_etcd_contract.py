from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


LOCKED = "requires the approved immutable image"
PATHS = "paths must match the role-owned fixed layout"
TLS = "TLS sources require pinned canonical outside-Git paths"
MEMBERS = "requires exactly three canonical members"
MEMBER = "members require exactly one safe name"
UNIQUE = "member names, addresses, and DNS identities must be unique"
LOCAL = "local name, address, and DNS must match"


VALID_MEMBERS = [
    {
        "name": "monitoring-etcd-1",
        "address": "127.0.0.2",
        "dns": "monitoring-etcd-1.test.invalid",
    },
    {
        "name": "monitoring-etcd-2",
        "address": "127.0.0.3",
        "dns": "monitoring-etcd-2.test.invalid",
    },
    {
        "name": "monitoring-etcd-3",
        "address": "127.0.0.4",
        "dns": "monitoring-etcd-3.test.invalid",
    },
]


@dataclass(frozen=True)
class InvalidCase:
    case_id: str
    variables: dict[str, Any]
    message: str


INVALID_CASES = (
    InvalidCase("contract-unready", {"monitoring_etcd_contract_ready": False}, LOCKED),
    InvalidCase("service-enabled", {"monitoring_etcd_service_enabled": True}, LOCKED),
    InvalidCase("service-started", {"monitoring_etcd_service_state": "started"}, LOCKED),
    InvalidCase("mutable-image", {"monitoring_etcd_image": "example/etcd:latest"}, LOCKED),
    InvalidCase("wrong-version", {"monitoring_etcd_version": "3.7.0"}, LOCKED),
    InvalidCase("wrong-data-path", {"monitoring_etcd_data_dir": "/tmp/etcd"}, PATHS),
    InvalidCase("relative-ca", {"monitoring_etcd_tls_ca_src": "ca.crt"}, TLS),
    InvalidCase(
        "moving-key-path",
        {"monitoring_etcd_tls_key_src": "/fixture/current/tls.key"},
        TLS,
    ),
    InvalidCase("unsafe-token", {"monitoring_etcd_initial_cluster_token": "bad token"}, LOCKED),
    InvalidCase("two-members", {"monitoring_etcd_cluster_members": VALID_MEMBERS[:2]}, MEMBERS),
    InvalidCase(
        "duplicate-name",
        {
            "monitoring_etcd_cluster_members": [
                VALID_MEMBERS[0],
                {**VALID_MEMBERS[1], "name": VALID_MEMBERS[0]["name"]},
                VALID_MEMBERS[2],
            ]
        },
        UNIQUE,
    ),
    InvalidCase(
        "invalid-address",
        {
            "monitoring_etcd_cluster_members": [
                {**VALID_MEMBERS[0], "address": "127.0.0.999"},
                *VALID_MEMBERS[1:],
            ]
        },
        MEMBER,
    ),
    InvalidCase(
        "uppercase-dns",
        {
            "monitoring_etcd_cluster_members": [
                {**VALID_MEMBERS[0], "dns": "ETCD-1.test.invalid"},
                *VALID_MEMBERS[1:],
            ]
        },
        MEMBER,
    ),
    InvalidCase("local-address-mismatch", {"monitoring_etcd_node_address": "127.0.0.9"}, LOCAL),
)


def _contract_playbook(repo_root: Path) -> Path:
    return repo_root / "tests/fixtures/monitoring-etcd-contract/validate.yml"


def test_monitoring_etcd_default_contract_is_valid(
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    run_playbook(command_runner, _contract_playbook(repo_root)).assert_success()


@pytest.mark.parametrize("case", INVALID_CASES, ids=lambda case: case.case_id)
def test_monitoring_etcd_rejects_invalid_contract(
    case: InvalidCase,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    result = run_playbook(
        command_runner,
        _contract_playbook(repo_root),
        extra_vars=(case.variables,),
    )
    assert_failed_with(result, case.message)


def test_monitoring_etcd_role_remains_validation_only(repo_root: Path) -> None:
    role = repo_root / "roles/monitoring_etcd"
    allowed_actions = {
        "ansible.builtin.assert",
        "ansible.builtin.include_tasks",
        "ansible.builtin.set_fact",
    }
    task_keywords = {
        "name",
        "loop",
        "loop_control",
        "no_log",
        "when",
    }
    for path in sorted((role / "tasks").glob("*.yml")):
        tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(tasks, list)
        for task in tasks:
            actions = set(task) - task_keywords
            assert len(actions) == 1, (path, task.get("name"), actions)
            assert actions.pop() in allowed_actions
    assert not (role / "handlers").exists()


def test_monitoring_etcd_defaults_are_inactive(repo_root: Path) -> None:
    defaults = yaml.safe_load(
        (repo_root / "roles/monitoring_etcd/defaults/main.yml").read_text(
            encoding="utf-8"
        )
    )
    assert defaults["monitoring_etcd_enabled"] is False
    assert defaults["monitoring_etcd_contract_ready"] is False
    assert defaults["monitoring_etcd_service_enabled"] is False
    assert defaults["monitoring_etcd_service_state"] == "stopped"
    assert defaults["monitoring_etcd_cluster_members"] == []
    assert defaults["monitoring_etcd_tls_ca_src"] == ""
    assert defaults["monitoring_etcd_tls_cert_src"] == ""
    assert defaults["monitoring_etcd_tls_key_src"] == ""


def test_monitoring_etcd_rendered_contract(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/monitoring-etcd/render-role.yml",
        extra_vars=({"monitoring_etcd_render_output_dir": str(isolated_test_dir)},),
    ).assert_success()

    expected_cluster = ",".join(
        f"{member['name']}=https://{member['dns']}:2380"
        for member in VALID_MEMBERS
    )
    for member in VALID_MEMBERS:
        config = yaml.safe_load(
            (isolated_test_dir / f"{member['name']}.yml").read_text(
                encoding="utf-8"
            )
        )
        assert config["name"] == member["name"]
        assert config["data-dir"] == "/var/lib/etcd"
        assert config["listen-client-urls"] == f"https://{member['address']}:2379"
        assert config["advertise-client-urls"] == f"https://{member['dns']}:2379"
        assert config["listen-peer-urls"] == f"https://{member['address']}:2380"
        assert config["initial-advertise-peer-urls"] == f"https://{member['dns']}:2380"
        assert config["initial-cluster"] == expected_cluster
        client_tls = config["client-transport-security"]
        assert client_tls["cert-file"] == "/etc/etcd/pki/tls.crt"
        assert client_tls["key-file"] == "/etc/etcd/pki/tls.key"
        assert client_tls["trusted-ca-file"] == "/etc/etcd/pki/ca.crt"
        assert client_tls["client-cert-auth"] is True
        assert client_tls["auto-tls"] is False
        peer_tls = config["peer-transport-security"]
        assert peer_tls["cert-file"] == "/etc/etcd/pki/tls.crt"
        assert peer_tls["key-file"] == "/etc/etcd/pki/tls.key"
        assert peer_tls["trusted-ca-file"] == "/etc/etcd/pki/ca.crt"
        assert peer_tls["client-cert-auth"] is True
        assert peer_tls["auto-tls"] is False
        assert config["enable-v2"] is False

    quadlet = (isolated_test_dir / "monitoring-etcd.container").read_text(
        encoding="utf-8"
    )
    for line in (
        "Image=gcr.io/etcd-development/etcd@sha256:a491baeaa0cb0c9cd89c0062ac44ece53886e3e5bddad18d2daf36678ce665b6",
        "User=10001:10001",
        "UserNS=keep-id:uid=10001,gid=10001",
        "Network=host",
        "ReadOnly=true",
        "NoNewPrivileges=true",
        "DropCapability=all",
        "PodmanArgs=--arch=amd64",
        "MemorySwapMax=0",
    ):
        assert line in quadlet
    assert "[Install]" not in quadlet


def test_monitoring_etcd_quotes_yaml_reserved_strings(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    reserved_members = [
        {"name": "null", "address": "127.0.0.2", "dns": "null.test.invalid"},
        *VALID_MEMBERS[1:],
    ]
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/monitoring-etcd/render-role.yml",
        extra_vars=(
            {
                "monitoring_etcd_render_output_dir": str(isolated_test_dir),
                "monitoring_etcd_initial_cluster_token": "true",
                "monitoring_etcd_node_name": "null",
                "monitoring_etcd_node_address": "127.0.0.2",
                "monitoring_etcd_node_dns": "null.test.invalid",
                "monitoring_etcd_cluster_members": reserved_members,
            },
        ),
    ).assert_success()

    config = yaml.safe_load(
        (isolated_test_dir / "null.yml").read_text(encoding="utf-8")
    )
    assert config["name"] == "null"
    assert config["initial-cluster-token"] == "true"
