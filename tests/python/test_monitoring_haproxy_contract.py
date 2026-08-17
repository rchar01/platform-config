from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@dataclass(frozen=True)
class Rejection:
    case_id: str
    extra_vars: dict[str, Any]
    message: str


SCALAR = "requires an explicitly ready contract"
LIFECYCLE = "Service activation remains unavailable"
IDENTITY = "an escape-free canonical RFC2253 subject DN"
SOURCE = "network-normalized IPv4 CIDR no broader than /24"
BACKENDS = "requires exactly Grafana, Loki, Mimir"
BACKEND_PORT = "requires exact private service and health ports"
BACKEND_COLLISION = "must not collide with HAProxy-owned"
BACKEND_PORT_UNIQUE = "backend ports must be unique"
BACKEND_TARGET = "backend targets require exactly a safe name"
BACKEND_TLS_TARGET = "TLS backend targets require a lowercase FQDN"
BACKEND_TARGET_UNIQUE = "unique target names and addresses"
BACKEND_TLS_TARGET_UNIQUE = "three unique TLS server identities"
INTEGRATED = "integrated Alertmanager must use the exact Mimir backend port"
HEALTH_POLICY = "health policies are role-owned exact status-only"
OPERATOR_ROUTE = "operator routes require exactly an approved service"
VALID_TARGETS = [
    {
        "name": "monitoring-1",
        "address": "192.0.2.64",
        "tls_server_name": "monitoring-1.backend.example.invalid",
    },
    {
        "name": "monitoring-2",
        "address": "192.0.2.75",
        "tls_server_name": "monitoring-2.backend.example.invalid",
    },
    {
        "name": "monitoring-3",
        "address": "192.0.2.76",
        "tls_server_name": "monitoring-3.backend.example.invalid",
    },
]
VALID_S3_TARGETS = [{"name": "local-garage", "address": "127.0.0.1"}]
VALID_BACKENDS = {
    "grafana": {
        "port": 13001,
        "health_port": 13001,
        "targets": copy.deepcopy(VALID_TARGETS),
    },
    "loki": {
        "port": 13002,
        "health_port": 13002,
        "targets": copy.deepcopy(VALID_TARGETS),
    },
    "mimir": {
        "port": 13003,
        "health_port": 13003,
        "targets": copy.deepcopy(VALID_TARGETS),
    },
    "alertmanager": {
        "port": 13003,
        "health_port": 13003,
        "targets": copy.deepcopy(VALID_TARGETS),
    },
    "s3": {
        "port": 13004,
        "health_port": 13006,
        "targets": copy.deepcopy(VALID_S3_TARGETS),
    },
    "postgresql": {
        "port": 13005,
        "health_port": 13007,
        "targets": copy.deepcopy(VALID_TARGETS),
    },
}


def replace_backend(service: str, value: Any) -> dict[str, Any]:
    backends = copy.deepcopy(VALID_BACKENDS)
    backends[service] = value
    return backends


def replace_target(
    service: str, index: int, value: Any
) -> dict[str, Any]:
    backends = copy.deepcopy(VALID_BACKENDS)
    backends[service]["targets"][index] = value
    return backends


def backend_value(service: str, **updates: Any) -> dict[str, Any]:
    value = copy.deepcopy(VALID_BACKENDS[service])
    value.update(updates)
    return value


REJECTIONS = (
    Rejection("unready", {"monitoring_haproxy_test_contract_ready": False}, SCALAR),
    Rejection("string-ready", {"monitoring_haproxy_test_contract_ready": "true"}, SCALAR),
    Rejection("active-service", {"monitoring_haproxy_test_service_enabled": True}, LIFECYCLE),
    Rejection("disabled-active", {"monitoring_haproxy_test_enabled": False, "monitoring_haproxy_test_service_enabled": True}, LIFECYCLE),
    Rejection("disabled-started", {"monitoring_haproxy_test_enabled": False, "monitoring_haproxy_test_service_state": "started"}, LIFECYCLE),
    Rejection("unpinned-package", {"monitoring_haproxy_test_package_nevra": "haproxy"}, SCALAR),
    Rejection("different-nevra", {"monitoring_haproxy_test_package_nevra": "haproxy-0:3.0.6-1.el10.x86_64"}, SCALAR),
    Rejection("port-collision", {"monitoring_haproxy_test_metrics_port": 443}, "unique HTTPS, PostgreSQL frontend, and metrics"),
    Rejection("string-port", {"monitoring_haproxy_test_metrics_port": "8405"}, SCALAR),
    Rejection("backends-not-mapping", {"monitoring_haproxy_test_backends": []}, BACKENDS),
    Rejection(
        "missing-backend",
        {"monitoring_haproxy_test_backends": {key: value for key, value in VALID_BACKENDS.items() if key != "s3"}},
        BACKENDS,
    ),
    Rejection(
        "unknown-backend",
        {"monitoring_haproxy_test_backends": {**VALID_BACKENDS, "unknown": {"port": 13006}}},
        BACKENDS,
    ),
    Rejection(
        "backend-entry-not-mapping",
        {"monitoring_haproxy_test_backends": replace_backend("grafana", 13001)},
        BACKEND_PORT,
    ),
    Rejection(
        "backend-extra-key",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana",
                {
                    "port": 13001,
                    "health_port": 13001,
                    "targets": copy.deepcopy(VALID_TARGETS),
                    "host": "fixture.invalid",
                },
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-string-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana",
                backend_value("grafana", port="13001"),
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-zero-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana", backend_value("grafana", port=0)
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-high-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana",
                backend_value("grafana", port=65536),
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-string-health-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana", backend_value("grafana", health_port="13001")
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-zero-health-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana", backend_value("grafana", health_port=0)
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "shared-listener-health-port-mismatch",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "loki", backend_value("loki", health_port=13006)
            )
        },
        "must share its service and health port",
    ),
    Rejection(
        "garage-shared-health-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "s3", backend_value("s3", health_port=13004)
            )
        },
        "requires a separate Garage Admin health port",
    ),
    Rejection(
        "patroni-shared-health-port",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "postgresql", backend_value("postgresql", health_port=13005)
            )
        },
        "requires a separate Patroni REST health port",
    ),
    Rejection(
        "backend-listener-collision",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana", backend_value("grafana", port=443)
            )
        },
        BACKEND_COLLISION,
    ),
    Rejection(
        "backend-unrelated-port-collision",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana",
                backend_value("grafana", port=13002, health_port=13002),
            )
        },
        BACKEND_PORT_UNIQUE,
    ),
    Rejection(
        "integrated-port-mismatch",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "alertmanager",
                backend_value("alertmanager", port=13006, health_port=13006),
            )
        },
        INTEGRATED,
    ),
    Rejection(
        "backend-targets-not-list",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana", backend_value("grafana", targets="invalid")
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-target-count",
        {
            "monitoring_haproxy_test_backends": replace_backend(
                "grafana", backend_value("grafana", targets=VALID_TARGETS[:2])
            )
        },
        BACKEND_PORT,
    ),
    Rejection(
        "backend-target-not-mapping",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, "invalid"
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-extra-key",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "port": 13001}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-leading-zero-address",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana",
                0,
                {**VALID_TARGETS[0], "address": "192.0.2.064"},
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-high-address",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana",
                0,
                {**VALID_TARGETS[0], "address": "192.0.2.256"},
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-invalid-tls-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana",
                0,
                {**VALID_TARGETS[0], "tls_server_name": "Monitoring-1"},
            )
        },
        BACKEND_TLS_TARGET,
    ),
    Rejection(
        "backend-target-integer-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "name": 1}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-boolean-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "name": True}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-null-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "name": None}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-integer-address",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "address": 1}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-boolean-address",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "address": False}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-null-address",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "address": None}
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "backend-target-integer-tls-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "tls_server_name": 1}
            )
        },
        BACKEND_TLS_TARGET,
    ),
    Rejection(
        "backend-target-boolean-tls-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "tls_server_name": True}
            )
        },
        BACKEND_TLS_TARGET,
    ),
    Rejection(
        "backend-target-null-tls-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana", 0, {**VALID_TARGETS[0], "tls_server_name": None}
            )
        },
        BACKEND_TLS_TARGET,
    ),
    Rejection(
        "backend-target-duplicate-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana",
                1,
                {**VALID_TARGETS[1], "name": "monitoring-1"},
            )
        },
        BACKEND_TARGET_UNIQUE,
    ),
    Rejection(
        "backend-target-duplicate-address",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana",
                1,
                {**VALID_TARGETS[1], "address": "192.0.2.64"},
            )
        },
        BACKEND_TARGET_UNIQUE,
    ),
    Rejection(
        "backend-target-duplicate-tls-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "grafana",
                1,
                {
                    **VALID_TARGETS[1],
                    "tls_server_name": "monitoring-1.backend.example.invalid",
                },
            )
        },
        BACKEND_TLS_TARGET_UNIQUE,
    ),
    Rejection(
        "integrated-target-mismatch",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "alertmanager",
                0,
                {
                    **VALID_TARGETS[0],
                    "tls_server_name": "alertmanager-1.backend.example.invalid",
                },
            )
        },
        INTEGRATED,
    ),
    Rejection(
        "s3-target-extra-tls-name",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "s3",
                0,
                {**VALID_S3_TARGETS[0], "tls_server_name": "garage.invalid"},
            )
        },
        BACKEND_TARGET,
    ),
    Rejection(
        "s3-target-not-loopback",
        {
            "monitoring_haproxy_test_backends": replace_target(
                "s3", 0, {**VALID_S3_TARGETS[0], "address": "192.0.2.64"}
            )
        },
        "must use the node-local 127.0.0.1 target",
    ),
    Rejection("leading-zero-address", {"monitoring_haproxy_test_metrics_address": "192.168.001.83"}, "restricted valid IPv4 bind address"),
    Rejection("duplicate-dns", {"monitoring_haproxy_test_alertmanager_dns": "grafana.monitoring.example.invalid"}, "service DNS names must be unique"),
    Rejection("escaped-dn", {"monitoring_haproxy_test_writer_dn": r"CN=alloy\,loki,OU=telemetry,O=platform,C=XX"}, IDENTITY),
    Rejection("identities-not-list", {"monitoring_haproxy_identity_roles": "invalid"}, "populated identity-role sequence"),
    Rejection("identity-not-mapping", {"monitoring_haproxy_identity_roles": [None] * 10}, IDENTITY),
    Rejection("identity-role-not-string", {"monitoring_haproxy_test_writer_role": 1}, IDENTITY),
    Rejection("unknown-role", {"monitoring_haproxy_test_writer_role": "arbitrary_admin"}, "an approved role"),
    Rejection("missing-probe-role", {"monitoring_haproxy_test_probe_role": "operator"}, "requires every mandatory identity role"),
    Rejection("missing-s3-probe-role", {"monitoring_haproxy_test_s3_probe_role": "operator"}, "requires every mandatory identity role"),
    Rejection("s3-probe-extra-method", {"monitoring_haproxy_s3_probe_methods": ["DELETE", "GET", "HEAD", "PUT"]}, "requires exact DELETE, GET, and PUT"),
    Rejection("grafana-probe-method", {"monitoring_haproxy_grafana_probe_routes": [{"method": "POST", "path": "/api/health"}]}, "probes require exact host-scoped GET routes"),
    Rejection("grafana-probe-path", {"monitoring_haproxy_grafana_probe_routes": [{"method": "GET", "path": "/"}]}, "probes require exact host-scoped GET routes"),
    Rejection("loki-probe-path", {"monitoring_haproxy_loki_probe_routes": [{"method": "GET", "path": "/loki/api/v1/query_range"}]}, "probes require exact host-scoped GET routes"),
    Rejection("mimir-probe-extra", {"monitoring_haproxy_mimir_probe_routes": [{"method": "GET", "path": "/ready"}, {"method": "GET", "path": "/prometheus/api/v1/query"}]}, "probes require exact host-scoped GET routes"),
    Rejection("wildcard-route", {"monitoring_haproxy_test_loki_query_path": "/loki/api/v1/*"}, "literal absolute path without wildcards"),
    Rejection("empty-routes", {"monitoring_haproxy_test_alertmanager_routes": []}, "requires observed exact routes"),
    Rejection("duplicate-routes", {"monitoring_haproxy_test_alertmanager_routes": [{"method": "GET", "path": "/alertmanager/api/v2/alerts"}, {"method": "GET", "path": "/alertmanager/api/v2/alerts"}]}, "duplicate method/path entries"),
    Rejection("route-not-mapping", {"monitoring_haproxy_test_alertmanager_routes": [None]}, "literal absolute path without wildcards"),
    Rejection("route-method-not-string", {"monitoring_haproxy_test_alertmanager_routes": [{"method": 1, "path": "/alertmanager/api/v2/alerts"}]}, "literal absolute path without wildcards"),
    Rejection("operator-missing-service", {"monitoring_haproxy_test_operator_routes": [{"method": "GET", "path": "/-/ready"}]}, OPERATOR_ROUTE),
    Rejection("operator-unknown-service", {"monitoring_haproxy_test_operator_routes": [{"service": "postgresql", "method": "GET", "path": "/-/ready"}]}, OPERATOR_ROUTE),
    Rejection("operator-wildcard-route", {"monitoring_haproxy_test_operator_routes": [{"service": "mimir", "method": "GET", "path": "/api/*"}]}, OPERATOR_ROUTE),
    Rejection("overridden-health-policy", {"monitoring_haproxy_health_policies": {"grafana": {"method": "POST", "path": "/"}}}, HEALTH_POLICY),
    Rejection("open-https", {"monitoring_haproxy_test_https_sources": ["0.0.0.0/0"]}, SOURCE),
    Rejection("unnormalized-https", {"monitoring_haproxy_test_https_sources": ["198.51.100.1/24"]}, SOURCE),
    Rejection("leading-zero-https", {"monitoring_haproxy_test_https_sources": ["198.051.100.0/24"]}, SOURCE),
    Rejection("duplicate-https", {"monitoring_haproxy_test_https_sources": ["198.51.100.0/24", "198.51.100.0/24"]}, "non-empty unique restricted CIDR list"),
    Rejection("broad-https", {"monitoring_haproxy_test_https_sources": ["198.0.0.0/8"]}, SOURCE),
    Rejection("empty-operator", {"monitoring_haproxy_test_operator_sources": []}, "operator sources must be a non-empty unique"),
    Rejection("open-operator", {"monitoring_haproxy_test_operator_sources": ["0.0.0.0/0"]}, SOURCE),
    Rejection("outside-operator", {"monitoring_haproxy_test_operator_sources": ["192.0.2.0/28"]}, "must be contained by the outer HTTPS source policy"),
)


def test_monitoring_haproxy_defaults_remain_inactive(repo_root: Path) -> None:
    defaults = (repo_root / "roles/monitoring_haproxy/defaults/main.yml").read_text(encoding="utf-8")
    for line in (
        "monitoring_haproxy_enabled: false",
        "monitoring_haproxy_service_enabled: false",
        "monitoring_haproxy_service_state: stopped",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)


def test_monitoring_haproxy_tasks_remain_validation_only(repo_root: Path) -> None:
    role = repo_root / "roles/monitoring_haproxy"
    allowed_actions = {
        "ansible.builtin.assert",
        "ansible.builtin.include_tasks",
        "ansible.builtin.set_fact",
    }
    task_keywords = {
        "changed_when",
        "check_mode",
        "failed_when",
        "loop",
        "loop_control",
        "name",
        "register",
        "tags",
        "vars",
        "when",
    }
    observed_actions: set[str] = set()
    for path in sorted((role / "tasks").rglob("*.yml")):
        tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(tasks, list)
        for task in tasks:
            assert isinstance(task, dict)
            action_keys = set(task) - task_keywords
            assert len(action_keys) == 1, (path, task.get("name"), action_keys)
            action = action_keys.pop()
            assert action in allowed_actions, (path, task.get("name"), action)
            observed_actions.add(action)
    assert observed_actions == allowed_actions
    assert not (role / "handlers").exists()


def test_monitoring_haproxy_default_fixture_is_valid(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/monitoring-haproxy-contract/validate.yml",
    ).assert_success()


@pytest.mark.parametrize("case", REJECTIONS, ids=lambda case: case.case_id)
def test_monitoring_haproxy_rejects_invalid_contract(
    case: Rejection, repo_root: Path, command_runner: CommandRunner
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/monitoring-haproxy-contract/validate.yml",
        extra_vars=(case.extra_vars,),
    )
    assert_failed_with(result, case.message)
