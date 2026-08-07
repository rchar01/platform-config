from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

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
REJECTIONS = (
    Rejection("unready", {"monitoring_haproxy_test_contract_ready": False}, SCALAR),
    Rejection("string-ready", {"monitoring_haproxy_test_contract_ready": "true"}, SCALAR),
    Rejection("active-service", {"monitoring_haproxy_test_service_enabled": True}, LIFECYCLE),
    Rejection("disabled-active", {"monitoring_haproxy_test_enabled": False, "monitoring_haproxy_test_service_enabled": True}, LIFECYCLE),
    Rejection("disabled-started", {"monitoring_haproxy_test_enabled": False, "monitoring_haproxy_test_service_state": "started"}, LIFECYCLE),
    Rejection("unpinned-package", {"monitoring_haproxy_test_package_nevra": "haproxy"}, SCALAR),
    Rejection("different-nevra", {"monitoring_haproxy_test_package_nevra": "haproxy-0:3.0.6-1.el10.x86_64"}, SCALAR),
    Rejection("port-collision", {"monitoring_haproxy_test_metrics_port": 443}, SCALAR),
    Rejection("string-port", {"monitoring_haproxy_test_metrics_port": "8405"}, SCALAR),
    Rejection("leading-zero-address", {"monitoring_haproxy_test_metrics_address": "192.168.001.83"}, "restricted valid IPv4 bind address"),
    Rejection("duplicate-dns", {"monitoring_haproxy_test_alertmanager_dns": "grafana.monitoring.example.invalid"}, "service DNS names must be unique"),
    Rejection("escaped-dn", {"monitoring_haproxy_test_writer_dn": r"CN=alloy\,loki,OU=telemetry,O=platform,C=XX"}, IDENTITY),
    Rejection("unknown-role", {"monitoring_haproxy_test_writer_role": "arbitrary_admin"}, "requires every mandatory identity role"),
    Rejection("wildcard-route", {"monitoring_haproxy_test_loki_query_path": "/loki/api/v1/*"}, "literal absolute path without wildcards"),
    Rejection("empty-routes", {"monitoring_haproxy_test_alertmanager_routes": []}, "requires observed exact routes"),
    Rejection("duplicate-routes", {"monitoring_haproxy_test_alertmanager_routes": [{"method": "GET", "path": "/alertmanager/api/v2/alerts"}, {"method": "GET", "path": "/alertmanager/api/v2/alerts"}]}, "duplicate method/path entries"),
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
