from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@pytest.fixture
def rendered_probe(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> dict[str, str]:
    output = isolated_test_dir / "rendered"
    output.mkdir()
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/platform-external-probe/render.yml",
        extra_vars=({"platform_external_probe_test_output_dir": str(output)},),
    ).assert_success()
    files = {
        "fragment": "external-probe.alloy",
        "config": "config.alloy",
        "collector": "collect-vip-ownership",
        "service": "platform-external-probe-ownership.service",
        "timer": "platform-external-probe-ownership.timer",
        "postgresql_collector": "collect-postgresql-primary",
        "postgresql_service": "platform-external-probe-postgresql-primary.service",
        "postgresql_timer": "platform-external-probe-postgresql-primary.timer",
        "garage_collector": "collect-garage-canary",
        "garage_service": "platform-external-probe-garage-canary.service",
        "garage_timer": "platform-external-probe-garage-canary.timer",
    }
    return {name: (output / path).read_text(encoding="utf-8") for name, path in files.items()}


def test_external_probe_and_alloy_are_staged_by_default(repo_root: Path) -> None:
    probe = (repo_root / "roles/platform_external_probe/defaults/main.yml").read_text(encoding="utf-8")
    alloy = (repo_root / "roles/grafana_alloy/defaults/main.yml").read_text(encoding="utf-8")
    assert re.search(r"^platform_external_probe_enabled: false$", probe, re.MULTILINE)
    assert re.search(r"^platform_external_probe_timer_enabled: false$", probe, re.MULTILINE)
    assert re.search(r"^grafana_alloy_enabled: false$", alloy, re.MULTILINE)
    assert re.search(r"^grafana_alloy_version: 1[.]18[.]1$", alloy, re.MULTILINE)
    assert re.search(
        r"^grafana_alloy_download_checksum: "
        r"sha256:7dbdc068feae7feaafbc48fefb9b41b6c91af24984c13277bf0a9d1a298a4126$",
        alloy,
        re.MULTILINE,
    )


def test_alloy_native_validation_and_owner_contract(repo_root: Path) -> None:
    tasks = (repo_root / "roles/grafana_alloy/tasks/main.yml").read_text(encoding="utf-8")
    defaults = (repo_root / "roles/grafana_alloy/defaults/main.yml").read_text(encoding="utf-8")
    assert "grafana_alloy_config_validate_command" in tasks
    assert "allow_downgrade: true" in tasks
    for root in ("/etc", "/run", "/usr/share"):
        for name in ("alloy.container", "monitoring-alloy.container"):
            path = f"  - {root}/containers/systemd/{name}"
            assert re.search(rf"^{re.escape(path)}$", defaults, re.MULTILINE)


def test_external_probe_fragment_has_strict_blackbox_contract(
    rendered_probe: dict[str, str]
) -> None:
    fragment = rendered_probe["fragment"]
    for pattern in (
        r'^prometheus[.]exporter[.]blackbox "platform_external_probe"',
        r"follow_redirects: false",
        r"fail_if_not_ssl: true",
        r'server_name: \\"bao[.]example[.]invalid\\"',
        r'Host: \\"bao[.]example[.]invalid\\"',
        r"valid_status_codes: \[200\]",
        r'observer\s*=\s*"monitoring-example-01"',
        r'environment\s*=\s*"dev"',
        r'endpoint\s*=\s*"openbao_vip"',
        r'address_mode\s*=\s*"vip"',
        r'\\n  grafana_health:',
        r'\\n  loki_ready:',
        r'\\n  mimir_ready:',
        r'^prometheus[.]exporter[.]unix "platform_external_probe_textfile"',
    ):
        assert re.search(pattern, fragment, re.MULTILINE), pattern
    assert not re.search(r"insecure_skip_verify: true|clustering", fragment)


def test_locked_monitoring_probe_profile_contract(repo_root: Path) -> None:
    profiles = (
        repo_root / "roles/platform_external_probe/vars/main.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "grafana_health:",
        "path: /api/health",
        "'\"database\"[[:space:]]*:[[:space:]]*\"ok\"'",
        "'\"version\"[[:space:]]*:[[:space:]]*\"13[.]1[.]3\"'",
        "loki_ready:",
        "mimir_ready:",
        "'^ready[[:space:]]*$'",
    ):
        assert required in profiles


def test_complete_alloy_config_composes_probe_fragment(
    rendered_probe: dict[str, str]
) -> None:
    config = rendered_probe["config"]
    assert re.search(r'^prometheus[.]remote_write "platform_metrics"', config, re.MULTILINE)
    assert "follow_redirects = false" in config
    assert "insecure_skip_verify = false" in config
    assert re.search(r'^prometheus[.]exporter[.]blackbox "platform_external_probe"', config, re.MULTILINE)


def test_vip_ownership_render_contract(rendered_probe: dict[str, str]) -> None:
    collector = rendered_probe["collector"]
    for pattern in (
        r"^#!/bin/bash$",
        r"^set -euo pipefail$",
        r"ip -o -4 address show dev eth0",
        r"local_cidr%%/\*.*192[.]0[.]2[.]200",
        r"mktemp .*metrics_dir.*/[.]vip-ownership",
        r"mv -f -- .*metrics_path",
        r"if \[\[ .*published.* -eq 0 \]\]",
        r"^trap cleanup EXIT$",
        r'environment="dev",endpoint="openbao_vip"',
        r'vip="192[.]0[.]2[.]200"',
    ):
        assert re.search(pattern, collector, re.MULTILINE), pattern
    assert not re.search(
        r"systemctl (start|stop|restart|reload)|ip address (add|del)|"
        r"keepalived.*(reload|restart)",
        collector,
    )
    service = rendered_probe["service"]
    assert re.search(r"^ProtectSystem=strict$", service, re.MULTILINE)
    assert re.search(r"^ReadWritePaths=/var/lib/alloy/platform-external-probe$", service, re.MULTILINE)
    assert re.search(r"^RestrictAddressFamilies=AF_UNIX AF_NETLINK$", service, re.MULTILINE)
    assert re.search(r"^OnUnitActiveSec=5s$", rendered_probe["timer"], re.MULTILINE)


def test_postgresql_primary_render_contract(rendered_probe: dict[str, str]) -> None:
    collector = rendered_probe["postgresql_collector"]
    for pattern in (
        r"^#!/bin/bash$",
        r"PGCONNECT_TIMEOUT=4",
        r"PGPASSWORD=",
        r"PGPASSFILE=/dev/null",
        r"PGGSSENCMODE=disable",
        r"PGSSLMODE=verify-full",
        r"PGSSLCERTMODE=require",
        r"PGREQUIREAUTH=none",
        r"default_transaction_read_only=on",
        r"search_path=",
        r"--no-password",
        r"--host=postgres[.]example[.]invalid",
        r"--port=5432",
        r"--dbname=observer",
        r"--username=monitoring_probe",
        r"SELECT NOT pg_catalog[.]pg_is_in_recovery[(][)];",
        r"platform_postgresql_primary_query_success",
        r"address_mode=\"vip\"",
    ):
        assert re.search(pattern, collector, re.MULTILINE), pattern
    assert "INSERT" not in collector
    assert "UPDATE" not in collector
    assert "DELETE" not in collector

    service = rendered_probe["postgresql_service"]
    assert re.search(r"^# Managed by platform_external_probe[.]$", service, re.MULTILINE)
    assert re.search(
        r"^ExecStartPre=-/usr/bin/rm -f "
        r"/var/lib/alloy/platform-external-probe/postgresql-primary[.]prom$",
        service,
        re.MULTILINE,
    )
    assert re.search(r"^TimeoutStartSec=7s$", service, re.MULTILINE)
    assert re.search(
        r"^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6$", service, re.MULTILINE
    )
    assert re.search(r"^ProtectSystem=strict$", service, re.MULTILINE)
    assert re.search(
        r"^OnUnitActiveSec=5s$", rendered_probe["postgresql_timer"], re.MULTILINE
    )


def test_garage_canary_render_contract(rendered_probe: dict[str, str]) -> None:
    collector = rendered_probe["garage_collector"]
    for required in (
        'HOST = "s3.example.invalid"',
        'PORT = 443',
        'REGION = "garage"',
        'BUCKET = "observer-canary-monitoring-example-01"',
        'OBJECT_KEY = "canary/monitoring-example-01"',
        'REQUEST_TIMEOUT = 3',
        'RUN_TIMEOUT = 10',
        'ssl.create_default_context',
        'context.load_cert_chain',
        'AWS4-HMAC-SHA256',
        'request("DELETE", b"", 204',
        'request("PUT", payload, 200',
        '"GET", b"", 200, credentials',
        'hmac.compare_digest',
        'platform_garage_canary_ambiguity',
    ):
        assert required in collector
    assert 'HEAD' not in collector
    assert 'POST' not in collector
    service = rendered_probe["garage_service"]
    assert re.search(
        r"^# Managed by platform_external_probe Garage canary[.]$",
        service,
        re.MULTILINE,
    )
    assert re.search(r"^TimeoutStartSec=12s$", service, re.MULTILINE)
    assert re.search(r"^ExecStartPre=-/usr/bin/rm -f .*garage-canary[.]prom$", service, re.MULTILINE)
    assert re.search(r"^OnUnitActiveSec=30s$", rendered_probe["garage_timer"], re.MULTILINE)


@pytest.mark.parametrize(
    ("case_id", "extra_vars"),
    [
        ("duplicate-name", {"platform_external_probe_test_target_2_name": "openbao_dns"}),
        ("plain-http", {"platform_external_probe_test_target_2_address": "http://192.0.2.200:8200/v1/sys/health"}),
        ("url-credentials", {"platform_external_probe_test_target_2_address": "https://user:secret@192.0.2.200/v1/sys/health"}),
        ("generic-query", {"platform_external_probe_test_target_2_address": "https://192.0.2.200/v1/sys/health?standbyok=true"}),
        ("generic-fragment", {"platform_external_probe_test_target_2_address": "https://192.0.2.200/v1/sys/health#status"}),
        ("generic-path-space", {"platform_external_probe_test_target_2_address": "https://192.0.2.200/v1/sys/health status"}),
        ("generic-path-percent", {"platform_external_probe_test_target_2_address": "https://192.0.2.200/v1/sys/bad%20path"}),
        ("generic-path-bare-percent", {"platform_external_probe_test_target_2_address": "https://192.0.2.200/v1/sys/bad%"}),
        ("generic-path-invalid-percent", {"platform_external_probe_test_target_2_address": "https://192.0.2.200/v1/sys/bad%G0"}),
        ("generic-authority-control", {"platform_external_probe_test_target_2_address": "https://192.0.2.200\u0007/v1/sys/health"}),
        ("generic-port-zero", {"platform_external_probe_test_target_2_address": "https://192.0.2.200:0/v1/sys/health"}),
        ("generic-port-high", {"platform_external_probe_test_target_2_address": "https://192.0.2.200:65536/v1/sys/health"}),
        ("wrong-host", {"platform_external_probe_test_target_2_host_header": "wrong.example.invalid"}),
        ("status-only", {"platform_external_probe_test_required_body_regexes": []}),
        ("mtls-no-ca", {"platform_external_probe_test_target_2_ca_file": "", "platform_external_probe_test_target_2_client_cert_file": "/run/secrets/probe.crt", "platform_external_probe_test_target_2_client_key_file": "/run/secrets/probe.key"}),
        ("invalid-vip", {"platform_external_probe_test_vip": "not-an-address"}),
        ("invalid-endpoint", {"platform_external_probe_test_endpoint": "INVALID-ENDPOINT"}),
        ("unknown-endpoint", {"platform_external_probe_test_endpoint": "unknown_vip"}),
        ("unknown-profile", {"platform_external_probe_test_grafana_profile": "unknown_profile"}),
        ("profile-service", {"platform_external_probe_test_grafana_service": "loki"}),
        ("profile-path", {"platform_external_probe_test_grafana_address": "https://grafana.example.invalid/ready"}),
        ("profile-query-path", {"platform_external_probe_test_grafana_address": "https://grafana.example.invalid?next=/api/health"}),
        ("profile-fragment-path", {"platform_external_probe_test_grafana_address": "https://grafana.example.invalid#/api/health"}),
        ("profile-trailing-newline", {"platform_external_probe_test_grafana_address": "https://grafana.example.invalid/api/health\n"}),
        ("profile-authority-newline", {"platform_external_probe_test_grafana_address": "https://grafana.example.invalid\n/api/health"}),
        ("profile-authority-space", {"platform_external_probe_test_grafana_address": "https://grafana.example.invalid /api/health"}),
        ("profile-override", {"platform_external_probe_locked_profiles": {}}),
        ("invalid-metrics", {"platform_external_probe_metrics_path": "/tmp/vip-ownership.txt"}),
        (
            "disabled-postgres-unit",
            {
                "platform_external_probe_enabled": False,
                "platform_external_probe_postgresql_service_name": "../unrelated.service",
            },
        ),
        ("incoherent-timer", {"platform_external_probe_test_timer_enabled": True, "platform_external_probe_test_timer_state": "stopped"}),
        ("postgres-host-ip", {"platform_external_probe_test_postgresql_host": "192.0.2.200"}),
        ("postgres-host-numeric", {"platform_external_probe_test_postgresql_host": "999.999.999.999"}),
        (
            "postgres-host-long-label",
            {"platform_external_probe_test_postgresql_host": f"{'a' * 64}.example.invalid"},
        ),
        (
            "postgres-host-long-name",
            {
                "platform_external_probe_test_postgresql_host": (
                    f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 61}.invalid"
                )
            },
        ),
        ("postgres-port", {"platform_external_probe_test_postgresql_port": 5433}),
        ("postgres-database", {"platform_external_probe_test_postgresql_database": "observer;DROP"}),
        ("postgres-user", {"platform_external_probe_test_postgresql_user": "monitoring-probe"}),
        ("postgres-interval", {"platform_external_probe_test_postgresql_timer_interval": "30s"}),
        ("postgres-connect-timeout", {"platform_external_probe_test_postgresql_connect_timeout": 5}),
        ("postgres-statement-timeout", {"platform_external_probe_test_postgresql_statement_timeout_ms": 4000}),
        ("garage-host", {"platform_external_probe_test_garage_host": "192.0.2.10"}),
        ("garage-port", {"platform_external_probe_test_garage_port": 8443}),
        ("garage-region", {"platform_external_probe_test_garage_region": "GARAGE"}),
        ("garage-bucket", {"platform_external_probe_test_garage_bucket": "Monitoring"}),
        ("garage-bucket-suffix", {"platform_external_probe_test_garage_bucket": "other-monitoring-example-01"}),
        ("garage-object", {"platform_external_probe_test_garage_object_key": "other/key"}),
        ("garage-interval", {"platform_external_probe_test_garage_timer_interval": "5s"}),
        ("garage-request-timeout", {"platform_external_probe_test_garage_request_timeout": 4}),
        ("garage-run-timeout", {"platform_external_probe_test_garage_run_timeout": 11}),
        (
            "garage-metrics-collision",
            {
                "platform_external_probe_enabled": False,
                "platform_external_probe_garage_metrics_path": (
                    "/var/lib/alloy/platform-external-probe/vip-ownership.prom"
                ),
            },
        ),
        (
            "garage-cross-path-collision",
            {
                "platform_external_probe_enabled": False,
                "platform_external_probe_garage_script_path": (
                    "/var/lib/alloy/platform-external-probe/vip-ownership.prom"
                ),
            },
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_external_probe_rejects_unsafe_inputs(
    case_id: str,
    extra_vars: dict[str, Any],
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    output = isolated_test_dir / case_id
    output.mkdir()
    variables = {"platform_external_probe_test_output_dir": str(output), **extra_vars}
    expected = {
        "plain-http": "must use HTTPS without URL credentials",
        "url-credentials": "must use HTTPS without URL credentials",
        "generic-query": "must use HTTPS without URL credentials",
        "generic-fragment": "must use HTTPS without URL credentials",
        "generic-path-space": "must use HTTPS without URL credentials",
        "generic-path-percent": "must use HTTPS without URL credentials",
        "generic-path-bare-percent": "must use HTTPS without URL credentials",
        "generic-path-invalid-percent": "must use HTTPS without URL credentials",
        "generic-authority-control": "must use HTTPS without URL credentials",
        "generic-port-zero": "must use HTTPS without URL credentials",
        "generic-port-high": "must use HTTPS without URL credentials",
        "wrong-host": "must use HTTPS without URL credentials",
        "status-only": "Generic external targets require explicit status",
        "mtls-no-ca": "must use HTTPS without URL credentials",
        "invalid-vip": "VIP ownership observations require safe service and endpoint labels",
        "invalid-endpoint": "VIP ownership observations require safe service and endpoint labels",
        "unknown-endpoint": "identify exactly one configured external probe target",
        "unknown-profile": "selects an unknown locked probe profile",
        "profile-service": "Locked external probe profiles require their exact service and path",
        "profile-path": "Locked external probe profiles require their exact service and path",
        "profile-query-path": "must use HTTPS without URL credentials",
        "profile-fragment-path": "must use HTTPS without URL credentials",
        "profile-trailing-newline": "must use HTTPS without URL credentials",
        "profile-authority-newline": "must use HTTPS without URL credentials",
        "profile-authority-space": "must use HTTPS without URL credentials",
        "profile-override": "Locked external probe profiles must match the role-owned contract",
        "invalid-metrics": (
            "External probe lifecycle inputs must use safe systemd and absolute path names"
        ),
        "disabled-postgres-unit": (
            "External probe lifecycle inputs must use safe systemd and absolute path names"
        ),
        "garage-metrics-collision": (
            "External probe lifecycle inputs must use safe systemd and absolute path names"
        ),
        "garage-cross-path-collision": (
            "External probe lifecycle inputs must use safe systemd and absolute path names"
        ),
    }.get(
        case_id,
        "The PostgreSQL primary probe requires"
        if case_id.startswith("postgres-")
        else "The Garage semantic canary requires"
        if case_id.startswith("garage-")
        else "External probes require",
    )
    assert_failed_with(
        run_playbook(
            command_runner,
            repo_root / "tests/fixtures/platform-external-probe/render.yml",
            extra_vars=(variables,),
        ),
        expected,
    )
