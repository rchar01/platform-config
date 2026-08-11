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
        r'address_mode\s*=\s*"vip"',
        r'^prometheus[.]exporter[.]unix "platform_vip_ownership"',
    ):
        assert re.search(pattern, fragment, re.MULTILINE), pattern
    assert not re.search(r"insecure_skip_verify: true|clustering", fragment)


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


@pytest.mark.parametrize(
    ("case_id", "extra_vars"),
    [
        ("duplicate-name", {"platform_external_probe_test_target_2_name": "openbao_dns"}),
        ("plain-http", {"platform_external_probe_test_target_2_address": "http://192.0.2.200:8200/v1/sys/health"}),
        ("url-credentials", {"platform_external_probe_test_target_2_address": "https://user:secret@192.0.2.200/v1/sys/health"}),
        ("wrong-host", {"platform_external_probe_test_target_2_host_header": "wrong.example.invalid"}),
        ("status-only", {"platform_external_probe_test_required_body_regexes": []}),
        ("mtls-no-ca", {"platform_external_probe_test_target_2_ca_file": "", "platform_external_probe_test_target_2_client_cert_file": "/run/secrets/probe.crt", "platform_external_probe_test_target_2_client_key_file": "/run/secrets/probe.key"}),
        ("invalid-vip", {"platform_external_probe_test_vip": "not-an-address"}),
        ("invalid-metrics", {"platform_external_probe_metrics_path": "/tmp/vip-ownership.txt"}),
        ("incoherent-timer", {"platform_external_probe_test_timer_enabled": True, "platform_external_probe_test_timer_state": "stopped"}),
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
        "wrong-host": "must use HTTPS without URL credentials",
        "status-only": "must use HTTPS without URL credentials",
        "mtls-no-ca": "must use HTTPS without URL credentials",
        "invalid-vip": "VIP ownership observations require safe labels",
        "invalid-metrics": (
            "External probe lifecycle inputs must use safe systemd and absolute path names"
        ),
    }.get(case_id, "External probes require")
    assert_failed_with(
        run_playbook(
            command_runner,
            repo_root / "tests/fixtures/platform-external-probe/render.yml",
            extra_vars=(variables,),
        ),
        expected,
    )
