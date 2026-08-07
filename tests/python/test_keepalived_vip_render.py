from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from ansible_test_helpers import run_playbook
from conftest import CommandRunner


def _render(
    repo_root: Path,
    command_runner: CommandRunner,
    output_dir: Path,
    extra_vars: dict[str, Any] | None = None,
) -> None:
    output_dir.mkdir()
    variables = {"keepalived_vip_test_output_dir": str(output_dir)}
    variables.update(extra_vars or {})
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/keepalived-vip/render.yml",
        extra_vars=(variables,),
    ).assert_success()


@pytest.fixture
def rendered_keepalived(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> dict[str, str]:
    output = isolated_test_dir / "rendered"
    _render(repo_root, command_runner, output)
    return {
        name: (output / filename).read_text(encoding="utf-8")
        for name, filename in {
            "config": "keepalived.conf",
            "script": "check-service",
            "drop_in": "platform.conf",
        }.items()
    }


def test_keepalived_vip_role_staging_defaults(repo_root: Path) -> None:
    defaults = (repo_root / "roles/keepalived_vip/defaults/main.yml").read_text(encoding="utf-8")
    for line in (
        "keepalived_vip_enabled: false",
        "keepalived_vip_service_enabled: false",
        "keepalived_vip_service_state: stopped",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)


def test_keepalived_vip_rendered_fail_closed_contract(
    rendered_keepalived: dict[str, str]
) -> None:
    config = rendered_keepalived["config"]
    for pattern in (
        r"^[ \t]+state BACKUP$",
        r"^[ \t]+preempt_delay 300$",
        r"^[ \t]+unicast_src_ip 192[.]0[.]2[.]10$",
        r"^[ \t]+weight 0$",
        r"^[ \t]+init_fail$",
        r"^[ \t]+check_unicast_src$",
        r"^[ \t]+unicast_fault_no_peer$",
    ):
        assert re.search(pattern, config, re.MULTILINE), pattern
    assert not re.search(r"^[ \t]+nopreempt$", config, re.MULTILINE)
    assert not re.search(r"^[ \t]+state MASTER$", config, re.MULTILINE)


def test_keepalived_vip_tracking_script_contract(
    rendered_keepalived: dict[str, str]
) -> None:
    script = rendered_keepalived["script"]
    assert re.search(r"^#!/bin/bash$", script, re.MULTILINE)
    assert "systemctl is-active --quiet haproxy.service" in script
    assert "ip link show up dev vrrp-test >/dev/null 2>&1" in script
    assert 'sport = :8200" 2>/dev/null' in script
    assert not re.search(r"openbao|grafana|loki|mimir|postgres", script)


def test_keepalived_vip_systemd_ordering_contract(
    rendered_keepalived: dict[str, str]
) -> None:
    assert re.search(
        r"^After=network-online[.]target haproxy[.]service$",
        rendered_keepalived["drop_in"],
        re.MULTILINE,
    )


@pytest.mark.parametrize("priority", [1, 254])
def test_keepalived_vip_accepts_priority_boundaries(
    priority: int,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    _render(
        repo_root,
        command_runner,
        isolated_test_dir / f"priority-{priority}",
        {
            "keepalived_vip_test_priority": priority,
            "keepalived_vip_test_canonical_priority": priority,
        },
    )


@pytest.mark.parametrize("delay", [60, 1000])
def test_keepalived_vip_accepts_preempt_delay_boundaries(
    delay: int,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    _render(
        repo_root,
        command_runner,
        isolated_test_dir / f"delay-{delay}",
        {"keepalived_vip_preempt_delay": delay},
    )


@pytest.mark.parametrize(
    ("case_id", "extra_vars"),
    [
        ("priority-255", {"keepalived_vip_test_priority": 255, "keepalived_vip_test_canonical_priority": 255}),
        ("delay-59", {"keepalived_vip_preempt_delay": 59}),
        ("delay-1001", {"keepalived_vip_preempt_delay": 1001}),
        ("string-delay", {"keepalived_vip_preempt_delay": "300"}),
        ("unpinned-package", {"keepalived_vip_test_package_nevra": ""}),
        ("duplicate-router", {"keepalived_vip_test_peer_2_router_id": "test-node-01"}),
        ("duplicate-priority", {"keepalived_vip_test_peer_2_priority": 150}),
        ("extra-instance", {"keepalived_vip_test_peer_2_extra_instances": {"EXTRA_VIP": {"source_address": "192.0.2.21", "priority": 120}}}),
        ("remote-priority-255", {"keepalived_vip_test_peer_2_priority": 255}),
        ("decimal-priority", {"keepalived_vip_test_canonical_priority": "150.9"}),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_keepalived_vip_rejects_unsafe_inputs(
    case_id: str,
    extra_vars: dict[str, Any],
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    output = isolated_test_dir / case_id
    output.mkdir()
    variables = {"keepalived_vip_test_output_dir": str(output), **extra_vars}
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/keepalived-vip/render.yml",
        extra_vars=(variables,),
    ).assert_failure()
