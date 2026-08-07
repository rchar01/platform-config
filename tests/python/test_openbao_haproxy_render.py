from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


@pytest.fixture
def rendered_haproxy(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> str:
    output = isolated_test_dir / "rendered"
    output.mkdir()
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/openbao-haproxy/render.yml",
        extra_vars=({"openbao_haproxy_test_output_dir": str(output)},),
    ).assert_success()
    return (output / "haproxy.cfg").read_text(encoding="utf-8")


def test_openbao_haproxy_role_staging_contract(repo_root: Path) -> None:
    defaults = (repo_root / "roles/openbao_haproxy/defaults/main.yml").read_text(encoding="utf-8")
    tasks = (repo_root / "roles/openbao_haproxy/tasks/main.yml").read_text(encoding="utf-8")
    for line in (
        "openbao_haproxy_enabled: false",
        "openbao_haproxy_service_enabled: false",
        "openbao_haproxy_service_state: stopped",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)
    assert re.search(r"^[ \t]+validate: >-$", tasks, re.MULTILINE)
    assert re.search(r"^[ \t]+allow_downgrade: true$", tasks, re.MULTILINE)


def test_openbao_haproxy_rendered_client_and_backend_contract(
    rendered_haproxy: str,
) -> None:
    patterns = (
        r"^frontend openbao_client$",
        r"^  bind [*]:8200$",
        r"^  mode tcp$",
        r"^  acl openbao_client_source src 198[.]51[.]100[.]0/24$",
        r"^  tcp-request connection reject unless openbao_client_source$",
        r"^  option httpchk$",
        r"^  http-check send meth GET uri /v1/sys/health ver HTTP/1[.]1 hdr Host bao[.]example[.]invalid$",
        r"^  http-check expect status 200$",
        r"^  server openbao-example-01 192[.]0[.]2[.]63:18200 check check-ssl check-sni bao-1[.]internal[.]invalid verify required ca-file /etc/openbao/tls/ca[.]crt verifyhost bao-1[.]internal[.]invalid$",
        r"^  server openbao-example-02 192[.]0[.]2[.]64:18200 check check-ssl check-sni bao-2[.]internal[.]invalid verify required ca-file /etc/openbao/tls/ca[.]crt verifyhost bao-2[.]internal[.]invalid$",
        r"^  server openbao-example-03 192[.]0[.]2[.]65:18200 check check-ssl check-sni bao-3[.]internal[.]invalid verify required ca-file /etc/openbao/tls/ca[.]crt verifyhost bao-3[.]internal[.]invalid$",
    )
    for pattern in patterns:
        assert re.search(pattern, rendered_haproxy, re.MULTILINE), pattern
    assert not re.search(
        r"server .*:18200 ssl(?:\s|$)|standbyok|:8201 check", rendered_haproxy
    )


def test_openbao_haproxy_rendered_metrics_contract(rendered_haproxy: str) -> None:
    for pattern in (
        r"^frontend openbao_metrics$",
        r"^  bind 192[.]0[.]2[.]63:8404$",
        r"^  acl openbao_metrics_source src 192[.]0[.]2[.]128/25$",
        r"^  http-request use-service prometheus-exporter if \{ path -m str /metrics \}$",
        r"^  http-request deny deny_status 404$",
    ):
        assert re.search(pattern, rendered_haproxy, re.MULTILINE), pattern


@pytest.mark.parametrize(
    ("case_id", "extra_vars"),
    [
        ("unpinned-package", {"openbao_haproxy_test_package_nevra": ""}),
        ("active-service", {"openbao_haproxy_test_service_enabled": True}),
        ("port-collision", {"openbao_haproxy_test_backend_port": 8200}),
        ("duplicate-dns", {"openbao_haproxy_test_backend_2_dns": "bao-1.internal.invalid"}),
        ("malformed-dns", {"openbao_haproxy_test_backend_2_dns": "-bao.internal.invalid"}),
        ("unsafe-name", {"openbao_haproxy_test_backend_2_name": "unsafe/name"}),
        ("invalid-source", {"openbao_haproxy_test_client_sources": ["198.51.100.999/24"]}),
        ("empty-stats", {"openbao_haproxy_test_stats_sources": []}),
        ("open-client", {"openbao_haproxy_test_client_sources": ["0.0.0.0/0"]}),
        ("open-stats", {"openbao_haproxy_test_stats_sources": ["0.0.0.0/0"]}),
        ("unnormalized-source", {"openbao_haproxy_test_client_sources": ["198.51.100.1/24"]}),
        ("unsafe-user", {"openbao_haproxy_test_user": "haproxy%0Aroot"}),
        ("zero-maxconn", {"openbao_haproxy_test_maxconn": 0}),
        ("standby-health", {"openbao_haproxy_test_health_path": "/v1/sys/health?standbyok=true"}),
        ("malformed-health-host", {"openbao_haproxy_test_health_host": ".bao.example.invalid"}),
        ("ownership-conflict", {"openbao_haproxy_test_workload_lb_enabled": True}),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_openbao_haproxy_rejects_unsafe_inputs(
    case_id: str,
    extra_vars: dict[str, Any],
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    output = isolated_test_dir / case_id
    output.mkdir()
    variables = {"openbao_haproxy_test_output_dir": str(output), **extra_vars}
    expected = {
        "malformed-dns": "OpenBao HAProxy backends require",
        "unsafe-name": "OpenBao HAProxy backends require",
        "invalid-source": "must be a restricted, network-normalized IPv4 CIDR",
        "open-client": "must be a restricted, network-normalized IPv4 CIDR",
        "open-stats": "must be a restricted, network-normalized IPv4 CIDR",
        "unnormalized-source": "must be a restricted, network-normalized IPv4 CIDR",
    }.get(case_id, "OpenBao HAProxy requires")
    assert_failed_with(
        run_playbook(
            command_runner,
            repo_root / "tests/fixtures/openbao-haproxy/render.yml",
            extra_vars=(variables,),
        ),
        expected,
    )
