from __future__ import annotations

import re
from pathlib import Path

import pytest

from ansible_test_helpers import run_playbook
from conftest import CommandRunner


@pytest.fixture
def rendered_monitoring_haproxy(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> tuple[str, str]:
    output = isolated_test_dir / "rendered"
    output.mkdir()
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/monitoring-haproxy/render.yml",
        extra_vars=({"monitoring_haproxy_test_output_dir": str(output)},),
    ).assert_success()
    return (
        (output / "haproxy.cfg").read_text(encoding="utf-8"),
        (output / "roles.map").read_text(encoding="utf-8"),
    )


def test_monitoring_haproxy_rendered_frontend_policy(
    rendered_monitoring_haproxy: tuple[str, str],
) -> None:
    config, roles = rendered_monitoring_haproxy
    for pattern in (
        r"^frontend monitoring_https$",
        r"^  bind [*]:443 ssl .* verify required strict-sni alpn http/1[.]1$",
        r"^  tcp-request connection reject unless monitoring_https_source$",
        r"^  acl monitoring_operator_source src 127[.]0[.]0[.]1/32$",
        r"^  http-request del-header X-Scope-OrgID$",
        r"^  http-request set-header X-Scope-OrgID synthetic-tenant if host_loki$",
        r"^  http-request set-header X-Scope-OrgID synthetic-tenant if host_mimir$",
        r"^  http-request set-header X-Scope-OrgID synthetic-tenant if host_alertmanager$",
        r"^  http-request set-var\(txn[.]authorized\) str\(yes\) if host_mimir role_operator monitoring_operator_source method_operator_0 path_operator_0$",
    ):
        assert re.search(pattern, config, re.MULTILINE), pattern
    assert "CN=operator,OU=operators,O=platform-test,C=XX operator" in roles
    assert len(roles.splitlines()) == 10


def test_monitoring_haproxy_rendered_health_contract(
    rendered_monitoring_haproxy: tuple[str, str],
) -> None:
    config, _ = rendered_monitoring_haproxy
    for health_line in (
        "http-check send meth GET uri /api/health ver HTTP/1.1 hdr Host grafana.test.invalid",
        "http-check send meth GET uri /ready ver HTTP/1.1 hdr Host loki.test.invalid",
        "http-check send meth GET uri /ready ver HTTP/1.1 hdr Host mimir.test.invalid",
        "http-check send meth GET uri /ready ver HTTP/1.1 hdr Host alertmanager.test.invalid",
        "http-check send meth GET uri /health ver HTTP/1.1 hdr Host localhost",
        "http-check send meth HEAD uri /primary ver HTTP/1.1 hdr Host postgresql.test.invalid",
    ):
        assert health_line in config
    assert re.search(
        r"^  server local-garage 127[.]0[.]0[.]1:19000 check port 19001 ",
        config,
        re.MULTILINE,
    )
    assert not re.search(r"^  server local-garage .*\bssl\b", config, re.MULTILINE)
    assert re.search(
        r"^  server postgresql-1 127[.]0[.]0[.]5:15433 check port 18448 check-ssl ",
        config,
        re.MULTILINE,
    )


def test_monitoring_haproxy_rendered_tls_backends_and_metrics(
    rendered_monitoring_haproxy: tuple[str, str],
) -> None:
    config, _ = rendered_monitoring_haproxy
    assert len(re.findall(r"^  server monitoring-[123] .* ssl check verify required ", config, re.MULTILINE)) == 12
    for pattern in (
        r"^frontend monitoring_postgresql$",
        r"^  tcp-request connection reject unless monitoring_postgresql_source$",
        r"^frontend monitoring_metrics$",
        r"^  bind 127[.]0[.]0[.]1:18404$",
        r"^  http-request use-service prometheus-exporter if \{ path -m str /metrics \}$",
        r"^  http-request deny deny_status 404$",
    ):
        assert re.search(pattern, config, re.MULTILINE), pattern
