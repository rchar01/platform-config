"""Real parser/socket regression; requires haproxy, curl and openssl in the container.

Run with python -m pytest -n 0 -s tests/python/test_openbao_haproxy_client_acl.py.
Only synthetic loopback listeners, ephemeral ports and temporary PKI are used.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
from jinja2 import Environment, StrictUndefined
import yaml

from conftest import CommandRunner


SERVICE_DNS = "bao.example.invalid"
NODE_DNS = "bao-node.internal.invalid"
KNOWN_CLIENT = "127.0.0.2"
CALLER = "127.0.0.3"
DENIED_CLIENT = "127.0.0.4"
BACKEND = "127.0.0.10"


@contextmanager
def running_process(argv, log_path: Path, environment):
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment
        )
        try:
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def unused_port(address: str) -> int:
    with socket.socket() as listener:
        listener.bind((address, 0))
        port = listener.getsockname()[1]
    assert port >= 1024
    return port


def wait_for_listener(process, address: str, port: int, log_path: Path) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, log_path.read_text(encoding="utf-8")
        try:
            with socket.create_connection((address, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    pytest.fail(f"Listener {address}:{port} not ready: {log_path.read_text()}")


def test_openbao_haproxy_exact_client_source_acl(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner
) -> None:
    missing = [name for name in ("haproxy", "curl", "openssl") if not shutil.which(name)]
    if missing:
        pytest.skip("Real HAProxy ACL regression requires container tools: " + ", ".join(missing))

    run = command_runner.run
    print(run(["haproxy", "-v"]).assert_success().stdout.strip())
    print(run(["curl", "--version"]).assert_success().stdout.splitlines()[0])
    work = isolated_test_dir
    ca, ca_key = work / "ca.crt", work / "ca.key"
    cert, key, csr = work / "backend.crt", work / "backend.key", work / "backend.csr"
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=synthetic-acl-test-ca", "-keyout", ca_key, "-out", ca,
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ]).assert_success()
    run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-subj", f"/CN={NODE_DNS}", "-keyout", key, "-out", csr,
        "-addext", f"subjectAltName=DNS:{NODE_DNS},DNS:{SERVICE_DNS}",
        "-addext", "extendedKeyUsage=serverAuth",
    ]).assert_success()
    run([
        "openssl", "x509", "-req", "-days", "1", "-in", csr,
        "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-copy_extensions", "copy",
        "-out", cert,
    ]).assert_success()
    for private_key in (ca_key, key):
        private_key.chmod(0o600)

    backend_port = unused_port(BACKEND)
    status_file, sni_log = work / "status", work / "sni.log"
    status_file.write_text("200\n", encoding="ascii")
    backend_log = work / "backend.log"
    backend_command = [
        sys.executable, str(repo_root / "tests/fixtures/openbao-haproxy/health_fixture.py"),
        "--bind", BACKEND, "--port", str(backend_port),
        "--cert", str(cert), "--key", str(key), "--status-file", str(status_file),
        "--sni-log", str(sni_log), "--node", "active-node",
        "--expected-host", SERVICE_DNS, "--expected-sni", NODE_DNS,
        "--expected-sni", SERVICE_DNS,
    ]
    role = repo_root / "roles/openbao_haproxy"
    variables = yaml.safe_load((role / "defaults/main.yml").read_text(encoding="utf-8"))
    variables.update({
        "openbao_haproxy_user": pwd.getpwuid(os.geteuid()).pw_name,
        "openbao_haproxy_group": grp.getgrgid(os.getegid()).gr_name,
        "openbao_haproxy_client_bind": "127.0.0.1",
        "openbao_haproxy_backend_port": backend_port,
        "openbao_haproxy_backend_ca_path": str(ca),
        "openbao_haproxy_backend_health_host": SERVICE_DNS,
        "openbao_cluster_members": [
            {"name": "active-node", "address": BACKEND, "dns": NODE_DNS},
        ],
    })
    template = Environment(
        undefined=StrictUndefined, trim_blocks=True, keep_trailing_newline=True
    ).from_string(
        (role / "templates/haproxy.cfg.j2").read_text(encoding="utf-8")
    )
    response_body = work / "response.json"

    def query(source: str, port: int):
        response_body.write_text("", encoding="utf-8")
        return run([
            "curl", "--disable", "--silent", "--show-error", "--fail",
            "--noproxy", "*", "--connect-timeout", "2", "--max-time", "3",
            "--interface", source, "--cacert", ca,
            "--resolve", f"{SERVICE_DNS}:{port}:127.0.0.1",
            "--header", f"Host: {SERVICE_DNS}", "--output", response_body,
            "--write-out", "%{http_code} %{time_appconnect}",
            f"https://{SERVICE_DNS}:{port}/v1/sys/health",
        ], timeout=5)

    def assert_allowed(result):
        result.assert_success()
        status, tls_time = result.stdout.split()
        assert status == "200", result.diagnostics()
        assert float(tls_time) > 0, result.diagnostics()
        assert json.loads(response_body.read_text(encoding="utf-8")) == {
            "initialized": True, "sealed": False, "standby": False, "node": "active-node",
        }

    def assert_denied(result):
        # curl's TLS backend can report either handshake failure or connection reset.
        # Neither an HTTP error nor a failure after a completed handshake qualifies.
        assert result.returncode in (35, 56), result.diagnostics()
        status, tls_time = result.stdout.split()
        assert status == "000" and float(tls_time) == 0, result.diagnostics()
        assert response_body.read_bytes() == b"", result.diagnostics()

    with running_process(backend_command, backend_log, command_runner.environment) as backend:
        wait_for_listener(backend, BACKEND, backend_port, backend_log)
        client_port = unused_port("127.0.0.1")
        stats_port = unused_port("127.0.0.1")
        while stats_port == client_port:
            stats_port = unused_port("127.0.0.1")
        variables.update({
            "openbao_haproxy_client_port": client_port,
            "openbao_haproxy_stats_port": stats_port,
        })
        for caller_included in (False, True):
            # Only the caller's exact /32 changes: baseline access is retained,
            # and the adjacent denied address never enters the allowlist.
            sources = [f"{KNOWN_CLIENT}/32"]
            if caller_included:
                sources.append(f"{CALLER}/32")
            variables["openbao_haproxy_client_allowed_sources"] = sources
            config = work / "haproxy.cfg"
            config.write_text(template.render(**variables), encoding="utf-8")
            run(["haproxy", "-c", "-f", config]).assert_success()
            print(f"allowlist={sources}: native parser accepted")
            haproxy_log = work / f"haproxy-{caller_included}.log"
            with running_process(
                ["haproxy", "-db", "-f", str(config)], haproxy_log,
                command_runner.environment,
            ) as haproxy:
                wait_for_listener(haproxy, "127.0.0.1", client_port, haproxy_log)
                baseline = query(KNOWN_CLIENT, client_port)
                assert_allowed(baseline)
                print(f"baseline {KNOWN_CLIENT}: rc={baseline.returncode} {baseline.stdout}")
                caller = query(CALLER, client_port)
                if caller_included:
                    assert_allowed(caller)
                else:
                    assert_denied(caller)
                print(f"caller {CALLER}: rc={caller.returncode} {caller.stdout}")
                denied = query(DENIED_CLIENT, client_port)
                assert_denied(denied)
                print(f"denied {DENIED_CLIENT}: rc={denied.returncode} {denied.stdout}")
                assert haproxy.poll() is None, haproxy_log.read_text(encoding="utf-8")

        # Independent backend health-check SNI and end-to-end client SNI both
        # reached the existing TLS fixture through the production configuration.
        observed_sni = sni_log.read_text(encoding="ascii").splitlines()
        assert NODE_DNS in observed_sni
        assert SERVICE_DNS in observed_sni
        assert backend.poll() is None, backend_log.read_text(encoding="utf-8")
