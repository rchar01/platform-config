"""Real node-side builtin URI probes over isolated loopback TLS; no live hosts."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from test_rke2_operations import _operation_fake_script, _write_executable


KEY = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-key\n"
PIN = hashlib.sha256(KEY).hexdigest()


@pytest.fixture
def endpoint(isolated_test_dir, command_runner):
    cert = isolated_test_dir / "ca.crt"
    key = isolated_test_dir / "ca.key"
    command_runner.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=bootstrap-loopback", "-keyout", key, "-out", cert,
        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        "-addext", "basicConstraints=critical,CA:TRUE",
    ]).assert_success()
    key.chmod(0o600)
    state = {"status": 200, "kind": "registry", "key_status": 200, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append(self.path)
            is_key = self.path == "/key"
            status = state["key_status"] if is_key else state["status"]
            self.send_response(status)
            self.send_header("Location", "/must-not-follow")
            if is_key:
                body = KEY
                self.send_header("Content-Type", "text/plain")
            else:
                kind = state["kind"]
                body = b"<html>login</html>" if kind == "html" else b"{}"
                if kind == "empty":
                    body = b""
                self.send_header("Content-Type", "text/html" if kind == "html" else "application/json")
                if kind != "nonregistry":
                    self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                self.send_header(
                    "WWW-Authenticate",
                    'Basic realm="registry"' if kind == "basic" else
                    'Bearer service="fixture", realm="https://127.0.0.1/token"',
                )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.update(origin=f"https://127.0.0.1:{server.server_port}", cert=cert)
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run_preflight(repo_root, isolated_test_dir, command_runner, endpoint, *,
                  updates=None, check=False, trusted=True, hosts=1, bad_last_host=False):
    origin = endpoint["origin"]
    variables = {
        "ansible_connection": "local",
        "ansible_python_interpreter": sys.executable,
        "ansible_become": False,
        "rke2_rpm_common_repository_url": origin + "/common%20repo",
        "rke2_rpm_version_repository_url": origin + "/version",
        "rke2_rpm_gpg_key_url": origin + "/key",
        "rke2_rpm_gpg_key_sha256": PIN,
        "rke2_disable_default_registry_endpoint": True,
        "rke2_registry_mirrors": {
            "docker.io": {"endpoint": [origin]},
            "ghcr.io": {"endpoint": [origin + "/", origin + "/v2/"]},
        },
    }
    variables.update(updates or {})
    # None here means absent inventory input, not a YAML null.
    variables = {key: value for key, value in variables.items() if value is not None}
    inventory = isolated_test_dir / "hosts.json"
    inventory.write_text(json.dumps({"all": {"vars": variables, "children": {
        "rke2_cluster": {"children": {
            "rke2_servers": {"hosts": {"node1": {}}},
            "rke2_agents": {"hosts": {
                f"node{i}": {"rke2_rpm_gpg_key_sha256": "0" * 64}
                if bad_last_host and i == hosts else {} for i in range(2, hosts + 1)
            }},
        }},
    }}}))
    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir(exist_ok=True)
    # Only the pristine RPM query is faked. stat, setup, URI and assertions are real.
    _write_executable(fake_bin / "rpm", "#!/bin/sh\n[ \"$1\" = --query ] || exit 99\nexit 1\n")
    environment = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "SSL_CERT_FILE": str(endpoint["cert"]) if trusted else "/nonexistent-fixture-ca",
        "SSL_CERT_DIR": "/nonexistent-fixture-ca-dir",
    }
    return command_runner.run([
        "ansible-playbook", "-i", inventory,
        repo_root / "playbooks/rke2-bootstrap-preflight.yml",
        *(["--check"] if check else []),
    ], environment=environment, timeout=90)


@pytest.mark.parametrize("case", [
    "valid-check", "bearer", "wrong-hash", "untrusted-key", "key-redirect",
    "403", "404", "redirect", "html", "nonregistry", "basic",
    "no-mirrors", "path-v2", "explicit-ca", "future-ca", "untrusted-registry",
])
def test_bootstrap_endpoint_contract(repo_root, isolated_test_dir, command_runner, endpoint, case):
    updates = {}
    success = case in {"valid-check", "bearer", "no-mirrors", "path-v2", "explicit-ca"}
    if case == "wrong-hash":
        updates["rke2_rpm_gpg_key_sha256"] = "0" * 64
    if case == "key-redirect":
        endpoint["key_status"] = 302
    if case == "valid-check":
        endpoint["kind"] = "empty"
    if case in {"403", "404", "redirect", "bearer", "basic"}:
        endpoint["status"] = {"redirect": 302, "bearer": 401, "basic": 401}.get(case, int(case) if case.isdigit() else 200)
    if case in {"html", "nonregistry", "basic"}:
        endpoint["kind"] = case
    if case == "no-mirrors":
        updates.update(rke2_registry_mirrors=None, rke2_disable_default_registry_endpoint=None)
    if case == "path-v2":
        updates["rke2_registry_mirrors"] = {
            "docker.io": {"endpoint": [endpoint["origin"] + "/repository/docker/v2"]},
        }
    if case in {"explicit-ca", "future-ca", "untrusted-registry"}:
        ca = endpoint["cert"]
        if case == "future-ca":
            ca = isolated_test_dir / "not-installed.crt"
        if case == "untrusted-registry":
            ca = "/etc/ssl/certs/ca-certificates.crt"
        updates.update(rke2_registry_ca_src="/controller-only/ca.crt", rke2_registry_ca_path=str(ca), rke2_registry_configs={
            endpoint["origin"].removeprefix("https://"): {"tls": {"ca_file": "{{ rke2_registry_ca_path }}"}},
        })
    result = run_preflight(repo_root, isolated_test_dir, command_runner, endpoint,
                           updates=updates, check=case == "valid-check", trusted=case != "untrusted-key")
    if success:
        result.assert_success()
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
    if case == "untrusted-key":
        assert endpoint["requests"] == []
        assert "CERTIFICATE_VERIFY_FAILED" in result.stdout
    elif case in {"wrong-hash", "key-redirect", "no-mirrors", "future-ca", "untrusted-registry"}:
        assert endpoint["requests"] == ["/key"]
    else:
        path = "/repository/docker/v2/" if case == "path-v2" else "/v2/"
        assert endpoint["requests"] == ["/key", path]
    if case == "wrong-hash":
        assert "SHA-256" in result.stdout
    if case in {"future-ca", "untrusted-registry"}:
        assert "preinstalled" in result.stdout


@pytest.mark.parametrize("updates", [
    {"rke2_rpm_gpg_key_sha256": ""},
    {"rke2_rpm_gpg_key_url": 42},
    {"rke2_rpm_gpg_key_url": "https://example.test/key\n"},
    {"rke2_rpm_gpg_key_url": "https://example.test/key%GG"},
    {"rke2_rpm_common_repository_url": "https://user:secret@example.test/repo"},
    {"rke2_registry_mirrors": {"docker.io": {"endpoint": "https://example.test"}}},
    {"rke2_registry_mirrors": {"docker.io": {"endpoint": ["https://example.test:99999/v2"]}}},
    {"rke2_registry_mirrors": {"docker.io": {"endpoint": ["https://example.test/v2?secret=x"]}}},
    {"rke2_registry_configs": []},
])
def test_bootstrap_invalid_sources_fail_before_http(
    repo_root, isolated_test_dir, command_runner, endpoint, updates,
):
    result = run_preflight(repo_root, isolated_test_dir, command_runner, endpoint,
                           updates=updates).assert_failure()
    assert endpoint["requests"] == []
    assert "user:secret" not in result.stdout + result.stderr


@pytest.mark.parametrize("case", ["valid", "wrong-hash", "untrusted", "registry-error", "invalid-type"])
def test_bootstrap_metadata_policy_preserves_source_checks(
    repo_root, isolated_test_dir, command_runner, endpoint, case,
):
    updates: dict[str, object] = {"rke2_rpm_repo_gpgcheck": False}
    if case == "wrong-hash":
        updates["rke2_rpm_gpg_key_sha256"] = "0" * 64
    if case == "registry-error":
        endpoint["status"] = 403
    if case == "invalid-type":
        updates["rke2_rpm_repo_gpgcheck"] = "false"
    result = run_preflight(repo_root, isolated_test_dir, command_runner, endpoint,
                           updates=updates, check=True, trusted=case != "untrusted")
    if case == "valid":
        result.assert_success()
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
    expected = [] if case in {"untrusted", "invalid-type"} else ["/key"]
    if case in {"valid", "registry-error"}:
        expected.append("/v2/")
    assert endpoint["requests"] == expected


def test_bootstrap_rejects_registry_tls_bypass_before_http(
    repo_root, isolated_test_dir, command_runner, endpoint,
):
    run_preflight(repo_root, isolated_test_dir, command_runner, endpoint, updates={
        "rke2_registry_configs": {
            endpoint["origin"].removeprefix("https://"): {"tls": {"insecure_skip_verify": True}},
        },
    }).assert_failure()
    assert endpoint["requests"] == []


@pytest.mark.parametrize("case", [
    "system-trust", "canonical-ca", "noncanonical-config", "noncanonical-endpoint",
])
def test_bootstrap_authority_case_and_path_identity(
    repo_root, isolated_test_dir, command_runner, endpoint, case,
):
    port = endpoint["origin"].rsplit(":", 1)[1]
    canonical = f"localhost:{port}"
    authorities = [canonical] * 3
    if case in {"system-trust", "noncanonical-endpoint"}:
        authorities = [f"LOCALhost:{port}", canonical, f"localHOST:{port}"]
    configs = {} if case == "system-trust" else {
        canonical: {"tls": {"ca_file": str(endpoint["cert"])}}
    }
    if case == "noncanonical-config":
        # Reject case-ambiguous keys even when they select the same CA.
        configs[canonical.upper()] = configs[canonical]
    result = run_preflight(repo_root, isolated_test_dir, command_runner, endpoint, check=True, updates={
        "rke2_registry_mirrors": {
            "docker.io": {"endpoint": [f"https://{authorities[0]}/Repository/v2"]},
            "ghcr.io": {"endpoint": [
                f"https://{authorities[1]}/Repository/v2/",
                f"https://{authorities[2]}/repository/v2",
            ]},
        },
        "rke2_registry_configs": configs,
    })
    if case in {"system-trust", "canonical-ca"}:
        result.assert_success()
        # DNS case aliases deduplicate, but case-distinct repository paths do not.
        assert endpoint["requests"] == ["/key", "/Repository/v2/", "/repository/v2/"]
        ca_path = "null" if case == "system-trust" else str(endpoint["cert"])
        assert result.stdout.count(f"ca_path: {ca_path}") == 2
        assert "changed=0" in result.stdout
    else:
        result.assert_failure()
        assert endpoint["requests"] == []
        assert "canonical lowercase authority key" in result.stdout


def test_bootstrap_checks_all_nine_pristine_hosts_before_source_failure(
    repo_root, isolated_test_dir, command_runner, endpoint,
):
    result = run_preflight(repo_root, isolated_test_dir, command_runner, endpoint,
                           hosts=9, bad_last_host=True, check=True).assert_failure()
    assert endpoint["requests"] == ["/key"] * 9
    for index in range(1, 10):
        assert f"ok: [node{index}] => (item=rke2-server)" in result.stdout
        assert f"ok: [node{index}] => (item=/var/lib/rancher/rke2)" in result.stdout
    assert "Bootstrap RPM key SHA-256 differs" in result.stdout


@pytest.mark.parametrize("operation", ["rke2-bootstrap-plan", "rke2-bootstrap"])
def test_bootstrap_launcher_stops_at_failed_preflight(
    repo_root, isolated_test_dir, command_runner, operation,
):
    inventory = isolated_test_dir / "hosts.yml"
    controller = isolated_test_dir / "controller.yml"
    log = isolated_test_dir / "commands.jsonl"
    inventory.write_text("all: {}\n")
    controller.write_text("{}\n")
    controller.chmod(0o600)
    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir()
    for name in ("ansible", "ansible-inventory", "ansible-playbook"):
        _write_executable(fake_bin / name, _operation_fake_script())
    result = command_runner.run([
        repo_root / "scripts/platform-config-operation", operation,
        "--inventory", inventory, "--controller-vars", controller,
    ], environment={
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "PLATFORM_CONFIG_OPERATION_LOG": str(log),
        "PLATFORM_CONFIG_FAIL_MATCH": "rke2-bootstrap-preflight.yml",
    }).assert_failure()
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert [command[0] for command in commands] == ["ansible-inventory", "ansible", "ansible-playbook"]
    assert str(repo_root / "playbooks/rke2-bootstrap-preflight.yml") in commands[-1]
    assert "Overall: FAIL" in result.stdout
