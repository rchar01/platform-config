from __future__ import annotations

import hashlib
import http.server
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

from conftest import CommandResult, CommandRunner


pytestmark = pytest.mark.pki

REQUEST_FILES = (
    "tls.csr",
    "request",
    "request.sig",
    "collection-receipt",
)
PACKAGE_FILES = (*REQUEST_FILES, "stage-manifest")
TRUST_NAMES = (
    "policy",
    "requesters.allowed_signers",
    "approvers.allowed_signers",
    "responses.allowed_signers",
    "deployers.allowed_signers",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, data: str | bytes) -> None:
    if isinstance(data, str):
        path.write_text(data, encoding="ascii")
    else:
        path.write_bytes(data)
    path.chmod(0o600)


def _mkdir_private(path: Path, *, parents: bool = False) -> None:
    path.mkdir(parents=parents)
    path.chmod(0o700)


@dataclass
class GitLabState:
    token: str
    project_path: str = "platform/pki-exchange"
    project_endpoint_id: int = 42
    project_id: Any = 42
    project_web_url: str | None = None
    package_status: str = "default"
    files: dict[str, bytes] = field(default_factory=dict)
    uploads: list[str] = field(default_factory=list)
    ambiguous: bool = False
    malformed_link: bool = False
    reject_auth: bool = False
    redirect_get: bool = False
    pause_error_response: bool = False
    error_request_started: threading.Event = field(default_factory=threading.Event)
    resume_error_response: threading.Event = field(default_factory=threading.Event)
    pause_first_upload: bool = False
    upload_started: threading.Event = field(default_factory=threading.Event)
    resume_upload: threading.Event = field(default_factory=threading.Event)
    pause_complete_inspection_number: int = 0
    complete_inspection_count: int = 0
    inspection_started: threading.Event = field(default_factory=threading.Event)
    resume_inspection: threading.Event = field(default_factory=threading.Event)
    request_count: int = 0


class GitLabFixture(http.server.ThreadingHTTPServer):
    state: GitLabState
    origin: str


class GitLabHandler(http.server.BaseHTTPRequestHandler):
    @property
    def fixture(self) -> GitLabFixture:
        return cast(GitLabFixture, self.server)

    def _authorized(self) -> bool:
        return (
            not self.fixture.state.reject_auth
            and self.headers.get("JOB-TOKEN") == self.fixture.state.token
        )

    def _json(
        self, status: int, value: Any, *, link: str | None = None
    ) -> None:
        data = json.dumps(value, sort_keys=True).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if link is not None:
            self.send_header("Link", link)
        self.end_headers()
        self.wfile.write(data)

    def _reject(self) -> None:
        if self.fixture.state.pause_error_response:
            self.fixture.state.error_request_started.set()
            if not self.fixture.state.resume_error_response.wait(timeout=10):
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        body = f"rejected token {self.headers.get('JOB-TOKEN', '')}".encode()
        self.send_response(401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _package_object(status: str, package_id: int = 7) -> dict[str, Any]:
        return {
            "id": package_id,
            "name": "pki-exchange-request-registry-test",
            "version": "0123456789abcdef0123456789abcdef",
            "package_type": "generic",
            "status": status,
        }

    def do_GET(self) -> None:  # noqa: N802
        self.fixture.state.request_count += 1
        if not self._authorized():
            self._reject()
            return
        if self.fixture.state.redirect_get:
            body = f"redirected token {self.headers.get('JOB-TOKEN', '')}".encode()
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/credential-capture")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        base = "/api/v4/projects/42/packages"
        if parsed.path == f"/api/v4/projects/{self.fixture.state.project_endpoint_id}":
            self._json(
                200,
                {
                    "id": self.fixture.state.project_id,
                    "path_with_namespace": self.fixture.state.project_path,
                    "web_url": self.fixture.state.project_web_url
                    or f"{self.fixture.origin}/{self.fixture.state.project_path}",
                },
            )
            return
        if parsed.path == base:
            status_name = query.get("status", [""])[0]
            page = query.get("page", [""])[0]
            if (
                status_name == "default"
                and page == "1"
                and set(self.fixture.state.files) == set(PACKAGE_FILES)
            ):
                self.fixture.state.complete_inspection_count += 1
                if (
                    self.fixture.state.complete_inspection_count
                    == self.fixture.state.pause_complete_inspection_number
                ):
                    self.fixture.state.inspection_started.set()
                    if not self.fixture.state.resume_inspection.wait(timeout=10):
                        self._json(500, {"message": "fixture inspection pause timed out"})
                        return
            if status_name != self.fixture.state.package_status or not self.fixture.state.files:
                self._json(200, [])
                return
            if page == "1":
                if self.fixture.state.malformed_link:
                    self._json(200, [], link="not-a-link")
                    return
                next_query = dict(query)
                next_query["page"] = ["2"]
                encoded = urllib.parse.urlencode(
                    [(key, item) for key, values in next_query.items() for item in values]
                )
                link = f'<{self.fixture.origin}{base}?{encoded}>; rel="next"'
                self._json(200, [], link=link)
                return
            values = [self._package_object(self.fixture.state.package_status)]
            if self.fixture.state.ambiguous:
                values.append(
                    self._package_object(self.fixture.state.package_status, package_id=8)
                )
            self._json(200, values)
            return
        if parsed.path == f"{base}/7/package_files":
            names = sorted(self.fixture.state.files)
            values = [
                {
                    "id": index + 1,
                    "package_id": 7,
                    "file_name": name,
                    "file_sha256": hashlib.sha256(
                        self.fixture.state.files[name]
                    ).hexdigest(),
                }
                for index, name in enumerate(names)
            ]
            page = query.get("page", [""])[0]
            if len(values) > 1 and page == "1":
                next_query = dict(query)
                next_query["page"] = ["2"]
                encoded = urllib.parse.urlencode(
                    [(key, item) for key, items in next_query.items() for item in items]
                )
                link = (
                    f'<{self.fixture.origin}{base}/7/package_files?{encoded}>; '
                    'rel="next"'
                )
                self._json(200, values[:1], link=link)
                return
            self._json(200, values[1:] if len(values) > 1 else values)
            return
        self._json(404, {"message": "not found"})

    def do_PUT(self) -> None:  # noqa: N802
        self.fixture.state.request_count += 1
        if not self._authorized():
            self._reject()
            return
        prefix = (
            "/api/v4/projects/42/packages/generic/"
            "pki-exchange-request-registry-test/"
            "0123456789abcdef0123456789abcdef/"
        )
        if not self.path.startswith(prefix):
            self._json(404, {"message": "not found"})
            return
        name = urllib.parse.unquote(self.path[len(prefix) :])
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        if name in self.fixture.state.files:
            self._json(400, {"message": "Duplicate package is not allowed"})
            return
        self.fixture.state.files[name] = data
        self.fixture.state.uploads.append(name)
        if self.fixture.state.pause_first_upload and len(self.fixture.state.uploads) == 1:
            self.fixture.state.upload_started.set()
            if not self.fixture.state.resume_upload.wait(timeout=10):
                self._json(500, {"message": "fixture pause timed out"})
                return
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


@dataclass
class PackageScenario:
    command_runner: CommandRunner
    helper: Path
    root: Path
    exchange: Path
    request_dir: Path
    trust_dir: Path
    request_key: Path
    leaf_key: Path
    token_file: Path
    ca_file: Path
    project_record: Path
    inventory_record: Path
    state: GitLabState
    server: GitLabFixture
    thread: threading.Thread
    token: str

    def argv(self) -> list[str | Path]:
        return [
            self.helper,
            "publish-request",
            "--exchange-root",
            self.exchange,
            "--service",
            "registry-test",
            "--target",
            "test-target",
            "--request-id",
            "0123456789abcdef0123456789abcdef",
            "--inventory-record",
            self.inventory_record,
            "--transport-host-key-sha256",
            "b" * 64,
            "--project-record",
            self.project_record,
            "--token-type",
            "job",
            "--token-file",
            self.token_file,
            "--ca-file",
            self.ca_file,
            "--processing-attempts",
            "2",
            "--processing-interval",
            "0",
        ]

    def run(self) -> CommandResult:
        return self.command_runner.run(self.argv(), timeout=60, redactions=(self.token,))

    def run_argv(self, argv: list[str | Path]) -> CommandResult:
        return self.command_runner.run(argv, timeout=60, redactions=(self.token,))

    def close(self) -> None:
        self.state.resume_upload.set()
        self.state.resume_inspection.set()
        self.state.resume_error_response.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        shutil.rmtree(self.root)


def _run_bytes(argv: list[str | Path], *, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        [os.fspath(value) for value in argv],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout


@pytest.fixture
def package_scenario(
    repo_root: Path,
    command_runner: CommandRunner,
) -> Iterator[PackageScenario]:
    root = Path(tempfile.mkdtemp(prefix="pki-gitlab-", dir="/tmp/platform-home"))
    root.chmod(0o700)
    exchange = root / "exchange"
    request_parent = exchange / "registry-test/0123456789abcdef0123456789abcdef"
    request_dir = request_parent / "request"
    trust_dir = request_parent / "trust"
    for path in (
        exchange,
        exchange / "registry-test",
        request_parent,
        request_dir,
        trust_dir,
    ):
        _mkdir_private(path)

    request_key = root / "request-key"
    _run_bytes(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", request_key])
    request_key.chmod(0o600)
    algorithm, payload, *_ = request_key.with_suffix(".pub").read_text(
        encoding="ascii"
    ).split()
    assert algorithm == "ssh-ed25519"
    principals = {
        "requesters.allowed_signers": "test-target",
        "approvers.allowed_signers": "test-approver",
        "responses.allowed_signers": "test-response",
        "deployers.allowed_signers": "test-target",
    }
    for name, principal in principals.items():
        _write_private(trust_dir / name, f"{principal} {algorithm} {payload}\n")
    _write_private(
        trust_dir / "policy",
        "\n".join(
            (
                "schema=2",
                "request_namespace=platform-pki-csr-request-v1",
                "approval_namespace=platform-pki-csr-approval-v1",
                "response_namespace=platform-pki-csr-response-v1",
                "deployment_namespace=platform-pki-csr-deployment-v1",
                "request_max_age_seconds=604800",
                "sole_operator_min_delay_seconds=86400",
                "approval_max_age_seconds=86400",
                "deployment_max_age_seconds=86400",
                "clock_skew_seconds=300",
                "approver_principal=test-approver",
                "response_principal=test-response",
                "",
            )
        ),
    )

    leaf_key = root / "leaf.key"
    csr = request_dir / "tls.csr"
    _run_bytes(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-384",
            "-nodes",
            "-sha384",
            "-subj",
            "/CN=registry.test",
            "-addext",
            "subjectAltName=DNS:registry.test,DNS:test-target",
            "-keyout",
            leaf_key,
            "-out",
            csr,
        ]
    )
    csr.chmod(0o600)
    csr_public = _run_bytes(["openssl", "req", "-in", csr, "-pubkey", "-noout"])
    csr_spki = _run_bytes(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], stdin=csr_public
    )
    created = int(time.time())
    request = request_dir / "request"
    _write_private(
        request,
        "\n".join(
            (
                "schema=1",
                "request_id=0123456789abcdef0123456789abcdef",
                "nonce=" + "a" * 64,
                f"created_epoch={created}",
                f"expires_epoch={created + 3600}",
                "operation=migrate",
                "service=registry-test",
                "target=test-target",
                "requester_principal=test-target",
                "inventory_sha256=" + "c" * 64,
                f"csr_sha256={_sha256(csr)}",
                f"csr_spki_sha256={hashlib.sha256(csr_spki).hexdigest()}",
                "current_cert_sha256=" + "d" * 64,
                "profile=server-p384-sha384-v1",
                "response_principal=test-response",
                "",
            )
        ),
    )
    _run_bytes(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            request_key,
            "-n",
            "platform-pki-csr-request-v1",
            request,
        ]
    )
    signature = request_dir / "request.sig"
    signature.chmod(0o600)

    trust_digests = {name: _sha256(trust_dir / name) for name in TRUST_NAMES}
    receipt = request_dir / "collection-receipt"
    _write_private(
        receipt,
        "\n".join(
            (
                "schema=1",
                "kind=pki-request-collection",
                "service=registry-test",
                "target=test-target",
                "request_id=0123456789abcdef0123456789abcdef",
                "transport=ssh",
                "transport_host_key_sha256=" + "b" * 64,
                f"csr_sha256={_sha256(csr)}",
                f"request_sha256={_sha256(request)}",
                f"request_signature_sha256={_sha256(signature)}",
                f"trust_policy_sha256={trust_digests['policy']}",
                f"request_trust_sha256={trust_digests['requesters.allowed_signers']}",
                f"approval_trust_sha256={trust_digests['approvers.allowed_signers']}",
                f"response_trust_sha256={trust_digests['responses.allowed_signers']}",
                f"deployment_trust_sha256={trust_digests['deployers.allowed_signers']}",
                "request_principal=test-target",
                "request_namespace=platform-pki-csr-request-v1",
                f"collected_epoch={created}",
                "verification_result=passed",
                "",
            )
        ),
    )
    manifest = request_dir / "stage-manifest"
    payload_lines = [
        f"payload={name} sha256={_sha256(request_dir / name)}"
        for name in REQUEST_FILES
    ]
    _write_private(
        manifest,
        "\n".join(
            (
                "schema=1",
                "kind=pki-exchange-stage",
                "stage=request",
                "service=registry-test",
                "request_id=0123456789abcdef0123456789abcdef",
                "package_version=0123456789abcdef0123456789abcdef",
                "payload_count=4",
                *payload_lines,
                "",
            )
        ),
    )

    server_key = root / "server.key"
    ca_file = root / "gitlab-ca.crt"
    _run_bytes(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            server_key,
            "-out",
            ca_file,
        ]
    )
    server_key.chmod(0o600)
    ca_file.chmod(0o600)
    token = "fixture-secret-token-value"
    token_file = root / "gitlab.token"
    _write_private(token_file, token + "\n")
    state = GitLabState(token=token)
    server = GitLabFixture(("127.0.0.1", 0), GitLabHandler)
    server.state = state
    server.origin = f"https://localhost:{server.server_port}"
    project_record = root / "gitlab-project"
    _write_private(
        project_record,
        "\n".join(
            (
                "schema=1",
                "kind=pki-exchange-project",
                f"origin={server.origin}",
                "project_id=42",
                "project_path=platform/pki-exchange",
                "gitlab_version=18.11.3-ce.0",
                "",
            )
        ),
    )
    inventory_record = root / "request-inventory"
    _write_private(
        inventory_record,
        "\n".join(
            (
                "schema=1",
                "kind=pki-request-inventory",
                "service=registry-test",
                "target=test-target",
                "inventory_sha256=" + "c" * 64,
                "common_name=registry.test",
                "dns_san_count=2",
                "dns_san=registry.test",
                "dns_san=test-target",
                "ip_san_count=0",
                "",
            )
        ),
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca_file, server_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    scenario = PackageScenario(
        command_runner=command_runner,
        helper=repo_root / "scripts/platform-pki-gitlab-package",
        root=root,
        exchange=exchange,
        request_dir=request_dir,
        trust_dir=trust_dir,
        request_key=request_key,
        leaf_key=leaf_key,
        token_file=token_file,
        ca_file=ca_file,
        project_record=project_record,
        inventory_record=inventory_record,
        state=state,
        server=server,
        thread=thread,
        token=token,
    )
    try:
        yield scenario
    finally:
        scenario.close()


def _json_result(result: CommandResult) -> dict[str, Any]:
    result.assert_success()
    assert result.stderr == "", result.diagnostics()
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return value


def _replace_record_fields(path: Path, updates: dict[str, str]) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    rewritten = []
    found: set[str] = set()
    for line in lines:
        key, value = line.split("=", 1)
        if key in updates:
            value = updates[key]
            found.add(key)
        rewritten.append(f"{key}={value}")
    assert found == set(updates)
    _write_private(path, "\n".join((*rewritten, "")))


def _refresh_manifest(scenario: PackageScenario) -> None:
    payload_lines = [
        f"payload={name} sha256={_sha256(scenario.request_dir / name)}"
        for name in REQUEST_FILES
    ]
    _write_private(
        scenario.request_dir / "stage-manifest",
        "\n".join(
            (
                "schema=1",
                "kind=pki-exchange-stage",
                "stage=request",
                "service=registry-test",
                "request_id=0123456789abcdef0123456789abcdef",
                "package_version=0123456789abcdef0123456789abcdef",
                "payload_count=4",
                *payload_lines,
                "",
            )
        ),
    )


def _replace_csr_and_rebind(
    scenario: PackageScenario,
    *,
    curve: str,
    digest: str,
    extra_extension: str | None = None,
) -> None:
    csr = scenario.request_dir / "tls.csr"
    replacement_key = scenario.root / f"replacement-{curve}-{digest}.key"
    argv: list[str | Path] = [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            f"ec_paramgen_curve:{curve}",
            "-nodes",
            f"-{digest}",
            "-subj",
            "/CN=registry.test",
            "-addext",
            "subjectAltName=DNS:registry.test,DNS:test-target",
    ]
    if extra_extension is not None:
        argv.extend(("-addext", extra_extension))
    argv.extend(
        [
            "-keyout",
            replacement_key,
            "-out",
            csr,
        ]
    )
    _run_bytes(argv)
    csr.chmod(0o600)
    csr_public = _run_bytes(["openssl", "req", "-in", csr, "-pubkey", "-noout"])
    csr_spki = _run_bytes(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], stdin=csr_public
    )
    request = scenario.request_dir / "request"
    _replace_record_fields(
        request,
        {
            "csr_sha256": _sha256(csr),
            "csr_spki_sha256": hashlib.sha256(csr_spki).hexdigest(),
        },
    )
    signature = scenario.request_dir / "request.sig"
    signature.unlink()
    _run_bytes(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            scenario.request_key,
            "-n",
            "platform-pki-csr-request-v1",
            request,
        ]
    )
    signature.chmod(0o600)
    _replace_record_fields(
        scenario.request_dir / "collection-receipt",
        {
            "csr_sha256": _sha256(csr),
            "request_sha256": _sha256(request),
            "request_signature_sha256": _sha256(signature),
        },
    )
    _refresh_manifest(scenario)


def _resign_request_and_rebind(scenario: PackageScenario) -> None:
    request = scenario.request_dir / "request"
    signature = scenario.request_dir / "request.sig"
    signature.unlink()
    _run_bytes(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            scenario.request_key,
            "-n",
            "platform-pki-csr-request-v1",
            request,
        ]
    )
    signature.chmod(0o600)
    _replace_record_fields(
        scenario.request_dir / "collection-receipt",
        {
            "csr_sha256": _sha256(scenario.request_dir / "tls.csr"),
            "request_sha256": _sha256(request),
            "request_signature_sha256": _sha256(signature),
        },
    )
    _refresh_manifest(scenario)


def _replace_during_final_inspection(
    scenario: PackageScenario,
    path: Path,
) -> tuple[int, str, str]:
    scenario.state.pause_complete_inspection_number = 2
    process = subprocess.Popen(
        [os.fspath(value) for value in scenario.argv()],
        cwd=scenario.command_runner.cwd,
        env=scenario.command_runner.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert scenario.state.inspection_started.wait(timeout=20)
        saved = scenario.root / f"{path.name}.final-inspection-saved"
        path.rename(saved)
        shutil.copyfile(saved, path)
        path.chmod(0o600)
        scenario.state.resume_inspection.set()
        stdout, stderr = process.communicate(timeout=20)
    finally:
        scenario.state.resume_inspection.set()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    assert process.returncode is not None
    return process.returncode, stdout, stderr


def _replace_during_http_failure(
    scenario: PackageScenario,
    path: Path,
    *,
    replace: bool = True,
) -> tuple[int, str, str]:
    scenario.state.reject_auth = True
    scenario.state.pause_error_response = True
    process = subprocess.Popen(
        [os.fspath(value) for value in scenario.argv()],
        cwd=scenario.command_runner.cwd,
        env=scenario.command_runner.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert scenario.state.error_request_started.wait(timeout=10)
        saved = scenario.root / f"{path.name}.http-failure-saved"
        path.rename(saved)
        if replace:
            shutil.copyfile(saved, path)
            path.chmod(0o600)
        scenario.state.resume_error_response.set()
        stdout, stderr = process.communicate(timeout=20)
    finally:
        scenario.state.resume_error_response.set()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    assert process.returncode is not None
    return process.returncode, stdout, stderr


def _chmod_during_first_upload(
    scenario: PackageScenario,
    path: Path,
    mode: int,
) -> tuple[int, str, str]:
    scenario.state.pause_first_upload = True
    process = subprocess.Popen(
        [os.fspath(value) for value in scenario.argv()],
        cwd=scenario.command_runner.cwd,
        env=scenario.command_runner.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert scenario.state.upload_started.wait(timeout=10)
        path.chmod(mode)
        scenario.state.resume_upload.set()
        stdout, stderr = process.communicate(timeout=20)
    finally:
        scenario.state.resume_upload.set()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    assert process.returncode is not None
    return process.returncode, stdout, stderr


def test_publish_request_uploads_exact_files_with_manifest_last(
    package_scenario: PackageScenario,
) -> None:
    output = _json_result(package_scenario.run())
    assert output["status"] == "published"
    assert output["project_id"] == 42
    assert output["project_path"] == "platform/pki-exchange"
    assert output["package_name"] == "pki-exchange-request-registry-test"
    assert output["package_version"] == "0123456789abcdef0123456789abcdef"
    assert package_scenario.state.uploads == list(PACKAGE_FILES)
    assert set(package_scenario.state.files) == set(PACKAGE_FILES)
    assert output["file_sha256"] == {
        name: _sha256(package_scenario.request_dir / name) for name in PACKAGE_FILES
    }


def test_publish_request_complete_rerun_is_idempotent(
    package_scenario: PackageScenario,
) -> None:
    _json_result(package_scenario.run())
    package_scenario.state.uploads.clear()
    output = _json_result(package_scenario.run())
    assert output["status"] == "existing"
    assert package_scenario.state.uploads == []


def test_publish_request_resumes_only_matching_partial_package(
    package_scenario: PackageScenario,
) -> None:
    for name in REQUEST_FILES[:2]:
        package_scenario.state.files[name] = (
            package_scenario.request_dir / name
        ).read_bytes()
    output = _json_result(package_scenario.run())
    assert output["status"] == "published"
    assert package_scenario.state.uploads == list(PACKAGE_FILES[2:])


def test_publish_request_rejects_conflicting_remote_file(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.files["tls.csr"] = b"conflict\n"
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "conflicts with protected local bytes" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_extra_remote_file(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.files["unexpected"] = b"unexpected\n"
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "unexpected file" in result.stderr
    assert package_scenario.state.uploads == []


@pytest.mark.parametrize(
    "remote_names",
    [
        ("stage-manifest",),
        ("tls.csr", "stage-manifest"),
        ("tls.csr", "request", "stage-manifest"),
    ],
)
def test_publish_request_rejects_manifest_present_partial(
    package_scenario: PackageScenario,
    remote_names: tuple[str, ...],
) -> None:
    for name in remote_names:
        package_scenario.state.files[name] = (
            package_scenario.request_dir / name
        ).read_bytes()
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "manifest-present request package is incomplete" in result.stderr
    assert package_scenario.state.uploads == []


@pytest.mark.parametrize("status_name", ["hidden", "error", "pending_destruction", "deprecated"])
def test_publish_request_rejects_blocked_status(
    package_scenario: PackageScenario,
    status_name: str,
) -> None:
    package_scenario.state.package_status = status_name
    package_scenario.state.files["tls.csr"] = (
        package_scenario.request_dir / "tls.csr"
    ).read_bytes()
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert f"blocked in status {status_name}" in result.stderr


def test_publish_request_rejects_ambiguous_package_objects(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.ambiguous = True
    package_scenario.state.files["tls.csr"] = (
        package_scenario.request_dir / "tls.csr"
    ).read_bytes()
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "ambiguous across package statuses" in result.stderr


def test_publish_request_rejects_malformed_pagination(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.malformed_link = True
    package_scenario.state.files["tls.csr"] = (
        package_scenario.request_dir / "tls.csr"
    ).read_bytes()
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "malformed pagination Link" in result.stderr


def test_publish_request_redacts_token_from_http_failure(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.reject_auth = True
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "HTTP 401" in result.stderr
    assert package_scenario.token not in result.stderr


def test_publish_request_rejects_redirect_without_disclosing_token(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.redirect_get = True
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "HTTP 302" in result.stderr
    assert package_scenario.token not in result.stderr


def test_publish_request_rejects_unsettled_processing_status(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.package_status = "processing"
    package_scenario.state.files["tls.csr"] = (
        package_scenario.request_dir / "tls.csr"
    ).read_bytes()
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "processing status did not settle" in result.stderr


def test_publish_request_rejects_noncanonical_local_manifest(
    package_scenario: PackageScenario,
) -> None:
    _write_private(package_scenario.request_dir / "stage-manifest", "malformed\n")
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "stage-manifest has an unexpected field count" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_unreviewed_inventory_digest(
    package_scenario: PackageScenario,
) -> None:
    _replace_record_fields(
        package_scenario.inventory_record,
        {"inventory_sha256": "e" * 64},
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "does not bind the selected package identity" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_wrong_inventory_san(
    package_scenario: PackageScenario,
) -> None:
    _write_private(
        package_scenario.inventory_record,
        package_scenario.inventory_record.read_text(encoding="ascii").replace(
            "dns_san=test-target\n", "dns_san=other-target\n"
        ),
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "CSR SANs differ from protected inventory input" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_non_p384_csr(
    package_scenario: PackageScenario,
) -> None:
    _replace_csr_and_rebind(package_scenario, curve="P-256", digest="sha384")
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "CSR key profile is not EC P-384" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_non_sha384_csr(
    package_scenario: PackageScenario,
) -> None:
    _replace_csr_and_rebind(package_scenario, curve="P-384", digest="sha256")
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "CSR signature profile is not SHA-384" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_unknown_numeric_csr_extension(
    package_scenario: PackageScenario,
) -> None:
    _replace_csr_and_rebind(
        package_scenario,
        curve="P-384",
        digest="sha384",
        extra_extension="1.2.3.4=ASN1:UTF8String:unexpected",
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "CSR contains unexpected requested extensions" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_private_key_appended_to_csr(
    package_scenario: PackageScenario,
) -> None:
    csr = package_scenario.request_dir / "tls.csr"
    csr.write_bytes(csr.read_bytes() + package_scenario.leaf_key.read_bytes())
    csr.chmod(0o600)
    _replace_record_fields(
        package_scenario.request_dir / "request",
        {"csr_sha256": _sha256(csr)},
    )
    _resign_request_and_rebind(package_scenario)

    result = package_scenario.run().assert_failure()

    assert result.stdout == ""
    assert "CSR is not one exact ASCII-armored object" in result.stderr
    assert package_scenario.state.request_count == 0
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_private_key_appended_to_signature(
    package_scenario: PackageScenario,
) -> None:
    signature = package_scenario.request_dir / "request.sig"
    signature.write_bytes(
        signature.read_bytes() + package_scenario.leaf_key.read_bytes()
    )
    signature.chmod(0o600)
    _replace_record_fields(
        package_scenario.request_dir / "collection-receipt",
        {"request_signature_sha256": _sha256(signature)},
    )
    _refresh_manifest(package_scenario)

    result = package_scenario.run().assert_failure()

    assert result.stdout == ""
    assert "request signature is not one exact ASCII-armored object" in result.stderr
    assert package_scenario.state.request_count == 0
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_noncanonical_requester_trust(
    package_scenario: PackageScenario,
) -> None:
    trust = package_scenario.trust_dir / "requesters.allowed_signers"
    _write_private(trust, "cert-authority " + trust.read_text(encoding="ascii"))
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "requester trust contains a noncanonical signer record" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_policy_field_drift(
    package_scenario: PackageScenario,
) -> None:
    _replace_record_fields(
        package_scenario.trust_dir / "policy",
        {"request_max_age_seconds": "604799"},
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "does not match frozen schema 2" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_extra_approver_principal(
    package_scenario: PackageScenario,
) -> None:
    trust = package_scenario.trust_dir / "approvers.allowed_signers"
    line = trust.read_text(encoding="ascii").strip().split(" ", 1)[1]
    _write_private(trust, trust.read_text(encoding="ascii") + f"other-approver {line}\n")
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "does not contain exactly the policy principal" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_missing_deployment_principal(
    package_scenario: PackageScenario,
) -> None:
    trust = package_scenario.trust_dir / "deployers.allowed_signers"
    _, key = trust.read_text(encoding="ascii").strip().split(" ", 1)
    _write_private(trust, f"other-target {key}\n")
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "absent from frozen requester or deployment trust" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_unpinned_gitlab_version(
    package_scenario: PackageScenario,
) -> None:
    _replace_record_fields(
        package_scenario.project_record,
        {"gitlab_version": "18.11.2-ce.0"},
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "does not pin 18.11.3-ce.0" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_invalid_project_origin(
    package_scenario: PackageScenario,
) -> None:
    _replace_record_fields(
        package_scenario.project_record,
        {"origin": "http://gitlab.example.test"},
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "project record origin is invalid" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_live_project_path_mismatch(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.project_path = "other/pki-exchange"
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "project metadata differs from the protected project record" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_boolean_live_project_id(
    package_scenario: PackageScenario,
) -> None:
    _replace_record_fields(package_scenario.project_record, {"project_id": "1"})
    package_scenario.state.project_endpoint_id = 1
    package_scenario.state.project_id = True
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "project metadata differs from the protected project record" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_live_project_id_mismatch(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.project_id = 41
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "project metadata differs from the protected project record" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_live_project_web_url_mismatch(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.project_web_url = (
        f"{package_scenario.server.origin}/other/pki-exchange"
    )
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "project metadata differs from the protected project record" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_symlinked_project_record(
    package_scenario: PackageScenario,
) -> None:
    saved = package_scenario.root / "gitlab-project.saved"
    package_scenario.project_record.rename(saved)
    package_scenario.project_record.symlink_to(saved)
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "cannot open GitLab exchange project record" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_world_readable_token(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.token_file.chmod(0o644)
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "GitLab token file has unsafe metadata" in result.stderr
    assert package_scenario.token not in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_private_key_in_package_directory(
    package_scenario: PackageScenario,
) -> None:
    _write_private(package_scenario.request_dir / "tls.key", "private\n")
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert "exact five files" in result.stderr
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_symlinked_payload(
    package_scenario: PackageScenario,
) -> None:
    csr = package_scenario.request_dir / "tls.csr"
    saved = package_scenario.root / "tls.csr.saved"
    csr.rename(saved)
    csr.symlink_to(saved)
    result = package_scenario.run().assert_failure()
    assert result.stdout == ""
    assert re.search(r"cannot open protected file tls\.csr", result.stderr)
    assert package_scenario.state.uploads == []


def test_publish_request_rejects_replaced_frozen_trust_during_upload(
    package_scenario: PackageScenario,
) -> None:
    package_scenario.state.pause_first_upload = True
    process = subprocess.Popen(
        [os.fspath(value) for value in package_scenario.argv()],
        cwd=package_scenario.command_runner.cwd,
        env=package_scenario.command_runner.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert package_scenario.state.upload_started.wait(timeout=10)
        trust = package_scenario.trust_dir / "requesters.allowed_signers"
        saved = package_scenario.root / "requesters.allowed_signers.saved"
        trust.rename(saved)
        shutil.copyfile(saved, trust)
        trust.chmod(0o600)
        package_scenario.state.resume_upload.set()
        stdout, stderr = process.communicate(timeout=20)
    finally:
        package_scenario.state.resume_upload.set()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    assert process.returncode != 0
    assert stdout == ""
    assert "protected file identity changed" in stderr


@pytest.mark.parametrize(
    ("source_name", "expected"),
    [
        ("request", "protected file metadata changed: request"),
        ("request-directory", "protected directory metadata changed"),
        ("token", "GitLab token file metadata changed"),
    ],
)
def test_publish_request_rejects_metadata_drift_during_upload(
    package_scenario: PackageScenario,
    source_name: str,
    expected: str,
) -> None:
    sources = {
        "request": package_scenario.request_dir / "request",
        "request-directory": package_scenario.request_dir,
        "token": package_scenario.token_file,
    }
    returncode, stdout, stderr = _chmod_during_first_upload(
        package_scenario,
        sources[source_name],
        0o644 if source_name != "request-directory" else 0o755,
    )

    assert returncode != 0
    assert stdout == ""
    assert expected in stderr
    assert package_scenario.token not in stderr
    assert "stage-manifest" not in package_scenario.state.files


@pytest.mark.parametrize(
    "source_name",
    ["request", "requesters.allowed_signers"],
)
def test_publish_request_rechecks_sources_after_final_inspection(
    package_scenario: PackageScenario,
    source_name: str,
) -> None:
    if source_name == "request":
        source = package_scenario.request_dir / source_name
    else:
        source = package_scenario.trust_dir / source_name
    returncode, stdout, stderr = _replace_during_final_inspection(
        package_scenario, source
    )
    assert returncode != 0
    assert stdout == ""
    assert "protected file identity changed" in stderr


@pytest.mark.parametrize("source_name", ["inventory", "project", "token", "ca"])
def test_publish_request_pins_configuration_through_final_inspection(
    package_scenario: PackageScenario,
    source_name: str,
) -> None:
    sources = {
        "inventory": package_scenario.inventory_record,
        "project": package_scenario.project_record,
        "token": package_scenario.token_file,
        "ca": package_scenario.ca_file,
    }
    returncode, stdout, stderr = _replace_during_final_inspection(
        package_scenario, sources[source_name]
    )
    assert returncode != 0
    assert stdout == ""
    assert "identity changed" in stderr
    assert package_scenario.token not in stderr


@pytest.mark.parametrize("source_name", ["inventory", "project", "token", "ca"])
def test_publish_request_rechecks_configuration_after_http_failure(
    package_scenario: PackageScenario,
    source_name: str,
) -> None:
    sources = {
        "inventory": package_scenario.inventory_record,
        "project": package_scenario.project_record,
        "token": package_scenario.token_file,
        "ca": package_scenario.ca_file,
    }
    returncode, stdout, stderr = _replace_during_http_failure(
        package_scenario, sources[source_name]
    )
    assert returncode != 0
    assert stdout == ""
    assert "identity changed" in stderr
    assert "HTTP 401" not in stderr
    assert package_scenario.token not in stderr


def test_publish_request_reports_controlled_source_removal_error(
    package_scenario: PackageScenario,
) -> None:
    returncode, stdout, stderr = _replace_during_http_failure(
        package_scenario,
        package_scenario.token_file,
        replace=False,
    )
    assert returncode != 0
    assert stdout == ""
    assert "cannot recheck GitLab token file" in stderr
    assert "Traceback" not in stderr
    assert package_scenario.token not in stderr
