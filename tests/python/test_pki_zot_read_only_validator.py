from __future__ import annotations

import hashlib
import http.server
import os
import runpy
import ssl
import stat
import subprocess
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from conftest import CommandResult, CommandRunner


pytestmark = pytest.mark.pki
SERVICE = "registry-test"
TARGET = "registry-target"
REMOTE_VALIDATOR = "runner.test"
REQUEST_ID = "0123456789abcdef0123456789abcdef"
ARTIFACT_SHA256 = "a" * 64
BOUNDARY_FIELDS = (
    "schema", "kind", "service", "target", "local_validator",
    "remote_validator", "endpoint", "local_check", "remote_check",
)
OBSERVATION_FIELDS = (
    "schema", "kind", "service", "target", "request_id",
    "artifact_manifest_sha256", "validation_boundary_sha256",
    "remote_validator", "endpoint", "remote_tls_result",
    "remote_application_result", "remote_http_status", "remote_api_version",
    "remote_auth_challenge", "served_certificate_sha256",
    "served_intermediate_sha256", "validation_epoch",
)


def digest(data: bytes | Path) -> str:
    content = data.read_bytes() if isinstance(data, Path) else data
    return hashlib.sha256(content).hexdigest()


def private_file(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


def record(fields: tuple[str, ...], values: Mapping[str, str]) -> bytes:
    assert set(fields) == set(values)
    return "".join(f"{name}={values[name]}\n" for name in fields).encode("ascii")


def ca_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def leaf_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


@dataclass(frozen=True)
class Certificate:
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate
    pem: bytes

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def make_ca(
    common_name: str,
    serial: int,
    *,
    issuer: Certificate | None = None,
    path_length: int,
) -> Certificate:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, common_name),))
    issuer_name = name if issuer is None else issuer.certificate.subject
    issuer_key = key if issuer is None else issuer.key
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(ca_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA384())
    )
    return Certificate(key, certificate, certificate.public_bytes(serialization.Encoding.PEM))


def make_leaf(
    hostname: str,
    serial: int,
    issuer: Certificate,
) -> Certificate:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, hostname),))
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.certificate.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(leaf_usage(), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,)),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName((x509.DNSName(hostname),)), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()),
            critical=False,
        )
        .sign(issuer.key, hashes.SHA384())
    )
    return Certificate(key, certificate, certificate.public_bytes(serialization.Encoding.PEM))


@dataclass
class ServerState:
    status: int = 200
    api_version: str | None = "registry/2.0"
    auth_challenge: str | None = None
    location: str | None = None
    body: bytes = b"{}"
    extra_header: tuple[str, str] | None = None
    requests: list[tuple[str, str]] = field(default_factory=list)
    request_received: threading.Event = field(default_factory=threading.Event)
    release_response: threading.Event | None = None


class ZotServer(http.server.ThreadingHTTPServer):
    state: ServerState


class ZotHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def fixture(self) -> ZotServer:
        return cast(ZotServer, self.server)

    def do_GET(self) -> None:  # noqa: N802
        state = self.fixture.state
        state.requests.append((self.command, self.path))
        state.request_received.set()
        if state.release_response is not None:
            state.release_response.wait(timeout=10)
        self.send_response(state.status)
        if state.api_version is not None:
            self.send_header("Docker-Distribution-Api-Version", state.api_version)
        if state.auth_challenge is not None:
            self.send_header("WWW-Authenticate", state.auth_challenge)
        if state.location is not None:
            self.send_header("Location", state.location)
        if state.extra_header is not None:
            self.send_header(*state.extra_header)
        self.send_header("Content-Length", str(len(state.body)))
        self.end_headers()
        try:
            self.wfile.write(state.body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def log_message(self, format: str, *args: object) -> None:
        del format, args
        pass


@dataclass
class RunningServer:
    server: ZotServer
    thread: threading.Thread
    endpoint: str
    state: ServerState

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@contextmanager
def serve(
    root: Path,
    name: str,
    chain: bytes,
    key: bytes,
    state: ServerState | None = None,
) -> Iterator[RunningServer]:
    cert_path = private_file(root / f"{name}.chain.pem", chain)
    key_path = private_file(root / f"{name}.key.pem", key)
    server = ZotServer(("127.0.0.1", 0), ZotHandler)
    server.state = ServerState() if state is None else state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    running = RunningServer(
        server=server,
        thread=thread,
        endpoint=f"https://localhost:{server.server_port}/v2/",
        state=server.state,
    )
    try:
        yield running
    finally:
        running.close()


@dataclass
class ValidatorCase:
    command_runner: CommandRunner
    helper: Path
    root: Path
    root_ca: Certificate
    intermediate: Certificate
    leaf: Certificate
    wrong_hostname_leaf: Certificate
    direct_leaf: Certificate
    alternate_root: Certificate
    server: RunningServer
    boundary: Path
    reviewed_ca: Path

    def boundary_bytes(
        self,
        endpoint: str,
        updates: Mapping[str, str] | None = None,
    ) -> bytes:
        values = {
            "schema": "1",
            "kind": "pki-validation-boundary",
            "service": SERVICE,
            "target": TARGET,
            "local_validator": TARGET,
            "remote_validator": REMOTE_VALIDATOR,
            "endpoint": endpoint,
            "local_check": "platform-zot-local-active-tls-v1",
            "remote_check": "platform-oci-v2-read-only-strict-tls-v1",
        }
        if updates:
            values.update(updates)
        return record(BOUNDARY_FIELDS, values)

    def args(
        self,
        *,
        server: RunningServer | None = None,
        ca: bytes | None = None,
        leaf_sha256: str | None = None,
        intermediate_sha256: str | None = None,
        boundary_updates: Mapping[str, str] | None = None,
        argument_updates: Mapping[str, str] | None = None,
    ) -> list[str | Path]:
        selected = self.server if server is None else server
        boundary_data = self.boundary_bytes(selected.endpoint, boundary_updates)
        private_file(self.boundary, boundary_data)
        ca_data = self.root_ca.pem if ca is None else ca
        private_file(self.reviewed_ca, ca_data)
        values = {
            "service": SERVICE,
            "target": TARGET,
            "request-id": REQUEST_ID,
            "artifact-sha256": ARTIFACT_SHA256,
            "validation-boundary": str(self.boundary),
            "validation-boundary-sha256": digest(boundary_data),
            "remote-validator": REMOTE_VALIDATOR,
            "endpoint": selected.endpoint,
            "reviewed-ca": str(self.reviewed_ca),
            "reviewed-ca-sha256": digest(ca_data),
            "expected-served-leaf-sha256": digest(self.leaf.pem) if leaf_sha256 is None else leaf_sha256,
            "expected-served-intermediate-sha256": digest(self.intermediate.pem) if intermediate_sha256 is None else intermediate_sha256,
        }
        if argument_updates:
            values.update(argument_updates)
        result: list[str | Path] = [self.helper]
        for name, value in values.items():
            result.extend((f"--{name}", value))
        return result

    def run(
        self,
        *,
        server: RunningServer | None = None,
        ca: bytes | None = None,
        leaf_sha256: str | None = None,
        intermediate_sha256: str | None = None,
        boundary_updates: Mapping[str, str] | None = None,
        argument_updates: Mapping[str, str] | None = None,
    ) -> CommandResult:
        return self.command_runner.run(
            self.args(
                server=server,
                ca=ca,
                leaf_sha256=leaf_sha256,
                intermediate_sha256=intermediate_sha256,
                boundary_updates=boundary_updates,
                argument_updates=argument_updates,
            ),
            timeout=20,
        )


@pytest.fixture
def validator_case(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> Iterator[ValidatorCase]:
    root = isolated_test_dir / "zot-validator"
    root.mkdir(mode=0o700)
    root_ca = make_ca("Test Root", 1, path_length=1)
    intermediate = make_ca(
        "Test Intermediate", 2, issuer=root_ca, path_length=0
    )
    leaf = make_leaf("localhost", 3, intermediate)
    wrong_hostname_leaf = make_leaf("wrong-host.test", 4, intermediate)
    direct_leaf = make_leaf("localhost", 5, root_ca)
    alternate_root = make_ca("Alternate Root", 6, path_length=1)
    boundary = root / "validation-boundary"
    reviewed_ca = root / "reviewed-ca.pem"
    with serve(root, "default", leaf.pem + intermediate.pem, leaf.key_pem) as server:
        yield ValidatorCase(
            command_runner=command_runner,
            helper=repo_root / "roles/pki_host_local_certificate/files/platform-pki-zot-read-only-validate",
            root=root,
            root_ca=root_ca,
            intermediate=intermediate,
            leaf=leaf,
            wrong_hostname_leaf=wrong_hostname_leaf,
            direct_leaf=direct_leaf,
            alternate_root=alternate_root,
            server=server,
            boundary=boundary,
            reviewed_ca=reviewed_ca,
        )


def assert_failure(result: CommandResult) -> None:
    result.assert_failure()
    assert result.stdout == "", result.diagnostics()
    assert result.stderr.startswith("platform-pki-zot-read-only-validate: ")


def test_chain_extraction_supports_cpython_312_private_api(repo_root: Path) -> None:
    helper = (
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-zot-read-only-validate"
    )
    extractor = runpy.run_path(str(helper))["unverified_chain_der"]
    observed_encodings: list[object] = []

    class PrivateCertificate:
        def __init__(self, value: bytes) -> None:
            self.value = value

        def public_bytes(self, encoding: object) -> bytes:
            observed_encodings.append(encoding)
            return self.value

    class PrivateSslObject:
        def get_unverified_chain(self) -> list[PrivateCertificate]:
            return [PrivateCertificate(b"leaf"), PrivateCertificate(b"intermediate")]

    class Python312Tls:
        _sslobj = PrivateSslObject()

    assert extractor(Python312Tls()) == [b"leaf", b"intermediate"]
    assert len(observed_encodings) == 2


@pytest.mark.parametrize(
    ("status", "challenge", "challenge_result"),
    (
        (200, None, "not-required"),
        (
            401,
            'Bearer realm="https://auth.example.test/token",service="registry.test"',
            "present",
        ),
    ),
)
def test_200_and_401_emit_exact_secret_free_observation(
    validator_case: ValidatorCase,
    status: int,
    challenge: str | None,
    challenge_result: str,
) -> None:
    case = validator_case
    case.server.state.status = status
    case.server.state.auth_challenge = challenge
    argv = case.args()
    before = {
        path: (path.stat().st_mode, path.stat().st_mtime_ns, digest(path))
        for path in (case.boundary, case.reviewed_ca)
    }
    result = case.command_runner.run(argv, timeout=20).assert_success()
    assert result.stderr == "", result.diagnostics()
    lines = result.stdout.splitlines()
    assert len(lines) == len(OBSERVATION_FIELDS)
    validation_epoch = lines[-1].removeprefix("validation_epoch=")
    assert validation_epoch.isdecimal() and int(validation_epoch) > 0
    boundary_sha256 = digest(case.boundary)
    expected = record(
        OBSERVATION_FIELDS,
        {
            "schema": "1",
            "kind": "pki-external-validation-observation",
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "artifact_manifest_sha256": ARTIFACT_SHA256,
            "validation_boundary_sha256": boundary_sha256,
            "remote_validator": REMOTE_VALIDATOR,
            "endpoint": case.server.endpoint,
            "remote_tls_result": "passed",
            "remote_application_result": "passed",
            "remote_http_status": str(status),
            "remote_api_version": "registry/2.0",
            "remote_auth_challenge": challenge_result,
            "served_certificate_sha256": digest(case.leaf.pem),
            "served_intermediate_sha256": digest(case.intermediate.pem),
            "validation_epoch": validation_epoch,
        },
    ).decode("ascii")
    assert result.stdout == expected
    assert challenge is None or challenge not in result.stdout
    assert case.server.state.requests == [("GET", "/v2/")]
    after = {
        path: (path.stat().st_mode, path.stat().st_mtime_ns, digest(path))
        for path in (case.boundary, case.reviewed_ca)
    }
    for path, metadata in before.items():
        assert after[path] == metadata


@pytest.mark.parametrize("failure", ("hostname", "chain"))
def test_strict_hostname_and_chain_failures(
    validator_case: ValidatorCase,
    failure: str,
) -> None:
    case = validator_case
    if failure == "hostname":
        chain = case.wrong_hostname_leaf.pem + case.intermediate.pem
        leaf = case.wrong_hostname_leaf
        ca = case.root_ca.pem
    else:
        chain = case.leaf.pem + case.intermediate.pem
        leaf = case.leaf
        ca = case.alternate_root.pem
    with serve(case.root, failure, chain, leaf.key_pem) as server:
        result = case.run(
            server=server,
            ca=ca,
            leaf_sha256=digest(leaf.pem),
        )
        assert_failure(result)
        assert server.state.requests == []


@pytest.mark.parametrize("digest_name", ("leaf", "intermediate"))
def test_wrong_served_certificate_digests_fail_closed(
    validator_case: ValidatorCase,
    digest_name: str,
) -> None:
    if digest_name == "leaf":
        result = validator_case.run(leaf_sha256="0" * 64)
    else:
        result = validator_case.run(intermediate_sha256="0" * 64)
    assert_failure(result)
    assert validator_case.server.state.requests == []


@pytest.mark.parametrize("failure", ("boundary-digest", "boundary-identity", "argument-identity"))
def test_wrong_boundary_or_remote_identity_fails_before_request(
    validator_case: ValidatorCase,
    failure: str,
) -> None:
    case = validator_case
    if failure == "boundary-digest":
        result = case.run(
            argument_updates={"validation-boundary-sha256": "0" * 64}
        )
    elif failure == "boundary-identity":
        result = case.run(boundary_updates={"remote_validator": "other.runner"})
    else:
        result = case.run(argument_updates={"remote-validator": "other.runner"})
    assert_failure(result)
    assert case.server.state.requests == []


def test_redirect_is_rejected_without_following(
    validator_case: ValidatorCase,
) -> None:
    state = validator_case.server.state
    state.status = 302
    state.location = "https://capture.invalid/"
    result = validator_case.run()
    assert_failure(result)
    assert state.requests == [("GET", "/v2/")]


@pytest.mark.parametrize(
    ("status", "api_version", "challenge"),
    (
        (200, "registry/2.1", None),
        (200, None, None),
        (200, "registry/2.0", 'Basic realm="unexpected"'),
        (401, "registry/2.0", None),
        (401, "registry/2.0", "Bearer"),
    ),
)
def test_wrong_api_or_auth_headers_fail_closed(
    validator_case: ValidatorCase,
    status: int,
    api_version: str | None,
    challenge: str | None,
) -> None:
    state = validator_case.server.state
    state.status = status
    state.api_version = api_version
    state.auth_challenge = challenge
    assert_failure(validator_case.run())
    assert state.requests == [("GET", "/v2/")]


def test_server_without_sent_intermediate_fails(
    validator_case: ValidatorCase,
) -> None:
    case = validator_case
    with serve(
        case.root,
        "no-intermediate",
        case.direct_leaf.pem,
        case.direct_leaf.key_pem,
    ) as server:
        result = case.run(
            server=server,
            leaf_sha256=digest(case.direct_leaf.pem),
            intermediate_sha256=digest(case.root_ca.pem),
        )
        assert_failure(result)
        assert server.state.requests == []


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://localhost/v2/",
        "https://user@localhost/v2/",
        "https://LOCALHOST/v2/",
        "https://127.0.0.1/v2/",
        "https://localhost:0443/v2/",
        "https://localhost/v2",
        "https://localhost/v2/?probe=1",
        "https://localhost/v2/#fragment",
    ),
)
def test_noncanonical_endpoint_is_rejected_without_network(
    validator_case: ValidatorCase,
    endpoint: str,
) -> None:
    case = validator_case
    result = case.run(
        boundary_updates={"endpoint": endpoint},
        argument_updates={"endpoint": endpoint},
    )
    assert_failure(result)
    assert case.server.state.requests == []


@pytest.mark.parametrize("limit", ("header", "body"))
def test_response_header_and_body_limits_are_enforced(
    validator_case: ValidatorCase,
    limit: str,
) -> None:
    state = validator_case.server.state
    if limit == "header":
        state.extra_header = ("X-Oversized", "x" * (33 * 1024))
    else:
        state.body = b"x" * (64 * 1024 + 1)
    assert_failure(validator_case.run())
    assert state.requests == [("GET", "/v2/")]


@pytest.mark.parametrize("unsafe", ("symlink", "hardlink", "mode"))
def test_boundary_requires_safe_singly_linked_regular_file(
    validator_case: ValidatorCase,
    unsafe: str,
) -> None:
    case = validator_case
    argv = case.args()
    if unsafe == "symlink":
        source = case.root / "boundary-source"
        case.boundary.replace(source)
        case.boundary.symlink_to(source)
    elif unsafe == "hardlink":
        os.link(case.boundary, case.root / "boundary-link")
    else:
        case.boundary.chmod(0o660)
    result = case.command_runner.run(argv, timeout=20)
    assert_failure(result)
    assert case.server.state.requests == []


def test_descriptor_pinning_detects_boundary_path_replacement(
    validator_case: ValidatorCase,
    test_environment: Mapping[str, str],
) -> None:
    case = validator_case
    state = case.server.state
    state.release_response = threading.Event()
    argv = [os.fspath(value) for value in case.args()]
    process = subprocess.Popen(
        argv,
        cwd=case.command_runner.cwd,
        env={**case.command_runner.environment, **test_environment},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert state.request_received.wait(timeout=10)
        replacement = private_file(
            case.root / "replacement-boundary", case.boundary.read_bytes()
        )
        replacement.replace(case.boundary)
        state.release_response.set()
        stdout, stderr = process.communicate(timeout=10)
    finally:
        state.release_response.set()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert process.returncode != 0
    assert stdout == ""
    assert stderr.startswith("platform-pki-zot-read-only-validate: ")
    assert state.requests == [("GET", "/v2/")]


def test_helper_is_executable(
    validator_case: ValidatorCase,
) -> None:
    metadata = validator_case.helper.stat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o755
