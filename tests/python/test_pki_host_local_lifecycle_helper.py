from __future__ import annotations

import fcntl
import hashlib
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from conftest import CommandResult, NamespaceRootRunner


pytestmark = pytest.mark.pki
REQUEST_ID = "0123456789abcdef0123456789abcdef"
SERVICE = "registry-test"
TARGET = "test-target"
RESPONSE_PRINCIPAL = "test-response"
ENDPOINT = "https://registry.test/v2/"
V2_HELPER_SHA256 = "5dfba20d0a6cc9691540bf038d2f1ef7a101e85dd8f5c6373e4c4c4de2c2048e"
V3_HELPER_SHA256 = "ff1b95aa9d905ecb611e7f68e242c517937fe19f96123ff7663c294b9cc35026"
V4_HELPER_SHA256 = "8d5f1f83ae3d6147070dde3b1073ea61bfbc2a13a6b50480f33c26a5c101d565"


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def private_file(path: Path, data: bytes | str, mode: int = 0o600) -> Path:
    if isinstance(data, str):
        path.write_text(data, encoding="ascii")
    else:
        path.write_bytes(data)
    path.chmod(mode)
    return path


def digest(data: bytes | Path) -> str:
    content = data.read_bytes() if isinstance(data, Path) else data
    return hashlib.sha256(content).hexdigest()


def record(fields: tuple[str, ...], values: dict[str, str]) -> bytes:
    assert set(fields) == set(values)
    return "".join(f"{name}={values[name]}\n" for name in fields).encode("ascii")


def load_helper(path: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("platform_pki_host_local_lifecycle", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def tree_snapshot(root: Path) -> tuple[tuple[Any, ...], ...]:
    if not root.exists():
        return ()
    result: list[tuple[Any, ...]] = []
    for current, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        for name in directories + files:
            path = Path(current) / name
            metadata = path.lstat()
            item: tuple[Any, ...] = (
                str(path.relative_to(root)), stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode), metadata.st_uid,
                metadata.st_gid, metadata.st_nlink, metadata.st_size,
            )
            if stat.S_ISREG(metadata.st_mode):
                item += (digest(path),)
            result.append(item)
    return tuple(result)


def test_target_local_parser_routes_do_not_accept_manual_coordinates(
    repo_root: Path,
) -> None:
    helper = load_helper(
        repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    )
    parser = helper.build_parser()
    common = [
        "--state-root", "/state", "--pending-root", "/pending",
        "--versions-root", "/versions", "--service", SERVICE,
        "--target", TARGET,
    ]
    candidate = [
        "--trust-id", "reviewed-v2", "--common-name", "registry.test",
        "--dns-san", "registry.test", "--minimum-remaining-lifetime-seconds", "1",
    ]
    config = ["--zot-config", "/zot/config.json"]
    commands = (
        ["target-request-export", *common, "--trust-id", "reviewed-v2", "--output-dir", "/output", "--output-owner-uid", "1000"],
        ["target-response-prepare", *common, "--trust-id", "reviewed-v2"],
        ["target-response-install", *common, *candidate],
        ["target-activate-start", *common, *config, *candidate, "--endpoint", ENDPOINT, "--reviewed-ca", "/ca.pem", "--rollback-seconds", "1209600"],
        ["target-activate-complete", *common, *config, *candidate, "--endpoint", ENDPOINT, "--reviewed-ca", "/ca.pem"],
        ["target-recover", *common, *config, *candidate],
        ["target-status", *common, *config, *candidate],
        ["openbao-staging-preflight", *common, "--trust-id", "reviewed-v2"],
    )

    parsed = tuple(parser.parse_args(command) for command in commands)

    assert set(parser._subparsers._group_actions[0].choices) == {
        "target-request-export",
        "target-response-prepare",
        "target-response-install",
        "target-activate-start",
        "target-activate-complete",
        "target-recover",
        "target-status",
        "active-paths",
        "zot-custody",
        "openbao-custody",
        "openbao-staging-preflight",
    }
    assert tuple(value.command for value in parsed) == (
        "target-request-export", "target-response-prepare", "target-response-install",
        "target-activate-start", "target-activate-complete", "target-recover",
        "target-status", "openbao-staging-preflight",
    )
    assert all(not hasattr(value, "target_local") for value in parsed)
    assert all(value.service_adapter == "zot-v1" for value in parsed)
    assert all(getattr(value, "request_id", None) is None for value in parsed)
    assert all(getattr(value, "artifact_sha256", None) is None for value in parsed)
    assert getattr(parsed[3], "operation", None) is None
    for removed in ("abandon-expired-request", "cancel-pending-request"):
        with pytest.raises(SystemExit):
            parser.parse_args([removed])


def ca_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True, crl_sign=True,
        encipher_only=False, decipher_only=False,
    )


def leaf_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )


@dataclass
class LifecycleCase:
    module: ModuleType
    runner: NamespaceRootRunner
    helper: Path
    root: Path
    state: Path
    pending_root: Path
    versions_root: Path
    pending: Path
    zot_config: Path
    signing_key: Path
    reviewed_ca: Path
    local_observation: Path
    systemctl: Path
    service_log: Path
    operation: str
    artifact_sha256: str
    certificate_sha256: str
    certificate_spki_sha256: str
    intermediate_sha256: str
    private_key_bytes: bytes

    def common(self, command: str, *, config: bool = False) -> list[str | Path]:
        argv: list[str | Path] = [
            self.helper, command,
            "--state-root", self.state,
            "--pending-root", self.pending_root,
            "--versions-root", self.versions_root,
            "--service", SERVICE,
            "--target", TARGET,
        ]
        if config:
            argv.extend(("--zot-config", "/etc/zot/config.json"))
        return argv

    def environment(self, additions: dict[str, str] | None = None) -> dict[str, str]:
        result = {
            "PLATFORM_PKI_LIFECYCLE_TESTING": "1",
            "PLATFORM_PKI_LIFECYCLE_TEST_SYSTEMCTL": str(self.systemctl),
            "PLATFORM_PKI_LIFECYCLE_TEST_LOCAL_VALIDATION": str(self.local_observation),
            "PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG": str(self.service_log),
            "PLATFORM_PKI_LIFECYCLE_TEST_ZOT_CONFIG": str(self.zot_config),
        }
        if additions:
            result.update(additions)
        return result

    def run(self, argv: list[str | Path], *, environment: dict[str, str] | None = None, timeout: float = 30) -> CommandResult:
        return self.runner.run(argv, environment=self.environment(environment), timeout=timeout)

    def zot_custody(self, *, managed_config_sha256: str | None = None) -> CommandResult:
        managed_cert = self.root / "zot/managed.crt"
        managed_key = self.root / "zot/managed.key"
        return self.run([
            *self.common("zot-custody", config=True),
            "--operation", self.operation,
            "--managed-cert", managed_cert,
            "--managed-key", managed_key,
            "--managed-config-sha256", managed_config_sha256 or digest(self.zot_config),
        ])


@pytest.fixture
def lifecycle_case(
    repo_root: Path,
    isolated_test_dir: Path,
    namespace_root_runner: NamespaceRootRunner,
) -> LifecycleCase:
    helper = repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    module = load_helper(helper)
    root = private_dir(isolated_test_dir / "lifecycle")
    zot_root = private_dir(root / "zot")
    pending_root = private_dir(zot_root / "tls-pending")
    versions_root = private_dir(zot_root / "tls-versions")
    pending = private_dir(pending_root / REQUEST_ID)
    state = private_dir(root / "state")
    private_file(state / "lock", b"")

    signing_key = root / "target-ed25519"
    namespace_root_runner.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", signing_key]
    ).assert_success()
    signing_key.chmod(0o600)
    algorithm, payload, *_ = signing_key.with_suffix(".pub").read_text(encoding="ascii").split()
    trust = private_dir(state / "trust/reviewed-v1")
    (state / "trust").chmod(0o700)
    for name, principal in {
        "requesters.allowed_signers": TARGET,
        "approvers.allowed_signers": "test-approver",
        "responses.allowed_signers": RESPONSE_PRINCIPAL,
    }.items():
        private_file(trust / name, f"{principal} {algorithm} {payload}\n")
    policy_values = {
        "schema": "3", "request_namespace": module.REQUEST_NAMESPACE_V2,
        "approval_namespace": "platform-pki-csr-approval-v2",
        "response_namespace": module.RESPONSE_NAMESPACE_V2,
        "request_max_age_seconds": "604800",
        "sole_operator_min_delay_seconds": "86400",
        "approval_max_age_seconds": "86400",
        "clock_skew_seconds": "300",
        "approver_principal": "test-approver",
        "response_principal": RESPONSE_PRINCIPAL,
    }
    private_file(trust / "policy", record(module.POLICY_V3_FIELDS, policy_values))

    now = int(time.time())
    before = datetime.now(UTC) - timedelta(minutes=1)
    after = datetime.now(UTC) + timedelta(days=2)
    root_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "Test Root"),))
    root_cert = (
        x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(1)
        .not_valid_before(before).not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(ca_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA384())
    )
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate"),))
    intermediate_cert = (
        x509.CertificateBuilder().subject_name(intermediate_name).issuer_name(root_name)
        .public_key(intermediate_key.public_key()).serial_number(2)
        .not_valid_before(before).not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA384())
    )
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    leaf_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "registry.test"),))
    sans = (
        x509.DNSName("registry.test"), x509.DNSName(TARGET),
        x509.IPAddress(ipaddress.ip_address("192.0.2.61")),
    )
    csr = (
        x509.CertificateSigningRequestBuilder().subject_name(leaf_name)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(leaf_key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)
    )
    leaf_cert = (
        x509.CertificateBuilder().subject_name(leaf_name).issuer_name(intermediate_name)
        .public_key(leaf_key.public_key()).serial_number(0x1234)
        .not_valid_before(before).not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(leaf_usage(), critical=True)
        .add_extension(x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,)), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)
        .sign(intermediate_key, hashes.SHA384())
    )
    key_bytes = leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    leaf = leaf_cert.public_bytes(serialization.Encoding.PEM)
    intermediate = intermediate_cert.public_bytes(serialization.Encoding.PEM)
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    chain = intermediate + root_pem
    fullchain = leaf + intermediate
    spki = leaf_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    for name, data in (("tls.key", key_bytes), ("tls.csr", csr)):
        private_file(pending / name, data)
    request_values = {
        "schema": "2", "request_id": REQUEST_ID, "nonce": "a" * 64,
        "created_epoch": str(now - 1), "expires_epoch": str(now + 3600),
        "operation": "issue", "service": SERVICE, "target": TARGET,
        "requester_principal": TARGET, "inventory_sha256": "b" * 64,
        "csr_sha256": digest(csr), "csr_spki_sha256": digest(spki),
        "current_cert_sha256": "none", "predecessor_request_id": "none",
        "profile": module.PROFILE,
        "response_principal": RESPONSE_PRINCIPAL,
    }

    managed_key = ec.generate_private_key(ec.SECP384R1())
    managed_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "managed.test"),))
    managed_cert = (
        x509.CertificateBuilder().subject_name(managed_name).issuer_name(managed_name)
        .public_key(managed_key.public_key()).serial_number(99)
        .not_valid_before(before).not_valid_after(after)
        .sign(managed_key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)
    )
    managed_key_bytes = managed_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    managed_cert_path = private_file(
        zot_root / "managed.crt", managed_cert + intermediate, 0o644
    )
    managed_key_path = private_file(zot_root / "managed.key", managed_key_bytes)
    request_bytes = record(module.REQUEST_V2_FIELDS, request_values)
    request_path = private_file(pending / "request", request_bytes)
    namespace_root_runner.run([
        "ssh-keygen", "-Y", "sign", "-f", signing_key,
        "-n", module.REQUEST_NAMESPACE_V2, request_path,
    ]).assert_success()
    Path(f"{request_path}.sig").chmod(0o600)

    response_values = {
        "schema": "2", "request_id": REQUEST_ID, "nonce": request_values["nonce"],
        "operation": "issue", "service": SERVICE, "target": TARGET,
        "request_sha256": digest(request_bytes), "approval_sha256": "c" * 64,
        "request_signature_sha256": digest(pending / "request.sig"),
        "approval_signature_sha256": "d" * 64,
        "request_trust_sha256": digest(trust / "requesters.allowed_signers"),
        "approval_trust_sha256": digest(trust / "approvers.allowed_signers"),
        "inventory_sha256": request_values["inventory_sha256"],
        "csr_sha256": digest(csr), "csr_spki_sha256": digest(spki),
        "current_cert_sha256": request_values["current_cert_sha256"],
        "predecessor_request_id": "none",
        "certificate_sha256": digest(leaf), "certificate_spki_sha256": digest(spki),
        "chain_sha256": digest(chain), "issuer_root": "g1",
        "issuer_intermediate": "g1-i1", "serial": "1234",
        "not_before_epoch": str(int(leaf_cert.not_valid_before_utc.timestamp())),
        "not_after_epoch": str(int(leaf_cert.not_valid_after_utc.timestamp())),
        "issuance_state": "issued", "response_principal": RESPONSE_PRINCIPAL,
        "created_epoch": str(now),
    }
    response_source = private_dir(root / "response-source")
    response_bytes = record(module.RESPONSE_V2_FIELDS, response_values)
    response_path = private_file(response_source / "response", response_bytes)
    namespace_root_runner.run([
        "ssh-keygen", "-Y", "sign", "-f", signing_key,
        "-n", module.RESPONSE_NAMESPACE_V2, response_path,
    ]).assert_success()
    response_signature = Path(f"{response_path}.sig")
    response_signature.chmod(0o600)
    artifact_values = {
        "schema": "2", "kind": "certificate-export", "service": SERVICE,
        "request_id": REQUEST_ID, "operation": "issue", "target": TARGET,
        "source_kind": "csr-response", "source_response_sha256": digest(response_bytes),
        "source_response_signature_sha256": digest(response_signature),
        "certificate_sha256": digest(leaf), "certificate_spki_sha256": digest(spki),
        "chain_sha256": digest(chain), "fullchain_sha256": digest(fullchain),
        "issuer_root": "g1", "issuer_intermediate": "g1-i1", "serial": "1234",
        "not_before_epoch": response_values["not_before_epoch"],
        "not_after_epoch": response_values["not_after_epoch"],
        "response_principal": RESPONSE_PRINCIPAL, "created_epoch": str(now),
    }
    artifact = record(module.ARTIFACT_FIELDS, artifact_values)
    for name, data in (
        ("artifact", artifact), ("tls.crt", leaf), ("ca-chain.crt", chain),
        ("fullchain.crt", fullchain),
    ):
        private_file(response_source / name, data)

    reviewed_ca = private_file(root / "reviewed-ca.crt", chain)
    intermediate_sha256 = digest(intermediate)
    local_values = {
        "schema": "2", "service_result": "passed", "tls_result": "passed",
        "served_certificate_sha256": digest(leaf),
        "served_intermediate_sha256": intermediate_sha256,
    }
    local_observation = private_file(
        root / "local-observation",
        record(("schema", "service_result", "tls_result", "served_certificate_sha256", "served_intermediate_sha256"), local_values),
    )
    service_log = root / "service.log"
    systemctl = private_file(
        root / "systemctl-stub",
        "#!/bin/sh\n"
        "set -eu\n"
        "if [ \"$1\" = is-active ]; then "
        "if [ -s \"$PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG\" ]; then printf 'active\\n'; exit 0; fi; "
        "printf 'inactive\\n'; exit 3; fi\n"
        "if [ \"$1\" = is-enabled ]; then "
        "if [ -s \"$PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG\" ]; then printf 'enabled\\n'; exit 0; fi; "
        "printf 'masked\\n'; exit 1; fi\n"
        "printf '%s\\n' \"$*\" >>\"$PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG\"\n",
        0o755,
    )
    zot_config = private_file(
        zot_root / "config.json",
        json.dumps({"http": {"address": "0.0.0.0", "tls": {"cert": str(managed_cert_path), "key": str(managed_key_path)}}}, indent=2) + "\n",
        0o644,
    )
    managed_cert_path.unlink()
    managed_key_path.unlink()
    return LifecycleCase(
        module=module, runner=namespace_root_runner, helper=helper, root=root,
        state=state, pending_root=pending_root, versions_root=versions_root,
        pending=pending, zot_config=zot_config, signing_key=signing_key,
        reviewed_ca=reviewed_ca, local_observation=local_observation,
        systemctl=systemctl, service_log=service_log, operation="issue",
        artifact_sha256=digest(artifact), certificate_sha256=digest(leaf),
        certificate_spki_sha256=digest(spki),
        intermediate_sha256=intermediate_sha256, private_key_bytes=key_bytes,
    )


def result_json(result: CommandResult) -> dict[str, Any]:
    result.assert_success()
    assert result.stderr == "", result.diagnostics()
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, dict)
    return parsed


def assert_failure(result: CommandResult) -> None:
    result.assert_failure()
    assert result.stdout == "", result.diagnostics()


def target_candidate_args(case: LifecycleCase) -> list[str | Path]:
    return [
        "--trust-id", "reviewed-v1", "--common-name", "registry.test",
        "--dns-san", "registry.test", "--dns-san", TARGET,
        "--ip-san", "192.0.2.61",
        "--minimum-remaining-lifetime-seconds", "3600",
    ]


def prepare_and_install_target_response(case: LifecycleCase) -> dict[str, Any]:
    prepared = result_json(case.run([
        *case.common("target-response-prepare"), "--trust-id", "reviewed-v1",
    ]))
    ingress = Path(prepared["ingress_dir"])
    for name in case.module.RESPONSE_NAMES:
        shutil.copyfile(case.root / "response-source" / name, ingress / name)
        ingress.joinpath(name).chmod(0o600)
    return result_json(case.run([
        *case.common("target-response-install"), *target_candidate_args(case),
    ]))


def target_activate_args(case: LifecycleCase) -> list[str | Path]:
    return [
        *case.common("target-activate-start", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
        "--rollback-seconds", "1209600",
    ]


def prepare_target_renewal(case: LifecycleCase) -> str:
    renewal_id = "fedcba9876543210fedcba9876543210"
    renewal = private_dir(case.pending_root / renewal_id)
    for name in ("tls.key", "tls.csr"):
        shutil.copyfile(case.pending / name, renewal / name)
        renewal.joinpath(name).chmod(0o600)
    now = int(time.time())
    request_values = case.module.parse_record(
        case.pending.joinpath("request").read_bytes(),
        case.module.REQUEST_V2_FIELDS,
        "fixture renewal request",
    )
    request_values.update(
        request_id=renewal_id,
        nonce="e" * 64,
        created_epoch=str(now - 1),
        expires_epoch=str(now + 3600),
        operation="renew",
        current_cert_sha256=case.certificate_sha256,
        predecessor_request_id=REQUEST_ID,
    )
    renewal_request = record(case.module.REQUEST_V2_FIELDS, request_values)
    request_path = private_file(renewal / "request", renewal_request)
    case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", case.signing_key,
        "-n", case.module.REQUEST_NAMESPACE_V2, request_path,
    ]).assert_success()
    renewal.joinpath("request.sig").chmod(0o600)

    response_source = case.root / "response-source"
    response_values = case.module.parse_record(
        response_source.joinpath("response").read_bytes(),
        case.module.RESPONSE_V2_FIELDS,
        "fixture renewal response",
    )
    response_values.update(
        request_id=renewal_id,
        nonce=request_values["nonce"],
        operation="renew",
        request_sha256=digest(renewal_request),
        request_signature_sha256=digest(renewal / "request.sig"),
        current_cert_sha256=case.certificate_sha256,
        predecessor_request_id=REQUEST_ID,
        created_epoch=str(now),
    )
    response_bytes = record(case.module.RESPONSE_V2_FIELDS, response_values)
    response_path = private_file(response_source / "response", response_bytes)
    response_source.joinpath("response.sig").unlink()
    case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", case.signing_key,
        "-n", case.module.RESPONSE_NAMESPACE_V2, response_path,
    ]).assert_success()
    response_source.joinpath("response.sig").chmod(0o600)
    artifact_values = case.module.parse_record(
        response_source.joinpath("artifact").read_bytes(),
        case.module.ARTIFACT_FIELDS,
        "fixture renewal artifact",
    )
    artifact_values.update(
        request_id=renewal_id,
        operation="renew",
        source_response_sha256=digest(response_bytes),
        source_response_signature_sha256=digest(response_source / "response.sig"),
        created_epoch=str(now),
    )
    private_file(
        response_source / "artifact",
        record(case.module.ARTIFACT_FIELDS, artifact_values),
    )
    return renewal_id


def start_target_renewal(
    case: LifecycleCase,
) -> tuple[str, dict[str, Any], bytes, bytes, bytes]:
    prepare_and_install_target_response(case)
    result_json(case.run(target_activate_args(case)))
    result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ]))
    prior_config = case.zot_config.read_bytes()
    prior_active = (case.state / "active").read_bytes()
    prior_rollback = (case.state / "rollback").read_bytes()
    renewal_id = prepare_target_renewal(case)
    prepare_and_install_target_response(case)
    activated = result_json(case.run(target_activate_args(case)))
    return renewal_id, activated, prior_config, prior_active, prior_rollback


def test_target_local_routes_reach_terminal_state_without_evidence(
    lifecycle_case: LifecycleCase,
) -> None:
    case = lifecycle_case
    exported = private_dir(case.root / "target-request-export")
    request_result = result_json(case.run([
        *case.common("target-request-export"), "--trust-id", "reviewed-v1",
        "--output-dir", exported, "--output-owner-uid", "0",
    ]))
    assert request_result["status"] == "collected"
    assert {path.name for path in exported.iterdir()} == {
        "request",
        "request.sig",
        "tls.csr",
    }

    prepared = result_json(case.run([
        *case.common("target-response-prepare"), "--trust-id", "reviewed-v1",
    ]))
    ingress = Path(prepared["ingress_dir"])
    for name in case.module.RESPONSE_NAMES:
        shutil.copyfile(case.root / "response-source" / name, ingress / name)
        ingress.joinpath(name).chmod(0o600)
    ingress.joinpath("artifact").write_bytes(
        ingress.joinpath("artifact").read_bytes().replace(
            b"schema=2\n", b"schema=1\n", 1
        )
    )
    rejected_schema = case.run([
        *case.common("target-response-install"), *target_candidate_args(case),
    ])
    assert_failure(rejected_schema)
    assert "artifact or response does not bind" in rejected_schema.stderr
    shutil.copyfile(case.root / "response-source/artifact", ingress / "artifact")
    ingress.joinpath("artifact").chmod(0o600)
    ingress.joinpath("response").write_bytes(
        ingress.joinpath("response").read_bytes() + b"unexpected=value\n"
    )
    ingress.joinpath("response").chmod(0o600)
    rejected = case.run([
        *case.common("target-response-install"), *target_candidate_args(case),
    ])
    assert_failure(rejected)
    assert "field count" in rejected.stderr
    shutil.copyfile(case.root / "response-source/response", ingress / "response")
    ingress.joinpath("response").chmod(0o600)
    installed = result_json(case.run([
        *case.common("target-response-install"), *target_candidate_args(case),
    ]))
    assert installed["artifact_sha256"] == case.artifact_sha256

    activated = result_json(case.run(target_activate_args(case)))
    assert activated["status"] == "local-validated"
    resumed = result_json(case.run(target_activate_args(case)))
    assert resumed == activated
    journal = case.module.parse_record(
        case.state.joinpath("activation-journal").read_bytes(),
        case.module.ACTIVATION_JOURNAL_FIELDS,
        "fixture activation journal",
    )
    assert tuple(journal) == case.module.ACTIVATION_JOURNAL_FIELDS
    assert journal["schema"] == "2"
    activating_status = result_json(case.run([
        *case.common("target-status", config=True), *target_candidate_args(case),
    ]))
    assert activating_status["status"] == "activating"
    assert activating_status["required_action"] == "complete-local-validation"

    completed = result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ]))
    assert completed["status"] == "complete"
    assert result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ])) == completed
    assert not os.path.lexists(case.state / "activation-journal")
    assert not os.path.lexists(case.state / "evidence")
    for name, fields in (
        ("active", case.module.ACTIVE_FIELDS),
        ("rollback", case.module.ROLLBACK_FIELDS),
        ("target-terminal", case.module.TARGET_TERMINAL_FIELDS),
    ):
        state_record = case.module.parse_record(
            case.state.joinpath(name).read_bytes(), fields, f"fixture {name} record"
        )
        assert tuple(state_record) == fields
        assert state_record["schema"] == "2"
    assert result_json(case.run([
        *case.common("target-status", config=True), *target_candidate_args(case),
    ]))["status"] == "complete"
    active_paths = result_json(case.run(case.common("active-paths", config=True)))
    assert active_paths["request_id"] == REQUEST_ID
    assert active_paths["artifact_sha256"] == case.artifact_sha256
    assert result_json(case.zot_custody())["custody"] == "host-local"
    active = case.state.joinpath("active").read_bytes()
    case.state.joinpath("active").unlink()
    unauthenticated = case.run([
        *case.common("target-status", config=True), *target_candidate_args(case),
    ])
    assert_failure(unauthenticated)
    assert "does not match authenticated active state" in unauthenticated.stderr
    private_file(case.state / "active", active)
    assert result_json(case.run([
        *case.common("target-recover", config=True), *target_candidate_args(case),
    ])) == {"status": "not-required", "terminal_state": "complete"}


@pytest.mark.parametrize(
    ("route", "deadline_offset"),
    (
        pytest.param("complete", 1, id="completion-after-deadline"),
        pytest.param("resume", 0, id="resume-at-deadline"),
        pytest.param("crossing", None, id="completion-crosses-deadline"),
    ),
)
def test_local_validated_deadline_recovers_predecessor_without_completion(
    lifecycle_case: LifecycleCase,
    route: str,
    deadline_offset: int | None,
) -> None:
    case = lifecycle_case
    (
        renewal_id, activated, prior_config, prior_active, prior_rollback,
    ) = start_target_renewal(case)
    deadline = int(activated["rollback_deadline_epoch"])
    command = (
        [
            *case.common("target-activate-complete", config=True),
            *target_candidate_args(case), "--endpoint", ENDPOINT,
            "--reviewed-ca", case.reviewed_ca,
        ]
        if route != "resume"
        else target_activate_args(case)
    )
    if route == "crossing":
        epoch_environment = {
            "PLATFORM_PKI_LIFECYCLE_TEST_EPOCH_SEQUENCE":
                f"{deadline - 1},{deadline}",
        }
    else:
        assert deadline_offset is not None
        epoch_environment = {
            "PLATFORM_PKI_LIFECYCLE_TEST_EPOCH": str(
                deadline + deadline_offset
            ),
        }

    expired = result_json(case.run(
        command,
        environment=epoch_environment,
    ))

    assert expired["status"] == "rolled-back"
    assert case.zot_config.read_bytes() == prior_config
    assert (case.state / "active").read_bytes() == prior_active
    assert (case.state / "rollback").read_bytes() == prior_rollback
    assert not (case.state / "activation-journal").exists()
    terminal = case.module.parse_target_terminal(
        (case.state / "target-terminal").read_bytes(),
        SimpleNamespace(service=SERVICE, target=TARGET),
    )
    assert terminal["request_id"] == renewal_id
    assert terminal["state"] == "rolled-back"
    assert terminal["validation_epoch"] == "none"
    history_terminal = case.module.parse_target_terminal(
        case.state.joinpath(
            "target-terminal-history", renewal_id
        ).read_bytes(),
        SimpleNamespace(service=SERVICE, target=TARGET),
    )
    assert history_terminal["state"] == "rolled-back"


def test_completion_value_error_restores_predecessor_and_terminalizes(
    lifecycle_case: LifecycleCase,
) -> None:
    case = lifecycle_case
    (
        renewal_id, _activated, prior_config, prior_active, prior_rollback,
    ) = start_target_renewal(case)
    command = [
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case),
        "--endpoint", "https://registry.test:notaport/v2/",
        "--reviewed-ca", case.reviewed_ca,
    ]

    failed = result_json(case.runner.run(command, environment={
        "PLATFORM_PKI_LIFECYCLE_TESTING": "1",
        "PLATFORM_PKI_LIFECYCLE_TEST_SYSTEMCTL": str(case.systemctl),
        "PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG": str(case.service_log),
        "PLATFORM_PKI_LIFECYCLE_TEST_ZOT_CONFIG": str(case.zot_config),
    }))

    assert failed["status"] == "rolled-back"
    assert case.zot_config.read_bytes() == prior_config
    assert (case.state / "active").read_bytes() == prior_active
    assert (case.state / "rollback").read_bytes() == prior_rollback
    terminal = case.module.parse_target_terminal(
        (case.state / "target-terminal").read_bytes(),
        SimpleNamespace(service=SERVICE, target=TARGET),
    )
    assert terminal["request_id"] == renewal_id
    assert terminal["state"] == "rolled-back"


def test_schema1_lifecycle_records_are_rejected_without_rewrite(
    lifecycle_case: LifecycleCase,
) -> None:
    case = lifecycle_case
    prepare_and_install_target_response(case)
    result_json(case.run(target_activate_args(case)))
    args = SimpleNamespace(
        service=SERVICE,
        target=TARGET,
        versions_root=str(case.versions_root),
    )
    for name, parser in (
        ("active", case.module.parse_active),
        ("rollback", case.module.parse_rollback),
        ("activation-journal", case.module.journal_record),
    ):
        path = case.state / name
        schema1 = path.read_bytes().replace(b"schema=2\n", b"schema=1\n", 1)
        private_file(path, schema1)
        with pytest.raises(case.module.LifecycleError):
            parser(path.read_bytes(), args)
        assert path.read_bytes() == schema1
        private_file(path, schema1.replace(b"schema=1\n", b"schema=2\n", 1))

    result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ]))
    terminal = case.state / "target-terminal"
    schema1 = terminal.read_bytes().replace(b"schema=2\n", b"schema=1\n", 1)
    private_file(terminal, schema1)
    with pytest.raises(case.module.LifecycleError):
        case.module.parse_target_terminal(terminal.read_bytes(), args)
    assert terminal.read_bytes() == schema1


@pytest.mark.parametrize(
    "retirement_fault",
    (
        None,
        "after-target-terminal-history",
        "after-target-terminal-retirement",
        "after-target-terminal-retirement-lock",
    ),
)
def test_target_local_completed_request_can_be_renewed(
    lifecycle_case: LifecycleCase,
    retirement_fault: str | None,
) -> None:
    case = lifecycle_case
    prepare_and_install_target_response(case)
    result_json(case.run(target_activate_args(case)))
    result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ]))
    first_terminal = case.state.joinpath("target-terminal").read_bytes()
    assert case.state.joinpath(
        "target-terminal-history", REQUEST_ID
    ).read_bytes() == first_terminal

    renewal_id = prepare_target_renewal(case)
    renewal = case.pending_root / renewal_id

    pending_status = result_json(case.run([
        *case.common("target-status", config=True), *target_candidate_args(case),
    ]))
    assert pending_status["status"] == "request-pending"
    assert pending_status["request_id"] == renewal_id
    prepare_and_install_target_response(case)
    before_preview = tree_snapshot(case.root)
    preview = result_json(case.run([*target_activate_args(case), "--check"]))
    assert preview["status"] == "would-activate"
    assert preview["request_id"] == renewal_id
    assert tree_snapshot(case.root) == before_preview
    if retirement_fault is not None:
        interrupted = case.run(
            target_activate_args(case),
            environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": retirement_fault},
        )
        assert_failure(interrupted)
        assert case.pending.exists()
        assert renewal.exists()
        assert case.state.joinpath(
            "target-terminal-history", REQUEST_ID
        ).read_bytes() == first_terminal
        interrupted_status = result_json(case.run([
            *case.common("target-status", config=True),
            *target_candidate_args(case),
        ]))
        assert interrupted_status["status"] == "response-ready"
        assert interrupted_status["request_id"] == renewal_id
    renewed = result_json(case.run(target_activate_args(case)))
    assert renewed["request_id"] == renewal_id
    assert case.pending.exists()
    assert renewal.exists()
    assert not case.state.joinpath("target-terminal").exists()
    assert case.state.joinpath(
        "target-terminal-history", REQUEST_ID
    ).read_bytes() == first_terminal

    completed = result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ]))
    assert completed["status"] == "complete"
    assert completed["request_id"] == renewal_id
    assert case.state.joinpath(
        "target-terminal-history", renewal_id
    ).read_bytes() == case.state.joinpath("target-terminal").read_bytes()


def test_initial_issue_validation_failure_terminalizes_as_not_activated(
    lifecycle_case: LifecycleCase,
) -> None:
    case = lifecycle_case
    prepare_and_install_target_response(case)
    activated = result_json(case.run(target_activate_args(case)))
    local = case.local_observation.read_text(encoding="ascii")
    private_file(
        case.local_observation,
        local.replace(case.certificate_sha256, "f" * 64),
    )
    failed = result_json(case.run([
        *case.common("target-activate-complete", config=True),
        *target_candidate_args(case), "--endpoint", ENDPOINT,
        "--reviewed-ca", case.reviewed_ca,
    ]))
    assert failed["status"] == "not-activated"
    assert not os.path.lexists(case.state / "activation-journal")
    assert not os.path.lexists(case.state / "active")
    assert result_json(case.run([
        *case.common("target-status", config=True), *target_candidate_args(case),
    ]))["status"] == "not-activated"


def test_target_recover_authenticates_interrupted_candidate_and_terminalizes(
    lifecycle_case: LifecycleCase,
) -> None:
    case = lifecycle_case
    prepare_and_install_target_response(case)
    interrupted = case.run(
        target_activate_args(case),
        environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": "after-active-records"},
    )
    assert_failure(interrupted)
    assert os.path.lexists(case.state / "activation-journal")
    recovered = result_json(case.run([
        *case.common("target-recover", config=True), *target_candidate_args(case),
    ]))
    assert recovered["status"] == "not-activated"
    assert not os.path.lexists(case.state / "activation-journal")
    assert result_json(case.run([
        *case.common("target-status", config=True), *target_candidate_args(case),
    ]))["status"] == "not-activated"


def test_target_expired_request_is_preserved_and_requires_reset(
    lifecycle_case: LifecycleCase,
) -> None:
    request_path = lifecycle_case.pending / "request"
    values = lifecycle_case.module.parse_record(
        request_path.read_bytes(),
        lifecycle_case.module.REQUEST_V2_FIELDS,
        "fixture request",
    )
    now = int(time.time())
    values.update(created_epoch=str(now - 3601), expires_epoch=str(now - 1))
    private_file(
        request_path,
        record(lifecycle_case.module.REQUEST_V2_FIELDS, values),
    )
    signature = lifecycle_case.pending / "request.sig"
    signature.unlink()
    lifecycle_case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", lifecycle_case.signing_key,
        "-n", lifecycle_case.module.REQUEST_NAMESPACE_V2, request_path,
    ]).assert_success()
    signature.chmod(0o600)
    before = tree_snapshot(lifecycle_case.pending)

    expired_status = result_json(lifecycle_case.run([
        *lifecycle_case.common("target-status", config=True),
        *target_candidate_args(lifecycle_case),
    ]))
    assert expired_status == {
        "schema": "2",
        "kind": "platform-config-target-local-certificate-status",
        "status": "request-expired",
        "service": SERVICE,
        "target": TARGET,
        "request_id": "none",
        "required_action": "reset-required",
    }
    assert tree_snapshot(lifecycle_case.pending) == before
