from __future__ import annotations

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
from types import ModuleType
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
REMOTE_VALIDATOR = "test-runner"
ENDPOINT = "https://registry.test/v2/"


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
    boundary: Path
    boundary_sha256: str
    reviewed_ca: Path
    local_observation: Path
    systemctl: Path
    service_log: Path
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
            argv.extend(("--zot-config", self.zot_config))
        return argv

    def candidate(self) -> list[str]:
        return [
            "--trust-id", "reviewed-v1",
            "--request-id", REQUEST_ID,
            "--artifact-sha256", self.artifact_sha256,
            "--common-name", "registry.test",
            "--dns-san", "registry.test",
            "--dns-san", TARGET,
            "--ip-san", "192.0.2.61",
            "--minimum-remaining-lifetime-seconds", "3600",
        ]

    def boundary_args(self) -> list[str | Path]:
        return [
            "--validation-boundary-sha256", self.boundary_sha256,
            "--remote-validator", REMOTE_VALIDATOR,
            "--endpoint", ENDPOINT,
        ]

    def environment(self, additions: dict[str, str] | None = None) -> dict[str, str]:
        result = {
            "PLATFORM_PKI_LIFECYCLE_TESTING": "1",
            "PLATFORM_PKI_LIFECYCLE_TEST_SYSTEMCTL": str(self.systemctl),
            "PLATFORM_PKI_LIFECYCLE_TEST_LOCAL_VALIDATION": str(self.local_observation),
            "PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG": str(self.service_log),
        }
        if additions:
            result.update(additions)
        return result

    def run(self, argv: list[str | Path], *, environment: dict[str, str] | None = None, timeout: float = 30) -> CommandResult:
        return self.runner.run(argv, environment=self.environment(environment), timeout=timeout)

    def prepare_response(self) -> Path:
        result = self.run([*self.common("response-prepare"), "--request-id", REQUEST_ID]).assert_success()
        ingress = Path(json.loads(result.stdout)["ingress_dir"])
        source = self.root / "response-source"
        for name in self.module.RESPONSE_NAMES:
            shutil.copyfile(source / name, ingress / name)
            (ingress / name).chmod(0o600)
        return ingress

    def expire_request(self) -> None:
        request_path = self.pending / "request"
        values = dict(
            line.split("=", 1)
            for line in request_path.read_text(encoding="ascii").splitlines()
        )
        now = int(time.time())
        values["created_epoch"] = str(now - 3601)
        values["expires_epoch"] = str(now - 1)
        private_file(request_path, record(self.module.REQUEST_FIELDS, values))
        signature = self.pending / "request.sig"
        signature.unlink()
        self.runner.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                self.signing_key,
                "-n",
                self.module.REQUEST_NAMESPACE,
                request_path,
            ]
        ).assert_success()
        signature.chmod(0o600)

    def abandon_expired(self, *, check: bool = False) -> CommandResult:
        argv = [
            *self.common("abandon-expired-request"),
            "--trust-id",
            "reviewed-v1",
            "--request-id",
            REQUEST_ID,
        ]
        if check:
            argv.append("--check")
        return self.run(argv)

    def cancel_pending(
        self,
        *,
        request_sha256: str | None = None,
        check: bool = False,
    ) -> CommandResult:
        argv = [
            *self.common("cancel-pending-request"),
            "--trust-id",
            "reviewed-v1",
            "--request-id",
            REQUEST_ID,
            "--request-sha256",
            request_sha256 or digest(self.pending / "request"),
        ]
        if check:
            argv.append("--check")
        return self.run(argv)

    def write_expired_abandonment_journal(self, source: Path | None = None) -> None:
        request_root = self.pending if source is None else source
        request_values = dict(
            line.split("=", 1)
            for line in (request_root / "request")
            .read_text(encoding="ascii")
            .splitlines()
        )
        values = {
            "schema": "1",
            "kind": "host-local-expired-request-abandonment",
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "request_sha256": digest(request_root / "request"),
            "request_signature_sha256": digest(request_root / "request.sig"),
            "csr_sha256": digest(request_root / "tls.csr"),
            "csr_spki_sha256": request_values["csr_spki_sha256"],
            "created_epoch": request_values["created_epoch"],
            "expires_epoch": request_values["expires_epoch"],
        }
        private_file(
            self.state / "expired-request-abandonment-journal",
            record(self.module.EXPIRED_REQUEST_ABANDONMENT_JOURNAL_FIELDS, values),
        )

    def write_pending_cancellation_journal(self, source: Path | None = None) -> None:
        request_root = self.pending if source is None else source
        request_values = dict(
            line.split("=", 1)
            for line in (request_root / "request")
            .read_text(encoding="ascii")
            .splitlines()
        )
        values = {
            "schema": "1",
            "kind": "host-local-pending-request-cancellation",
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "request_sha256": digest(request_root / "request"),
            "request_signature_sha256": digest(request_root / "request.sig"),
            "csr_sha256": digest(request_root / "tls.csr"),
            "csr_spki_sha256": request_values["csr_spki_sha256"],
            "created_epoch": request_values["created_epoch"],
            "expires_epoch": request_values["expires_epoch"],
        }
        private_file(
            self.state / "pending-request-cancellation-journal",
            record(self.module.EXPIRED_REQUEST_ABANDONMENT_JOURNAL_FIELDS, values),
        )

    def install_response(self, *, check: bool = False) -> CommandResult:
        argv = [*self.common("response-install"), *self.candidate()]
        if check:
            argv.append("--check")
        return self.run(argv)

    def activate(self, *, check: bool = False, environment: dict[str, str] | None = None) -> CommandResult:
        argv = [
            *self.common("activate-start", config=True), *self.candidate(),
            *self.boundary_args(),
            "--validation-boundary", self.boundary,
            "--reviewed-ca", self.reviewed_ca,
            "--rollback-seconds", "1209600",
        ]
        if check:
            argv.append("--check")
        return self.run(argv, environment=environment)

    def observation(
        self,
        validation_epoch: int,
        *,
        served_certificate_sha256: str | None = None,
        served_intermediate_sha256: str | None = None,
    ) -> Path:
        values = {
            "schema": "1", "kind": "pki-external-validation-observation",
            "service": SERVICE, "target": TARGET, "request_id": REQUEST_ID,
            "artifact_manifest_sha256": self.artifact_sha256,
            "validation_boundary_sha256": self.boundary_sha256,
            "remote_validator": REMOTE_VALIDATOR, "endpoint": ENDPOINT,
            "remote_tls_result": "passed", "remote_application_result": "passed",
            "remote_http_status": "200", "remote_api_version": "registry/2.0",
            "remote_auth_challenge": "not-required",
            "served_certificate_sha256": (
                self.certificate_sha256
                if served_certificate_sha256 is None else served_certificate_sha256
            ),
            "served_intermediate_sha256": (
                self.intermediate_sha256
                if served_intermediate_sha256 is None else served_intermediate_sha256
            ),
            "validation_epoch": str(validation_epoch),
        }
        return private_file(
            self.root / "external-observation",
            record(self.module.EXTERNAL_OBSERVATION_FIELDS, values),
        )

    def finish(
        self,
        observation: Path | None,
        *,
        check: bool = False,
        fresh: bool = False,
        action: str = "finalize",
        result: str = "activated",
        served_intermediate_sha256: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> CommandResult:
        argv = [
            *self.common("activate-finish", config=True),
            *self.candidate(),
            *self.boundary_args(),
            "--validation-boundary", self.boundary,
            "--served-intermediate-sha256", (
                self.intermediate_sha256
                if served_intermediate_sha256 is None else served_intermediate_sha256
            ),
            "--deployment-signing-key", self.signing_key,
            "--reviewed-ca", self.reviewed_ca,
            "--rollback-seconds", "1209600",
            "--action", action,
            "--result", result,
        ]
        if observation is not None:
            argv.extend(("--observation-file", observation))
        if check:
            argv.append("--check")
        if fresh:
            argv.append("--fresh-evidence")
        return self.run(argv, environment=environment)

    def prepare_rolled_back_abandonment(
        self, *extra: str | Path
    ) -> CommandResult:
        return self.run([
            *self.common("activate-finish", config=True),
            *self.candidate(),
            *self.boundary_args(),
            "--validation-boundary", self.boundary,
            "--deployment-signing-key", self.signing_key,
            "--reviewed-ca", self.reviewed_ca,
            "--rollback-seconds", "1209600",
            "--action", "abandon",
            "--result", "rolled-back",
            "--prepare-rolled-back-abandonment",
            *extra,
        ])

    def recover(self, *, check: bool = False) -> CommandResult:
        argv = [
            *self.common("recover", config=True),
            "--request-id", REQUEST_ID,
            "--artifact-sha256", self.artifact_sha256,
        ]
        if check:
            argv.append("--check")
        return self.run(argv)

    def collect_evidence(
        self,
        deployment_sha256: str,
        output: Path,
        *,
        check: bool = False,
    ) -> CommandResult:
        argv = [
            *self.common("evidence-collection-prepare"),
            "--trust-id", "reviewed-v1",
            "--request-id", REQUEST_ID,
            "--artifact-sha256", self.artifact_sha256,
            "--deployment-sha256", deployment_sha256,
            "--output-dir", output,
            "--output-owner-uid", "0",
        ]
        if check:
            argv.append("--check")
        return self.run(argv)

    def status(self, *extra: str | Path) -> CommandResult:
        return self.run([
            *self.common("status", config=True),
            "--trust-id", "reviewed-v1",
            "--common-name", "registry.test",
            "--dns-san", "registry.test",
            "--dns-san", TARGET,
            "--ip-san", "192.0.2.61",
            *extra,
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
        "deployers.allowed_signers": TARGET,
    }.items():
        private_file(trust / name, f"{principal} {algorithm} {payload}\n")
    policy_values = {
        "schema": "2", "request_namespace": module.REQUEST_NAMESPACE,
        "approval_namespace": "platform-pki-csr-approval-v1",
        "response_namespace": module.RESPONSE_NAMESPACE,
        "deployment_namespace": module.DEPLOYMENT_NAMESPACE,
        "request_max_age_seconds": "604800",
        "sole_operator_min_delay_seconds": "86400",
        "approval_max_age_seconds": "86400",
        "deployment_max_age_seconds": "86400", "clock_skew_seconds": "300",
        "approver_principal": "test-approver",
        "response_principal": RESPONSE_PRINCIPAL,
    }
    private_file(trust / "policy", record(module.POLICY_FIELDS, policy_values))

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
        "schema": "1", "request_id": REQUEST_ID, "nonce": "a" * 64,
        "created_epoch": str(now - 1), "expires_epoch": str(now + 3600),
        "operation": "migrate", "service": SERVICE, "target": TARGET,
        "requester_principal": TARGET, "inventory_sha256": "b" * 64,
        "csr_sha256": digest(csr), "csr_spki_sha256": digest(spki),
        "current_cert_sha256": "placeholder", "profile": module.PROFILE,
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
    managed_cert_path = private_file(zot_root / "managed.crt", managed_cert, 0o644)
    managed_key_path = private_file(zot_root / "managed.key", managed_key_bytes)
    request_values["current_cert_sha256"] = digest(managed_cert)
    request_bytes = record(module.REQUEST_FIELDS, request_values)
    request_path = private_file(pending / "request", request_bytes)
    namespace_root_runner.run([
        "ssh-keygen", "-Y", "sign", "-f", signing_key,
        "-n", module.REQUEST_NAMESPACE, request_path,
    ]).assert_success()
    Path(f"{request_path}.sig").chmod(0o600)

    response_values = {
        "schema": "1", "request_id": REQUEST_ID, "nonce": request_values["nonce"],
        "operation": "migrate", "service": SERVICE, "target": TARGET,
        "request_sha256": digest(request_bytes), "approval_sha256": "c" * 64,
        "inventory_sha256": request_values["inventory_sha256"],
        "csr_sha256": digest(csr), "csr_spki_sha256": digest(spki),
        "certificate_sha256": digest(leaf), "certificate_spki_sha256": digest(spki),
        "chain_sha256": digest(chain), "issuer_root": "g1",
        "issuer_intermediate": "g1-i1", "serial": "1234",
        "not_before_epoch": str(int(leaf_cert.not_valid_before_utc.timestamp())),
        "not_after_epoch": str(int(leaf_cert.not_valid_after_utc.timestamp())),
        "candidate_state": "pending", "response_principal": RESPONSE_PRINCIPAL,
        "created_epoch": str(now),
    }
    response_source = private_dir(root / "response-source")
    response_bytes = record(module.RESPONSE_FIELDS, response_values)
    response_path = private_file(response_source / "response", response_bytes)
    namespace_root_runner.run([
        "ssh-keygen", "-Y", "sign", "-f", signing_key,
        "-n", module.RESPONSE_NAMESPACE, response_path,
    ]).assert_success()
    response_signature = Path(f"{response_path}.sig")
    response_signature.chmod(0o600)
    artifact_values = {
        "schema": "1", "kind": "certificate-export", "service": SERVICE,
        "request_id": REQUEST_ID, "operation": "migrate", "target": TARGET,
        "source_kind": "csr-response", "source_response_sha256": digest(response_bytes),
        "source_response_signature_sha256": digest(response_signature),
        "certificate_sha256": digest(leaf), "certificate_spki_sha256": digest(spki),
        "chain_sha256": digest(chain), "fullchain_sha256": digest(fullchain),
        "issuer_root": "g1", "issuer_intermediate": "g1-i1", "serial": "1234",
        "not_before_epoch": response_values["not_before_epoch"],
        "not_after_epoch": response_values["not_after_epoch"],
        "candidate_state": "pending", "deployment_state": "unfinalized",
        "response_principal": RESPONSE_PRINCIPAL, "created_epoch": str(now),
    }
    artifact = record(module.ARTIFACT_FIELDS, artifact_values)
    for name, data in (
        ("artifact", artifact), ("tls.crt", leaf), ("ca-chain.crt", chain),
        ("fullchain.crt", fullchain),
    ):
        private_file(response_source / name, data)

    boundary_values = {
        "schema": "1", "kind": "pki-validation-boundary", "service": SERVICE,
        "target": TARGET, "local_validator": TARGET,
        "remote_validator": REMOTE_VALIDATOR, "endpoint": ENDPOINT,
        "local_check": module.LOCAL_CHECK, "remote_check": module.REMOTE_CHECK,
    }
    boundary = private_file(root / "validation-boundary", record(module.VALIDATION_BOUNDARY_FIELDS, boundary_values))
    reviewed_ca = private_file(root / "reviewed-ca.crt", chain)
    intermediate_sha256 = digest(intermediate)
    local_values = {
        "schema": "1", "service_result": "passed", "tls_result": "passed",
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
        "if [ \"$1\" = is-active ]; then printf 'active\\n'; exit 0; fi\n"
        "printf '%s\\n' \"$1 $2\" >>\"$PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG\"\n",
        0o755,
    )
    zot_config = private_file(
        zot_root / "config.json",
        json.dumps({"http": {"address": "0.0.0.0", "tls": {"cert": str(managed_cert_path), "key": str(managed_key_path)}}}, indent=2) + "\n",
        0o644,
    )
    return LifecycleCase(
        module=module, runner=namespace_root_runner, helper=helper, root=root,
        state=state, pending_root=pending_root, versions_root=versions_root,
        pending=pending, zot_config=zot_config, signing_key=signing_key,
        boundary=boundary, boundary_sha256=digest(boundary),
        reviewed_ca=reviewed_ca, local_observation=local_observation,
        systemctl=systemctl, service_log=service_log,
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


def activate_and_finish(case: LifecycleCase) -> tuple[dict[str, Any], dict[str, Any], Path]:
    case.prepare_response()
    result_json(case.install_response())
    activated = result_json(case.activate())
    observation = case.observation(activated["activation_epoch"] + 1)
    finished = result_json(case.finish(observation))
    return activated, finished, observation


def test_frozen_record_constants_and_parser_are_exact(
    lifecycle_case: LifecycleCase,
) -> None:
    module = lifecycle_case.module
    assert module.DEPLOYMENT_FIELDS == tuple(
        "schema request_id nonce operation service target request_sha256 response_sha256 response_signature_sha256 candidate_sha256 artifact_request_id artifact_manifest_sha256 certificate_sha256 certificate_spki_sha256 chain_sha256 fullchain_sha256 action result local_certificate_sha256 local_key_spki_sha256 local_key_certificate_match served_certificate_sha256 served_intermediate_sha256 validation_boundary_sha256 validation_result activation_epoch validation_epoch rollback_state rollback_hold_until_epoch deployment_principal created_epoch expires_epoch".split()
    )
    assert module.VALIDATION_RESULT_FIELDS == tuple(
        "schema kind service target request_id artifact_manifest_sha256 validation_boundary_sha256 action result local_validator remote_validator endpoint local_service_result local_tls_result remote_tls_result remote_application_result remote_http_status remote_api_version remote_auth_challenge served_certificate_sha256 served_intermediate_sha256 activation_epoch validation_epoch deployment_sha256".split()
    )
    canonical = module.serialize_record(("schema", "kind"), {"schema": "1", "kind": "fixed"}, "fixture")
    assert module.parse_record(canonical, ("schema", "kind"), "fixture") == {"schema": "1", "kind": "fixed"}
    for malformed in (
        b"kind=fixed\nschema=1\n", canonical + b"extra=value\n",
        canonical.rstrip(b"\n"), canonical.replace(b"\n", b"\r\n"),
        canonical + b"\n",
    ):
        with pytest.raises(module.LifecycleError):
            module.parse_record(malformed, ("schema", "kind"), "fixture")


def test_status_precedence_never_claims_complete_or_renewal(
    lifecycle_case: LifecycleCase,
) -> None:
    initial = result_json(lifecycle_case.status())
    assert initial["status"] == "request-pending"
    assert tuple(initial) == tuple(sorted(initial))
    assert set(initial) == {
        "schema", "kind", "status", "service", "target", "active_request_id",
        "active_artifact_sha256", "active_certificate_sha256", "active_spki_sha256",
        "active_not_before_epoch", "active_not_after_epoch", "remaining_lifetime_seconds",
        "pending_request_id", "pending_expires_epoch", "recovery_required",
        "evidence_state", "signer_outcome_state", "renewal_eligible", "required_action",
    }
    lifecycle_case.prepare_response()
    assert result_json(lifecycle_case.status())["status"] == "response-ready"
    result_json(lifecycle_case.install_response())
    activated = result_json(lifecycle_case.activate())
    recovering = result_json(lifecycle_case.status())
    assert recovering["status"] == "activation-recovery-required"
    observation = lifecycle_case.observation(activated["activation_epoch"] + 1)
    finished = result_json(lifecycle_case.finish(observation))
    active = result_json(lifecycle_case.status())
    assert active["status"] == "activated-and-validated"
    assert active["renewal_eligible"] is False
    exported = result_json(lifecycle_case.status(
        "--controller-evidence-exported", "--deployment-sha256", finished["deployment_sha256"]
    ))
    assert exported["status"] == "evidence-exported"
    assert exported["signer_outcome_state"] == "unavailable"


def test_expired_request_abandonment_is_explicit_and_checkable(
    lifecycle_case: LifecycleCase,
) -> None:
    active_key = Path(
        json.loads(lifecycle_case.zot_config.read_text(encoding="ascii"))["http"]["tls"]["key"]
    )
    active_key_before = active_key.read_bytes()
    assert_failure(lifecycle_case.abandon_expired())
    assert lifecycle_case.pending.is_dir()

    lifecycle_case.expire_request()
    assert result_json(lifecycle_case.status())["status"] == "request-expired"
    checked = result_json(lifecycle_case.abandon_expired(check=True))
    assert checked == {"request_id": REQUEST_ID, "status": "would-abandon"}
    assert lifecycle_case.pending.is_dir()

    abandoned = result_json(lifecycle_case.abandon_expired())
    assert abandoned == {"request_id": REQUEST_ID, "status": "abandoned"}
    assert not lifecycle_case.pending.exists()
    assert not any(lifecycle_case.pending_root.iterdir())
    assert active_key.read_bytes() == active_key_before


def test_pending_request_cancellation_requires_exact_id_and_digest(
    lifecycle_case: LifecycleCase,
) -> None:
    active_key = Path(
        json.loads(lifecycle_case.zot_config.read_text(encoding="ascii"))["http"]["tls"]["key"]
    )
    active_key_before = active_key.read_bytes()
    assert_failure(lifecycle_case.cancel_pending(request_sha256="0" * 64))
    assert lifecycle_case.pending.is_dir()

    checked = result_json(lifecycle_case.cancel_pending(check=True))
    assert checked == {"request_id": REQUEST_ID, "status": "would-cancel"}
    assert lifecycle_case.pending.is_dir()

    cancelled = result_json(lifecycle_case.cancel_pending())
    assert cancelled == {"request_id": REQUEST_ID, "status": "cancelled"}
    assert not lifecycle_case.pending.exists()
    assert not any(lifecycle_case.pending_root.iterdir())
    assert active_key.read_bytes() == active_key_before


def test_pending_request_cancellation_refuses_response_state(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()

    assert_failure(lifecycle_case.cancel_pending())
    assert lifecycle_case.pending.is_dir()


def test_pending_request_cancellation_resumes_exact_partial_cleanup(
    lifecycle_case: LifecycleCase,
) -> None:
    request_sha256 = digest(lifecycle_case.pending / "request")
    lifecycle_case.write_pending_cancellation_journal()
    stage = lifecycle_case.pending_root / f".cancel-pending-{REQUEST_ID}"
    lifecycle_case.pending.rename(stage)
    (stage / "tls.key").unlink()

    checked = result_json(
        lifecycle_case.cancel_pending(
            request_sha256=request_sha256,
            check=True,
        )
    )
    assert checked == {
        "request_id": REQUEST_ID,
        "status": "would-complete-cancellation",
    }
    assert result_json(
        lifecycle_case.cancel_pending(request_sha256=request_sha256)
    )["status"] == "cancelled"
    assert not stage.exists()


def test_request_is_expired_at_exact_expiry_epoch(
    lifecycle_case: LifecycleCase,
) -> None:
    expires = 1_800_000_000

    assert lifecycle_case.module.request_is_expired(expires, expires - 1) is False
    assert lifecycle_case.module.request_is_expired(expires, expires) is True
    assert lifecycle_case.module.request_is_expired(expires, expires + 1) is True


def test_expired_request_abandonment_resumes_exact_partial_cleanup(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.expire_request()
    stage = lifecycle_case.pending_root / f".abandon-expired-{REQUEST_ID}"
    lifecycle_case.pending.rename(stage)
    assert_failure(lifecycle_case.abandon_expired())
    lifecycle_case.write_expired_abandonment_journal(stage)
    (stage / "tls.key").unlink()

    checked = result_json(lifecycle_case.abandon_expired(check=True))
    assert checked == {
        "request_id": REQUEST_ID,
        "status": "would-complete-abandonment",
    }
    assert stage.is_dir()
    assert result_json(lifecycle_case.abandon_expired())["status"] == "abandoned"
    assert not stage.exists()


def test_expired_request_abandonment_recovers_partial_journal_stage(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.expire_request()
    private_file(
        lifecycle_case.state / "expired-request-abandonment-journal.stage",
        b"partial\n",
    )

    assert result_json(lifecycle_case.abandon_expired())["status"] == "abandoned"
    assert not lifecycle_case.pending.exists()
    assert not (
        lifecycle_case.state / "expired-request-abandonment-journal.stage"
    ).exists()
    assert not (
        lifecycle_case.state / "expired-request-abandonment-journal"
    ).exists()


def test_expired_request_abandonment_refuses_response_state(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.expire_request()
    lifecycle_case.prepare_response()

    assert_failure(lifecycle_case.abandon_expired())
    assert lifecycle_case.pending.is_dir()


def test_response_preparation_cannot_interrupt_abandonment_recovery(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.expire_request()
    lifecycle_case.write_expired_abandonment_journal()

    assert_failure(
        lifecycle_case.run(
            [
                *lifecycle_case.common("response-prepare"),
                "--request-id",
                REQUEST_ID,
            ]
        )
    )
    assert not (lifecycle_case.versions_root / f".ingress-{REQUEST_ID}").exists()
    assert result_json(lifecycle_case.abandon_expired())["status"] == "abandoned"


def test_expired_request_cannot_be_collected_or_consume_response(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.expire_request()
    output = private_dir(lifecycle_case.root / "expired-collection")
    collection = [
        *lifecycle_case.common("collection-prepare"),
        "--trust-id",
        "reviewed-v1",
        "--request-id",
        REQUEST_ID,
        "--output-dir",
        output,
        "--output-owner-uid",
        "0",
    ]

    assert_failure(lifecycle_case.run(collection))
    assert not any(output.iterdir())
    lifecycle_case.prepare_response()
    assert_failure(lifecycle_case.install_response())
    assert lifecycle_case.pending.is_dir()


def test_collection_exports_only_public_files_and_rechecks_key_locally(
    lifecycle_case: LifecycleCase,
) -> None:
    output = private_dir(lifecycle_case.root / "collection")
    output_owner_uid = 1234 if os.geteuid() == 0 else 0
    if output_owner_uid:
        os.chown(output, output_owner_uid, output_owner_uid)
    expected_owner_uid = output.stat().st_uid
    before_key = lifecycle_case.pending.joinpath("tls.key").read_bytes()
    argv = [
        *lifecycle_case.common("collection-prepare"),
        "--trust-id", "reviewed-v1", "--request-id", REQUEST_ID,
        "--output-dir", output, "--output-owner-uid", str(output_owner_uid),
    ]
    result = lifecycle_case.run(argv)
    parsed = result_json(result)
    assert parsed["status"] == "collected"
    assert {path.name for path in output.iterdir()} == {"tls.csr", "request", "request.sig"}
    assert lifecycle_case.pending.joinpath("tls.key").read_bytes() == before_key
    metadata = {
        path.name: (stat.S_IMODE(path.stat().st_mode), path.stat().st_uid)
        for path in output.iterdir()
    }
    assert metadata == {
        name: (0o600, expected_owner_uid)
        for name in ("tls.csr", "request", "request.sig")
    }
    combined = result.stdout.encode() + result.stderr.encode() + b"".join(path.read_bytes() for path in output.iterdir())
    assert b"PRIVATE KEY" not in combined
    assert lifecycle_case.private_key_bytes not in combined
    assert result_json(lifecycle_case.run(argv))["status"] == "existing"


@pytest.mark.parametrize("conflict", ("partial", "changed"))
def test_collection_rejects_partial_or_conflicting_existing_output(
    lifecycle_case: LifecycleCase,
    conflict: str,
) -> None:
    output = private_dir(lifecycle_case.root / "collection-conflict")
    argv = [
        *lifecycle_case.common("collection-prepare"),
        "--trust-id", "reviewed-v1", "--request-id", REQUEST_ID,
        "--output-dir", output, "--output-owner-uid", "0",
    ]
    if conflict == "partial":
        private_file(output / "request", lifecycle_case.pending.joinpath("request").read_bytes())
    else:
        result_json(lifecycle_case.run(argv))
        private_file(output / "request", b"conflicting\n")
    before = tree_snapshot(output)
    assert_failure(lifecycle_case.run(argv))
    assert tree_snapshot(output) == before


def test_response_install_publishes_exact_version_and_requires_local_key_match(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    original_key = lifecycle_case.pending.joinpath("tls.key").read_bytes()
    other_key = ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    lifecycle_case.pending.joinpath("tls.key").write_bytes(other_key)
    lifecycle_case.pending.joinpath("tls.key").chmod(0o600)
    assert_failure(lifecycle_case.install_response())
    lifecycle_case.pending.joinpath("tls.key").write_bytes(original_key)
    lifecycle_case.pending.joinpath("tls.key").chmod(0o600)
    installed = result_json(lifecycle_case.install_response())
    assert installed["status"] == "installed"
    version = lifecycle_case.versions_root / REQUEST_ID
    assert {path.name for path in version.iterdir()} == set(lifecycle_case.module.VERSION_NAMES)
    for path in version.iterdir():
        expected = 0o644 if path.name in lifecycle_case.module.CERTIFICATE_NAMES else 0o600
        assert stat.S_IMODE(path.stat().st_mode) == expected
        assert path.stat().st_nlink == 1
    assert (version / "tls.key").read_bytes() == lifecycle_case.pending.joinpath("tls.key").read_bytes()
    assert not (lifecycle_case.versions_root / f".ingress-{REQUEST_ID}").exists()


def test_response_and_activation_check_modes_are_read_only(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    before = tree_snapshot(lifecycle_case.root)
    assert result_json(lifecycle_case.install_response(check=True))["status"] == "would-install"
    assert tree_snapshot(lifecycle_case.root) == before
    result_json(lifecycle_case.install_response())
    before = tree_snapshot(lifecycle_case.root)
    assert result_json(lifecycle_case.activate(check=True))["status"] == "would-activate"
    assert tree_snapshot(lifecycle_case.root) == before


def test_migration_activation_binds_leaf_from_managed_predecessor_fullchain(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    config = json.loads(lifecycle_case.zot_config.read_text(encoding="ascii"))
    predecessor = Path(config["http"]["tls"]["cert"])
    leaf = predecessor.read_bytes()
    with predecessor.open("ab") as stream:
        stream.write(leaf)

    assert result_json(lifecycle_case.activate(check=True))["status"] == "would-activate"


def test_activation_journal_is_durable_before_config_mutation(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    original_config = lifecycle_case.zot_config.read_bytes()
    assert_failure(lifecycle_case.activate(environment={
        "PLATFORM_PKI_LIFECYCLE_FAIL_AT": "after-activation-journal"
    }))
    assert lifecycle_case.zot_config.read_bytes() == original_config
    journal = lifecycle_case.state / "activation-journal"
    values = lifecycle_case.module.parse_record(
        journal.read_bytes(), lifecycle_case.module.ACTIVATION_JOURNAL_FIELDS,
        "activation journal",
    )
    assert values["checkpoint"] == "prepared"
    assert values["prior_zot_config_sha256"] == digest(original_config)
    assert not (lifecycle_case.state / "active").exists()


def test_local_validation_waits_for_listener_readiness(
    lifecycle_case: LifecycleCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    closed = False

    class Connection:
        def close(self) -> None:
            nonlocal closed
            closed = True

    def connect(address: tuple[str, int], *, timeout: float) -> Connection:
        nonlocal attempts
        assert address == ("registry.test", 443)
        assert timeout > 0
        attempts += 1
        if attempts == 1:
            raise ConnectionRefusedError
        return Connection()

    monkeypatch.setattr(lifecycle_case.module.socket, "create_connection", connect)
    lifecycle_case.module.wait_for_tls_listener(
        "registry.test", 443, timeout_seconds=1, interval_seconds=0
    )

    assert attempts == 2
    assert closed


def test_successful_activation_and_exact_failure_rollback(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    original_config = lifecycle_case.zot_config.read_bytes()
    activated = result_json(lifecycle_case.activate())
    assert activated["status"] == "local-validated"
    assert lifecycle_case.state.joinpath("activation-journal").is_file()
    config = json.loads(lifecycle_case.zot_config.read_text(encoding="ascii"))
    assert config["http"]["tls"] == {
        "cert": str(lifecycle_case.versions_root / REQUEST_ID / "fullchain.crt"),
        "key": str(lifecycle_case.versions_root / REQUEST_ID / "tls.key"),
    }
    assert lifecycle_case.service_log.read_text(encoding="ascii").splitlines() == ["restart zot.service"]

    assert_failure(lifecycle_case.recover(check=True))
    assert result_json(lifecycle_case.recover())["status"] == "restored"
    assert lifecycle_case.zot_config.read_bytes() == original_config
    assert not lifecycle_case.state.joinpath("active").exists()
    assert not lifecycle_case.state.joinpath("rollback").exists()
    journal = lifecycle_case.module.journal_record(
        lifecycle_case.state.joinpath("activation-journal").read_bytes(),
        type("Args", (), {
            "service": SERVICE, "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    assert journal["checkpoint"] == "rolled-back"


def test_local_validation_failure_restores_exact_predecessor(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    original_config = lifecycle_case.zot_config.read_bytes()
    lifecycle_case.local_observation.write_text(
        "schema=1\nservice_result=passed\ntls_result=failed\n"
        f"served_certificate_sha256={lifecycle_case.certificate_sha256}\n"
        f"served_intermediate_sha256={lifecycle_case.intermediate_sha256}\n",
        encoding="ascii",
    )
    lifecycle_case.local_observation.chmod(0o600)
    assert_failure(lifecycle_case.activate())
    assert lifecycle_case.zot_config.read_bytes() == original_config
    assert not lifecycle_case.state.joinpath("active").exists()
    assert not lifecycle_case.state.joinpath("rollback").exists()
    journal = lifecycle_case.module.journal_record(
        lifecycle_case.state.joinpath("activation-journal").read_bytes(),
        type("Args", (), {
            "service": SERVICE, "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    assert journal["checkpoint"] == "rolled-back"


@pytest.mark.parametrize(
    "checkpoint",
    ("after-active-records", "after-config", "after-restart", "after-local-validation"),
)
def test_interruption_checkpoints_recover_only_the_encoded_predecessor(
    lifecycle_case: LifecycleCase,
    checkpoint: str,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    original_config = lifecycle_case.zot_config.read_bytes()
    assert_failure(lifecycle_case.activate(environment={
        "PLATFORM_PKI_LIFECYCLE_CRASH_AT": checkpoint
    }))
    assert lifecycle_case.state.joinpath("activation-journal").is_file()
    assert result_json(lifecycle_case.status())["status"] == "activation-recovery-required"
    assert result_json(lifecycle_case.recover())["status"] == "restored"
    assert lifecycle_case.zot_config.read_bytes() == original_config
    assert not lifecycle_case.state.joinpath("active").exists()
    assert not lifecycle_case.state.joinpath("rollback").exists()


def test_recovery_rejects_replacement_race_and_preserves_foreign_config(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    assert_failure(lifecycle_case.activate(environment={
        "PLATFORM_PKI_LIFECYCLE_CRASH_AT": "after-config"
    }))
    foreign = b'{"http":{"tls":{"cert":"/foreign/cert","key":"/foreign/key"}}}\n'
    lifecycle_case.zot_config.write_bytes(foreign)
    lifecycle_case.zot_config.chmod(0o644)
    assert_failure(lifecycle_case.recover())
    assert lifecycle_case.zot_config.read_bytes() == foreign
    assert lifecycle_case.state.joinpath("activation-journal").is_file()


@pytest.mark.parametrize(
    "checkpoint,expected_status",
    (
        ("before-evidence-publication", "restored"),
        ("after-evidence-publication", "evidence-completed"),
    ),
)
def test_initial_evidence_recovery_respects_publication_boundary(
    lifecycle_case: LifecycleCase,
    checkpoint: str,
    expected_status: str,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    original_config = lifecycle_case.zot_config.read_bytes()
    activated = result_json(lifecycle_case.activate())
    observation = lifecycle_case.observation(activated["activation_epoch"] + 1)
    assert_failure(lifecycle_case.finish(
        observation,
        environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": checkpoint},
    ))
    journal = lifecycle_case.module.journal_record(
        lifecycle_case.state.joinpath("activation-journal").read_bytes(),
        type("Args", (), {
            "service": SERVICE, "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    assert journal["checkpoint"] == "evidence-ready"
    assert result_json(lifecycle_case.recover())["status"] == expected_status
    if expected_status == "restored":
        assert lifecycle_case.zot_config.read_bytes() == original_config
        assert not lifecycle_case.state.joinpath("active").exists()
    else:
        assert lifecycle_case.zot_config.read_bytes() != original_config
        assert lifecycle_case.state.joinpath("active").is_file()
        assert result_json(lifecycle_case.status())["evidence_state"] == "target-published"
    if expected_status == "restored":
        retained = lifecycle_case.module.journal_record(
            lifecycle_case.state.joinpath("activation-journal").read_bytes(),
            type("Args", (), {
                "service": SERVICE, "target": TARGET,
                "versions_root": str(lifecycle_case.versions_root),
            })(),
        )
        assert retained["checkpoint"] == "rolled-back"
    else:
        assert not lifecycle_case.state.joinpath("activation-journal").exists()


def test_active_paths_authenticates_record_version_and_config(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, _finished, _observation = activate_and_finish(lifecycle_case)
    paths = result_json(lifecycle_case.run(lifecycle_case.common("active-paths", config=True)))
    assert paths == {
        "request_id": REQUEST_ID,
        "cert_path": str(lifecycle_case.versions_root / REQUEST_ID / "fullchain.crt"),
        "key_path": str(lifecycle_case.versions_root / REQUEST_ID / "tls.key"),
        "artifact_sha256": lifecycle_case.artifact_sha256,
        "certificate_sha256": lifecycle_case.certificate_sha256,
        "spki_sha256": lifecycle_case.certificate_spki_sha256,
        "chain_sha256": digest(lifecycle_case.versions_root / REQUEST_ID / "ca-chain.crt"),
        "fullchain_sha256": digest(lifecycle_case.versions_root / REQUEST_ID / "fullchain.crt"),
        "zot_config_sha256": digest(lifecycle_case.zot_config),
    }
    config = json.loads(lifecycle_case.zot_config.read_text(encoding="ascii"))
    config["http"]["tls"]["cert"] = "/foreign/cert"
    lifecycle_case.zot_config.write_text(json.dumps(config) + "\n", encoding="ascii")
    lifecycle_case.zot_config.chmod(0o644)
    assert_failure(lifecycle_case.run(lifecycle_case.common("active-paths", config=True)))


def test_evidence_is_canonical_signed_idempotent_and_no_clobber(
    lifecycle_case: LifecycleCase,
) -> None:
    activated, finished, observation = activate_and_finish(lifecycle_case)
    evidence = Path(finished["evidence_path"])
    assert {path.name for path in evidence.iterdir()} == set(lifecycle_case.module.EVIDENCE_NAMES)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in evidence.iterdir())
    deployment = evidence.joinpath("deployment").read_bytes()
    deployment_record = lifecycle_case.module.parse_record(
        deployment, lifecycle_case.module.DEPLOYMENT_FIELDS, "deployment"
    )
    result_record = lifecycle_case.module.parse_record(
        evidence.joinpath("validation-result").read_bytes(),
        lifecycle_case.module.VALIDATION_RESULT_FIELDS, "validation result",
    )
    assert digest(deployment) == finished["deployment_sha256"]
    assert result_record["deployment_sha256"] == finished["deployment_sha256"]
    assert deployment_record["created_epoch"] == str(activated["activation_epoch"])
    assert deployment_record["rollback_hold_until_epoch"] == str(activated["rollback_deadline_epoch"])
    for name in ("deployment", "validation-result"):
        verification = subprocess.run(
            lifecycle_case.runner.argv([
                "ssh-keygen", "-Y", "verify",
                "-f", lifecycle_case.state / "trust/reviewed-v1/deployers.allowed_signers",
                "-I", TARGET, "-n", lifecycle_case.module.DEPLOYMENT_NAMESPACE,
                "-s", evidence / f"{name}.sig",
            ]),
            input=evidence.joinpath(name).read_bytes(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=lifecycle_case.runner.environment(),
            cwd=lifecycle_case.runner.command_runner.cwd,
        )
        assert verification.returncode == 0, verification.stderr.decode(errors="replace")
    rerun = result_json(lifecycle_case.finish(observation))
    assert rerun["status"] == "evidence-existing"
    assert rerun["deployment_sha256"] == finished["deployment_sha256"]

    deployment_path = evidence / "deployment"
    deployment_path.write_bytes(b"foreign\n")
    deployment_path.chmod(0o600)
    assert_failure(lifecycle_case.finish(observation))
    assert deployment_path.read_bytes() == b"foreign\n"


def test_evidence_collection_is_exact_idempotent_public_only_and_check_safe(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    output = private_dir(lifecycle_case.root / "evidence-collection")
    before = tree_snapshot(lifecycle_case.root)
    checked = result_json(lifecycle_case.collect_evidence(
        finished["deployment_sha256"], output, check=True,
    ))
    assert checked["status"] == "would-collect"
    assert tree_snapshot(lifecycle_case.root) == before

    collected = result_json(lifecycle_case.collect_evidence(
        finished["deployment_sha256"], output,
    ))
    assert collected["status"] == "collected"
    assert collected["action"] == "finalize"
    assert collected["result"] == "activated"
    assert set(path.name for path in output.iterdir()) == set(
        lifecycle_case.module.EVIDENCE_NAMES
    )
    assert "tls.key" not in {path.name for path in output.iterdir()}
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    for name in lifecycle_case.module.EVIDENCE_NAMES:
        key = f"{name.replace('-', '_').replace('.', '_')}_sha256"
        assert collected[key] == digest(output / name)
    existing = result_json(lifecycle_case.collect_evidence(
        finished["deployment_sha256"], output,
    ))
    assert existing["status"] == "existing"
    assert existing["deployment_sha256"] == finished["deployment_sha256"]


def test_evidence_collection_rejects_wrong_exact_coordinate(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, _finished, _observation = activate_and_finish(lifecycle_case)
    output = private_dir(lifecycle_case.root / "wrong-evidence-coordinate")
    before = tree_snapshot(output)
    assert_failure(lifecycle_case.collect_evidence("f" * 64, output))
    assert tree_snapshot(output) == before


@pytest.mark.parametrize("complete", (False, True))
def test_evidence_collection_allows_only_exact_terminal_published_journal(
    lifecycle_case: LifecycleCase,
    complete: bool,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    activated = result_json(lifecycle_case.activate())
    observation = lifecycle_case.observation(activated["activation_epoch"] + 1)
    assert_failure(lifecycle_case.finish(
        observation,
        environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": "after-evidence-publication"},
    ))
    journal_path = lifecycle_case.state / "activation-journal"
    journal = lifecycle_case.module.journal_record(
        journal_path.read_bytes(),
        type("Args", (), {
            "service": SERVICE, "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    deployment_sha256 = journal["deployment_sha256"]
    if not complete:
        journal["checkpoint"] = "local-validated"
        for name in (
            "deployment_sha256", "deployment_signature_sha256",
            "validation_boundary_sha256", "validation_result_sha256",
            "validation_result_signature_sha256", "evidence_action",
            "evidence_result", "evidence_created_epoch",
        ):
            journal[name] = "none"
        private_file(
            journal_path,
            record(lifecycle_case.module.ACTIVATION_JOURNAL_FIELDS, journal),
        )
    output = private_dir(lifecycle_case.root / f"journal-evidence-{complete}")
    collected = lifecycle_case.collect_evidence(deployment_sha256, output)
    if complete:
        assert result_json(collected)["status"] == "collected"
    else:
        assert_failure(collected)
        assert tuple(output.iterdir()) == ()


@pytest.mark.parametrize("alteration", ("signature", "cross-binding"))
def test_evidence_collection_rejects_signature_or_cross_binding_substitution(
    lifecycle_case: LifecycleCase,
    alteration: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    evidence = Path(finished["evidence_path"])
    if alteration == "signature":
        private_file(evidence / "deployment.sig", b"invalid-signature\n")
    else:
        result_path = evidence / "validation-result"
        values = lifecycle_case.module.parse_record(
            result_path.read_bytes(), lifecycle_case.module.VALIDATION_RESULT_FIELDS,
            "validation result",
        )
        values["served_certificate_sha256"] = "e" * 64
        private_file(
            result_path,
            record(lifecycle_case.module.VALIDATION_RESULT_FIELDS, values),
        )
        signature = evidence / "validation-result.sig"
        signature.unlink()
        lifecycle_case.runner.run([
            "ssh-keygen", "-Y", "sign", "-f", lifecycle_case.signing_key,
            "-n", lifecycle_case.module.DEPLOYMENT_NAMESPACE, result_path,
        ]).assert_success()
        signature.chmod(0o600)
    output = private_dir(lifecycle_case.root / f"altered-evidence-{alteration}")
    assert_failure(lifecycle_case.collect_evidence(
        finished["deployment_sha256"], output,
    ))
    assert tuple(output.iterdir()) == ()


@pytest.mark.parametrize("shape", ("partial", "extra"))
def test_evidence_collection_rejects_partial_or_extra_output(
    lifecycle_case: LifecycleCase,
    shape: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    output = private_dir(lifecycle_case.root / f"evidence-output-{shape}")
    evidence = Path(finished["evidence_path"])
    if shape == "partial":
        private_file(output / "deployment", evidence.joinpath("deployment").read_bytes())
    else:
        result_json(lifecycle_case.collect_evidence(
            finished["deployment_sha256"], output,
        ))
        private_file(output / "unexpected", b"foreign\n")
    before = tree_snapshot(output)
    assert_failure(lifecycle_case.collect_evidence(
        finished["deployment_sha256"], output,
    ))
    assert tree_snapshot(output) == before


def test_not_activated_abandonment_uses_only_canonical_none_and_not_run_fields(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    abandoned = result_json(lifecycle_case.finish(
        None, action="abandon", result="not-activated",
    ))
    evidence = Path(abandoned["evidence_path"])
    deployment = lifecycle_case.module.parse_record(
        evidence.joinpath("deployment").read_bytes(),
        lifecycle_case.module.DEPLOYMENT_FIELDS, "deployment",
    )
    validation = lifecycle_case.module.parse_record(
        evidence.joinpath("validation-result").read_bytes(),
        lifecycle_case.module.VALIDATION_RESULT_FIELDS, "validation result",
    )
    assert deployment["action"] == validation["action"] == "abandon"
    assert deployment["result"] == validation["result"] == "not-activated"
    assert deployment["request_id"] == REQUEST_ID
    assert deployment["artifact_manifest_sha256"] == lifecycle_case.artifact_sha256
    assert deployment["served_certificate_sha256"] == "none"
    assert deployment["served_intermediate_sha256"] == "none"
    assert deployment["activation_epoch"] == "none"
    assert deployment["validation_epoch"] == "none"
    assert deployment["validation_result"] == "not-run"
    assert deployment["rollback_state"] == "none"
    assert deployment["rollback_hold_until_epoch"] == "none"
    assert {
        validation[name]
        for name in (
            "local_service_result", "local_tls_result", "remote_tls_result",
            "remote_application_result", "remote_http_status",
            "remote_api_version", "remote_auth_challenge",
        )
    } == {"not-run"}
    assert validation["served_certificate_sha256"] == "none"
    assert validation["served_intermediate_sha256"] == "none"
    assert validation["activation_epoch"] == "none"
    assert validation["validation_epoch"] == "none"
    assert not lifecycle_case.state.joinpath("active").exists()
    output = private_dir(lifecycle_case.root / "not-activated-evidence-collection")
    collected = result_json(lifecycle_case.collect_evidence(
        abandoned["deployment_sha256"], output,
    ))
    assert (collected["action"], collected["result"]) == (
        "abandon", "not-activated",
    )


@pytest.mark.parametrize(
    "checkpoint,expected_status",
    (
        ("before-evidence-publication", "restored"),
        ("after-abandonment-publication", "evidence-completed"),
    ),
)
def test_not_activated_abandonment_publication_recovers_exactly(
    lifecycle_case: LifecycleCase,
    checkpoint: str,
    expected_status: str,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    assert_failure(lifecycle_case.finish(
        None,
        action="abandon",
        result="not-activated",
        environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": checkpoint},
    ))
    assert lifecycle_case.state.joinpath("abandonment-journal").is_file()
    recovered = result_json(lifecycle_case.recover())
    assert recovered["status"] == expected_status
    assert not lifecycle_case.state.joinpath("abandonment-journal").exists()
    request_evidence = lifecycle_case.state / "evidence" / REQUEST_ID
    attempts = tuple(request_evidence.iterdir())
    if expected_status == "restored":
        assert attempts == ()
    else:
        assert len(attempts) == 1
        assert {path.name for path in attempts[0].iterdir()} == set(
            lifecycle_case.module.EVIDENCE_NAMES
        )


def test_rolled_back_abandonment_binds_restored_predecessor_and_retained_hold(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    activated = result_json(lifecycle_case.activate())
    assert result_json(lifecycle_case.recover())["status"] == "restored"
    journal = lifecycle_case.module.journal_record(
        lifecycle_case.state.joinpath("activation-journal").read_bytes(),
        type("Args", (), {
            "service": SERVICE, "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    rollback = lifecycle_case.module.parse_rollback(
        lifecycle_case.module.decode_bound_bytes(
            journal["new_rollback_b64"], journal["new_rollback_sha256"],
            "rollback",
        ),
        type("Args", (), {"service": SERVICE, "target": TARGET})(),
    )
    predecessor_certificate = rollback["predecessor_certificate_sha256"]
    predecessor_intermediate = lifecycle_case.intermediate_sha256
    lifecycle_case.local_observation.write_bytes(record(
        ("schema", "service_result", "tls_result", "served_certificate_sha256", "served_intermediate_sha256"),
        {
            "schema": "1", "service_result": "passed", "tls_result": "passed",
            "served_certificate_sha256": predecessor_certificate,
            "served_intermediate_sha256": predecessor_intermediate,
        },
    ))
    lifecycle_case.local_observation.chmod(0o600)
    prepared_snapshot = tree_snapshot(lifecycle_case.root)
    prepared = result_json(lifecycle_case.prepare_rolled_back_abandonment())
    assert prepared == {
        "status": "rolled-back-abandonment-local-validated",
        "action": "abandon",
        "result": "rolled-back",
        "request_id": REQUEST_ID,
        "artifact_sha256": lifecycle_case.artifact_sha256,
        "served_certificate_sha256": predecessor_certificate,
        "served_intermediate_sha256": predecessor_intermediate,
        "activation_epoch": activated["activation_epoch"],
        "rollback_deadline_epoch": activated["rollback_deadline_epoch"],
    }
    assert tree_snapshot(lifecycle_case.root) == prepared_snapshot
    assert lifecycle_case.state.joinpath("activation-journal").is_file()
    evidence_epoch = activated["activation_epoch"] + 10
    observation = lifecycle_case.observation(
        evidence_epoch + 1,
        served_certificate_sha256=predecessor_certificate,
        served_intermediate_sha256=predecessor_intermediate,
    )
    abandoned = result_json(lifecycle_case.finish(
        observation,
        action="abandon",
        result="rolled-back",
        served_intermediate_sha256=predecessor_intermediate,
        environment={"PLATFORM_PKI_LIFECYCLE_TEST_EPOCH": str(evidence_epoch)},
    ))
    evidence = Path(abandoned["evidence_path"])
    deployment = lifecycle_case.module.parse_record(
        evidence.joinpath("deployment").read_bytes(),
        lifecycle_case.module.DEPLOYMENT_FIELDS, "deployment",
    )
    validation = lifecycle_case.module.parse_record(
        evidence.joinpath("validation-result").read_bytes(),
        lifecycle_case.module.VALIDATION_RESULT_FIELDS, "validation result",
    )
    assert deployment["action"] == validation["action"] == "abandon"
    assert deployment["result"] == validation["result"] == "rolled-back"
    assert deployment["served_certificate_sha256"] == predecessor_certificate
    assert deployment["served_intermediate_sha256"] == predecessor_intermediate
    assert deployment["activation_epoch"] == str(activated["activation_epoch"])
    assert deployment["validation_epoch"] == str(evidence_epoch + 1)
    assert deployment["validation_result"] == "passed"
    assert deployment["rollback_state"] == "restored"
    assert int(deployment["rollback_hold_until_epoch"]) >= evidence_epoch + 1209600
    assert {
        validation[name]
        for name in (
            "local_service_result", "local_tls_result", "remote_tls_result",
            "remote_application_result",
        )
    } == {"passed"}
    assert validation["deployment_sha256"] == abandoned["deployment_sha256"]
    assert not lifecycle_case.state.joinpath("activation-journal").exists()
    assert not lifecycle_case.state.joinpath("active").exists()
    output = private_dir(lifecycle_case.root / "rolled-back-evidence-collection")
    collected = result_json(lifecycle_case.collect_evidence(
        abandoned["deployment_sha256"], output,
    ))
    assert (collected["action"], collected["result"]) == (
        "abandon", "rolled-back",
    )


@pytest.mark.parametrize(
    "conflict",
    (
        ("--action", "finalize"),
        ("--result", "not-activated"),
        ("--observation-file", "/tmp/unexpected-observation"),
        ("--served-intermediate-sha256", "d" * 64),
        ("--fresh-evidence",),
        ("--check",),
    ),
)
def test_rolled_back_abandonment_preparation_rejects_conflicting_arguments(
    lifecycle_case: LifecycleCase,
    conflict: tuple[str, ...],
) -> None:
    assert_failure(
        lifecycle_case.prepare_rolled_back_abandonment(*conflict)
    )


def test_rolled_back_abandonment_preparation_failure_preserves_journal(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    result_json(lifecycle_case.activate())
    assert result_json(lifecycle_case.recover())["status"] == "restored"
    journal = lifecycle_case.state.joinpath("activation-journal")
    journal_before = journal.read_bytes()

    # The fixture still describes the failed candidate, not the predecessor.
    assert_failure(lifecycle_case.prepare_rolled_back_abandonment())

    assert journal.read_bytes() == journal_before
    assert not lifecycle_case.state.joinpath("evidence").exists()


def test_retry_after_rolled_back_evidence_ignores_authenticated_history(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    first_activation = result_json(lifecycle_case.activate())
    assert result_json(lifecycle_case.recover())["status"] == "restored"
    journal = lifecycle_case.module.journal_record(
        lifecycle_case.state.joinpath("activation-journal").read_bytes(),
        type("Args", (), {
            "service": SERVICE,
            "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    rollback = lifecycle_case.module.parse_rollback(
        lifecycle_case.module.decode_bound_bytes(
            journal["new_rollback_b64"],
            journal["new_rollback_sha256"],
            "rollback",
        ),
        type("Args", (), {"service": SERVICE, "target": TARGET})(),
    )
    predecessor_certificate = rollback["predecessor_certificate_sha256"]
    private_file(
        lifecycle_case.local_observation,
        record(
            (
                "schema",
                "service_result",
                "tls_result",
                "served_certificate_sha256",
                "served_intermediate_sha256",
            ),
            {
                "schema": "1",
                "service_result": "passed",
                "tls_result": "passed",
                "served_certificate_sha256": predecessor_certificate,
                "served_intermediate_sha256": lifecycle_case.intermediate_sha256,
            },
        ),
    )
    rollback_observation = lifecycle_case.observation(
        first_activation["activation_epoch"] + 1,
        served_certificate_sha256=predecessor_certificate,
    )
    rolled_back = result_json(lifecycle_case.finish(
        rollback_observation,
        action="abandon",
        result="rolled-back",
    ))

    private_file(
        lifecycle_case.local_observation,
        record(
            (
                "schema",
                "service_result",
                "tls_result",
                "served_certificate_sha256",
                "served_intermediate_sha256",
            ),
            {
                "schema": "1",
                "service_result": "passed",
                "tls_result": "passed",
                "served_certificate_sha256": lifecycle_case.certificate_sha256,
                "served_intermediate_sha256": lifecycle_case.intermediate_sha256,
            },
        ),
    )
    second_activation = result_json(lifecycle_case.activate())
    activated_observation = lifecycle_case.observation(
        second_activation["activation_epoch"] + 1
    )
    activated = result_json(lifecycle_case.finish(activated_observation))

    status = result_json(lifecycle_case.status(
        "--controller-evidence-exported",
        "--deployment-sha256",
        activated["deployment_sha256"],
    ))
    assert status["status"] == "evidence-exported"
    assert status["evidence_state"] == "controller-exported"

    historical = Path(rolled_back["evidence_path"])
    result_path = historical / "validation-result"
    result = lifecycle_case.module.parse_record(
        result_path.read_bytes(),
        lifecycle_case.module.VALIDATION_RESULT_FIELDS,
        "historical validation result",
    )
    result["kind"] = "malformed-history"
    private_file(
        result_path,
        record(lifecycle_case.module.VALIDATION_RESULT_FIELDS, result),
    )
    signature = historical / "validation-result.sig"
    signature.unlink()
    lifecycle_case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", lifecycle_case.signing_key,
        "-n", lifecycle_case.module.DEPLOYMENT_NAMESPACE, result_path,
    ]).assert_success()
    signature.chmod(0o600)
    assert_failure(lifecycle_case.status(
        "--controller-evidence-exported",
        "--deployment-sha256",
        activated["deployment_sha256"],
    ))


def test_fresh_evidence_extends_hold_revalidates_and_retains_attempts(
    lifecycle_case: LifecycleCase,
) -> None:
    activated, first, _observation = activate_and_finish(lifecycle_case)
    active_before = lifecycle_case.state.joinpath("active").read_bytes()
    rollback_before = lifecycle_case.state.joinpath("rollback").read_bytes()
    fresh_epoch = activated["activation_epoch"] + 301
    environment = {"PLATFORM_PKI_LIFECYCLE_TEST_EPOCH": str(fresh_epoch)}

    snapshot = tree_snapshot(lifecycle_case.root)
    checked = result_json(lifecycle_case.finish(
        None, fresh=True, check=True, environment=environment,
    ))
    assert checked["status"] == "would-prepare-fresh-evidence"
    assert tree_snapshot(lifecycle_case.root) == snapshot

    prepared = result_json(lifecycle_case.finish(
        None, fresh=True, environment=environment,
    ))
    assert prepared["status"] == "fresh-evidence-local-validated"
    journal = lifecycle_case.module.evidence_journal_record(
        lifecycle_case.state.joinpath("evidence-attempt-journal").read_bytes(),
        type("Args", (), {
            "service": SERVICE, "target": TARGET,
            "versions_root": str(lifecycle_case.versions_root),
        })(),
    )
    assert journal["checkpoint"] == "local-validated"
    assert lifecycle_case.state.joinpath("active").read_bytes() != active_before
    assert lifecycle_case.state.joinpath("rollback").read_bytes() != rollback_before

    fresh_observation = lifecycle_case.observation(fresh_epoch + 1)
    second = result_json(lifecycle_case.finish(
        fresh_observation, environment=environment,
    ))
    assert second["status"] == "evidence-published"
    assert second["deployment_sha256"] != first["deployment_sha256"]
    attempts = lifecycle_case.state / "evidence" / REQUEST_ID
    assert set(path.name for path in attempts.iterdir()) == {
        first["deployment_sha256"], second["deployment_sha256"],
    }
    assert not lifecycle_case.state.joinpath("evidence-attempt-journal").exists()
    assert result_json(lifecycle_case.status())["evidence_state"] == "target-published"


@pytest.mark.parametrize(
    "checkpoint,expected_status",
    (
        ("after-evidence-attempt-records", "restored"),
        ("after-evidence-publication", "evidence-completed"),
    ),
)
def test_fresh_evidence_recovery_respects_publication_boundary(
    lifecycle_case: LifecycleCase,
    checkpoint: str,
    expected_status: str,
) -> None:
    activated, first, _observation = activate_and_finish(lifecycle_case)
    active_before = lifecycle_case.state.joinpath("active").read_bytes()
    rollback_before = lifecycle_case.state.joinpath("rollback").read_bytes()
    fresh_epoch = activated["activation_epoch"] + 301
    environment = {"PLATFORM_PKI_LIFECYCLE_TEST_EPOCH": str(fresh_epoch)}

    if checkpoint == "after-evidence-attempt-records":
        crashed = lifecycle_case.finish(
            None, fresh=True,
            environment={**environment, "PLATFORM_PKI_LIFECYCLE_CRASH_AT": checkpoint},
        )
    else:
        result_json(lifecycle_case.finish(None, fresh=True, environment=environment))
        fresh_observation = lifecycle_case.observation(fresh_epoch + 1)
        crashed = lifecycle_case.finish(
            fresh_observation,
            environment={**environment, "PLATFORM_PKI_LIFECYCLE_CRASH_AT": checkpoint},
        )
    assert_failure(crashed)
    assert lifecycle_case.state.joinpath("evidence-attempt-journal").is_file()
    recovered = result_json(lifecycle_case.recover())
    assert recovered["status"] == expected_status
    assert not lifecycle_case.state.joinpath("evidence-attempt-journal").exists()
    attempts = lifecycle_case.state / "evidence" / REQUEST_ID
    if expected_status == "restored":
        assert lifecycle_case.state.joinpath("active").read_bytes() == active_before
        assert lifecycle_case.state.joinpath("rollback").read_bytes() == rollback_before
        assert set(path.name for path in attempts.iterdir()) == {first["deployment_sha256"]}
    else:
        assert lifecycle_case.state.joinpath("active").read_bytes() != active_before
        assert lifecycle_case.state.joinpath("rollback").read_bytes() != rollback_before
        assert len(tuple(attempts.iterdir())) == 2
    assert result_json(lifecycle_case.status())["status"] == "activated-and-validated"


def test_all_success_and_failure_output_is_secret_free(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    outputs = [lifecycle_case.install_response(), lifecycle_case.activate(check=True)]
    bad = lifecycle_case.run([
        *lifecycle_case.common("response-install"), *lifecycle_case.candidate(),
        "--artifact-sha256", "0" * 64,
    ])
    outputs.append(bad)
    secret_lines = [line for line in lifecycle_case.private_key_bytes.splitlines() if len(line) > 16]
    for output in outputs:
        combined = (output.stdout + output.stderr).encode()
        assert b"PRIVATE KEY" not in combined
        assert not any(line in combined for line in secret_lines)
