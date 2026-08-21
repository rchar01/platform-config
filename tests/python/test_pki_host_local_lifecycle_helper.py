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
REMOTE_VALIDATOR = "test-runner"
ENDPOINT = "https://registry.test/v2/"
V2_HELPER_SHA256 = "3044058c3d4884a3ab1d51f1dc128a5c84407e387d2805fa99087c65d98eb280"
V3_HELPER_SHA256 = "9b6c62c6380fb1ab00e0a10dc5905ec4f88af2b57b503c1b44ec4db497b68fb3"
V4_HELPER_SHA256 = "3d446de2d3e56314ca70e881b5354a2c341566f17a6e4472f58faced92daa7c0"


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
        result = self.run(
            [
                *self.common("response-prepare"),
                "--trust-id",
                "reviewed-v1",
                "--request-id",
                REQUEST_ID,
            ]
        ).assert_success()
        ingress = Path(json.loads(result.stdout)["ingress_dir"])
        source = self.root / "response-source"
        for name in self.module.RESPONSE_NAMES:
            shutil.copyfile(source / name, ingress / name)
            (ingress / name).chmod(0o600)
        return ingress

    def set_response_created_epoch(self, created_epoch: int) -> None:
        source = self.root / "response-source"
        response_path = source / "response"
        response_values = dict(
            line.split("=", 1)
            for line in response_path.read_text(encoding="ascii").splitlines()
        )
        response_values["created_epoch"] = str(created_epoch)
        response_bytes = record(self.module.RESPONSE_FIELDS, response_values)
        private_file(response_path, response_bytes)
        response_signature = source / "response.sig"
        response_signature.unlink()
        self.runner.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                self.signing_key,
                "-n",
                self.module.RESPONSE_NAMESPACE,
                response_path,
            ]
        ).assert_success()
        response_signature.chmod(0o600)

        artifact_path = source / "artifact"
        artifact_values = dict(
            line.split("=", 1)
            for line in artifact_path.read_text(encoding="ascii").splitlines()
        )
        artifact_values["source_response_sha256"] = digest(response_bytes)
        artifact_values["source_response_signature_sha256"] = digest(
            response_signature
        )
        artifact_values["created_epoch"] = str(created_epoch)
        private_file(
            artifact_path,
            record(self.module.ARTIFACT_FIELDS, artifact_values),
        )
        self.artifact_sha256 = digest(artifact_path)

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
            "--operation", self.operation,
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
            "--operation", self.operation,
            "--trust-id", "reviewed-v1",
            "--common-name", "registry.test",
            "--dns-san", "registry.test",
            "--dns-san", TARGET,
            "--ip-san", "192.0.2.61",
            *extra,
        ])

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

    def make_dormant_issue(self) -> None:
        request_path = self.pending / "request"
        request_values = self.module.parse_record(
            request_path.read_bytes(), self.module.REQUEST_FIELDS, "fixture request"
        )
        request_values.update(operation="issue", current_cert_sha256="none")
        request_bytes = record(self.module.REQUEST_FIELDS, request_values)
        private_file(request_path, request_bytes)
        request_signature = self.pending / "request.sig"
        request_signature.unlink()
        self.runner.run([
            "ssh-keygen", "-Y", "sign", "-f", self.signing_key,
            "-n", self.module.REQUEST_NAMESPACE, request_path,
        ]).assert_success()
        request_signature.chmod(0o600)

        source = self.root / "response-source"
        response_path = source / "response"
        response_values = self.module.parse_record(
            response_path.read_bytes(), self.module.RESPONSE_FIELDS, "fixture response"
        )
        response_values.update(
            operation="issue", request_sha256=digest(request_bytes)
        )
        response_bytes = record(self.module.RESPONSE_FIELDS, response_values)
        private_file(response_path, response_bytes)
        response_signature = source / "response.sig"
        response_signature.unlink()
        self.runner.run([
            "ssh-keygen", "-Y", "sign", "-f", self.signing_key,
            "-n", self.module.RESPONSE_NAMESPACE, response_path,
        ]).assert_success()
        response_signature.chmod(0o600)

        artifact_path = source / "artifact"
        artifact_values = self.module.parse_record(
            artifact_path.read_bytes(), self.module.ARTIFACT_FIELDS, "fixture artifact"
        )
        artifact_values.update(
            operation="issue",
            source_response_sha256=digest(response_bytes),
            source_response_signature_sha256=digest(response_signature),
        )
        private_file(
            artifact_path, record(self.module.ARTIFACT_FIELDS, artifact_values)
        )
        self.artifact_sha256 = digest(artifact_path)
        self.operation = "issue"

        (self.root / "zot/managed.crt").unlink()
        (self.root / "zot/managed.key").unlink()
        private_file(
            self.systemctl,
            "#!/bin/sh\n"
            "set -eu\n"
            "if [ \"$1\" = is-active ]; then printf 'inactive\\n'; exit 3; fi\n"
            "if [ \"$1\" = is-enabled ]; then printf 'masked\\n'; exit 1; fi\n"
            "printf '%s\\n' \"$*\" >>\"$PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG\"\n",
            0o755,
        )

    def outcome_package(self, evidence_path: Path) -> tuple[Path, str]:
        package = private_dir(self.root / "outcome-package")
        deployment_bytes = evidence_path.joinpath("deployment").read_bytes()
        deployment = self.module.parse_record(
            deployment_bytes, self.module.DEPLOYMENT_FIELDS, "deployment"
        )
        action = deployment["action"]
        if action == "finalize":
            rollback = self.module.parse_rollback(
                self.state.joinpath("rollback").read_bytes(),
                type("Args", (), {"service": SERVICE, "target": TARGET})(),
            )
            predecessor_kind = rollback["predecessor_kind"]
            predecessor_request_id = rollback["predecessor_request_id"]
            predecessor_certificate = rollback["predecessor_certificate_sha256"]
            predecessor_spki = rollback["predecessor_certificate_spki_sha256"]
            if predecessor_kind == "managed":
                predecessor_chain = Path(
                    rollback["prior_zot_cert_path"]
                ).read_bytes()
            else:
                predecessor_chain = Path(
                    rollback["predecessor_version_path"]
                ).joinpath("ca-chain.crt").read_bytes()
        else:
            predecessor_kind = "managed"
            predecessor_request_id = "none"
            predecessor_certificate = self.module.parse_record(
                self.pending.joinpath("request").read_bytes(),
                self.module.REQUEST_FIELDS,
                "request",
            )["current_cert_sha256"]
            config = json.loads(self.zot_config.read_text(encoding="ascii"))
            managed = x509.load_pem_x509_certificate(
                Path(config["http"]["tls"]["cert"]).read_bytes()
            )
            predecessor_spki = digest(managed.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            predecessor_chain = Path(config["http"]["tls"]["cert"]).read_bytes()
        predecessor_certificates = self.module.pem_certificates(
            predecessor_chain, None, "fixture predecessor public chain"
        )
        predecessor_intermediate = digest(
            predecessor_certificates[1].public_bytes(serialization.Encoding.PEM)
        )
        predecessor = {
            "predecessor_kind": predecessor_kind,
            "predecessor_request_id": predecessor_request_id,
            "predecessor_certificate_sha256": predecessor_certificate,
            "predecessor_certificate_spki_sha256": predecessor_spki,
            "predecessor_intermediate_sha256": predecessor_intermediate,
            "predecessor_response_sha256": "none",
            "predecessor_artifact_manifest_sha256": "none",
            "predecessor_deployment_sha256": "none",
            "predecessor_decision_sha256": "none",
        }
        decision_values = {
            "schema": "1",
            "action": action,
            "state": "finalized" if action == "finalize" else "abandoned",
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "operation": deployment["operation"],
            "request_sha256": deployment["request_sha256"],
            "response_sha256": deployment["response_sha256"],
            "response_signature_sha256": deployment["response_signature_sha256"],
            "candidate_sha256": deployment["candidate_sha256"],
            "artifact_manifest_sha256": deployment["artifact_manifest_sha256"],
            "certificate_sha256": deployment["certificate_sha256"],
            "certificate_spki_sha256": deployment["certificate_spki_sha256"],
            "chain_sha256": deployment["chain_sha256"],
            "fullchain_sha256": deployment["fullchain_sha256"],
            "deployment_sha256": digest(deployment_bytes),
            "deployment_signature_sha256": digest(evidence_path / "deployment.sig"),
            "deployers_sha256": digest(
                self.state / "trust/reviewed-v1/deployers.allowed_signers"
            ),
            **predecessor,
            "resulting_active_request_id": (
                REQUEST_ID if action == "finalize" else "none"
            ),
            "created_epoch": deployment["created_epoch"],
        }
        decision = record(self.module.DECISION_FIELDS, decision_values)
        outcome_values = {
            name: decision_values[name]
            for name in self.module.OUTCOME_FIELDS
            if name in decision_values
        }
        outcome_values.update(
            kind="csr-signer-outcome",
            decision_sha256=digest(decision),
            outcome_principal=RESPONSE_PRINCIPAL,
        )
        outcome = record(self.module.OUTCOME_FIELDS, outcome_values)
        for name, data in (
            ("outcome", outcome),
            ("deployment", deployment_bytes),
            ("deployment.sig", evidence_path.joinpath("deployment.sig").read_bytes()),
            (
                "deployers.allowed_signers",
                self.state.joinpath(
                    "trust/reviewed-v1/deployers.allowed_signers"
                ).read_bytes(),
            ),
            ("decision", decision),
        ):
            private_file(package / name, data)
        self.runner.run([
            "ssh-keygen", "-Y", "sign", "-f", self.signing_key,
            "-n", self.module.OUTCOME_NAMESPACE, package / "outcome",
        ]).assert_success()
        package.joinpath("outcome.sig").chmod(0o600)
        return package, digest(outcome)

    def import_outcome(
        self,
        package: Path,
        outcome_sha256: str,
        deployment_sha256: str,
        *,
        check: bool = False,
        environment: dict[str, str] | None = None,
    ) -> CommandResult:
        command = "outcome-import"
        argv = [
            *self.common(command, config=True),
            "--trust-id", "reviewed-v1",
            "--request-id", REQUEST_ID,
            "--artifact-sha256", self.artifact_sha256,
            "--deployment-sha256", deployment_sha256,
            "--outcome-sha256", outcome_sha256,
        ]
        argv.extend(("--outcome-dir", package))
        if check:
            argv.append("--check")
        return self.run(argv, environment=environment)


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
    managed_cert_path = private_file(
        zot_root / "managed.crt", managed_cert + intermediate, 0o644
    )
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
        "if [ \"$1\" = is-enabled ]; then printf 'enabled\\n'; exit 0; fi\n"
        "printf '%s\\n' \"$*\" >>\"$PLATFORM_PKI_LIFECYCLE_TEST_SERVICE_LOG\"\n",
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
        systemctl=systemctl, service_log=service_log, operation="migrate",
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


def test_status_falls_back_until_authenticated_outcome(
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


def test_zot_custody_selects_exact_managed_config_before_activation(
    lifecycle_case: LifecycleCase,
) -> None:
    selected = result_json(lifecycle_case.zot_custody())

    assert selected == {
        "schema": "1",
        "kind": "platform-config-zot-tls-custody",
        "custody": "managed",
        "request_id": "none",
        "cert_path": str(lifecycle_case.root / "zot/managed.crt"),
        "key_path": str(lifecycle_case.root / "zot/managed.key"),
        "artifact_sha256": "none",
        "certificate_sha256": "none",
        "spki_sha256": "none",
        "chain_sha256": "none",
        "fullchain_sha256": "none",
        "zot_config_sha256": digest(lifecycle_case.zot_config),
    }


def test_fresh_issue_reports_dormant_custody_and_initial_status(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.make_dormant_issue()

    selected = result_json(lifecycle_case.zot_custody())
    assert selected["custody"] == "dormant"
    assert selected["request_id"] == "none"
    assert selected["cert_path"] == str(lifecycle_case.root / "zot/managed.crt")
    assert selected["key_path"] == str(lifecycle_case.root / "zot/managed.key")
    assert result_json(lifecycle_case.status())["status"] == "request-pending"

    shutil.rmtree(lifecycle_case.pending)
    initial = result_json(lifecycle_case.status())
    assert initial["status"] == "initial-issuance-needed"
    assert initial["required_action"] == "create-issuance-request"


def test_fresh_issue_activation_enables_zot_and_selects_host_local_custody(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.make_dormant_issue()
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    before = tree_snapshot(lifecycle_case.root)

    preview = result_json(lifecycle_case.activate(check=True))
    assert preview["status"] == "would-activate"
    assert tree_snapshot(lifecycle_case.root) == before

    activated = result_json(lifecycle_case.activate())
    assert lifecycle_case.service_log.read_text(encoding="ascii").splitlines() == [
        "unmask zot.service",
        "start zot.service",
    ]
    rollback = lifecycle_case.module.parse_rollback(
        lifecycle_case.state.joinpath("rollback").read_bytes(),
        type("Args", (), {"service": SERVICE, "target": TARGET})(),
    )
    assert rollback["predecessor_kind"] == "none"

    observation = lifecycle_case.observation(activated["activation_epoch"] + 1)
    result_json(lifecycle_case.finish(observation))
    assert_failure(lifecycle_case.activate())
    selected = result_json(lifecycle_case.zot_custody())
    assert selected["custody"] == "host-local"
    assert selected["request_id"] == REQUEST_ID


def test_fresh_issue_activation_failure_restores_dormant_not_activated_state(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.make_dormant_issue()
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    dormant_config = lifecycle_case.zot_config.read_bytes()

    failed = lifecycle_case.activate(
        environment={"PLATFORM_PKI_LIFECYCLE_FAIL_AT": "after-restart"}
    )
    assert_failure(failed)
    assert lifecycle_case.zot_config.read_bytes() == dormant_config
    assert not lifecycle_case.state.joinpath("active").exists()
    assert not lifecycle_case.state.joinpath("rollback").exists()
    journal = lifecycle_case.module.parse_record(
        lifecycle_case.state.joinpath("activation-journal").read_bytes(),
        lifecycle_case.module.ACTIVATION_JOURNAL_FIELDS,
        "activation journal",
    )
    assert journal["checkpoint"] == "not-activated"
    assert lifecycle_case.service_log.read_text(encoding="ascii").splitlines() == [
        "unmask zot.service",
        "start zot.service",
        "stop zot.service",
        "mask zot.service",
    ]
    status = result_json(lifecycle_case.status())
    assert status["status"] == "abandonment-evidence-required"
    assert status["required_action"] == "publish-not-activated-evidence"


def test_no_active_renew_fails_closed(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.operation = "renew"

    assert_failure(lifecycle_case.zot_custody())
    shutil.rmtree(lifecycle_case.pending)
    assert_failure(lifecycle_case.status())


@pytest.mark.parametrize("operation", ["issue", "migrate"])
def test_status_rejects_rollback_without_authenticated_active(
    lifecycle_case: LifecycleCase,
    operation: str,
) -> None:
    activate_and_finish(lifecycle_case)
    lifecycle_case.state.joinpath("active").unlink()
    shutil.rmtree(lifecycle_case.pending_root)
    lifecycle_case.operation = operation

    assert_failure(lifecycle_case.status())


def test_zot_custody_selects_only_finished_authenticated_active_version(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    activated = result_json(lifecycle_case.activate())
    assert_failure(lifecycle_case.zot_custody())

    observation = lifecycle_case.observation(activated["activation_epoch"] + 1)
    result_json(lifecycle_case.finish(observation))
    selected = result_json(lifecycle_case.zot_custody())

    assert selected["custody"] == "host-local"
    assert selected["request_id"] == REQUEST_ID
    assert selected["cert_path"] == str(
        lifecycle_case.versions_root / REQUEST_ID / "fullchain.crt"
    )
    assert selected["key_path"] == str(
        lifecycle_case.versions_root / REQUEST_ID / "tls.key"
    )
    assert selected["artifact_sha256"] == lifecycle_case.artifact_sha256
    assert selected["certificate_sha256"] == lifecycle_case.certificate_sha256
    assert selected["spki_sha256"] == lifecycle_case.certificate_spki_sha256
    assert selected["zot_config_sha256"] == digest(lifecycle_case.zot_config)


def test_zot_registry_migrates_exact_v2_helper_before_authenticated_custody(
    repo_root: Path,
    lifecycle_case: LifecycleCase,
) -> None:
    activate_and_finish(lifecycle_case)
    installed_helper = lifecycle_case.root / "installed-lifecycle-helper"
    v4_source = lifecycle_case.helper.read_text(encoding="ascii")
    assert digest(v4_source.encode("ascii")) == V4_HELPER_SHA256

    def replace_once(value: str, current: str, predecessor: str) -> str:
        assert value.count(current) == 1
        return value.replace(current, predecessor, 1)

    v3_source = v4_source
    v3_source = replace_once(
        v3_source,
        '''def service_enabled_state() -> str:
    result = run((systemctl_path(), "is-enabled", "zot.service"), "Zot service enablement query", accepted=frozenset((0, 1)))
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        fail("Zot service enablement state is not ASCII")
    if value not in {"enabled", "disabled", "generated", "masked"}:
        fail("Zot service enablement state is not canonical")
    return value


def service_action(action: str) -> None:
    if action not in {"restart", "stop", "enable-start", "disable-stop"}:
        fail("service recovery action is invalid")
    commands = {
        "restart": (("restart", "zot.service"),),
        "stop": (("stop", "zot.service"),),
        "enable-start": (("unmask", "zot.service"), ("start", "zot.service")),
        "disable-stop": (("stop", "zot.service"), ("mask", "zot.service")),
    }[action]
    for command in commands:
        run((systemctl_path(), *command), f"systemctl {' '.join(command)}")
''',
        '''def service_action(action: str) -> None:
    if action not in {"restart", "stop"}:
        fail("service recovery action is invalid")
    run((systemctl_path(), action, "zot.service"), f"systemctl {action} zot.service")
''',
    )
    for current, predecessor in (
        (
            '''    rollback = parse_rollback(new_rollback, args)
    predecessor_free = rollback["predecessor_kind"] == "none"
    if record["prior_service_state"] == "active":
        service_action("restart")
    elif predecessor_free:
        service_action("disable-stop")
    else:
        service_action("stop")
''',
            '''    if record["prior_service_state"] == "active":
        service_action("restart")
    else:
        service_action("stop")
''',
        ),
        ('        terminal = "not-activated" if predecessor_free else (\n', '        terminal = (\n'),
        (
            '''        if validated["request"]["operation"] != args.operation:
            fail("candidate operation differs from the requested lifecycle operation")
''',
            "",
        ),
        (
            '''        if prior_active is not None:
            authenticate_active(state, args)
            if args.operation == "issue":
                fail("issue activation requires no authenticated active version")
        elif prior_rollback is not None:
            fail("rollback state exists without an authenticated active version")
        prior_state = service_state()
        initial_issue = prior_active is None and args.operation == "issue"
        if initial_issue:
            if prior_state != "inactive" or service_enabled_state() != "masked":
                fail("predecessor-free issue requires masked and inactive Zot")
            if os.path.lexists(prior_cert) or os.path.lexists(prior_key):
                fail("predecessor-free issue requires absent dormant TLS material")
        elif prior_state != "active":
            fail("Zot must be active before certificate activation")
        if prior_active is None and args.operation == "renew":
            fail("renew requires an authenticated active version")
''',
            '''        if prior_active is not None:
            authenticate_active(state, args)
        prior_state = service_state()
        if prior_state != "active":
            fail("Zot must be active before certificate activation")
''',
        ),
        ('            service_action("enable-start" if initial_issue else "restart")\n', '            service_action("restart")\n'),
        (
            '''                    if pending_state["record"]["operation"] != args.operation:
                        fail("pending request operation differs from lifecycle operation")
''',
            "",
        ),
        (
            '''        rollback_data, _ = read_optional_state(state, "rollback")
        if active_auth is None and rollback_data is not None:
            fail("rollback state exists without an authenticated active version")
''',
            "",
        ),
        (
            '''        if active_auth is not None:
            active = active_auth["record"]
            if rollback_data is None:
''',
            '''        if active_auth is not None:
            active = active_auth["record"]
            rollback_data, _ = read_optional_state(state, "rollback")
            if rollback_data is None:
''',
        ),
        (
            '''        elif args.operation == "issue":
            selected = ("initial-issuance-needed", "create-issuance-request")
        elif args.operation == "renew":
            fail("renew requires an authenticated active version")
''',
            "",
        ),
        (
            '''            if args.operation == "renew":
                fail("renew requires an authenticated active version")
            custody = "dormant" if args.operation == "issue" else "managed"
            if custody == "dormant" and (
                os.path.lexists(args.managed_cert) or os.path.lexists(args.managed_key)
            ):
                fail("dormant Zot TLS destination material must be absent")
''',
            "",
        ),
        ('                "custody": custody,\n', '                "custody": "managed",\n'),
        ('    start.add_argument("--operation", choices=("issue", "migrate", "renew"), required=True)\n', ""),
        ('    status_parser.add_argument("--operation", choices=("issue", "migrate", "renew"), required=True)\n', ""),
        (
            '        help="derive exact dormant, managed, or authenticated host-local Zot TLS custody",\n',
            '        help="derive exact managed or authenticated host-local Zot TLS custody",\n',
        ),
        ('    custody.add_argument("--operation", choices=("issue", "migrate", "renew"), required=True)\n', ""),
    ):
        v3_source = replace_once(v3_source, current, predecessor)
    assert digest(v3_source.encode("ascii")) == V3_HELPER_SHA256

    def remove_v3_section(value: str, start: str, end: str) -> str:
        first = value.index(start)
        last = value.index(end, first)
        return value[:first] + value[last:]

    v2_source = remove_v3_section(
        v3_source, "\n\ndef zot_custody", "\n\ndef add_common"
    )
    v2_source = remove_v3_section(
        v2_source,
        "\n\n    custody = commands.add_parser(",
        "\n    return parser",
    )
    v2_source = remove_v3_section(
        v2_source,
        '\n    if hasattr(args, "managed_config_sha256"):',
        '\n    if hasattr(args, "request_sha256")',
    )
    v2_bytes = v2_source.encode("ascii")
    assert digest(v2_bytes) == V2_HELPER_SHA256
    private_file(installed_helper, v2_bytes, 0o755)

    expected_version = lifecycle_case.versions_root / REQUEST_ID
    variables = {
        "zot_registry_tls_enabled": True,
        "zot_registry_tls_host_local_lifecycle_helper_path": str(installed_helper),
        "zot_registry_tls_host_local_state_root": str(lifecycle_case.state),
        "zot_registry_tls_host_local_pending_root": str(lifecycle_case.pending_root),
        "zot_registry_tls_host_local_versions_root": str(lifecycle_case.versions_root),
        "zot_registry_tls_host_local_service": SERVICE,
        "zot_registry_tls_host_local_target": TARGET,
        "zot_registry_tls_host_local_zot_config_path": str(lifecycle_case.zot_config),
        "zot_registry_config_path": str(lifecycle_case.zot_config),
        "zot_registry_tls_cert_path": str(lifecycle_case.root / "zot/managed.crt"),
        "zot_registry_tls_key_path": str(lifecycle_case.root / "zot/managed.key"),
        "zot_registry_test_expected_cert_path": str(expected_version / "fullchain.crt"),
        "zot_registry_test_expected_key_path": str(expected_version / "tls.key"),
        "zot_registry_test_request_id": REQUEST_ID,
    }
    playbook = (
        repo_root
        / "tests/fixtures/pki-host-local-zot-one-runner/custody-upgrade.yml"
    )

    def converge(*, check: bool = False) -> CommandResult:
        argv: list[str | Path] = [
            "ansible-playbook",
            "-i",
            "localhost,",
            playbook,
            "--extra-vars",
            json.dumps(variables, separators=(",", ":"), sort_keys=True),
        ]
        if check:
            argv.append("--check")
        return lifecycle_case.runner.run(argv, timeout=120)

    def helper_snapshot() -> tuple[Any, ...]:
        metadata = installed_helper.lstat()
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            installed_helper.read_bytes(),
        )

    first = converge().assert_success()
    assert digest(installed_helper) == V4_HELPER_SHA256
    assert installed_helper.read_bytes() == lifecycle_case.helper.read_bytes()
    assert "Derive Zot TLS custody from initialized lifecycle state" in first.stdout
    assert "Require exact derived Zot TLS custody result" in first.stdout
    assert "Require authenticated custody after helper migration" in first.stdout
    first_recap = next(line for line in first.stdout.splitlines() if "failed=" in line)
    assert "changed=1" in first_recap
    assert "failed=0" in first_recap

    migrated_snapshot = helper_snapshot()
    second = converge().assert_success()
    assert digest(installed_helper) == V4_HELPER_SHA256
    assert installed_helper.read_bytes() == lifecycle_case.helper.read_bytes()
    assert helper_snapshot() == migrated_snapshot
    second_recap = next(line for line in second.stdout.splitlines() if "failed=" in line)
    assert "changed=0" in second_recap
    assert "failed=0" in second_recap

    private_file(installed_helper, v2_bytes, 0o755)
    predecessor_snapshot = helper_snapshot()
    check_result = converge(check=True)
    check_result.assert_failure()
    assert digest(installed_helper) == V2_HELPER_SHA256
    assert helper_snapshot() == predecessor_snapshot
    assert "Derive Zot TLS custody from initialized lifecycle state" not in check_result.stdout

    unknown_bytes = b"unknown helper drift\n"
    private_file(installed_helper, unknown_bytes, 0o755)
    unknown_snapshot = helper_snapshot()
    unknown_result = converge()
    unknown_result.assert_failure()
    assert installed_helper.read_bytes() == unknown_bytes
    assert helper_snapshot() == unknown_snapshot
    assert "Derive Zot TLS custody from initialized lifecycle state" not in unknown_result.stdout


@pytest.mark.parametrize(
    "journal",
    (
        "activation-journal",
        "evidence-attempt-journal",
        "abandonment-journal",
        "expired-request-abandonment-journal",
        "pending-request-cancellation-journal",
        "request.journal",
        "trust-install.journal",
    ),
)
def test_zot_custody_rejects_every_unresolved_journal_without_fallback(
    lifecycle_case: LifecycleCase,
    journal: str,
) -> None:
    private_file(lifecycle_case.state / journal, b"unresolved\n")

    result = lifecycle_case.zot_custody()

    assert_failure(result)
    assert "unresolved lifecycle state blocks Zot TLS custody selection" in result.stderr


@pytest.mark.parametrize("corruption", ("managed-config", "active", "rollback"))
def test_zot_custody_rejects_config_and_authenticated_state_corruption(
    lifecycle_case: LifecycleCase,
    corruption: str,
) -> None:
    if corruption == "managed-config":
        expected_config_sha256 = digest(lifecycle_case.zot_config)
        config = json.loads(lifecycle_case.zot_config.read_text(encoding="ascii"))
        config["http"]["address"] = "127.0.0.1"
        lifecycle_case.zot_config.write_text(
            json.dumps(config, indent=2) + "\n", encoding="ascii"
        )
        result = lifecycle_case.zot_custody(
            managed_config_sha256=expected_config_sha256
        )
    else:
        activate_and_finish(lifecycle_case)
        path = lifecycle_case.state / corruption
        fields = (
            lifecycle_case.module.ACTIVE_FIELDS
            if corruption == "active"
            else lifecycle_case.module.ROLLBACK_FIELDS
        )
        values = lifecycle_case.module.parse_record(
            path.read_bytes(), fields, f"fixture {corruption}"
        )
        values["activating_certificate_sha256" if corruption == "rollback" else "certificate_sha256"] = "f" * 64
        private_file(path, record(fields, values))
        result = lifecycle_case.zot_custody()

    assert_failure(result)
    assert result.stdout == ""


def test_zot_custody_rejects_ambiguous_state_and_obeys_shared_lock(
    lifecycle_case: LifecycleCase,
) -> None:
    private_file(lifecycle_case.state / "unexpected", b"ambiguous\n")
    ambiguous = lifecycle_case.zot_custody()
    assert_failure(ambiguous)
    assert "state root contains unexpected entries" in ambiguous.stderr
    lifecycle_case.state.joinpath("unexpected").unlink()

    with lifecycle_case.state.joinpath("lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        blocked = lifecycle_case.zot_custody()
    assert_failure(blocked)
    assert "another lifecycle operation holds the state lock" in blocked.stderr


def rewrite_lifecycle_outcome_decision(
    lifecycle_case: LifecycleCase,
    package: Path,
    updates: dict[str, str],
) -> str:
    decision = lifecycle_case.module.parse_record(
        package.joinpath("decision").read_bytes(),
        lifecycle_case.module.DECISION_FIELDS,
        "fixture decision",
    )
    decision.update(updates)
    decision_bytes = record(lifecycle_case.module.DECISION_FIELDS, decision)
    private_file(package / "decision", decision_bytes)
    outcome = lifecycle_case.module.parse_record(
        package.joinpath("outcome").read_bytes(),
        lifecycle_case.module.OUTCOME_FIELDS,
        "fixture outcome",
    )
    for name, value in updates.items():
        if name in lifecycle_case.module.OUTCOME_FIELDS:
            outcome[name] = value
    outcome["decision_sha256"] = digest(decision_bytes)
    outcome_bytes = record(lifecycle_case.module.OUTCOME_FIELDS, outcome)
    private_file(package / "outcome", outcome_bytes)
    package.joinpath("outcome.sig").unlink()
    lifecycle_case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", lifecycle_case.signing_key,
        "-n", lifecycle_case.module.OUTCOME_NAMESPACE, package / "outcome",
    ]).assert_success()
    package.joinpath("outcome.sig").chmod(0o600)
    return digest(outcome_bytes)


def rewrite_signed_validation_result(
    lifecycle_case: LifecycleCase,
    evidence: Path,
    field: str,
    value: str,
) -> None:
    result_path = evidence / "validation-result"
    result = lifecycle_case.module.parse_record(
        result_path.read_bytes(),
        lifecycle_case.module.VALIDATION_RESULT_FIELDS,
        "fixture validation result",
    )
    result[field] = value
    private_file(
        result_path,
        record(lifecycle_case.module.VALIDATION_RESULT_FIELDS, result),
    )
    evidence.joinpath("validation-result.sig").unlink()
    lifecycle_case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", lifecycle_case.signing_key,
        "-n", lifecycle_case.module.DEPLOYMENT_NAMESPACE, result_path,
    ]).assert_success()
    evidence.joinpath("validation-result.sig").chmod(0o600)


def test_finalized_outcome_import_is_checkable_idempotent_and_completes_status(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    evidence = Path(finished["evidence_path"])
    package, outcome_sha = lifecycle_case.outcome_package(evidence)
    before = tree_snapshot(lifecycle_case.state)
    checked = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"], check=True,
    ))
    assert checked["status"] == "would-import"
    assert tree_snapshot(lifecycle_case.state) == before

    imported = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert imported["status"] == "imported"
    history = Path(imported["history_path"])
    assert {path.name for path in history.iterdir()} == set(
        lifecycle_case.module.OUTCOME_NAMES
    )
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in history.iterdir())
    assert stat.S_IMODE(history.stat().st_mode) == 0o700
    assert stat.S_IMODE(history.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(history.parent.parent.stat().st_mode) == 0o700
    assert "tls.key" not in {path.name for path in history.iterdir()}
    assert lifecycle_case.pending.joinpath("tls.key").read_bytes() == (
        lifecycle_case.private_key_bytes
    )
    before_existing_preflight = tree_snapshot(lifecycle_case.state)
    existing_preflight = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"], check=True,
    ))
    assert existing_preflight["status"] == "existing"
    assert tree_snapshot(lifecycle_case.state) == before_existing_preflight
    assert result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))["status"] == "existing"
    status = result_json(lifecycle_case.status(
        "--minimum-remaining-lifetime-seconds", "999999999",
    ))
    assert status["status"] == "complete"
    assert status["signer_outcome_state"] == "finalized"
    assert status["evidence_state"] == "controller-exported"
    assert status["renewal_eligible"] is False
    assert status["required_action"] == "none"


def test_status_exact_outcome_match_and_mismatch_are_read_only(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(
        Path(finished["evidence_path"])
    )
    lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"]
    ).assert_success()

    before_match = tree_snapshot(lifecycle_case.state)
    matched = result_json(
        lifecycle_case.status("--outcome-sha256", outcome_sha)
    )
    assert matched["status"] == "complete"
    assert matched["signer_outcome_state"] == "finalized"
    assert tree_snapshot(lifecycle_case.state) == before_match

    before_mismatch = tree_snapshot(lifecycle_case.state)
    mismatch = lifecycle_case.status("--outcome-sha256", "f" * 64)
    assert_failure(mismatch)
    assert "differs from the exact requested coordinate" in mismatch.stderr
    assert tree_snapshot(lifecycle_case.state) == before_mismatch


@pytest.mark.parametrize("alteration", ("malformed", "conflicting"))
def test_outcome_preflight_rejects_invalid_target_state_without_mutation(
    lifecycle_case: LifecycleCase,
    alteration: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    active_path = lifecycle_case.state / "active"
    if alteration == "malformed":
        private_file(active_path, b"malformed\n")
    else:
        active = lifecycle_case.module.parse_record(
            active_path.read_bytes(), lifecycle_case.module.ACTIVE_FIELDS, "active"
        )
        active["certificate_sha256"] = "f" * 64
        private_file(active_path, record(lifecycle_case.module.ACTIVE_FIELDS, active))
    before = tree_snapshot(lifecycle_case.state)
    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"], check=True,
    )
    assert_failure(failure)
    assert tree_snapshot(lifecycle_case.state) == before
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


def test_outcome_preflight_public_authentication_never_accesses_private_key(
    lifecycle_case: LifecycleCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    module = lifecycle_case.module
    version_path = lifecycle_case.versions_root / REQUEST_ID
    accessed: list[tuple[str, str]] = []
    original_read_at = module.read_at
    original_scan = module.scan
    original_directory_open = module.PinnedDirectory.open.__func__

    def mapped_directory_open(cls, path, label, **kwargs):
        metadata = os.stat(path, follow_symlinks=False)
        owners = {0, os.getuid(), os.getgid(), metadata.st_uid, metadata.st_gid}
        kwargs.setdefault("allowed_owner_uids", owners)
        kwargs.setdefault("final_owner_uid", metadata.st_uid)
        return original_directory_open(cls, path, label, **kwargs)

    def guarded_read_at(directory, name, label, **kwargs):
        assert name != "tls.key"
        accessed.append((directory.path, name))
        metadata = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        kwargs.setdefault("owner_uid", metadata.st_uid)
        kwargs.setdefault("owner_gid", metadata.st_gid)
        return original_read_at(directory, name, label, **kwargs)

    def guarded_scan(directory, label):
        assert directory.path != str(version_path)
        return original_scan(directory, label)

    monkeypatch.setattr(
        module.PinnedDirectory, "open", classmethod(mapped_directory_open)
    )
    monkeypatch.setattr(module, "read_at", guarded_read_at)
    monkeypatch.setattr(module, "scan", guarded_scan)
    state = module.PinnedDirectory.open(str(lifecycle_case.state), "test state")
    trust, policy = module.load_trust(state, "reviewed-v1", TARGET)
    args = SimpleNamespace(
        versions_root=str(lifecycle_case.versions_root),
        pending_root=str(lifecycle_case.pending_root),
        service=SERVICE,
        target=TARGET,
        trust_id="reviewed-v1",
        request_id=REQUEST_ID,
        deployment_sha256=finished["deployment_sha256"],
    )
    try:
        authenticated = module.authenticate_active_public(
            state, args, trust, policy
        )
    finally:
        state.close()

    assert authenticated["record"]["request_id"] == REQUEST_ID
    assert (str(version_path), "artifact") in accessed
    assert not any(name == "tls.key" for _path, name in accessed)


def test_outcome_preflight_rejects_forged_public_version_without_mutation(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(
        Path(finished["evidence_path"])
    )
    artifact_path = lifecycle_case.versions_root / REQUEST_ID / "artifact"
    artifact = lifecycle_case.module.parse_record(
        artifact_path.read_bytes(), lifecycle_case.module.ARTIFACT_FIELDS,
        "fixture artifact",
    )
    artifact["issuer_root"] = "forged-root"
    private_file(
        artifact_path,
        record(lifecycle_case.module.ARTIFACT_FIELDS, artifact),
    )
    before = tree_snapshot(lifecycle_case.state)

    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"], check=True,
    )

    assert_failure(failure)
    assert tree_snapshot(lifecycle_case.state) == before
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


def test_outcome_preflight_rejects_canonical_active_forged_against_evidence(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(
        Path(finished["evidence_path"])
    )
    active_path = lifecycle_case.state / "active"
    active = lifecycle_case.module.parse_record(
        active_path.read_bytes(), lifecycle_case.module.ACTIVE_FIELDS,
        "fixture active",
    )
    active["activation_epoch"] = str(int(active["activation_epoch"]) + 1)
    private_file(
        active_path,
        record(lifecycle_case.module.ACTIVE_FIELDS, active),
    )
    before = tree_snapshot(lifecycle_case.state)

    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"], check=True,
    )

    assert_failure(failure)
    assert tree_snapshot(lifecycle_case.state) == before
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


@pytest.mark.parametrize("forgery", ("pointer", "history"))
def test_outcome_preflight_rejects_forged_accepted_state_without_mutation(
    lifecycle_case: LifecycleCase,
    forgery: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(
        Path(finished["evidence_path"])
    )
    imported = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    if forgery == "pointer":
        pointer_path = lifecycle_case.state / "accepted-outcome"
        pointer = lifecycle_case.module.parse_record(
            pointer_path.read_bytes(),
            lifecycle_case.module.ACCEPTED_OUTCOME_FIELDS,
            "fixture accepted pointer",
        )
        pointer["decision_sha256"] = "f" * 64
        private_file(
            pointer_path,
            record(lifecycle_case.module.ACCEPTED_OUTCOME_FIELDS, pointer),
        )
    else:
        private_file(Path(imported["history_path"]) / "outcome.sig", b"forged\n")
    before = tree_snapshot(lifecycle_case.state)

    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"], check=True,
    )

    assert_failure(failure)
    assert tree_snapshot(lifecycle_case.state) == before


def test_outcome_import_does_not_depend_on_candidate_private_key_entries(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    private_entries = (
        lifecycle_case.pending / "tls.key",
        lifecycle_case.versions_root / REQUEST_ID / "tls.key",
    )
    saved = []
    for index, path in enumerate(private_entries):
        destination = lifecycle_case.root / f"saved-private-entry-{index}"
        path.rename(destination)
        saved.append((destination, path))

    imported = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert imported["status"] == "imported"
    assert all(source.exists() and not original.exists() for source, original in saved)


def test_abandoned_outcome_with_unrecorded_managed_predecessor_fails_closed(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
    result_json(lifecycle_case.install_response())
    abandoned = result_json(lifecycle_case.finish(
        None, action="abandon", result="not-activated",
    ))
    package, outcome_sha = lifecycle_case.outcome_package(
        Path(abandoned["evidence_path"])
    )
    failure = lifecycle_case.import_outcome(
        package, outcome_sha, abandoned["deployment_sha256"],
    )
    assert_failure(failure)
    assert "candidate rollback record" in failure.stderr
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("service", "other-service"),
        ("target", "other-target"),
        ("request_id", "f" * 32),
        ("artifact_manifest_sha256", "f" * 64),
        ("validation_boundary_sha256", "f" * 64),
        ("action", "abandon"),
        ("result", "rolled-back"),
        ("local_validator", "other-local"),
        ("remote_validator", "other-remote"),
        ("endpoint", "https://other.example/v2/"),
        ("served_certificate_sha256", "f" * 64),
        ("served_intermediate_sha256", "f" * 64),
        ("activation_epoch", "1"),
        ("validation_epoch", "1"),
        ("deployment_sha256", "f" * 64),
        ("local_service_result", "failed"),
        ("local_tls_result", "failed"),
        ("remote_tls_result", "failed"),
        ("remote_application_result", "failed"),
        ("remote_http_status", "500"),
        ("remote_api_version", "other"),
        ("remote_auth_challenge", "other"),
    ),
)
def test_outcome_import_rejects_each_signed_validation_result_mismatch(
    lifecycle_case: LifecycleCase,
    field: str,
    value: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    evidence = Path(finished["evidence_path"])
    rewrite_signed_validation_result(lifecycle_case, evidence, field, value)
    package, outcome_sha = lifecycle_case.outcome_package(evidence)
    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"]
    )
    assert_failure(failure)
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("predecessor_kind", "none"),
        ("predecessor_request_id", "f" * 32),
        ("predecessor_certificate_sha256", "f" * 64),
        ("predecessor_certificate_spki_sha256", "f" * 64),
        ("predecessor_intermediate_sha256", "f" * 64),
        ("predecessor_response_sha256", "f" * 64),
        ("predecessor_artifact_manifest_sha256", "f" * 64),
        ("predecessor_deployment_sha256", "f" * 64),
        ("predecessor_decision_sha256", "f" * 64),
    ),
)
def test_outcome_import_rejects_each_signed_managed_predecessor_mismatch(
    lifecycle_case: LifecycleCase,
    field: str,
    value: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, _outcome_sha = lifecycle_case.outcome_package(
        Path(finished["evidence_path"])
    )
    outcome_sha = rewrite_lifecycle_outcome_decision(
        lifecycle_case, package, {field: value}
    )
    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"]
    )
    assert_failure(failure)
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


def test_outcome_import_rejects_host_local_predecessor_without_history_digests(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, _outcome_sha = lifecycle_case.outcome_package(
        Path(finished["evidence_path"])
    )
    predecessor_id = "f" * 32
    predecessor = {
        "predecessor_kind": "host-local",
        "predecessor_request_id": predecessor_id,
        "predecessor_certificate_sha256": "a" * 64,
        "predecessor_certificate_spki_sha256": "b" * 64,
        "predecessor_intermediate_sha256": "c" * 64,
        "predecessor_response_sha256": "d" * 64,
        "predecessor_artifact_manifest_sha256": "e" * 64,
        "predecessor_deployment_sha256": "1" * 64,
        "predecessor_decision_sha256": "2" * 64,
    }
    outcome_sha = rewrite_lifecycle_outcome_decision(
        lifecycle_case, package, predecessor
    )
    rollback_path = lifecycle_case.state / "rollback"
    rollback = lifecycle_case.module.parse_record(
        rollback_path.read_bytes(), lifecycle_case.module.ROLLBACK_FIELDS, "rollback"
    )
    rollback.update(
        predecessor_kind="host-local",
        predecessor_request_id=predecessor_id,
        predecessor_artifact_manifest_sha256="e" * 64,
        predecessor_certificate_sha256="a" * 64,
        predecessor_certificate_spki_sha256="b" * 64,
        predecessor_chain_sha256="3" * 64,
        predecessor_fullchain_sha256="4" * 64,
    )
    private_file(
        rollback_path, record(lifecycle_case.module.ROLLBACK_FIELDS, rollback)
    )
    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"]
    )
    assert_failure(failure)
    assert "absent from the rollback record" in failure.stderr


def test_outcome_publication_interruption_recovers_by_exact_rerun(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    interrupted = lifecycle_case.import_outcome(
        package,
        outcome_sha,
        finished["deployment_sha256"],
        environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": "after-outcome-history-publication"},
    )
    assert_failure(interrupted)
    history = lifecycle_case.state / "outcomes" / REQUEST_ID / outcome_sha
    assert history.is_dir()
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()
    assert_failure(lifecycle_case.status())
    recovered = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert recovered["status"] == "imported"
    assert result_json(lifecycle_case.status())["status"] == "complete"


def test_outcome_pointer_stage_failure_cleans_and_exact_rerun_recovers(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    failed = lifecycle_case.import_outcome(
        package,
        outcome_sha,
        finished["deployment_sha256"],
        environment={
            "PLATFORM_PKI_LIFECYCLE_FAIL_AT": "after-accepted-outcome-stage"
        },
    )
    assert_failure(failed)
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()
    assert not tuple(lifecycle_case.state.glob(".accepted-outcome-stage-*"))
    history = lifecycle_case.state / "outcomes" / REQUEST_ID / outcome_sha
    assert history.is_dir()
    recovered = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert recovered["status"] == "imported"


def test_outcome_pointer_post_publication_interruption_is_idempotent(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    interrupted = lifecycle_case.import_outcome(
        package,
        outcome_sha,
        finished["deployment_sha256"],
        environment={
            "PLATFORM_PKI_LIFECYCLE_CRASH_AT": "after-accepted-outcome-publication"
        },
    )
    assert_failure(interrupted)
    assert lifecycle_case.state.joinpath("accepted-outcome").is_file()
    assert not tuple(lifecycle_case.state.glob(".accepted-outcome-stage-*"))
    assert result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))["status"] == "existing"


def test_atomic_outcome_pointer_fsyncs_stage_and_parent(
    lifecycle_case: LifecycleCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    pointer_root = private_dir(lifecycle_case.root / "pointer-fsync")
    opened = lifecycle_case.module.PinnedDirectory.open(
        os.fspath(pointer_root),
        "pointer fsync root",
        allowed_owner_uids={0, os.geteuid(), os.getegid()},
        final_owner_uid=os.geteuid(),
    )
    directory_descriptor = opened.fd
    original_fsync = lifecycle_case.module.os.fsync
    calls: list[int] = []

    def tracking_fsync(descriptor: int) -> None:
        calls.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(lifecycle_case.module.os, "fsync", tracking_fsync)
    monkeypatch.setattr(lifecycle_case.module.os, "fchown", lambda *_args: None)
    try:
        lifecycle_case.module.atomic_create_at(
            opened, "accepted-outcome", b"exact-pointer\n", "test pointer"
        )
    finally:
        opened.close()
    assert pointer_root.joinpath("accepted-outcome").read_bytes() == b"exact-pointer\n"
    assert len(calls) >= 3
    assert calls.count(directory_descriptor) >= 2


def test_atomic_outcome_pointer_reports_retained_stage_on_cleanup_failure(
    lifecycle_case: LifecycleCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    pointer_root = private_dir(lifecycle_case.root / "pointer-cleanup-failure")
    opened = lifecycle_case.module.PinnedDirectory.open(
        os.fspath(pointer_root),
        "pointer cleanup root",
        allowed_owner_uids={0, os.geteuid(), os.getegid()},
        final_owner_uid=os.geteuid(),
    )
    original_unlink = lifecycle_case.module.os.unlink

    def fail_after_stage(point: str) -> None:
        if point == "after-accepted-outcome-stage":
            raise lifecycle_case.module.LifecycleError("injected pointer failure")

    def fail_stage_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if path.startswith(".accepted-outcome-stage-"):
            raise PermissionError("injected cleanup failure")
        original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(lifecycle_case.module, "fault", fail_after_stage)
    monkeypatch.setattr(lifecycle_case.module.os, "unlink", fail_stage_unlink)
    monkeypatch.setattr(lifecycle_case.module.os, "fchown", lambda *_args: None)
    try:
        with pytest.raises(
            lifecycle_case.module.LifecycleError,
            match="retained after cleanup failure",
        ):
            lifecycle_case.module.atomic_create_at(
                opened, "accepted-outcome", b"exact-pointer\n", "test pointer"
            )
    finally:
        opened.close()
    assert not pointer_root.joinpath("accepted-outcome").exists()
    assert len(tuple(pointer_root.glob(".accepted-outcome-stage-*"))) == 1


@pytest.mark.parametrize("race", ("exact", "conflict"))
def test_outcome_pointer_publication_race_never_clobbers(
    lifecycle_case: LifecycleCase,
    race: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    outcome = lifecycle_case.module.parse_record(
        package.joinpath("outcome").read_bytes(),
        lifecycle_case.module.OUTCOME_FIELDS,
        "outcome",
    )
    pointer_values = {
        "schema": "1",
        "kind": "host-local-accepted-signer-outcome",
        "service": SERVICE,
        "target": TARGET,
        "request_id": REQUEST_ID,
        "artifact_manifest_sha256": lifecycle_case.artifact_sha256,
        "deployment_sha256": finished["deployment_sha256"],
        "outcome_sha256": outcome_sha if race == "exact" else "f" * 64,
        "decision_sha256": digest(package / "decision"),
        "action": outcome["action"],
        "state": outcome["state"],
        "resulting_active_request_id": outcome["resulting_active_request_id"],
    }
    pointer = record(lifecycle_case.module.ACCEPTED_OUTCOME_FIELDS, pointer_values)
    process = subprocess.Popen(
        lifecycle_case.runner.argv([
            *lifecycle_case.common("outcome-import", config=True),
            "--trust-id", "reviewed-v1",
            "--request-id", REQUEST_ID,
            "--artifact-sha256", lifecycle_case.artifact_sha256,
            "--deployment-sha256", finished["deployment_sha256"],
            "--outcome-sha256", outcome_sha,
            "--outcome-dir", package,
        ]),
        env=lifecycle_case.runner.environment(lifecycle_case.environment({
            "PLATFORM_PKI_LIFECYCLE_PAUSE_AT": "before-accepted-outcome-publication"
        })),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    history = lifecycle_case.state / "outcomes" / REQUEST_ID / outcome_sha
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if history.is_dir():
            break
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"outcome import exited before pointer race: {stdout} {stderr}")
        time.sleep(0.01)
    else:
        process.kill()
        pytest.fail("outcome import did not reach pointer race seam")
    private_file(lifecycle_case.state / "accepted-outcome", pointer)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode != 0
    assert stdout == ""
    assert "appeared during no-clobber publication" in stderr
    assert lifecycle_case.state.joinpath("accepted-outcome").read_bytes() == pointer
    assert not tuple(lifecycle_case.state.glob(".accepted-outcome-stage-*"))
    rerun = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"]
    )
    if race == "exact":
        assert result_json(rerun)["status"] == "existing"
    else:
        assert_failure(rerun)


def test_outcome_import_rejects_remote_package_replacement_before_publication(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    argv = [
        *lifecycle_case.common("outcome-import", config=True),
        "--trust-id", "reviewed-v1",
        "--request-id", REQUEST_ID,
        "--artifact-sha256", lifecycle_case.artifact_sha256,
        "--deployment-sha256", finished["deployment_sha256"],
        "--outcome-sha256", outcome_sha,
        "--outcome-dir", package,
    ]
    process = subprocess.Popen(
        lifecycle_case.runner.argv(argv),
        env=lifecycle_case.runner.environment(
            lifecycle_case.environment(
                {"PLATFORM_PKI_LIFECYCLE_PAUSE_AT": "before-outcome-history-publication"}
            )
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    request_history = lifecycle_case.state / "outcomes" / REQUEST_ID
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        stages = tuple(request_history.glob(".outcome-stage-*"))
        if stages and {path.name for path in stages[0].iterdir()} == set(
            lifecycle_case.module.OUTCOME_NAMES
        ):
            break
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "outcome import exited before reaching its publication race seam\n"
                f"stdout: {stdout}\nstderr: {stderr}"
            )
        time.sleep(0.01)
    else:
        process.kill()
        pytest.fail("outcome import did not reach its publication race seam")

    signature = package / "outcome.sig"
    signature.write_bytes(signature.read_bytes())
    signature.chmod(0o600)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode != 0
    assert stdout == ""
    assert "imported signer-outcome package file outcome.sig path binding changed" in stderr
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()
    assert not (request_history / outcome_sha).exists()
    assert not tuple(request_history.glob(".outcome-stage-*"))

    assert result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))["status"] == "imported"


def test_outcome_import_rejects_unresolved_journal_and_wrong_coordinates(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    assert_failure(lifecycle_case.import_outcome(
        package, "f" * 64, finished["deployment_sha256"],
    ))
    private_file(lifecycle_case.state / "request.journal", b"unresolved\n")
    assert_failure(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


@pytest.mark.parametrize("mismatch", ("active", "rollback", "evidence"))
def test_outcome_import_rejects_live_target_and_evidence_mismatch(
    lifecycle_case: LifecycleCase,
    mismatch: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    if mismatch == "active":
        path = lifecycle_case.state / "active"
        values = lifecycle_case.module.parse_record(
            path.read_bytes(), lifecycle_case.module.ACTIVE_FIELDS, "active"
        )
        values["certificate_sha256"] = "f" * 64
    elif mismatch == "rollback":
        path = lifecycle_case.state / "rollback"
        values = lifecycle_case.module.parse_record(
            path.read_bytes(), lifecycle_case.module.ROLLBACK_FIELDS, "rollback"
        )
        values["predecessor_certificate_sha256"] = "f" * 64
    else:
        path = Path(finished["evidence_path"]) / "deployment.sig"
        path.write_bytes(b"conflicting target evidence\n")
        path.chmod(0o600)
        values = None
    if values is not None:
        private_file(path, record(
            lifecycle_case.module.ACTIVE_FIELDS
            if mismatch == "active"
            else lifecycle_case.module.ROLLBACK_FIELDS,
            values,
        ))

    assert_failure(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


def test_outcome_import_rejects_conflicting_pointer_and_unknown_history_state(
    lifecycle_case: LifecycleCase,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    result_json(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    pointer = lifecycle_case.state / "accepted-outcome"
    values = lifecycle_case.module.parse_record(
        pointer.read_bytes(), lifecycle_case.module.ACCEPTED_OUTCOME_FIELDS, "pointer"
    )
    values["outcome_sha256"] = "f" * 64
    private_file(pointer, record(lifecycle_case.module.ACCEPTED_OUTCOME_FIELDS, values))
    assert_failure(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert_failure(lifecycle_case.status())

    private_file(pointer, record(
        lifecycle_case.module.ACCEPTED_OUTCOME_FIELDS,
        {**values, "outcome_sha256": outcome_sha},
    ))
    unknown = private_dir(
        lifecycle_case.state / "outcomes" / REQUEST_ID / ".outcome-stage-unknown"
    )
    private_file(unknown / "partial", b"partial\n")
    assert_failure(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert_failure(lifecycle_case.status())


@pytest.mark.parametrize("count", (1, 2))
def test_outcome_import_rejects_retained_pointer_stage_ambiguity(
    lifecycle_case: LifecycleCase,
    count: int,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    for index in range(count):
        private_file(
            lifecycle_case.state / f".accepted-outcome-stage-{'a' * 31}{index}",
            b"retained pointer evidence\n",
        )
    failure = lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"]
    )
    assert_failure(failure)
    assert "retained accepted signer outcome pointer stage" in failure.stderr
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()


@pytest.mark.parametrize("alteration", ("namespace", "decision", "deployment"))
def test_outcome_import_rejects_signature_and_digest_cross_binding_changes(
    lifecycle_case: LifecycleCase,
    alteration: str,
) -> None:
    _activated, finished, _observation = activate_and_finish(lifecycle_case)
    package, outcome_sha = lifecycle_case.outcome_package(Path(finished["evidence_path"]))
    if alteration == "namespace":
        package.joinpath("outcome.sig").unlink()
        lifecycle_case.runner.run([
            "ssh-keygen", "-Y", "sign", "-f", lifecycle_case.signing_key,
            "-n", "wrong-outcome-namespace", package / "outcome",
        ]).assert_success()
        package.joinpath("outcome.sig").chmod(0o600)
    elif alteration == "decision":
        private_file(package / "decision", package.joinpath("decision").read_bytes() + b"extra=x\n")
    else:
        private_file(package / "deployment", package.joinpath("deployment").read_bytes() + b"extra=x\n")
    before = tree_snapshot(lifecycle_case.state)
    assert_failure(lifecycle_case.import_outcome(
        package, outcome_sha, finished["deployment_sha256"],
    ))
    assert tree_snapshot(lifecycle_case.state) == before


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
    lifecycle_case.prepare_response()
    lifecycle_case.expire_request()

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
                "--trust-id",
                "reviewed-v1",
                "--request-id",
                REQUEST_ID,
            ]
        )
    )
    assert not (lifecycle_case.versions_root / f".ingress-{REQUEST_ID}").exists()
    assert result_json(lifecycle_case.abandon_expired())["status"] == "abandoned"


def test_response_preparation_requires_exact_pending_request(
    lifecycle_case: LifecycleCase,
) -> None:
    shutil.rmtree(lifecycle_case.pending)

    assert_failure(
        lifecycle_case.run(
            [
                *lifecycle_case.common("response-prepare"),
                "--trust-id",
                "reviewed-v1",
                "--request-id",
                REQUEST_ID,
            ]
        )
    )
    assert not (lifecycle_case.versions_root / f".ingress-{REQUEST_ID}").exists()


def test_expired_request_cannot_be_collected_or_consume_response(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.prepare_response()
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


@pytest.mark.parametrize(
    ("created_offset", "accepted"),
    ((-300, True), (-301, False)),
)
def test_response_install_allows_only_bounded_creation_before_validity(
    lifecycle_case: LifecycleCase,
    created_offset: int,
    accepted: bool,
) -> None:
    response = dict(
        line.split("=", 1)
        for line in (
            lifecycle_case.root / "response-source/response"
        ).read_text(encoding="ascii").splitlines()
    )
    lifecycle_case.set_response_created_epoch(
        int(response["not_before_epoch"]) + created_offset
    )
    lifecycle_case.prepare_response()

    result = lifecycle_case.install_response()
    if accepted:
        assert result_json(result)["status"] == "installed"
    else:
        assert_failure(result)
        assert "certificate validity or signed metadata is invalid" in result.stderr


def test_response_install_rejects_future_creation_metadata(
    lifecycle_case: LifecycleCase,
) -> None:
    lifecycle_case.set_response_created_epoch(int(time.time()) + 600)
    lifecycle_case.prepare_response()

    result = lifecycle_case.install_response()
    assert_failure(result)
    assert "certificate validity or signed metadata is invalid" in result.stderr


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
    package, outcome_sha = lifecycle_case.outcome_package(evidence)
    restored_config = json.loads(
        lifecycle_case.zot_config.read_text(encoding="ascii")
    )
    restored_certificate = Path(restored_config["http"]["tls"]["cert"])
    restored_certificate_bytes = restored_certificate.read_bytes()
    private_file(
        restored_certificate,
        lifecycle_case.versions_root.joinpath(
            REQUEST_ID, "fullchain.crt"
        ).read_bytes(),
        0o644,
    )
    mismatched = lifecycle_case.import_outcome(
        package, outcome_sha, abandoned["deployment_sha256"],
    )
    assert_failure(mismatched)
    assert "restored Zot certificate and rollback evidence" in mismatched.stderr
    assert not lifecycle_case.state.joinpath("accepted-outcome").exists()
    private_file(restored_certificate, restored_certificate_bytes, 0o644)
    imported = result_json(lifecycle_case.import_outcome(
        package, outcome_sha, abandoned["deployment_sha256"],
    ))
    assert imported["status"] == "imported"
    assert imported["action"] == "abandon"
    assert imported["state"] == "abandoned"
    status = result_json(lifecycle_case.status())
    assert status["status"] == "signer-outcome-abandoned"
    assert status["signer_outcome_state"] == "abandoned"
    assert status["evidence_state"] == "controller-exported"
    assert status["active_request_id"] == "none"
    assert status["required_action"] == "none"


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
