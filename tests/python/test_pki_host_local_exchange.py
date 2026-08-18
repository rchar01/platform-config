from __future__ import annotations

import ipaddress
import errno
import json
import os
import posixpath
import shlex
import shutil
import stat
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from ansible.errors import AnsibleActionFail
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from plugins.action import platform_pki_request_collection as collection_action
from plugins.action import platform_pki_evidence_collection as evidence_action
from plugins.action import platform_pki_evidence_status as evidence_status_action
from plugins.action import platform_pki_response_ingress as ingress_action
from plugins.action import platform_pki_response_intake as response_action
from plugins.action import platform_pki_outcome_import as outcome_action
from plugins.module_utils import platform_pki_exchange as exchange_module
from plugins.module_utils.platform_pki_exchange import (
    ARTIFACT_FIELDS,
    DEPLOYMENT_FIELDS,
    EVIDENCE_NAMES,
    DECISION_FIELDS,
    OUTCOME_FIELDS,
    OUTCOME_NAMES,
    POLICY_FIELDS,
    RECEIPT_FIELDS,
    REQUEST_FIELDS,
    REQUEST_PUBLICATION_NAMES,
    REQUEST_REMOTE_NAMES,
    RESPONSE_FIELDS,
    RESPONSE_NAMES,
    TRUST_NAMES,
    VALIDATION_BOUNDARY_FIELDS,
    VALIDATION_RESULT_FIELDS,
    ExchangeError,
    DescriptorCleanupError,
    PinnedDirectory,
    PinnedTree,
    collection_receipt,
    parse_record,
    pin_trust,
    prepare_request_parent,
    prepare_evidence_parent,
    publish_exact_tree,
    serialize_record,
    sha256,
    validate_collection_receipt,
    validate_evidence_snapshot,
    validate_outcome_snapshot,
    validate_request_payload,
    validate_response_snapshot,
)


pytestmark = pytest.mark.pki
REQUEST_ID = "0123456789abcdef0123456789abcdef"
SERVICE = "registry-test"
TARGET = "test-target"
RESPONSE_PRINCIPAL = "test-response"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def _private_file(path: Path, data: bytes | str) -> Path:
    if isinstance(data, str):
        path.write_text(data, encoding="ascii")
    else:
        path.write_bytes(data)
    path.chmod(0o600)
    return path


def _ssh_key(root: Path) -> tuple[Path, str]:
    key = root / "signing-key"
    subprocess.run(
        ("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.fspath(key)),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    algorithm, payload, *_ = key.with_suffix(".pub").read_text(encoding="ascii").split()
    return key, f"{algorithm} {payload}"


def _ssh_sign(path: Path, key: Path, namespace: str) -> Path:
    subprocess.run(
        ("ssh-keygen", "-Y", "sign", "-f", os.fspath(key), "-n", namespace, os.fspath(path)),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    signature = Path(f"{path}.sig")
    signature.chmod(0o600)
    return signature


def _trust_tree(root: Path, public: str) -> tuple[Path, dict[str, str], dict[str, str]]:
    trust = _private_dir(root / "trust")
    principals = {
        "requesters.allowed_signers": TARGET,
        "approvers.allowed_signers": "test-approver",
        "responses.allowed_signers": RESPONSE_PRINCIPAL,
        "deployers.allowed_signers": TARGET,
    }
    for name, principal in principals.items():
        _private_file(trust / name, f"{principal} {public}\n")
    policy = serialize_record(
        POLICY_FIELDS,
        {
            "schema": "2",
            "request_namespace": "platform-pki-csr-request-v1",
            "approval_namespace": "platform-pki-csr-approval-v1",
            "response_namespace": "platform-pki-csr-response-v1",
            "deployment_namespace": "platform-pki-csr-deployment-v1",
            "request_max_age_seconds": "604800",
            "sole_operator_min_delay_seconds": "86400",
            "approval_max_age_seconds": "86400",
            "deployment_max_age_seconds": "86400",
            "clock_skew_seconds": "300",
            "approver_principal": "test-approver",
            "response_principal": RESPONSE_PRINCIPAL,
        },
        "policy",
    )
    _private_file(trust / "policy", policy)
    paths = {name: os.fspath(trust / name) for name in TRUST_NAMES}
    digests = {name: sha256((trust / name).read_bytes()) for name in TRUST_NAMES}
    return trust, paths, digests


def _request_material(
    root: Path,
) -> tuple[
    dict[str, bytes],
    dict[str, object],
    Path,
    dict[str, str],
    dict[str, str],
    Path,
    ec.EllipticCurvePrivateKey,
]:
    key, public = _ssh_key(root)
    _trust, trust_paths, trust_digests = _trust_tree(root, public)
    request_dir = _private_dir(root / "request-source")
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "registry.test"),)))
        .add_extension(
            x509.SubjectAlternativeName(
                (
                    x509.DNSName("registry.test"),
                    x509.DNSName(TARGET),
                    x509.IPAddress(ipaddress.ip_address("192.0.2.61")),
                )
            ),
            critical=False,
        )
        .sign(leaf_key, hashes.SHA384())
        .public_bytes(serialization.Encoding.PEM)
    )
    spki = leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())
    request = serialize_record(
        REQUEST_FIELDS,
        {
            "schema": "1",
            "request_id": REQUEST_ID,
            "nonce": "a" * 64,
            "created_epoch": str(now - 1),
            "expires_epoch": str(now + 3600),
            "operation": "migrate",
            "service": SERVICE,
            "target": TARGET,
            "requester_principal": TARGET,
            "inventory_sha256": "b" * 64,
            "csr_sha256": sha256(csr),
            "csr_spki_sha256": sha256(spki),
            "current_cert_sha256": "c" * 64,
            "profile": "server-p384-sha384-v1",
            "response_principal": RESPONSE_PRINCIPAL,
        },
        "request",
    )
    _private_file(request_dir / "tls.csr", csr)
    request_path = _private_file(request_dir / "request", request)
    signature = _ssh_sign(request_path, key, "platform-pki-csr-request-v1")
    files = {
        "tls.csr": csr,
        "request": request,
        "request.sig": signature.read_bytes(),
    }
    bindings: dict[str, object] = {
        "request_id": REQUEST_ID,
        "service": SERVICE,
        "target": TARGET,
        "transport": "ssh",
        "transport_host_key_sha256": "d" * 64,
        "inventory_sha256": "b" * 64,
        "profile": "server-p384-sha384-v1",
        "requester_principal": TARGET,
        "response_principal": RESPONSE_PRINCIPAL,
        "common_name": "registry.test",
        "dns_sans": ["registry.test", TARGET],
        "ip_sans": ["192.0.2.61"],
        "expected_request_sha256": sha256(request),
        "expected_csr_sha256": sha256(csr),
        "expected_csr_spki_sha256": sha256(spki),
    }
    return files, bindings, request_dir, trust_paths, trust_digests, key, leaf_key


def _ca_usage() -> x509.KeyUsage:
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


def _response_material(
    root: Path,
    response_key: Path,
    leaf_key: ec.EllipticCurvePrivateKey,
    request_files: dict[str, bytes],
) -> tuple[Path, dict[str, object]]:
    request = parse_record(request_files["request"], REQUEST_FIELDS, "fixture request")
    now = int(time.time())
    before = datetime.fromtimestamp(now - 60, UTC)
    after = datetime.fromtimestamp(now + 86400, UTC)
    root_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "Test Root"),))
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA384())
    )
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate"),))
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(2)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA384())
    )
    leaf_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "registry.test"),))
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(intermediate_name)
        .public_key(leaf_key.public_key())
        .serial_number(0x1234)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,)), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                (
                    x509.DNSName("registry.test"),
                    x509.DNSName(TARGET),
                    x509.IPAddress(ipaddress.ip_address("192.0.2.61")),
                )
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA384())
    )
    leaf = leaf_cert.public_bytes(serialization.Encoding.PEM)
    intermediate = intermediate_cert.public_bytes(serialization.Encoding.PEM)
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM)
    chain = intermediate + root_pem
    fullchain = leaf + intermediate
    spki = leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    response_dir = _private_dir(root / "response-source")
    response = serialize_record(
        RESPONSE_FIELDS,
        {
            "schema": "1",
            "request_id": REQUEST_ID,
            "nonce": request["nonce"],
            "operation": request["operation"],
            "service": SERVICE,
            "target": TARGET,
            "request_sha256": sha256(request_files["request"]),
            "approval_sha256": "2" * 64,
            "inventory_sha256": request["inventory_sha256"],
            "csr_sha256": request["csr_sha256"],
            "csr_spki_sha256": sha256(spki),
            "certificate_sha256": sha256(leaf),
            "certificate_spki_sha256": sha256(spki),
            "chain_sha256": sha256(chain),
            "issuer_root": "g1",
            "issuer_intermediate": "g1-i1",
            "serial": "1234",
            "not_before_epoch": str(now - 60),
            "not_after_epoch": str(now + 86400),
            "candidate_state": "pending",
            "response_principal": RESPONSE_PRINCIPAL,
            "created_epoch": str(now),
        },
        "response",
    )
    response_path = _private_file(response_dir / "response", response)
    response_signature = _ssh_sign(
        response_path, response_key, "platform-pki-csr-response-v1"
    ).read_bytes()
    artifact = serialize_record(
        ARTIFACT_FIELDS,
        {
            "schema": "1",
            "kind": "certificate-export",
            "service": SERVICE,
            "request_id": REQUEST_ID,
            "operation": request["operation"],
            "target": TARGET,
            "source_kind": "csr-response",
            "source_response_sha256": sha256(response),
            "source_response_signature_sha256": sha256(response_signature),
            "certificate_sha256": sha256(leaf),
            "certificate_spki_sha256": sha256(spki),
            "chain_sha256": sha256(chain),
            "fullchain_sha256": sha256(fullchain),
            "issuer_root": "g1",
            "issuer_intermediate": "g1-i1",
            "serial": "1234",
            "not_before_epoch": str(now - 60),
            "not_after_epoch": str(now + 86400),
            "candidate_state": "pending",
            "deployment_state": "unfinalized",
            "response_principal": RESPONSE_PRINCIPAL,
            "created_epoch": str(now),
        },
        "artifact",
    )
    for name, data in (
        ("artifact", artifact),
        ("tls.crt", leaf),
        ("ca-chain.crt", chain),
        ("fullchain.crt", fullchain),
        ("response.sig", response_signature),
    ):
        _private_file(response_dir / name, data)
    bindings: dict[str, object] = {
        "request_id": REQUEST_ID,
        "service": SERVICE,
        "target": TARGET,
        "inventory_sha256": request["inventory_sha256"],
        "expected_artifact_sha256": sha256(artifact),
        "response_principal": RESPONSE_PRINCIPAL,
        "common_name": "registry.test",
        "dns_sans": ["registry.test", TARGET],
        "ip_sans": ["192.0.2.61"],
        "minimum_remaining_lifetime_seconds": 3600,
    }
    return response_dir, bindings


def _response_scenario(
    root: Path,
) -> tuple[Path, Path, dict[str, str], dict[str, str], dict[str, object]]:
    (
        files,
        request_bindings,
        request_source,
        trust_paths,
        trust_digests,
        response_key,
        leaf_key,
    ) = _request_material(root)
    exchange = _private_dir(root / "exchange")
    trust = pin_trust(trust_paths, trust_digests)
    source = PinnedTree.open(request_source, REQUEST_REMOTE_NAMES, "request source")
    parent = prepare_request_parent(exchange, SERVICE, REQUEST_ID)
    try:
        now = int(time.time())
        request = validate_request_payload(
            files, request_bindings, trust, source.files["request.sig"], now=now
        )
        receipt = collection_receipt(files, request_bindings, trust, now)
        validate_collection_receipt(
            receipt, files, request_bindings, trust, request, now=now
        )
        assert publish_exact_tree(
            parent,
            "trust",
            {name: trust[name].data for name in TRUST_NAMES},
        )
        assert publish_exact_tree(
            parent, "request", {**files, "collection-receipt": receipt}
        )
    finally:
        parent.close()
        source.close()
        for item in trust.values():
            item.close()
    response_dir, bindings = _response_material(
        root, response_key, leaf_key, files
    )
    bindings.update(
        {
            "response_dir": os.fspath(response_dir),
            "exchange_root": os.fspath(exchange),
            "trust_paths": trust_paths,
            "trust_sha256": trust_digests,
        }
    )
    return response_dir, exchange, trust_paths, trust_digests, bindings


def _replace_record_field(path: Path, field: str, value: str) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    replaced = False
    result: list[str] = []
    for line in lines:
        key, current = line.split("=", 1)
        if key == field:
            current = value
            replaced = True
        result.append(f"{key}={current}")
    assert replaced
    _private_file(path, "\n".join((*result, "")))


def _validate_response_scenario(
    response_dir: Path,
    exchange: Path,
    trust_paths: dict[str, str],
    trust_digests: dict[str, str],
    bindings: dict[str, object],
) -> dict[str, str]:
    source = PinnedTree.open(response_dir, RESPONSE_NAMES, "response source")
    request = PinnedTree.open(
        exchange / SERVICE / REQUEST_ID / "request",
        REQUEST_PUBLICATION_NAMES,
        "controller request publication",
    )
    trust = pin_trust(trust_paths, trust_digests)
    try:
        return validate_response_snapshot(
            source, request, bindings, trust, now=int(time.time())
        )
    finally:
        for item in trust.values():
            item.close()
        request.close()
        source.close()


def _ingress_material(root: Path) -> tuple[Path, Path, dict[str, str]]:
    exchange = _private_dir(root / "exchange")
    request_parent = _private_dir(exchange / SERVICE / REQUEST_ID)
    response = _private_dir(request_parent / "response")
    digests: dict[str, str] = {}
    for name in RESPONSE_NAMES:
        data = f"fixed response ingress bytes: {name}\n".encode("ascii")
        _private_file(response / name, data)
        digests[name] = sha256(data)
    return exchange, response, digests


def _evidence_material(
    root: Path,
) -> tuple[Path, Path, dict[str, object], Path]:
    response_source, exchange, _trust_paths, _trust_digests, _bindings = _response_scenario(root)
    request_parent_path = exchange / SERVICE / REQUEST_ID
    parent = PinnedDirectory.open(request_parent_path, "evidence fixture request parent")
    response_tree = PinnedTree.open(
        response_source, RESPONSE_NAMES, "evidence fixture response"
    )
    try:
        assert publish_exact_tree(parent, "response", response_tree.data)
    finally:
        response_tree.close()
        parent.close()
    request = parse_record(
        (request_parent_path / "request/request").read_bytes(),
        REQUEST_FIELDS,
        "evidence fixture request",
    )
    response = parse_record(
        (request_parent_path / "response/response").read_bytes(),
        RESPONSE_FIELDS,
        "evidence fixture response",
    )
    artifact = parse_record(
        (request_parent_path / "response/artifact").read_bytes(),
        ARTIFACT_FIELDS,
        "evidence fixture artifact",
    )
    artifact_sha = sha256((request_parent_path / "response/artifact").read_bytes())
    boundary = serialize_record(
        VALIDATION_BOUNDARY_FIELDS,
        {
            "schema": "1",
            "kind": "pki-validation-boundary",
            "service": SERVICE,
            "target": TARGET,
            "local_validator": TARGET,
            "remote_validator": "test-runner",
            "endpoint": "https://registry.test/v2/",
            "local_check": "platform-zot-local-active-tls-v1",
            "remote_check": "platform-oci-v2-read-only-strict-tls-v1",
        },
        "validation boundary",
    )
    now = int(time.time())
    deployment = serialize_record(
        DEPLOYMENT_FIELDS,
        {
            "schema": "1",
            "request_id": REQUEST_ID,
            "nonce": response["nonce"],
            "operation": response["operation"],
            "service": SERVICE,
            "target": TARGET,
            "request_sha256": sha256(
                (request_parent_path / "request/request").read_bytes()
            ),
            "response_sha256": sha256(
                (request_parent_path / "response/response").read_bytes()
            ),
            "response_signature_sha256": sha256(
                (request_parent_path / "response/response.sig").read_bytes()
            ),
            "candidate_sha256": "9" * 64,
            "artifact_request_id": REQUEST_ID,
            "artifact_manifest_sha256": artifact_sha,
            "certificate_sha256": artifact["certificate_sha256"],
            "certificate_spki_sha256": artifact["certificate_spki_sha256"],
            "chain_sha256": artifact["chain_sha256"],
            "fullchain_sha256": artifact["fullchain_sha256"],
            "action": "finalize",
            "result": "activated",
            "local_certificate_sha256": artifact["certificate_sha256"],
            "local_key_spki_sha256": artifact["certificate_spki_sha256"],
            "local_key_certificate_match": "true",
            "served_certificate_sha256": artifact["certificate_sha256"],
            "served_intermediate_sha256": "8" * 64,
            "validation_boundary_sha256": sha256(boundary),
            "validation_result": "passed",
            "activation_epoch": str(now - 10),
            "validation_epoch": str(now - 5),
            "rollback_state": "retained",
            "rollback_hold_until_epoch": str(now + 1209600),
            "deployment_principal": TARGET,
            "created_epoch": str(now),
            "expires_epoch": str(now + 3600),
        },
        "deployment",
    )
    deployment_sha = sha256(deployment)
    validation_result = serialize_record(
        VALIDATION_RESULT_FIELDS,
        {
            "schema": "1",
            "kind": "pki-validation-result",
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "artifact_manifest_sha256": artifact_sha,
            "validation_boundary_sha256": sha256(boundary),
            "action": "finalize",
            "result": "activated",
            "local_validator": TARGET,
            "remote_validator": "test-runner",
            "endpoint": "https://registry.test/v2/",
            "local_service_result": "passed",
            "local_tls_result": "passed",
            "remote_tls_result": "passed",
            "remote_application_result": "passed",
            "remote_http_status": "200",
            "remote_api_version": "registry/2.0",
            "remote_auth_challenge": "not-required",
            "served_certificate_sha256": artifact["certificate_sha256"],
            "served_intermediate_sha256": "8" * 64,
            "activation_epoch": str(now - 10),
            "validation_epoch": str(now - 5),
            "deployment_sha256": deployment_sha,
        },
        "validation result",
    )
    evidence_source = _private_dir(root / "target-evidence")
    deployment_path = _private_file(evidence_source / "deployment", deployment)
    signing_key = root / "signing-key"
    _ssh_sign(deployment_path, signing_key, "platform-pki-csr-deployment-v1")
    _private_file(evidence_source / "validation-boundary", boundary)
    result_path = _private_file(
        evidence_source / "validation-result", validation_result
    )
    _ssh_sign(result_path, signing_key, "platform-pki-csr-deployment-v1")
    args: dict[str, object] = {
        "lifecycle_helper_path": "/usr/local/libexec/platform-pki-host-local-lifecycle",
        "state_root": "/var/lib/platform-pki/state",
        "pending_root": "/var/lib/platform-pki/pending",
        "versions_root": "/var/lib/platform-pki/versions",
        "trust_id": "reviewed-v1",
        "exchange_root": os.fspath(exchange),
        "service": SERVICE,
        "target": TARGET,
        "request_id": REQUEST_ID,
        "artifact_sha256": artifact_sha,
        "deployment_sha256": deployment_sha,
    }
    assert request["request_id"] == REQUEST_ID
    return evidence_source, exchange, args, signing_key


def _publish_evidence_material(
    source: Path, exchange: Path, deployment_sha256: str
) -> Path:
    parent = PinnedDirectory.open(
        exchange / SERVICE / REQUEST_ID, "evidence publication request parent"
    )
    evidence_parent = prepare_evidence_parent(parent)
    tree = PinnedTree.open(source, EVIDENCE_NAMES, "evidence publication source")
    try:
        assert publish_exact_tree(
            evidence_parent, deployment_sha256, tree.data
        )
        return Path(evidence_parent.path) / deployment_sha256
    finally:
        tree.close()
        evidence_parent.close()
        parent.close()


def _outcome_material(
    root: Path,
) -> tuple[Path, Path, dict[str, object]]:
    evidence_source, exchange, args, signing_key = _evidence_material(root)
    evidence = _publish_evidence_material(
        evidence_source, exchange, str(args["deployment_sha256"])
    )
    workspace = exchange / SERVICE / REQUEST_ID
    deployment = parse_record(
        evidence.joinpath("deployment").read_bytes(), DEPLOYMENT_FIELDS, "deployment"
    )
    decision_values = {
        "schema": "1",
        "action": "finalize",
        "state": "finalized",
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
        "deployment_sha256": str(args["deployment_sha256"]),
        "deployment_signature_sha256": sha256(evidence.joinpath("deployment.sig").read_bytes()),
        "deployers_sha256": sha256(
            workspace.joinpath("trust/deployers.allowed_signers").read_bytes()
        ),
        "predecessor_kind": "managed",
        "predecessor_request_id": "none",
        "predecessor_certificate_sha256": "1" * 64,
        "predecessor_certificate_spki_sha256": "2" * 64,
        "predecessor_intermediate_sha256": "3" * 64,
        "predecessor_response_sha256": "none",
        "predecessor_artifact_manifest_sha256": "none",
        "predecessor_deployment_sha256": "none",
        "predecessor_decision_sha256": "none",
        "resulting_active_request_id": REQUEST_ID,
        "created_epoch": deployment["created_epoch"],
    }
    decision = serialize_record(DECISION_FIELDS, decision_values, "decision")
    outcome_values = {
        name: decision_values[name] for name in OUTCOME_FIELDS if name in decision_values
    }
    outcome_values.update(
        kind="csr-signer-outcome",
        decision_sha256=sha256(decision),
        outcome_principal=RESPONSE_PRINCIPAL,
    )
    outcome = serialize_record(OUTCOME_FIELDS, outcome_values, "outcome")
    package = _private_dir(root / "outcome-package")
    for name, data in (
        ("outcome", outcome),
        ("deployment", evidence.joinpath("deployment").read_bytes()),
        ("deployment.sig", evidence.joinpath("deployment.sig").read_bytes()),
        (
            "deployers.allowed_signers",
            workspace.joinpath("trust/deployers.allowed_signers").read_bytes(),
        ),
        ("decision", decision),
    ):
        _private_file(package / name, data)
    _ssh_sign(package / "outcome", signing_key, "platform-pki-csr-outcome-v1")
    args.update(
        outcome_dir=os.fspath(package),
        outcome_sha256=sha256(outcome),
        response_principal=RESPONSE_PRINCIPAL,
        zot_config_path="/etc/zot/config.json",
    )
    return package, exchange, args


def _workspace_snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
    snapshot: list[tuple[object, ...]] = []
    for item in sorted((path, *path.rglob("*"))):
        metadata = item.lstat()
        snapshot.append(
            (
                os.fspath(item.relative_to(path.parent)),
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                sha256(item.read_bytes()) if item.is_file() else "directory",
            )
        )
    return tuple(snapshot)


def test_fixed_file_and_action_argument_allowlists_exclude_private_keys() -> None:
    assert REQUEST_REMOTE_NAMES == ("tls.csr", "request", "request.sig")
    assert set(REQUEST_PUBLICATION_NAMES) == {
        "tls.csr",
        "request",
        "request.sig",
        "collection-receipt",
    }
    assert OUTCOME_NAMES == (
        "outcome", "outcome.sig", "deployment", "deployment.sig",
        "deployers.allowed_signers", "decision",
    )
    assert "tls.key" not in OUTCOME_NAMES
    assert set(RESPONSE_NAMES) == {
        "artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response", "response.sig",
    }
    assert all("key" not in name for name in (*REQUEST_REMOTE_NAMES, *RESPONSE_NAMES))
    assert collection_action.ACTION_ARGUMENTS == {
        "lifecycle_helper_path", "state_root", "pending_root", "versions_root",
        "trust_id", "request_id", "exchange_root", "service", "target",
        "transport", "transport_host_key_sha256", "inventory_sha256", "profile",
        "requester_principal", "response_principal", "common_name", "dns_sans",
        "ip_sans", "trust_paths", "trust_sha256", "expected_request_sha256",
        "expected_csr_sha256", "expected_csr_spki_sha256",
    }
    assert response_action.ACTION_ARGUMENTS == {
        "response_dir", "exchange_root", "service", "target", "request_id",
        "inventory_sha256", "expected_artifact_sha256", "response_principal",
        "trust_paths", "trust_sha256", "common_name", "dns_sans", "ip_sans",
        "minimum_remaining_lifetime_seconds",
    }
    assert ingress_action.ACTION_ARGUMENTS == {
        "exchange_root", "service", "request_id", "ingress_root", "artifact_sha256",
    }
    assert evidence_action.ACTION_ARGUMENTS == {
        "lifecycle_helper_path", "state_root", "pending_root", "versions_root",
        "trust_id", "exchange_root", "service", "target", "request_id",
        "artifact_sha256", "deployment_sha256",
    }
    assert evidence_status_action.ACTION_ARGUMENTS == {
        "exchange_root", "service", "target", "request_id", "artifact_sha256",
        "deployment_sha256",
    }
    assert outcome_action.ACTION_ARGUMENTS == {
        "lifecycle_helper_path", "state_root", "pending_root", "versions_root",
        "zot_config_path",
        "trust_id", "exchange_root", "outcome_dir", "service", "target",
        "request_id", "artifact_sha256", "deployment_sha256", "outcome_sha256",
        "response_principal",
    }
    assert EVIDENCE_NAMES == (
        "deployment", "deployment.sig", "validation-boundary", "validation-result",
        "validation-result.sig",
    )
    assert all("key" not in name for name in EVIDENCE_NAMES)
    assert ingress_action.response_source_path(
        "/outside-git/exchange", SERVICE, REQUEST_ID
    ) == f"/outside-git/exchange/{SERVICE}/{REQUEST_ID}/response"
    expected_ingress = f"/var/lib/zot/tls-versions/.ingress-{REQUEST_ID}"
    assert ingress_action.validate_ingress_root(expected_ingress, REQUEST_ID) == expected_ingress
    with pytest.raises(ExchangeError):
        ingress_action.validate_ingress_root(
            f"/var/lib/zot/other/.ingress-{REQUEST_ID}", REQUEST_ID
        )
    with pytest.raises(AnsibleActionFail):
        collection_action._remote_path("/var/lib/pending/" + REQUEST_ID, "tls.key")


def _validate_outcome_fixture(
    package_path: Path, exchange: Path, args: dict[str, object]
) -> dict[str, str]:
    workspace = exchange / SERVICE / REQUEST_ID
    package = PinnedTree.open(package_path, OUTCOME_NAMES, "test outcome package")
    request = PinnedTree.open(
        workspace / "request", REQUEST_PUBLICATION_NAMES, "test request"
    )
    response = PinnedTree.open(
        workspace / "response", RESPONSE_NAMES, "test response"
    )
    trust = PinnedTree.open(workspace / "trust", TRUST_NAMES, "test trust")
    evidence = PinnedTree.open(
        workspace / "evidence" / str(args["deployment_sha256"]),
        EVIDENCE_NAMES,
        "test evidence",
    )
    try:
        return validate_outcome_snapshot(
            package, evidence, request, response, trust, args, now=int(time.time())
        )
    finally:
        evidence.close()
        trust.close()
        response.close()
        request.close()
        package.close()


def _rewrite_signed_outcome_decision(
    package: Path,
    signing_key: Path,
    updates: dict[str, str],
) -> None:
    decision = parse_record(
        (package / "decision").read_bytes(), DECISION_FIELDS, "fixture decision"
    )
    decision.update(updates)
    decision_bytes = serialize_record(DECISION_FIELDS, decision, "fixture decision")
    _private_file(package / "decision", decision_bytes)
    outcome = parse_record(
        (package / "outcome").read_bytes(), OUTCOME_FIELDS, "fixture outcome"
    )
    for name, value in updates.items():
        if name in OUTCOME_FIELDS:
            outcome[name] = value
    outcome["decision_sha256"] = sha256(decision_bytes)
    _private_file(
        package / "outcome",
        serialize_record(OUTCOME_FIELDS, outcome, "fixture outcome"),
    )
    (package / "outcome.sig").unlink()
    _ssh_sign(package / "outcome", signing_key, "platform-pki-csr-outcome-v1")


def test_outcome_snapshot_authenticates_exact_package_and_cross_bindings(
    isolated_test_dir: Path,
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    assert metadata["action"] == "finalize"
    assert metadata["state"] == "finalized"
    assert metadata["resulting_active_request_id"] == REQUEST_ID
    assert metadata["outcome_sha256"] == args["outcome_sha256"]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("service", "other-service"),
        ("target", "other-target"),
        ("request_id", "f" * 32),
        ("operation", "renew"),
        ("request_sha256", "0" * 64),
        ("response_sha256", "0" * 64),
        ("response_signature_sha256", "0" * 64),
        ("candidate_sha256", "0" * 64),
        ("artifact_manifest_sha256", "0" * 64),
        ("certificate_sha256", "0" * 64),
        ("certificate_spki_sha256", "0" * 64),
        ("chain_sha256", "0" * 64),
        ("fullchain_sha256", "0" * 64),
        ("deployment_sha256", "0" * 64),
        ("deployment_signature_sha256", "0" * 64),
        ("deployers_sha256", "0" * 64),
        ("action", "abandon"),
        ("created_epoch", "1"),
    ),
)
def test_outcome_snapshot_rejects_each_signed_decision_deployment_mismatch(
    isolated_test_dir: Path,
    field: str,
    value: str,
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    updates = {field: value}
    if field == "action":
        updates.update(state="abandoned", resulting_active_request_id="none")
    _rewrite_signed_outcome_decision(
        package, isolated_test_dir / "signing-key", updates
    )
    args["outcome_sha256"] = sha256((package / "outcome").read_bytes())
    with pytest.raises(ExchangeError, match="cross-binding"):
        _validate_outcome_fixture(package, exchange, args)


@pytest.mark.parametrize(
    "alteration",
    ("namespace", "principal", "decision-order", "extra", "deployment", "trust"),
)
def test_outcome_snapshot_rejects_signature_record_and_package_mismatch(
    isolated_test_dir: Path,
    alteration: str,
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    if alteration == "namespace":
        package.joinpath("outcome.sig").unlink()
        _ssh_sign(
            package / "outcome",
            isolated_test_dir / "signing-key",
            "wrong-outcome-namespace",
        )
    elif alteration == "principal":
        args["response_principal"] = "wrong-response"
    elif alteration == "decision-order":
        lines = package.joinpath("decision").read_text(encoding="ascii").splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        _private_file(package / "decision", "\n".join(lines) + "\n")
    elif alteration == "extra":
        _private_file(package / "unexpected", b"extra\n")
    elif alteration == "deployment":
        _private_file(package / "deployment", b"replacement\n")
    else:
        _private_file(package / "deployers.allowed_signers", b"other ssh-ed25519 AAAA\n")
    with pytest.raises((ExchangeError, OSError)):
        _validate_outcome_fixture(package, exchange, args)


@pytest.mark.parametrize("unsafe", ("mode", "hardlink", "symlink"))
def test_outcome_source_rejects_unsafe_file_metadata(
    isolated_test_dir: Path,
    unsafe: str,
) -> None:
    package, _exchange, _args = _outcome_material(isolated_test_dir)
    outcome = package / "outcome"
    if unsafe == "mode":
        outcome.chmod(0o640)
    elif unsafe == "hardlink":
        os.link(outcome, package.parent / "outcome-link")
    else:
        outcome.unlink()
        outcome.symlink_to(package / "decision")
    with pytest.raises((ExchangeError, OSError)):
        PinnedTree.open(package, OUTCOME_NAMES, "unsafe outcome package")


def test_outcome_remote_metadata_validation_rejects_unsafe_stage_objects() -> None:
    directory = {
        "exists": True,
        "isdir": True,
        "islnk": False,
        "uid": 0,
        "gid": 0,
        "mode": "0700",
        "rusr": True,
        "wusr": True,
        "xusr": True,
        "rgrp": False,
        "wgrp": False,
        "xgrp": False,
        "roth": False,
        "woth": False,
        "xoth": False,
        "dev": 1,
        "inode": 2,
    }
    file_metadata = {
        **directory,
        "isdir": False,
        "isreg": True,
        "mode": "0600",
        "nlink": 1,
        "size": 16,
        "xusr": False,
        "mtime": 1.0,
        "ctime": 1.0,
        "checksum": "a" * 64,
    }
    assert outcome_action._directory_identity(directory)
    assert outcome_action._file_identity(
        file_metadata, "outcome", "a" * 64
    )
    for unsafe in (
        {**directory, "mode": "0755"},
        {**directory, "uid": 1000},
        {**directory, "islnk": True},
    ):
        with pytest.raises(ExchangeError):
            outcome_action._directory_identity(unsafe)
    for unsafe in (
        {**file_metadata, "mode": "0640"},
        {**file_metadata, "nlink": 2},
        {**file_metadata, "checksum": "b" * 64},
        {**file_metadata, "islnk": True},
    ):
        with pytest.raises(ExchangeError):
            outcome_action._file_identity(unsafe, "outcome", "a" * 64)


def _inject_early_close_failure(
    monkeypatch: pytest.MonkeyPatch, failed_descriptor: int
) -> tuple[list[int], Any]:
    real_close = exchange_module.os.close
    attempted: list[int] = []
    failed = False

    def close(descriptor: int) -> None:
        nonlocal failed
        attempted.append(descriptor)
        if descriptor == failed_descriptor and not failed:
            failed = True
            raise OSError("injected descriptor close failure")
        real_close(descriptor)

    monkeypatch.setattr(exchange_module.os, "close", close)
    return attempted, real_close


def test_pinned_directory_close_attempts_all_ancestors_and_retains_failure(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_dir(isolated_test_dir / "close-directory/a/b")
    pinned = PinnedDirectory.open(path, "close directory")
    expected = list(reversed(pinned.descriptors))
    failed_descriptor = expected[0]
    attempted, real_close = _inject_early_close_failure(
        monkeypatch, failed_descriptor
    )
    with pytest.raises(DescriptorCleanupError) as failure:
        pinned.close()
    monkeypatch.setattr(exchange_module.os, "close", real_close)
    assert attempted == expected
    assert pinned.descriptors == [failed_descriptor]
    assert failure.value.failed_descriptors == [failed_descriptor]
    pinned.close()
    assert pinned.descriptors == []


def test_pinned_file_close_attempts_file_and_all_parent_descriptors(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_file(
        _private_dir(isolated_test_dir / "close-file") / "outcome", b"outcome\n"
    )
    pinned = exchange_module.PinnedFile.open(path, "close file")
    failed_descriptor = pinned.descriptor
    expected = [failed_descriptor, *reversed(pinned.parent.descriptors)]
    attempted, real_close = _inject_early_close_failure(
        monkeypatch, failed_descriptor
    )
    with pytest.raises(DescriptorCleanupError) as failure:
        pinned.close()
    monkeypatch.setattr(exchange_module.os, "close", real_close)
    assert attempted == expected
    assert pinned.descriptor == failed_descriptor
    assert pinned.parent.descriptors == []
    assert failure.value.failed_descriptors == [failed_descriptor]
    pinned.close()
    assert pinned.descriptor == -1


def test_pinned_tree_close_attempts_every_file_and_directory_descriptor(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_dir(isolated_test_dir / "close-tree")
    for name in OUTCOME_NAMES:
        _private_file(path / name, f"{name}\n")
    pinned = PinnedTree.open(path, OUTCOME_NAMES, "close tree")
    file_descriptors = [source.descriptor for source in pinned.files.values()]
    directory_descriptors = list(reversed(pinned.directory.descriptors))
    failed_descriptor = file_descriptors[0]
    attempted, real_close = _inject_early_close_failure(
        monkeypatch, failed_descriptor
    )
    with pytest.raises(DescriptorCleanupError) as failure:
        pinned.close()
    monkeypatch.setattr(exchange_module.os, "close", real_close)
    assert attempted == [*file_descriptors, *directory_descriptors]
    assert list(pinned.files) == [OUTCOME_NAMES[0]]
    assert pinned.files[OUTCOME_NAMES[0]].descriptor == failed_descriptor
    assert pinned.directory.descriptors == []
    assert failure.value.failed_descriptors == [failed_descriptor]
    pinned.close()
    assert not pinned.files


def test_pinned_tree_construction_cleanup_attempts_all_and_supports_retry(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_dir(isolated_test_dir / "failed-tree-construction")
    for name in OUTCOME_NAMES:
        _private_file(path / name, f"{name}\n")
    (path / OUTCOME_NAMES[0]).chmod(0o640)
    real_close = exchange_module.os.close
    attempted: list[int] = []
    first = True

    def close(descriptor: int) -> None:
        nonlocal first
        attempted.append(descriptor)
        if first:
            first = False
            raise OSError("injected construction cleanup failure")
        real_close(descriptor)

    monkeypatch.setattr(exchange_module.os, "close", close)
    with pytest.raises(DescriptorCleanupError) as failure:
        PinnedTree.open(path, OUTCOME_NAMES, "failed tree construction")
    monkeypatch.setattr(exchange_module.os, "close", real_close)
    assert len(attempted) > 1
    assert len(failure.value.failed_descriptors) == 1
    failure.value.retry_close()
    assert failure.value.failed_descriptors == []


def test_outcome_action_retries_constructor_cleanup_without_masking_primary(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    package.joinpath(OUTCOME_NAMES[0]).chmod(0o640)
    remote = _OutcomeRemote(package, args, metadata)
    real_close = exchange_module.os.close
    attempted: list[int] = []
    failed_descriptor: list[int] = []

    def close(descriptor: int) -> None:
        attempted.append(descriptor)
        if not failed_descriptor:
            failed_descriptor.append(descriptor)
            raise OSError("injected constructor close failure")
        real_close(descriptor)

    monkeypatch.setattr(exchange_module.os, "close", close)
    try:
        with pytest.raises(AnsibleActionFail) as failure:
            _run_outcome_action(monkeypatch, args, remote)
    finally:
        monkeypatch.setattr(exchange_module.os, "close", real_close)
    message = str(failure.value)
    assert "reviewed signer-outcome package file has unsafe metadata" in message
    assert "construction descriptor closure failed" in message
    assert "unexpected signer-outcome import failure" not in message
    assert attempted.count(failed_descriptor[0]) == 2
    with pytest.raises(OSError) as closed:
        os.fstat(failed_descriptor[0])
    assert closed.value.errno == errno.EBADF
    assert remote.stage_exists is False


class _OutcomeRemote:
    def __init__(
        self,
        package: Path,
        args: dict[str, object],
        metadata: dict[str, str],
        *,
        check_mode: bool = False,
        copy_failure_index: int | None = None,
        helper_failure: bool = False,
        stage_mode: str = "0700",
        stage_uid: int = 0,
        create_failure: bool = False,
    ) -> None:
        self.package = package
        self.args = args
        self.metadata = metadata
        self.check_mode = check_mode
        self.copy_failure_index = copy_failure_index
        self.helper_failure = helper_failure
        self.stage_mode = stage_mode
        self.stage_uid = stage_uid
        self.create_failure = create_failure
        self.stage = "/remote-stage/.platform-pki-outcome-fixed"
        self.remote_tmp = "/remote/ansible/tmp"
        self.stage_exists = False
        self.files: dict[str, bytes] = {}
        self.transfers: dict[str, bytes] = {}
        self.helper_argv: list[list[object]] = []
        self.module_paths: list[str] = []
        self.made_tmp: list[str] = []
        self.removed_tmp: list[str] = []
        self.command_check_modes: list[bool] = []
        self.low_level_commands: list[str] = []
        self.low_level_sudoable: list[bool] = []
        self.current_check_mode = lambda: self.check_mode

    @staticmethod
    def _permissions(*, directory: bool) -> dict[str, object]:
        return {
            "rusr": True,
            "wusr": True,
            "xusr": directory,
            "rgrp": False,
            "wgrp": False,
            "xgrp": False,
            "roth": False,
            "woth": False,
            "xoth": False,
        }

    def _directory_metadata(self) -> dict[str, object]:
        return {
            "exists": True,
            "isdir": True,
            "isreg": False,
            "islnk": False,
            "uid": self.stage_uid,
            "gid": 0,
            "mode": self.stage_mode,
            "dev": 1,
            "inode": 2,
            **self._permissions(directory=True),
        }

    def _file_metadata(self, name: str, *, checksum: bool) -> dict[str, object]:
        data = self.files[name]
        metadata: dict[str, object] = {
            "exists": True,
            "isdir": False,
            "isreg": True,
            "islnk": False,
            "uid": 0,
            "gid": 0,
            "mode": "0600",
            "nlink": 1,
            "size": len(data),
            "dev": 1,
            "inode": 100 + OUTCOME_NAMES.index(name),
            "mtime": 1.0,
            "ctime": 1.0,
            **self._permissions(directory=False),
        }
        if checksum:
            metadata["checksum"] = sha256(data)
        return metadata

    def transfer(self, path: str, data: bytes) -> None:
        self.transfers[path] = data

    def remove_tmp(self, path: str) -> None:
        self.removed_tmp.append(path)

    def make_tmp(self) -> str:
        self.made_tmp.append(self.remote_tmp)
        return self.remote_tmp

    def execute_module(
        self, *, module_name: str, module_args: dict[str, object], task_vars: object
    ) -> dict[str, object]:
        assert not self.check_mode, "check mode must not execute an Ansible module"
        del task_vars
        path = module_args.get("path")
        if isinstance(path, str):
            self.module_paths.append(path)
        if module_name == "ansible.legacy.stat":
            assert isinstance(path, str)
            checksum = module_args["get_checksum"] is True
            if path == self.stage:
                return {
                    "stat": self._directory_metadata()
                    if self.stage_exists
                    else {"exists": False}
                }
            prefix = self.stage + "/"
            assert path.startswith(prefix)
            name = path.removeprefix(prefix)
            return {
                "stat": self._file_metadata(name, checksum=checksum)
                if self.stage_exists and name in self.files
                else {"exists": False}
            }
        if module_name == "ansible.legacy.file":
            if module_args.get("state") == "directory":
                assert path == self.stage
                assert not self.stage_exists
                self.stage_exists = True
                if self.create_failure:
                    return {"failed": True}
                return {"changed": True}
            assert module_args.get("state") == "absent"
            assert isinstance(path, str) and path.startswith(self.stage + "/")
            self.files.pop(path.rsplit("/", 1)[1], None)
            return {"changed": True}
        if module_name == "ansible.legacy.copy":
            assert isinstance(path, str) or path is None
            destination = module_args["dest"]
            assert isinstance(destination, str)
            name = destination.rsplit("/", 1)[1]
            source = module_args["src"]
            assert isinstance(source, str)
            self.files[name] = self.transfers[source]
            if self.copy_failure_index == OUTCOME_NAMES.index(name):
                return {"failed": True}
            return {"changed": True}
        assert module_name == "ansible.legacy.command"
        self.command_check_modes.append(self.current_check_mode())
        argv = module_args["argv"]
        assert isinstance(argv, list)
        if argv[:2] == ["rmdir", "--"]:
            if self.files:
                return {"failed": True, "rc": 1}
            self.stage_exists = False
            return {"rc": 0}
        self.helper_argv.append(argv)
        return self._helper_result()

    def _helper_result(self) -> dict[str, object]:
        if self.helper_failure:
            return {"failed": True, "rc": 1, "stdout": "", "stderr": "failed"}
        result = {
            "status": "would-import" if self.check_mode else "imported",
            "request_id": REQUEST_ID,
            "artifact_sha256": str(self.args["artifact_sha256"]),
            "deployment_sha256": str(self.args["deployment_sha256"]),
            "outcome_sha256": str(self.args["outcome_sha256"]),
            "action": self.metadata["action"],
            "result": self.metadata["result"],
            "state": self.metadata["state"],
            "resulting_active_request_id": self.metadata["resulting_active_request_id"],
            "history_path": (
                f"{self.args['state_root']}/outcomes/{REQUEST_ID}/"
                f"{self.args['outcome_sha256']}"
            ),
        }
        return {
            "rc": 0,
            "stdout": json.dumps(result, sort_keys=True, separators=(",", ":")),
            "stderr": "",
        }

    def low_level_execute_command(
        self, command: str, *, sudoable: bool
    ) -> dict[str, object]:
        self.low_level_commands.append(command)
        self.low_level_sudoable.append(sudoable)
        parsed: list[object] = list(shlex.split(command))
        self.helper_argv.append(parsed)
        result = self._helper_result()
        stderr = result["stderr"] or "Shared connection to 192.0.2.10 closed.\r\n"
        return {
            "rc": result["rc"],
            "stdout": result["stdout"],
            "stdout_lines": str(result["stdout"]).splitlines(),
            "stderr": stderr,
            "stderr_lines": str(stderr).splitlines(),
        }


def _run_outcome_action(
    monkeypatch: pytest.MonkeyPatch,
    args: dict[str, object],
    remote: _OutcomeRemote,
) -> dict[str, object]:
    monkeypatch.setattr(outcome_action.ActionBase, "run", lambda self, **kwargs: {})
    monkeypatch.setattr(outcome_action, "_REMOTE_STAGE_ROOT", "/remote-stage")
    monkeypatch.setattr(outcome_action.secrets, "token_hex", lambda _length: "fixed")
    action = object.__new__(outcome_action.ActionModule)
    action._task = SimpleNamespace(args=args, check_mode=remote.check_mode)
    action._connection = SimpleNamespace(_shell=SimpleNamespace(join_path=posixpath.join))
    action._make_tmp_path = remote.make_tmp
    action._remove_tmp_path = remote.remove_tmp
    action._transfer_data = remote.transfer
    action._execute_module = remote.execute_module
    action._low_level_execute_command = remote.low_level_execute_command
    remote.current_check_mode = lambda: action._task.check_mode
    return action.run(task_vars={})


def test_outcome_action_check_mode_does_not_allocate_framework_tmp() -> None:
    action = object.__new__(outcome_action.ActionModule)
    action._task = SimpleNamespace(args={}, check_mode=True, async_val=0)
    action._connection = SimpleNamespace(_shell=SimpleNamespace(tmpdir=None))
    action._make_tmp_path = lambda: pytest.fail(
        "check mode allocated an Ansible transfer workspace"
    )

    with pytest.raises(
        AnsibleActionFail,
        match="requires its exact structured argument set",
    ):
        action.run(task_vars={})


@pytest.mark.parametrize("check_mode", (False, True))
def test_outcome_action_transfers_exact_package_invokes_helper_and_cleans(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    check_mode: bool,
) -> None:
    assert outcome_action.ActionModule.TRANSFERS_FILES is False
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, check_mode=check_mode)
    result = _run_outcome_action(monkeypatch, args, remote)

    assert remote.current_check_mode() is check_mode
    assert result == {
        "changed": True,
        "status": "would-import" if check_mode else "imported",
        "request_id": REQUEST_ID,
        "artifact_sha256": args["artifact_sha256"],
        "deployment_sha256": args["deployment_sha256"],
        "outcome_sha256": args["outcome_sha256"],
        "action": "finalize",
        "result": "activated",
        "state": "finalized",
        "resulting_active_request_id": REQUEST_ID,
        "history_path": (
            f"{args['state_root']}/outcomes/{REQUEST_ID}/{args['outcome_sha256']}"
        ),
    }
    common_argv = [
        "--state-root", args["state_root"],
        "--pending-root", args["pending_root"],
        "--versions-root", args["versions_root"],
        "--zot-config", args["zot_config_path"],
        "--service", SERVICE,
        "--target", TARGET,
        "--trust-id", args["trust_id"],
        "--request-id", REQUEST_ID,
        "--artifact-sha256", args["artifact_sha256"],
        "--deployment-sha256", args["deployment_sha256"],
        "--outcome-sha256", args["outcome_sha256"],
    ]
    if check_mode:
        decision = parse_record(
            package.joinpath("decision").read_bytes(),
            DECISION_FIELDS,
            "expected preflight decision",
        )
        outcome = parse_record(
            package.joinpath("outcome").read_bytes(),
            OUTCOME_FIELDS,
            "expected preflight outcome",
        )
        expected_argv = [
            args["lifecycle_helper_path"], "outcome-preflight", *common_argv,
            "--decision-sha256", sha256(package.joinpath("decision").read_bytes()),
            "--outcome-principal", outcome["outcome_principal"],
        ]
        for field in DECISION_FIELDS:
            if field != "schema":
                expected_argv.extend((
                    f"--decision-{field.replace('_', '-')}", decision[field]
                ))
    else:
        expected_argv = [
            args["lifecycle_helper_path"], "outcome-import", *common_argv,
            "--outcome-dir", remote.stage,
        ]
    assert remote.helper_argv == [expected_argv]
    if check_mode:
        assert remote.low_level_commands == [
            " ".join(shlex.quote(str(value)) for value in expected_argv)
        ]
        assert remote.low_level_sudoable == [True]
        assert remote.command_check_modes == []
        assert remote.transfers == {}
        assert remote.module_paths == []
        assert remote.made_tmp == []
        assert remote.removed_tmp == []
    else:
        assert remote.low_level_commands == []
        assert remote.command_check_modes[-1] is False
        assert remote.made_tmp == [remote.remote_tmp]
        assert tuple(Path(path).name for path in remote.transfers) == tuple(
            f".platform-pki-outcome-{name}" for name in OUTCOME_NAMES
        )
        assert remote.removed_tmp == [remote.remote_tmp]
    assert not any("tls.key" in path for path in (*remote.transfers, *remote.module_paths))
    assert not remote.files
    assert remote.stage_exists is False


def test_outcome_preflight_shell_command_quotes_every_argument() -> None:
    argv = [
        "/fixed/helper",
        "plain",
        "argument with spaces",
        "value;touch /tmp/not-created",
        "$(not-executed)",
        "single'quote",
    ]
    command = outcome_action._shell_command(argv)

    assert command == (
        "/fixed/helper plain 'argument with spaces' "
        "'value;touch /tmp/not-created' '$(not-executed)' "
        "'single'\"'\"'quote'"
    )
    assert shlex.split(command) == argv


def test_outcome_action_check_mode_rejects_unbound_low_level_result(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, check_mode=True)
    remote.metadata = {**metadata, "result": "rolled-back"}

    with pytest.raises(AnsibleActionFail, match="differs from reviewed package"):
        _run_outcome_action(monkeypatch, args, remote)

    assert remote.low_level_sudoable == [True]
    assert remote.module_paths == []
    assert remote.transfers == {}
    assert remote.made_tmp == []
    assert remote.removed_tmp == []


def test_outcome_action_rejects_stage_metadata_and_removes_created_directory(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, stage_mode="0755")
    with pytest.raises(AnsibleActionFail, match="unsafe metadata"):
        _run_outcome_action(monkeypatch, args, remote)
    assert remote.stage_exists is False
    assert not remote.files


def test_outcome_action_cleans_directory_created_by_failed_create_module(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, create_failure=True)
    with pytest.raises(AnsibleActionFail, match="cannot create"):
        _run_outcome_action(monkeypatch, args, remote)
    assert remote.stage_exists is False
    assert not remote.files


def test_outcome_action_reports_stage_retained_when_identity_is_unattributable(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, stage_uid=1000)
    with pytest.raises(AnsibleActionFail) as failure:
        _run_outcome_action(monkeypatch, args, remote)
    assert "safe identity unavailable" in str(failure.value)
    assert remote.stage in str(failure.value)
    assert remote.stage_exists is True


@pytest.mark.parametrize("failure_index", range(len(OUTCOME_NAMES)))
def test_outcome_action_cleans_partial_destination_after_each_copy_failure(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(
        package, args, metadata, copy_failure_index=failure_index
    )
    with pytest.raises(AnsibleActionFail, match="cannot stage"):
        _run_outcome_action(monkeypatch, args, remote)
    assert len(remote.transfers) == failure_index + 1
    assert remote.stage_exists is False
    assert not remote.files
    assert remote.removed_tmp == [remote.remote_tmp]


def test_outcome_action_cleans_after_helper_failure(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, helper_failure=True)
    with pytest.raises(AnsibleActionFail, match="target signer-outcome import failed"):
        _run_outcome_action(monkeypatch, args, remote)
    assert remote.stage_exists is False
    assert not remote.files
    assert remote.removed_tmp == [remote.remote_tmp]


def test_outcome_action_cleanup_attempts_are_independent_and_preserve_failure(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    remote = _OutcomeRemote(package, args, metadata, helper_failure=True)
    original_tree_close = outcome_action.PinnedTree.close
    real_close = exchange_module.os.close
    attempted: list[int] = []
    expected_evidence_attempts: list[int] = []
    failed_descriptor: list[int] = []
    closed_trees = 0
    injected = False
    failed_once = False

    def tree_close(tree: PinnedTree) -> None:
        nonlocal closed_trees, injected
        closed_trees += 1
        if not injected:
            injected = True
            failed_descriptor.append(next(iter(tree.files.values())).descriptor)
            expected_evidence_attempts.extend(
                source.descriptor for source in tree.files.values()
            )
            expected_evidence_attempts.extend(reversed(tree.directory.descriptors))

            def close(descriptor: int) -> None:
                nonlocal failed_once
                attempted.append(descriptor)
                if descriptor == failed_descriptor[0] and not failed_once:
                    failed_once = True
                    raise OSError("injected close failure")
                real_close(descriptor)

            exchange_module.os.close = close
        original_tree_close(tree)

    def fail_tmp(path: str) -> None:
        remote.removed_tmp.append(path)
        raise OSError("injected tmp cleanup failure")

    remote.remove_tmp = fail_tmp
    monkeypatch.setattr(outcome_action.PinnedTree, "close", tree_close)
    try:
        with pytest.raises(AnsibleActionFail) as failure:
            _run_outcome_action(monkeypatch, args, remote)
    finally:
        exchange_module.os.close = real_close
    message = str(failure.value)
    assert "target signer-outcome import failed" in message
    assert "temporary Ansible workspace cleanup failed" in message
    assert "controller evidence descriptor closure failed" in message
    assert remote.stage_exists is False
    assert not remote.files
    assert attempted[:len(expected_evidence_attempts)] == expected_evidence_attempts
    assert attempted.count(failed_descriptor[0]) == 2
    assert closed_trees == 6


def test_outcome_action_rejects_controller_source_replacement_and_cleans_stage(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, exchange, args = _outcome_material(isolated_test_dir)
    metadata = _validate_outcome_fixture(package, exchange, args)
    original = {name: (package / name).read_bytes() for name in OUTCOME_NAMES}
    remote = _OutcomeRemote(package, args, metadata)

    def replace_source(path: str, data: bytes) -> None:
        del path, data
        package.rename(package.with_name("outcome-package-original"))
        _private_dir(package)
        for name, data in original.items():
            _private_file(package / name, data)

    remote.transfer = replace_source
    with pytest.raises(AnsibleActionFail, match="changed"):
        _run_outcome_action(monkeypatch, args, remote)
    assert remote.stage_exists is False
    assert not remote.files
    assert remote.removed_tmp == [remote.remote_tmp]


def test_actions_reject_unknown_argument_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(collection_action.ActionBase, "run", lambda self, **kwargs: {})
    monkeypatch.setattr(response_action.ActionBase, "run", lambda self, **kwargs: {})
    monkeypatch.setattr(ingress_action.ActionBase, "run", lambda self, **kwargs: {})
    monkeypatch.setattr(evidence_action.ActionBase, "run", lambda self, **kwargs: {})
    monkeypatch.setattr(
        evidence_status_action.ActionBase, "run", lambda self, **kwargs: {}
    )
    for action_class in (
        collection_action.ActionModule,
        response_action.ActionModule,
        ingress_action.ActionModule,
        evidence_action.ActionModule,
        evidence_status_action.ActionModule,
        outcome_action.ActionModule,
    ):
        action = object.__new__(action_class)
        action._task = SimpleNamespace(args={"unexpected": "value"}, check_mode=False)
        with pytest.raises(AnsibleActionFail, match="exact structured argument set"):
            action.run(task_vars={})


def test_canonical_parser_rejects_reordered_extra_and_noncanonical_records() -> None:
    canonical = serialize_record(("schema", "kind"), {"schema": "1", "kind": "fixed"}, "test")
    assert parse_record(canonical, ("schema", "kind"), "test") == {
        "schema": "1",
        "kind": "fixed",
    }
    for malformed in (
        b"kind=fixed\nschema=1\n",
        canonical + b"extra=value\n",
        canonical.rstrip(b"\n"),
        canonical.replace(b"\n", b"\r\n"),
        canonical + b"\n",
    ):
        with pytest.raises(ExchangeError):
            parse_record(malformed, ("schema", "kind"), "test")


def test_collection_validates_real_request_and_publishes_idempotently(
    isolated_test_dir: Path,
) -> None:
    root = _private_dir(isolated_test_dir / "collection")
    (
        files,
        bindings,
        request_source,
        trust_paths,
        trust_digests,
        _response_key,
        _leaf_key,
    ) = _request_material(root)
    trust = pin_trust(trust_paths, trust_digests)
    source = PinnedTree.open(request_source, REQUEST_REMOTE_NAMES, "request source")
    exchange = _private_dir(root / "exchange")
    parent = prepare_request_parent(exchange, SERVICE, REQUEST_ID)
    try:
        now = int(time.time())
        request = validate_request_payload(
            files, bindings, trust, source.files["request.sig"], now=now
        )
        receipt = collection_receipt(files, bindings, trust, now)
        assert tuple(line.split(b"=", 1)[0].decode() for line in receipt.splitlines()) == RECEIPT_FIELDS
        validate_collection_receipt(receipt, files, bindings, trust, request, now=now)
        trust_publication = {
            name: trust[name].data for name in TRUST_NAMES
        }
        assert publish_exact_tree(parent, "trust", trust_publication)
        assert not publish_exact_tree(parent, "trust", trust_publication)
        published_trust = Path(parent.path) / "trust"
        assert {path.name for path in published_trust.iterdir()} == set(TRUST_NAMES)
        assert all(
            sha256((published_trust / name).read_bytes()) == trust_digests[name]
            for name in TRUST_NAMES
        )
        conflicting_trust = dict(trust_publication)
        conflicting_trust["policy"] += b"conflict=true\n"
        with pytest.raises(ExchangeError, match="conflicts"):
            publish_exact_tree(parent, "trust", conflicting_trust)
        publication = {**files, "collection-receipt": receipt}
        assert publish_exact_tree(parent, "request", publication)
        assert not publish_exact_tree(parent, "request", publication)
        published = Path(parent.path) / "request"
        assert {path.name for path in published.iterdir()} == set(REQUEST_PUBLICATION_NAMES)
        assert not list(published.rglob("*.key"))
        conflicting = dict(publication)
        conflicting["collection-receipt"] = receipt.replace(b"transport=ssh", b"transport=sftp")
        with pytest.raises(ExchangeError, match="conflicts"):
            publish_exact_tree(parent, "request", conflicting)
    finally:
        parent.close()
        source.close()
        for item in trust.values():
            item.close()


def test_trust_conflict_fails_before_request_publication(
    isolated_test_dir: Path,
) -> None:
    root = _private_dir(isolated_test_dir / "trust-conflict")
    (
        files,
        bindings,
        request_source,
        trust_paths,
        trust_digests,
        _response_key,
        _leaf_key,
    ) = _request_material(root)
    trust = pin_trust(trust_paths, trust_digests)
    source = PinnedTree.open(request_source, REQUEST_REMOTE_NAMES, "request source")
    exchange = _private_dir(root / "exchange")
    parent = prepare_request_parent(exchange, SERVICE, REQUEST_ID)
    try:
        now = int(time.time())
        validate_request_payload(
            files, bindings, trust, source.files["request.sig"], now=now
        )
        conflicting = {name: trust[name].data for name in TRUST_NAMES}
        conflicting["policy"] += b"conflict=true\n"
        assert publish_exact_tree(parent, "trust", conflicting)
        with pytest.raises(ExchangeError, match="conflicts"):
            publish_exact_tree(
                parent,
                "trust",
                {name: trust[name].data for name in TRUST_NAMES},
            )
        assert not (Path(parent.path) / "request").exists()
    finally:
        parent.close()
        source.close()
        for item in trust.values():
            item.close()


def test_collection_action_fetches_only_exact_public_remote_paths(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_dir(isolated_test_dir / "collection-action")
    (
        _files,
        bindings,
        request_source,
        trust_paths,
        trust_digests,
        _response_key,
        _leaf_key,
    ) = _request_material(root)
    exchange = _private_dir(root / "exchange")
    remote_temp = _private_dir(root / "remote-temp")
    remote_collection = remote_temp / ".platform-pki-request-fixed"
    remote_uid = 1234
    fetched_paths: list[str] = []
    stat_paths: list[str] = []
    helper_argv: list[list[object]] = []
    removed_paths: list[str] = []
    events: list[str] = []

    def remote_stat(path: Path) -> dict[str, object]:
        metadata = path.lstat()
        is_directory = stat.S_ISDIR(metadata.st_mode)
        value: dict[str, object] = {
            "exists": True,
            "isdir": is_directory,
            "isreg": stat.S_ISREG(metadata.st_mode),
            "islnk": False,
            "uid": remote_uid,
            "gid": 0,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "nlink": metadata.st_nlink,
            "size": metadata.st_size,
            "dev": metadata.st_dev,
            "inode": metadata.st_ino,
            "mtime": metadata.st_mtime,
            "ctime": metadata.st_ctime,
            "rusr": True,
            "wusr": True,
            "xusr": is_directory,
            "rgrp": False,
            "wgrp": False,
            "xgrp": False,
            "roth": False,
            "woth": False,
            "xoth": False,
        }
        if path.is_file():
            value["checksum"] = sha256(path.read_bytes())
        return value

    def execute_module(*, module_name: str, module_args: dict[str, object], task_vars: object):
        del task_vars
        if module_name == "ansible.legacy.file":
            if module_args.get("state") == "directory":
                assert module_args == {
                    "path": os.fspath(remote_collection),
                    "state": "directory",
                    "owner": "rocky",
                    "mode": "0700",
                }
                remote_collection.mkdir(mode=0o700)
                return {"changed": True}
            assert module_args == {
                "path": os.fspath(remote_collection),
                "state": "absent",
            }
            shutil.rmtree(remote_collection)
            removed_paths.append(os.fspath(remote_collection))
            return {"changed": True}
        if module_name == "ansible.legacy.stat":
            remote_value = module_args["path"]
            assert isinstance(remote_value, str)
            stat_paths.append(remote_value)
            assert remote_value == os.fspath(remote_temp) or remote_value.startswith(
                os.fspath(remote_temp) + "/"
            )
            return {"stat": remote_stat(Path(remote_value))}
        assert module_name == "ansible.legacy.command"
        assert set(module_args) == {"argv"}
        argv = module_args["argv"]
        assert isinstance(argv, list)
        helper_argv.append(argv)
        output_dir = Path(argv[argv.index("--output-dir") + 1])
        if len(helper_argv) == 1:
            for name in REQUEST_REMOTE_NAMES:
                _private_file(output_dir / name, (request_source / name).read_bytes())
            status = "collected"
        else:
            status = "existing"
        events.append(f"helper:{status}")
        metadata = {
            "status": status,
            "request_id": REQUEST_ID,
            "request_sha256": bindings["expected_request_sha256"],
            "csr_sha256": bindings["expected_csr_sha256"],
            "request_signature_sha256": sha256(
                (request_source / "request.sig").read_bytes()
            ),
        }
        return {
            "rc": 0,
            "stdout": json.dumps(
                metadata, sort_keys=True, separators=(",", ":")
            ),
            "stderr": "",
        }

    def fetch_file(remote: str, local: str) -> None:
        fetched_paths.append(remote)
        events.append(f"fetch:{Path(remote).name}")
        Path(local).write_bytes(Path(remote).read_bytes())

    monkeypatch.setattr(collection_action.ActionBase, "run", lambda self, **kwargs: {})
    action = object.__new__(collection_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            **bindings,
            "lifecycle_helper_path": "/usr/local/libexec/platform-pki-host-local-lifecycle",
            "state_root": "/var/lib/platform-pki/state",
            "pending_root": "/var/lib/platform-pki/pending",
            "versions_root": "/var/lib/platform-pki/versions",
            "trust_id": "reviewed-v1",
            "exchange_root": os.fspath(exchange),
            "trust_paths": trust_paths,
            "trust_sha256": trust_digests,
        },
        check_mode=False,
    )
    action._connection = SimpleNamespace(
        fetch_file=fetch_file,
        get_option=lambda name: "rocky" if name == "remote_user" else None,
    )
    action._execute_module = execute_module
    monkeypatch.setattr(collection_action, "_REMOTE_STAGE_ROOT", os.fspath(remote_temp))
    monkeypatch.setattr(collection_action.secrets, "token_hex", lambda _length: "fixed")
    result = action.run(task_vars={"ansible_user": "ignored-inventory-user"})
    assert result["status"] == "collected"
    published_trust = exchange / SERVICE / REQUEST_ID / "trust"
    assert result["trust_dir"] == os.fspath(published_trust)
    assert {path.name for path in published_trust.iterdir()} == set(TRUST_NAMES)
    assert all(
        sha256((published_trust / name).read_bytes()) == trust_digests[name]
        for name in TRUST_NAMES
    )
    assert fetched_paths == [f"{remote_collection}/{name}" for name in REQUEST_REMOTE_NAMES]
    assert all("key" not in path for path in fetched_paths)
    assert all("/pending/" not in path for path in fetched_paths)
    assert len(helper_argv) == 2
    expected_argv = [
        "/usr/local/libexec/platform-pki-host-local-lifecycle",
        "collection-prepare",
        "--state-root",
        "/var/lib/platform-pki/state",
        "--pending-root",
        "/var/lib/platform-pki/pending",
        "--versions-root",
        "/var/lib/platform-pki/versions",
        "--service",
        SERVICE,
        "--target",
        TARGET,
        "--trust-id",
        "reviewed-v1",
        "--request-id",
        REQUEST_ID,
        "--output-dir",
        os.fspath(remote_collection),
        "--output-owner-uid",
        str(remote_uid),
    ]
    assert helper_argv == [expected_argv, expected_argv]
    assert events == [
        "helper:collected",
        "fetch:tls.csr",
        "fetch:request",
        "fetch:request.sig",
        "helper:existing",
    ]
    assert stat_paths and all(
        path == os.fspath(remote_temp) or path.startswith(os.fspath(remote_temp) + "/")
        for path in stat_paths
    )
    assert removed_paths == [os.fspath(remote_collection)]


@pytest.mark.parametrize(
    ("module", "remote_user"),
    (
        (collection_action, None),
        (evidence_action, None),
        (collection_action, "bad user"),
        (evidence_action, "bad user"),
    ),
)
def test_collection_actions_require_effective_connection_user(
    module: Any, remote_user: object
) -> None:
    connection = SimpleNamespace(get_option=lambda name: remote_user)
    with pytest.raises(ExchangeError, match="not canonical"):
        module._authenticated_remote_user(connection)

    with pytest.raises(ExchangeError, match="unavailable"):
        module._authenticated_remote_user(SimpleNamespace())


@pytest.mark.parametrize("module", (collection_action, evidence_action))
@pytest.mark.parametrize("transport", ("ssh", "sftp"))
def test_collection_actions_never_derive_nonlocal_connection_user(
    module: Any,
    transport: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_lookup(_uid: int) -> None:
        raise AssertionError("non-local transport attempted a passwd lookup")

    monkeypatch.setattr(module.pwd, "getpwuid", reject_lookup)

    with pytest.raises(ExchangeError, match="not canonical"):
        module._authenticated_remote_user(
            SimpleNamespace(
                transport=transport,
                get_option=lambda _name: None,
            )
        )
    with pytest.raises(ExchangeError, match="unavailable"):
        module._authenticated_remote_user(SimpleNamespace(transport=transport))


@pytest.mark.parametrize("module", (collection_action, evidence_action))
def test_collection_actions_derive_effective_local_connection_user(
    module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def local_account(uid: int) -> SimpleNamespace:
        assert uid == 4321
        return SimpleNamespace(pw_name="local-user")

    monkeypatch.setattr(module.os, "geteuid", lambda: 4321)
    monkeypatch.setattr(module.pwd, "getpwuid", local_account)
    connection = SimpleNamespace(
        transport="local",
        get_option=lambda _name: None,
    )

    assert module._authenticated_remote_user(connection) == "local-user"


@pytest.mark.parametrize("module", (collection_action, evidence_action))
def test_collection_actions_reject_missing_local_account(
    module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_account(_uid: int) -> None:
        raise KeyError

    monkeypatch.setattr(module.pwd, "getpwuid", missing_account)

    with pytest.raises(ExchangeError, match="authenticated local user is unavailable"):
        module._authenticated_remote_user(
            SimpleNamespace(
                transport="local",
                get_option=lambda _name: None,
            )
        )


@pytest.mark.parametrize("module", (collection_action, evidence_action))
def test_collection_actions_reject_noncanonical_local_account(
    module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="bad user"),
    )

    with pytest.raises(ExchangeError, match="not canonical"):
        module._authenticated_remote_user(
            SimpleNamespace(
                transport="local",
                get_option=lambda _name: None,
            )
        )


def test_request_collection_helper_failure_exposes_only_safe_diagnostics() -> None:
    assert collection_action._helper_failure_message(
        {
            "stderr": (
                "platform-pki-host-local-lifecycle: "
                "collection output directory owner is invalid"
            )
        }
    ) == (
        "lifecycle helper request collection failed: "
        "collection output directory owner is invalid"
    )
    assert collection_action._helper_failure_message(
        {"stderr": "platform-pki-host-local-lifecycle: unsafe path /root/private"}
    ) == "lifecycle helper request collection failed"


def test_evidence_collection_uses_helper_temp_and_publishes_idempotently(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_dir(isolated_test_dir / "evidence-action")
    source, exchange, args, _signing_key = _evidence_material(root)
    remote_stage_root = _private_dir(root / "remote-stage-root")
    remote_temp = remote_stage_root / (".platform-pki-evidence-" + "a" * 32)
    owner_uid = 2345
    fetches: list[str] = []
    helper_argv: list[list[object]] = []
    events: list[str] = []

    def remote_stat(path: Path) -> dict[str, object]:
        metadata = path.lstat()
        directory = stat.S_ISDIR(metadata.st_mode)
        value: dict[str, object] = {
            "exists": True,
            "isdir": directory,
            "isreg": stat.S_ISREG(metadata.st_mode),
            "islnk": False,
            "uid": owner_uid,
            "gid": 0,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "nlink": metadata.st_nlink,
            "size": metadata.st_size,
            "dev": metadata.st_dev,
            "inode": metadata.st_ino,
            "mtime": metadata.st_mtime,
            "ctime": metadata.st_ctime,
            "rusr": True,
            "wusr": True,
            "xusr": directory,
            "rgrp": False,
            "wgrp": False,
            "xgrp": False,
            "roth": False,
            "woth": False,
            "xoth": False,
        }
        if path.is_file():
            value["checksum"] = sha256(path.read_bytes())
        return value

    def execute_module(*, module_name: str, module_args: dict[str, object], task_vars: object):
        del task_vars
        if module_name == "ansible.legacy.file":
            if module_args.get("state") == "directory":
                assert module_args == {
                    "path": os.fspath(remote_temp),
                    "state": "directory",
                    "mode": "0700",
                    "owner": "rocky",
                }
                remote_temp.mkdir(mode=0o700)
                return {"changed": True}
            assert module_args == {
                "path": os.fspath(remote_temp),
                "state": "absent",
            }
            shutil.rmtree(remote_temp)
            return {"changed": True}
        if module_name == "ansible.legacy.stat":
            path = module_args["path"]
            assert isinstance(path, str)
            assert path == os.fspath(remote_temp) or path.startswith(
                os.fspath(remote_temp) + "/"
            )
            return {"stat": remote_stat(Path(path))}
        assert module_name == "ansible.legacy.command"
        assert set(module_args) == {"argv"}
        argv = module_args["argv"]
        assert isinstance(argv, list)
        helper_argv.append(argv)
        output_dir = Path(argv[argv.index("--output-dir") + 1])
        first_for_run = not any(output_dir.iterdir())
        if first_for_run:
            for name in EVIDENCE_NAMES:
                _private_file(output_dir / name, (source / name).read_bytes())
            status = "collected"
        else:
            status = "existing"
        events.append(f"helper:{status}")
        deployment = parse_record(
            (source / "deployment").read_bytes(), DEPLOYMENT_FIELDS, "fixture deployment"
        )
        metadata: dict[str, str] = {
            "status": status,
            "request_id": REQUEST_ID,
            "artifact_sha256": str(args["artifact_sha256"]),
            "deployment_sha256": str(args["deployment_sha256"]),
            "action": deployment["action"],
            "result": deployment["result"],
        }
        for name in EVIDENCE_NAMES:
            key = f"{name.replace('-', '_').replace('.', '_')}_sha256"
            metadata[key] = sha256((source / name).read_bytes())
        return {
            "rc": 0,
            "stdout": json.dumps(metadata, sort_keys=True, separators=(",", ":")),
            "stderr": "",
        }

    def fetch_file(remote: str, local: str) -> None:
        fetches.append(remote)
        events.append(f"fetch:{Path(remote).name}")
        Path(local).write_bytes(Path(remote).read_bytes())

    monkeypatch.setattr(evidence_action.ActionBase, "run", lambda self, **kwargs: {})
    monkeypatch.setattr(evidence_action, "_REMOTE_STAGE_ROOT", os.fspath(remote_stage_root))
    monkeypatch.setattr(evidence_action.secrets, "token_hex", lambda _length: "a" * 32)

    def run_action() -> dict[str, object]:
        action = object.__new__(evidence_action.ActionModule)
        action._task = SimpleNamespace(args=args, check_mode=False)
        action._connection = SimpleNamespace(
            fetch_file=fetch_file,
            get_option=lambda name: "rocky" if name == "remote_user" else None,
        )
        action._execute_module = execute_module
        return action.run(task_vars={"ansible_user": "ignored-inventory-user"})

    first = run_action()
    assert first["status"] == "collected"
    assert first["action"] == "finalize"
    assert first["result"] == "activated"
    published = (
        exchange
        / SERVICE
        / REQUEST_ID
        / "evidence"
        / str(args["deployment_sha256"])
    )
    assert {path.name for path in published.iterdir()} == set(EVIDENCE_NAMES)
    assert not any("key" in path.name for path in published.iterdir())
    second = run_action()
    assert second["status"] == "existing"
    remote_evidence = remote_temp
    assert fetches == [
        f"{remote_evidence}/{name}" for name in (*EVIDENCE_NAMES, *EVIDENCE_NAMES)
    ]
    assert events == [
        "helper:collected",
        *(f"fetch:{name}" for name in EVIDENCE_NAMES),
        "helper:existing",
        "helper:collected",
        *(f"fetch:{name}" for name in EVIDENCE_NAMES),
        "helper:existing",
    ]
    assert len(helper_argv) == 4
    expected_argv = [
        args["lifecycle_helper_path"],
        "evidence-collection-prepare",
        "--state-root",
        args["state_root"],
        "--pending-root",
        args["pending_root"],
        "--versions-root",
        args["versions_root"],
        "--service",
        SERVICE,
        "--target",
        TARGET,
        "--trust-id",
        args["trust_id"],
        "--request-id",
        REQUEST_ID,
        "--artifact-sha256",
        args["artifact_sha256"],
        "--deployment-sha256",
        args["deployment_sha256"],
        "--output-dir",
        os.fspath(remote_evidence),
        "--output-owner-uid",
        str(owner_uid),
    ]
    assert helper_argv == [expected_argv] * 4
    assert all(
        path == os.fspath(remote_temp) or path.startswith(os.fspath(remote_temp) + "/")
        for path in fetches
    )
    assert all("/pending/" not in path for path in fetches)

    _private_file(published / "deployment", b"conflicting deployment\n")
    with pytest.raises(AnsibleActionFail, match="conflicts"):
        run_action()


@pytest.mark.parametrize("alteration", ("signature", "cross-binding"))
def test_evidence_validation_rejects_signature_and_cross_binding_substitution(
    isolated_test_dir: Path, alteration: str
) -> None:
    root = _private_dir(isolated_test_dir / f"evidence-invalid-{alteration}")
    source, exchange, args, signing_key = _evidence_material(root)
    if alteration == "signature":
        _private_file(source / "deployment.sig", b"invalid-signature\n")
    else:
        result_path = source / "validation-result"
        _replace_record_field(result_path, "served_certificate_sha256", "7" * 64)
        (source / "validation-result.sig").unlink()
        _ssh_sign(result_path, signing_key, "platform-pki-csr-deployment-v1")
    parent_path = exchange / SERVICE / REQUEST_ID
    evidence = PinnedTree.open(source, EVIDENCE_NAMES, "evidence source")
    request = PinnedTree.open(
        parent_path / "request", REQUEST_PUBLICATION_NAMES, "request publication"
    )
    response = PinnedTree.open(
        parent_path / "response", RESPONSE_NAMES, "response publication"
    )
    trust = PinnedTree.open(parent_path / "trust", TRUST_NAMES, "frozen trust")
    try:
        with pytest.raises(ExchangeError):
            validate_evidence_snapshot(
                evidence, request, response, trust, args, now=int(time.time())
            )
    finally:
        trust.close()
        response.close()
        request.close()
        evidence.close()


def test_evidence_collection_rejects_workspace_trust_discontinuity(
    isolated_test_dir: Path,
) -> None:
    root = _private_dir(isolated_test_dir / "evidence-trust-discontinuity")
    source, exchange, args, _signing_key = _evidence_material(root)
    parent_path = exchange / SERVICE / REQUEST_ID
    alternate = _private_dir(root / "alternate-deployer")
    _alternate_key, alternate_public = _ssh_key(alternate)
    _private_file(
        parent_path / "trust/deployers.allowed_signers",
        f"{TARGET} {alternate_public}\n",
    )
    evidence = PinnedTree.open(source, EVIDENCE_NAMES, "evidence source")
    request = PinnedTree.open(
        parent_path / "request", REQUEST_PUBLICATION_NAMES, "request publication"
    )
    response = PinnedTree.open(
        parent_path / "response", RESPONSE_NAMES, "response publication"
    )
    trust = PinnedTree.open(parent_path / "trust", TRUST_NAMES, "frozen trust")
    try:
        with pytest.raises(ExchangeError, match="collected request trust"):
            validate_evidence_snapshot(
                evidence, request, response, trust, args, now=int(time.time())
            )
    finally:
        trust.close()
        response.close()
        request.close()
        evidence.close()


@pytest.mark.parametrize("check_mode", (False, True))
def test_evidence_status_verifies_without_mutation_or_target_connection(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    check_mode: bool,
) -> None:
    root = _private_dir(isolated_test_dir / f"evidence-status-{check_mode}")
    source, exchange, args, _signing_key = _evidence_material(root)
    published = _publish_evidence_material(
        source, exchange, str(args["deployment_sha256"])
    )
    before = _workspace_snapshot(exchange)
    monkeypatch.setattr(
        evidence_status_action.ActionBase, "run", lambda self, **kwargs: {}
    )
    action = object.__new__(evidence_status_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            "exchange_root": os.fspath(exchange),
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "artifact_sha256": args["artifact_sha256"],
            "deployment_sha256": args["deployment_sha256"],
        },
        check_mode=check_mode,
    )
    result = action.run(task_vars={})
    assert result == {
        "changed": False,
        "status": "verified",
        "service": SERVICE,
        "target": TARGET,
        "request_id": REQUEST_ID,
        "artifact_sha256": args["artifact_sha256"],
        "deployment_sha256": args["deployment_sha256"],
        "action": "finalize",
        "result": "activated",
    }
    assert _workspace_snapshot(exchange) == before
    assert published.exists()
    assert not hasattr(action, "_connection")


def test_evidence_status_fails_when_publication_is_absent(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_dir(isolated_test_dir / "evidence-status-absent")
    _source, exchange, args, _signing_key = _evidence_material(root)
    before = _workspace_snapshot(exchange)
    monkeypatch.setattr(
        evidence_status_action.ActionBase, "run", lambda self, **kwargs: {}
    )
    action = object.__new__(evidence_status_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            "exchange_root": os.fspath(exchange),
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "artifact_sha256": args["artifact_sha256"],
            "deployment_sha256": args["deployment_sha256"],
        },
        check_mode=False,
    )
    with pytest.raises(AnsibleActionFail, match="absent or unsafe"):
        action.run(task_vars={})
    assert _workspace_snapshot(exchange) == before


@pytest.mark.parametrize("alteration", ("bytes", "extra"))
def test_evidence_status_rejects_altered_or_conflicting_publication(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    alteration: str,
) -> None:
    root = _private_dir(isolated_test_dir / f"evidence-status-{alteration}")
    source, exchange, args, _signing_key = _evidence_material(root)
    published = _publish_evidence_material(
        source, exchange, str(args["deployment_sha256"])
    )
    if alteration == "bytes":
        _private_file(published / "validation-result", b"altered\n")
    else:
        _private_file(published / "conflicting-extra", b"extra\n")
    before = _workspace_snapshot(exchange)
    monkeypatch.setattr(
        evidence_status_action.ActionBase, "run", lambda self, **kwargs: {}
    )
    action = object.__new__(evidence_status_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            "exchange_root": os.fspath(exchange),
            "service": SERVICE,
            "target": TARGET,
            "request_id": REQUEST_ID,
            "artifact_sha256": args["artifact_sha256"],
            "deployment_sha256": args["deployment_sha256"],
        },
        check_mode=False,
    )
    with pytest.raises(AnsibleActionFail):
        action.run(task_vars={})
    assert _workspace_snapshot(exchange) == before


@pytest.mark.parametrize("coordinate", ("artifact", "deployment"))
def test_evidence_status_rejects_wrong_coordinate(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    coordinate: str,
) -> None:
    root = _private_dir(isolated_test_dir / f"evidence-status-coordinate-{coordinate}")
    source, exchange, args, _signing_key = _evidence_material(root)
    _publish_evidence_material(source, exchange, str(args["deployment_sha256"]))
    status_args = {
        "exchange_root": os.fspath(exchange),
        "service": SERVICE,
        "target": TARGET,
        "request_id": REQUEST_ID,
        "artifact_sha256": args["artifact_sha256"],
        "deployment_sha256": args["deployment_sha256"],
    }
    status_args[f"{coordinate}_sha256"] = "0" * 64
    before = _workspace_snapshot(exchange)
    monkeypatch.setattr(
        evidence_status_action.ActionBase, "run", lambda self, **kwargs: {}
    )
    action = object.__new__(evidence_status_action.ActionModule)
    action._task = SimpleNamespace(args=status_args, check_mode=False)
    with pytest.raises(AnsibleActionFail):
        action.run(task_vars={})
    assert _workspace_snapshot(exchange) == before


def test_evidence_publication_rejects_unsafe_parent_and_source_replacement(
    isolated_test_dir: Path,
) -> None:
    root = _private_dir(isolated_test_dir / "evidence-publication-race")
    request_parent_path = _private_dir(root / "exchange" / SERVICE / REQUEST_ID)
    unsafe_target = _private_dir(root / "unsafe-evidence-target")
    (request_parent_path / "evidence").symlink_to(unsafe_target)
    parent = PinnedDirectory.open(request_parent_path, "request parent")
    try:
        with pytest.raises((ExchangeError, OSError)):
            prepare_evidence_parent(parent)
    finally:
        parent.close()

    (request_parent_path / "evidence").unlink()
    source = _private_dir(root / "evidence-source")
    for name in EVIDENCE_NAMES:
        _private_file(source / name, f"{name}\n")
    pinned = PinnedTree.open(source, EVIDENCE_NAMES, "evidence race source")
    parent = PinnedDirectory.open(request_parent_path, "request parent")
    evidence_parent = prepare_evidence_parent(parent)
    deployment_sha = sha256(pinned.files["deployment"].data)

    def replace_source() -> None:
        source.rename(source.with_name("evidence-source-original"))
        _private_dir(source)
        for name in EVIDENCE_NAMES:
            _private_file(source / name, f"{name}\n")
        pinned.recheck()

    try:
        with pytest.raises(ExchangeError, match="changed"):
            publish_exact_tree(
                evidence_parent,
                deployment_sha,
                pinned.data,
                pre_publish=replace_source,
            )
        assert not (Path(evidence_parent.path) / deployment_sha).exists()
    finally:
        evidence_parent.close()
        parent.close()
        pinned.close()


@pytest.mark.parametrize("unsafe", ("extra", "symlink", "hardlink", "mode"))
def test_protected_response_tree_rejects_unsafe_sets_links_and_modes(
    isolated_test_dir: Path, unsafe: str
) -> None:
    root = _private_dir(isolated_test_dir / f"unsafe-{unsafe}")
    source = _private_dir(root / "source")
    for name in RESPONSE_NAMES:
        _private_file(source / name, f"{name}\n")
    if unsafe == "extra":
        _private_file(source / "extra", "extra\n")
    elif unsafe == "symlink":
        (source / "artifact").unlink()
        (source / "artifact").symlink_to(source / "response")
    elif unsafe == "hardlink":
        saved = _private_file(root / "saved", "artifact\n")
        (source / "artifact").unlink()
        os.link(saved, source / "artifact")
    else:
        (source / "artifact").chmod(0o644)
    with pytest.raises(ExchangeError):
        PinnedTree.open(source, RESPONSE_NAMES, "unsafe response")


def test_protected_paths_must_be_outside_repository(repo_root: Path) -> None:
    with pytest.raises(ExchangeError, match="outside the public repository"):
        PinnedDirectory.open(repo_root, "unsafe source")


def test_response_ingress_transfers_exact_six_files_in_protocol_order(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_dir(isolated_test_dir / "response-ingress")
    exchange, source, digests = _ingress_material(root)
    ingress_root = f"/var/lib/zot/tls-versions/.ingress-{REQUEST_ID}"
    remote_tmp = "/remote/ansible/action-temp"
    transfers: list[tuple[str, bytes]] = []
    copies: list[dict[str, object]] = []
    removed: list[str] = []

    monkeypatch.setattr(ingress_action.ActionBase, "run", lambda self, **kwargs: {})
    action = object.__new__(ingress_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            "exchange_root": os.fspath(exchange),
            "service": SERVICE,
            "request_id": REQUEST_ID,
            "ingress_root": ingress_root,
            "artifact_sha256": digests["artifact"],
        },
        check_mode=False,
    )
    action._connection = SimpleNamespace(
        _shell=SimpleNamespace(join_path=posixpath.join)
    )
    action._make_tmp_path = lambda: remote_tmp
    action._remove_tmp_path = lambda path: removed.append(path)
    action._transfer_data = lambda path, data: transfers.append((path, data))

    def copy_module(*, module_name: str, module_args: dict[str, object], task_vars: object):
        del task_vars
        assert module_name == "ansible.legacy.copy"
        copies.append(module_args)
        return {"changed": True}

    action._execute_module = copy_module
    result = action.run(task_vars={})
    assert result == {
        "changed": True,
        "status": "transferred",
        "request_id": REQUEST_ID,
        "ingress_root": ingress_root,
        "artifact_sha256": digests["artifact"],
        "sha256": digests,
    }
    assert [Path(path).name for path, _data in transfers] == [
        f".platform-pki-response-{name}" for name in RESPONSE_NAMES
    ]
    assert [sha256(data) for _path, data in transfers] == [
        digests[name] for name in RESPONSE_NAMES
    ]
    assert copies == [
        {
            "src": posixpath.join(remote_tmp, f".platform-pki-response-{name}"),
            "dest": posixpath.join(ingress_root, name),
            "remote_src": True,
            "owner": "root",
            "group": "root",
            "mode": "0600",
            "force": True,
            "follow": False,
        }
        for name in RESPONSE_NAMES
    ]
    assert removed == [remote_tmp]
    assert all("key" not in path for path, _data in transfers)
    assert {path.name for path in source.iterdir()} == set(RESPONSE_NAMES)
    assert not any(isinstance(value, bytes) for value in result.values())


@pytest.mark.parametrize("unsafe", ("legacy-mapping", "wrong-artifact", "extra-file"))
def test_response_ingress_rejects_generic_digest_input_or_invalid_source(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe: str,
) -> None:
    root = _private_dir(isolated_test_dir / f"response-ingress-{unsafe}")
    exchange, source, digests = _ingress_material(root)
    artifact_sha = digests["artifact"]
    if unsafe == "wrong-artifact":
        artifact_sha = "0" * 64
    elif unsafe == "extra-file":
        _private_file(source / "unexpected", b"unexpected\n")
    monkeypatch.setattr(ingress_action.ActionBase, "run", lambda self, **kwargs: {})
    action = object.__new__(ingress_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            "exchange_root": os.fspath(exchange),
            "service": SERVICE,
            "request_id": REQUEST_ID,
            "ingress_root": f"/var/lib/zot/tls-versions/.ingress-{REQUEST_ID}",
            "artifact_sha256": artifact_sha,
        },
        check_mode=False,
    )
    if unsafe == "legacy-mapping":
        action._task.args["sha256"] = digests
    action._make_tmp_path = lambda: pytest.fail("remote temp must not be created")
    with pytest.raises(AnsibleActionFail):
        action.run(task_vars={})


def test_response_ingress_detects_source_directory_replacement_during_transfer(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_dir(isolated_test_dir / "response-ingress-replaced")
    exchange, source, digests = _ingress_material(root)
    original = {name: (source / name).read_bytes() for name in RESPONSE_NAMES}
    copies: list[dict[str, object]] = []
    removed: list[str] = []
    monkeypatch.setattr(ingress_action.ActionBase, "run", lambda self, **kwargs: {})
    action = object.__new__(ingress_action.ActionModule)
    action._task = SimpleNamespace(
        args={
            "exchange_root": os.fspath(exchange),
            "service": SERVICE,
            "request_id": REQUEST_ID,
            "ingress_root": f"/var/lib/zot/tls-versions/.ingress-{REQUEST_ID}",
            "artifact_sha256": digests["artifact"],
        },
        check_mode=False,
    )
    action._connection = SimpleNamespace(
        _shell=SimpleNamespace(join_path=posixpath.join)
    )
    action._make_tmp_path = lambda: "/remote/ansible/action-temp"
    action._remove_tmp_path = lambda path: removed.append(path)

    def replace_source(_path: str, _data: bytes) -> None:
        source.rename(source.with_name("response-original"))
        _private_dir(source)
        for name, data in original.items():
            _private_file(source / name, data)

    action._transfer_data = replace_source
    action._execute_module = lambda **kwargs: copies.append(kwargs) or {"changed": True}
    with pytest.raises(AnsibleActionFail, match="changed"):
        action.run(task_vars={})
    assert copies == []
    assert removed == ["/remote/ansible/action-temp"]


def test_response_action_authenticates_published_request_and_snapshots_real_crypto(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_dir(isolated_test_dir / "response")
    response_dir, exchange, _trust_paths, _trust_digests, bindings = _response_scenario(root)
    monkeypatch.setattr(response_action.ActionBase, "run", lambda self, **kwargs: {})

    def run_action() -> dict[str, object]:
        action = object.__new__(response_action.ActionModule)
        action._task = SimpleNamespace(args=bindings, check_mode=False)
        return action.run(task_vars={})

    result = run_action()
    assert result["status"] == "received"
    assert result["approval_sha256"] == "2" * 64
    request = (exchange / SERVICE / REQUEST_ID / "request" / "request").read_bytes()
    assert result["request_sha256"] == sha256(request)
    existing = run_action()
    assert existing["status"] == "existing"
    published = exchange / SERVICE / REQUEST_ID / "response"
    assert {path.name for path in published.iterdir()} == set(RESPONSE_NAMES)
    assert stat.S_IMODE(published.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in published.iterdir())
    assert not list(published.rglob("*.key"))
    assert response_dir != published


def test_response_rejects_wrong_artifact_pin_without_publishing(
    isolated_test_dir: Path,
) -> None:
    root = _private_dir(isolated_test_dir / "wrong-pin")
    response_dir, exchange, trust_paths, trust_digests, bindings = _response_scenario(root)
    bindings["expected_artifact_sha256"] = "0" * 64
    with pytest.raises(ExchangeError, match="artifact digest"):
        _validate_response_scenario(
            response_dir, exchange, trust_paths, trust_digests, bindings
        )
    assert not (exchange / SERVICE / REQUEST_ID / "response").exists()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("nonce", "f" * 64, "exact request bindings"),
        ("operation", "renew", "exact request bindings"),
        ("approval_sha256", "A" * 64, "lowercase SHA-256"),
    ),
)
def test_response_rejects_wrong_request_cross_bindings_before_publication(
    isolated_test_dir: Path, field: str, value: str, message: str
) -> None:
    root = _private_dir(isolated_test_dir / f"wrong-response-{field}")
    response_dir, exchange, trust_paths, trust_digests, bindings = _response_scenario(root)
    _replace_record_field(response_dir / "response", field, value)
    with pytest.raises(ExchangeError, match=message):
        _validate_response_scenario(
            response_dir, exchange, trust_paths, trust_digests, bindings
        )
    assert not (exchange / SERVICE / REQUEST_ID / "response").exists()


@pytest.mark.parametrize("request_part", ("request", "request.sig"))
def test_response_rejects_changed_request_publication_before_publication(
    isolated_test_dir: Path, request_part: str
) -> None:
    root = _private_dir(isolated_test_dir / f"changed-{request_part}")
    response_dir, exchange, trust_paths, trust_digests, bindings = _response_scenario(root)
    request_dir = exchange / SERVICE / REQUEST_ID / "request"
    if request_part == "request":
        _replace_record_field(request_dir / "request", "current_cert_sha256", "e" * 64)
    else:
        _private_file(request_dir / "request.sig", b"invalid-signature\n")
    with pytest.raises(ExchangeError, match="signature verification"):
        _validate_response_scenario(
            response_dir, exchange, trust_paths, trust_digests, bindings
        )
    assert not (exchange / SERVICE / REQUEST_ID / "response").exists()


def test_response_rejects_frozen_trust_discontinuity_before_publication(
    isolated_test_dir: Path,
) -> None:
    root = _private_dir(isolated_test_dir / "trust-discontinuity")
    response_dir, exchange, trust_paths, trust_digests, bindings = _response_scenario(root)
    alternate = _private_dir(root / "alternate")
    _key, alternate_public = _ssh_key(alternate)
    deployer = Path(trust_paths["deployers.allowed_signers"])
    _private_file(deployer, f"{TARGET} {alternate_public}\n")
    trust_digests["deployers.allowed_signers"] = sha256(deployer.read_bytes())
    with pytest.raises(ExchangeError, match="collection receipt"):
        _validate_response_scenario(
            response_dir, exchange, trust_paths, trust_digests, bindings
        )
    assert not (exchange / SERVICE / REQUEST_ID / "response").exists()
