from __future__ import annotations

import ipaddress
import json
import os
import posixpath
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
from plugins.module_utils.platform_pki_exchange import (
    ARTIFACT_FIELDS,
    DEPLOYMENT_FIELDS,
    EVIDENCE_NAMES,
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
    assert set(RESPONSE_NAMES) == {
        "artifact",
        "tls.crt",
        "ca-chain.crt",
        "fullchain.crt",
        "response",
        "response.sig",
    }
    assert all("key" not in name for name in (*REQUEST_REMOTE_NAMES, *RESPONSE_NAMES))
    assert collection_action.ACTION_ARGUMENTS == {
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "trust_id",
        "request_id",
        "exchange_root",
        "service",
        "target",
        "transport",
        "transport_host_key_sha256",
        "inventory_sha256",
        "profile",
        "requester_principal",
        "response_principal",
        "common_name",
        "dns_sans",
        "ip_sans",
        "trust_paths",
        "trust_sha256",
        "expected_request_sha256",
        "expected_csr_sha256",
        "expected_csr_spki_sha256",
    }
    assert response_action.ACTION_ARGUMENTS == {
        "response_dir",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "inventory_sha256",
        "expected_artifact_sha256",
        "response_principal",
        "trust_paths",
        "trust_sha256",
        "common_name",
        "dns_sans",
        "ip_sans",
        "minimum_remaining_lifetime_seconds",
    }
    assert ingress_action.ACTION_ARGUMENTS == {
        "exchange_root",
        "service",
        "request_id",
        "ingress_root",
        "artifact_sha256",
    }
    assert evidence_action.ACTION_ARGUMENTS == {
        "lifecycle_helper_path",
        "state_root",
        "pending_root",
        "versions_root",
        "trust_id",
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    }
    assert evidence_status_action.ACTION_ARGUMENTS == {
        "exchange_root",
        "service",
        "target",
        "request_id",
        "artifact_sha256",
        "deployment_sha256",
    }
    assert EVIDENCE_NAMES == (
        "deployment",
        "deployment.sig",
        "validation-boundary",
        "validation-result",
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
