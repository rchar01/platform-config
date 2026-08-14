#!/usr/bin/env python3
"""Create one synthetic, certificate-only host-local PKI response."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from plugins.module_utils.platform_pki_exchange import (
    ExchangeError,
    PinnedTree,
    REQUEST_PUBLICATION_NAMES,
    TRUST_NAMES,
    pin_trust,
    validate_request_publication,
)


REQUEST_FIELDS = (
    "schema", "request_id", "nonce", "created_epoch", "expires_epoch",
    "operation", "service", "target", "requester_principal",
    "inventory_sha256", "csr_sha256", "csr_spki_sha256",
    "current_cert_sha256", "profile", "response_principal",
)
RESPONSE_FIELDS = (
    "schema", "request_id", "nonce", "operation", "service", "target",
    "request_sha256", "approval_sha256", "inventory_sha256", "csr_sha256",
    "csr_spki_sha256", "certificate_sha256", "certificate_spki_sha256",
    "chain_sha256", "issuer_root", "issuer_intermediate", "serial",
    "not_before_epoch", "not_after_epoch", "candidate_state",
    "response_principal", "created_epoch",
)
ARTIFACT_FIELDS = (
    "schema", "kind", "service", "request_id", "operation", "target",
    "source_kind", "source_response_sha256", "source_response_signature_sha256",
    "certificate_sha256", "certificate_spki_sha256", "chain_sha256",
    "fullchain_sha256", "issuer_root", "issuer_intermediate", "serial",
    "not_before_epoch", "not_after_epoch", "candidate_state",
    "deployment_state", "response_principal", "created_epoch",
)
APPROVAL_FIELDS = (
    "schema", "kind", "request_id", "request_sha256", "decision",
    "approver_principal", "created_epoch",
)
RESPONSE_NAMES = {
    "artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response",
    "response.sig",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"synthetic_signer: {message}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_record(data: bytes, fields: tuple[str, ...], label: str) -> dict[str, str]:
    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\r" in data:
        fail(f"{label} is not canonical LF-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    if len(lines) != len(fields):
        fail(f"{label} has an unexpected field count")
    values: dict[str, str] = {}
    for expected, line in zip(fields, lines, strict=True):
        if "=" not in line:
            fail(f"{label} contains a malformed field")
        name, value = line.split("=", 1)
        if name != expected or not value:
            fail(f"{label} contains an unexpected or empty field")
        values[name] = value
    return values


def record(fields: tuple[str, ...], values: dict[str, str]) -> bytes:
    if set(fields) != set(values):
        fail("attempted to serialize an incomplete record")
    return "".join(f"{name}={values[name]}\n" for name in fields).encode("ascii")


def private_file(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                fail(f"cannot finish writing {path.name}")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ssh_sign(path: Path, key: Path, namespace: str) -> Path:
    subprocess.run(
        ("ssh-keygen", "-Y", "sign", "-f", os.fspath(key), "-n", namespace, os.fspath(path)),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    signature = Path(f"{path}.sig")
    signature.chmod(0o600)
    return signature


def ca_key_usage() -> x509.KeyUsage:
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


def leaf_key_usage() -> x509.KeyUsage:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-dir", type=Path, required=True)
    parser.add_argument("--trust-dir", type=Path, required=True)
    parser.add_argument("--response-dir", type=Path, required=True)
    parser.add_argument("--approval-dir", type=Path, required=True)
    parser.add_argument("--reviewed-ca", type=Path, required=True)
    parser.add_argument("--result-json", type=Path, required=True)
    parser.add_argument("--response-key", type=Path, required=True)
    parser.add_argument("--approver-key", type=Path, required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--response-principal", required=True)
    parser.add_argument("--approver-principal", required=True)
    parser.add_argument("--common-name", required=True)
    parser.add_argument("--dns-san", action="append", default=[])
    parser.add_argument("--ip-san", action="append", default=[])
    return parser


def main() -> None:
    os.umask(0o077)
    args = build_parser().parse_args()
    expected_request_names = {"tls.csr", "request", "request.sig", "collection-receipt"}
    if {path.name for path in args.request_dir.iterdir()} != expected_request_names:
        fail("controller request publication is not the exact three-file transfer plus receipt")

    request_bytes = (args.request_dir / "request").read_bytes()
    request = parse_record(request_bytes, REQUEST_FIELDS, "request")
    if (
        request["service"] != args.service
        or request["target"] != args.target
        or request["requester_principal"] != args.target
        or request["response_principal"] != args.response_principal
        or request["profile"] != "server-p384-sha384-v1"
    ):
        fail("request identity differs from signer bindings")

    trust_paths = {name: os.fspath(args.trust_dir / name) for name in TRUST_NAMES}
    trust_digests = {
        name: digest((args.trust_dir / name).read_bytes()) for name in TRUST_NAMES
    }
    trust = {}
    publication = None
    try:
        trust = pin_trust(trust_paths, trust_digests)
        publication = PinnedTree.open(
            args.request_dir, REQUEST_PUBLICATION_NAMES, "controller request publication"
        )
        authenticated = validate_request_publication(
            publication,
            {
                "request_id": request["request_id"],
                "service": args.service,
                "target": args.target,
                "response_principal": args.response_principal,
                "inventory_sha256": request["inventory_sha256"],
                "common_name": args.common_name,
                "dns_sans": args.dns_san,
                "ip_sans": args.ip_san,
            },
            trust,
            now=int(time.time()),
        )
        if authenticated != request:
            fail("authenticated request differs from the parsed signer input")
    except ExchangeError as error:
        fail(f"request publication authentication failed: {error}")
    finally:
        if publication is not None:
            publication.close()
        for source in trust.values():
            source.close()

    csr_bytes = (args.request_dir / "tls.csr").read_bytes()
    try:
        csr = x509.load_pem_x509_csr(csr_bytes)
    except ValueError:
        fail("request CSR is invalid")
    if csr.public_bytes(serialization.Encoding.PEM) != csr_bytes or not csr.is_signature_valid:
        fail("request CSR is not canonical or self-signed")
    key = csr.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        fail("request CSR key is not P-384")
    if not isinstance(csr.signature_hash_algorithm, hashes.SHA384):
        fail("request CSR signature is not SHA-384")
    expected_subject = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, args.common_name),))
    expected_sans = tuple(x509.DNSName(value) for value in args.dns_san) + tuple(
        x509.IPAddress(ipaddress.ip_address(value)) for value in args.ip_san
    )
    try:
        actual_sans = tuple(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        fail("request CSR lacks SANs")
    if csr.subject != expected_subject or actual_sans != expected_sans or len(csr.extensions) != 1:
        fail("request CSR identities differ from exact signer bindings")

    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if (
        digest(csr_bytes) != request["csr_sha256"]
        or digest(spki) != request["csr_spki_sha256"]
    ):
        fail("request CSR digest bindings are invalid")

    args.response_dir.mkdir(mode=0o700)
    args.approval_dir.mkdir(mode=0o700)
    now = int(time.time())
    before = datetime.fromtimestamp(now - 60, UTC)
    after = datetime.fromtimestamp(now, UTC) + timedelta(days=7)

    root_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, "Disposable PKI Root g1"),))
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA384())
    )
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_name = x509.Name(
        (x509.NameAttribute(NameOID.COMMON_NAME, "Disposable PKI Intermediate g1-i1"),)
    )
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(2)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA384())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(expected_subject)
        .issuer_name(intermediate_name)
        .public_key(key)
        .serial_number(0x1234)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(leaf_key_usage(), critical=True)
        .add_extension(x509.ExtendedKeyUsage((ExtendedKeyUsageOID.SERVER_AUTH,)), critical=False)
        .add_extension(x509.SubjectAlternativeName(expected_sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA384())
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
    intermediate_pem = intermediate.public_bytes(serialization.Encoding.PEM)
    root_pem = root.public_bytes(serialization.Encoding.PEM)
    chain = intermediate_pem + root_pem
    fullchain = leaf_pem + intermediate_pem
    private_file(args.reviewed_ca, chain)

    approval = record(
        APPROVAL_FIELDS,
        {
            "schema": "1",
            "kind": "synthetic-offline-approval",
            "request_id": request["request_id"],
            "request_sha256": digest(request_bytes),
            "decision": "approved",
            "approver_principal": args.approver_principal,
            "created_epoch": str(now),
        },
    )
    approval_path = args.approval_dir / "approval"
    private_file(approval_path, approval)
    ssh_sign(approval_path, args.approver_key, "platform-pki-csr-approval-v1")

    response = record(
        RESPONSE_FIELDS,
        {
            "schema": "1",
            "request_id": request["request_id"],
            "nonce": request["nonce"],
            "operation": request["operation"],
            "service": request["service"],
            "target": request["target"],
            "request_sha256": digest(request_bytes),
            "approval_sha256": digest(approval),
            "inventory_sha256": request["inventory_sha256"],
            "csr_sha256": request["csr_sha256"],
            "csr_spki_sha256": request["csr_spki_sha256"],
            "certificate_sha256": digest(leaf_pem),
            "certificate_spki_sha256": digest(spki),
            "chain_sha256": digest(chain),
            "issuer_root": "g1",
            "issuer_intermediate": "g1-i1",
            "serial": "1234",
            "not_before_epoch": str(int(leaf.not_valid_before_utc.timestamp())),
            "not_after_epoch": str(int(leaf.not_valid_after_utc.timestamp())),
            "candidate_state": "pending",
            "response_principal": args.response_principal,
            "created_epoch": str(now),
        },
    )
    response_path = args.response_dir / "response"
    private_file(response_path, response)
    response_signature = ssh_sign(
        response_path, args.response_key, "platform-pki-csr-response-v1"
    ).read_bytes()
    private_file(args.response_dir / "tls.crt", leaf_pem)
    private_file(args.response_dir / "ca-chain.crt", chain)
    private_file(args.response_dir / "fullchain.crt", fullchain)

    artifact = record(
        ARTIFACT_FIELDS,
        {
            "schema": "1",
            "kind": "certificate-export",
            "service": request["service"],
            "request_id": request["request_id"],
            "operation": request["operation"],
            "target": request["target"],
            "source_kind": "csr-response",
            "source_response_sha256": digest(response),
            "source_response_signature_sha256": digest(response_signature),
            "certificate_sha256": digest(leaf_pem),
            "certificate_spki_sha256": digest(spki),
            "chain_sha256": digest(chain),
            "fullchain_sha256": digest(fullchain),
            "issuer_root": "g1",
            "issuer_intermediate": "g1-i1",
            "serial": "1234",
            "not_before_epoch": str(int(leaf.not_valid_before_utc.timestamp())),
            "not_after_epoch": str(int(leaf.not_valid_after_utc.timestamp())),
            "candidate_state": "pending",
            "deployment_state": "unfinalized",
            "response_principal": args.response_principal,
            "created_epoch": str(now),
        },
    )
    private_file(args.response_dir / "artifact", artifact)
    if {path.name for path in args.response_dir.iterdir()} != RESPONSE_NAMES:
        fail("response directory is not the exact six-file protocol set")

    result = {
        "approval_sha256": digest(approval),
        "artifact_sha256": digest(artifact),
        "certificate_sha256": digest(leaf_pem),
        "reviewed_ca_sha256": digest(chain),
        "served_intermediate_sha256": digest(intermediate_pem),
    }
    private_file(
        args.result_json,
        (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
    )


if __name__ == "__main__":
    main()
