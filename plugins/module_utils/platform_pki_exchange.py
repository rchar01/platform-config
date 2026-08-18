"""Narrow controller-side primitives for the host-local PKI exchange."""

from __future__ import annotations

import base64
import binascii
import ctypes
import datetime
import errno
import hashlib
import ipaddress
import os
import re
import secrets
import stat
import subprocess
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, NoReturn, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


TRUST_NAMES = (
    "policy",
    "requesters.allowed_signers",
    "approvers.allowed_signers",
    "responses.allowed_signers",
    "deployers.allowed_signers",
)
REQUEST_REMOTE_NAMES = ("tls.csr", "request", "request.sig")
REQUEST_PUBLICATION_NAMES = (*REQUEST_REMOTE_NAMES, "collection-receipt")
RESPONSE_NAMES = (
    "artifact",
    "tls.crt",
    "ca-chain.crt",
    "fullchain.crt",
    "response",
    "response.sig",
)
EVIDENCE_NAMES = (
    "deployment",
    "deployment.sig",
    "validation-boundary",
    "validation-result",
    "validation-result.sig",
)
REQUEST_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "created_epoch",
    "expires_epoch",
    "operation",
    "service",
    "target",
    "requester_principal",
    "inventory_sha256",
    "csr_sha256",
    "csr_spki_sha256",
    "current_cert_sha256",
    "profile",
    "response_principal",
)
RECEIPT_FIELDS = (
    "schema",
    "kind",
    "service",
    "target",
    "request_id",
    "transport",
    "transport_host_key_sha256",
    "csr_sha256",
    "request_sha256",
    "request_signature_sha256",
    "trust_policy_sha256",
    "request_trust_sha256",
    "approval_trust_sha256",
    "response_trust_sha256",
    "deployment_trust_sha256",
    "request_principal",
    "request_namespace",
    "collected_epoch",
    "verification_result",
)
POLICY_FIELDS = (
    "schema",
    "request_namespace",
    "approval_namespace",
    "response_namespace",
    "deployment_namespace",
    "request_max_age_seconds",
    "sole_operator_min_delay_seconds",
    "approval_max_age_seconds",
    "deployment_max_age_seconds",
    "clock_skew_seconds",
    "approver_principal",
    "response_principal",
)
RESPONSE_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "operation",
    "service",
    "target",
    "request_sha256",
    "approval_sha256",
    "inventory_sha256",
    "csr_sha256",
    "csr_spki_sha256",
    "certificate_sha256",
    "certificate_spki_sha256",
    "chain_sha256",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "not_before_epoch",
    "not_after_epoch",
    "candidate_state",
    "response_principal",
    "created_epoch",
)
ARTIFACT_FIELDS = (
    "schema",
    "kind",
    "service",
    "request_id",
    "operation",
    "target",
    "source_kind",
    "source_response_sha256",
    "source_response_signature_sha256",
    "certificate_sha256",
    "certificate_spki_sha256",
    "chain_sha256",
    "fullchain_sha256",
    "issuer_root",
    "issuer_intermediate",
    "serial",
    "not_before_epoch",
    "not_after_epoch",
    "candidate_state",
    "deployment_state",
    "response_principal",
    "created_epoch",
)
VALIDATION_BOUNDARY_FIELDS = (
    "schema",
    "kind",
    "service",
    "target",
    "local_validator",
    "remote_validator",
    "endpoint",
    "local_check",
    "remote_check",
)
DEPLOYMENT_FIELDS = (
    "schema",
    "request_id",
    "nonce",
    "operation",
    "service",
    "target",
    "request_sha256",
    "response_sha256",
    "response_signature_sha256",
    "candidate_sha256",
    "artifact_request_id",
    "artifact_manifest_sha256",
    "certificate_sha256",
    "certificate_spki_sha256",
    "chain_sha256",
    "fullchain_sha256",
    "action",
    "result",
    "local_certificate_sha256",
    "local_key_spki_sha256",
    "local_key_certificate_match",
    "served_certificate_sha256",
    "served_intermediate_sha256",
    "validation_boundary_sha256",
    "validation_result",
    "activation_epoch",
    "validation_epoch",
    "rollback_state",
    "rollback_hold_until_epoch",
    "deployment_principal",
    "created_epoch",
    "expires_epoch",
)
VALIDATION_RESULT_FIELDS = (
    "schema",
    "kind",
    "service",
    "target",
    "request_id",
    "artifact_manifest_sha256",
    "validation_boundary_sha256",
    "action",
    "result",
    "local_validator",
    "remote_validator",
    "endpoint",
    "local_service_result",
    "local_tls_result",
    "remote_tls_result",
    "remote_application_result",
    "remote_http_status",
    "remote_api_version",
    "remote_auth_challenge",
    "served_certificate_sha256",
    "served_intermediate_sha256",
    "activation_epoch",
    "validation_epoch",
    "deployment_sha256",
)

MAX_SIZES = {
    "tls.csr": 65536,
    "request": 16384,
    "request.sig": 16384,
    "collection-receipt": 16384,
    "artifact": 16384,
    "tls.crt": 65536,
    "ca-chain.crt": 131072,
    "fullchain.crt": 131072,
    "response": 16384,
    "response.sig": 16384,
    "policy": 65536,
    "requesters.allowed_signers": 65536,
    "approvers.allowed_signers": 65536,
    "responses.allowed_signers": 65536,
    "deployers.allowed_signers": 65536,
    "deployment": 32768,
    "deployment.sig": 16384,
    "validation-boundary": 16384,
    "validation-result": 32768,
    "validation-result.sig": 16384,
}
REPOSITORY_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
REQUEST_NAMESPACE = "platform-pki-csr-request-v1"
RESPONSE_NAMESPACE = "platform-pki-csr-response-v1"
DEPLOYMENT_NAMESPACE = "platform-pki-csr-deployment-v1"
PROFILE = "server-p384-sha384-v1"
LOCAL_CHECK = "platform-zot-local-active-tls-v1"
REMOTE_CHECK = "platform-oci-v2-read-only-strict-tls-v1"
MIN_ROLLBACK_SECONDS = 1209600

_HEX_32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SERVICE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z", re.ASCII)
_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z", re.ASCII)
_ROOT_GENERATION = re.compile(r"g[1-9][0-9]*\Z", re.ASCII)
_INTERMEDIATE_GENERATION = re.compile(r"g[1-9][0-9]*-i[1-9][0-9]*\Z", re.ASCII)
_SERIAL = re.compile(r"(?:[0-9A-F]{2})+\Z", re.ASCII)
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9_@%+=:,.-]+\Z", re.ASCII)
_CERTIFICATE_PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]+={0,2}\n)+"
    rb"-----END CERTIFICATE-----\n"
)


class ExchangeError(RuntimeError):
    """A fixed PKI exchange invariant failed."""


def fail(message: str) -> NoReturn:
    raise ExchangeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_request_id(value: object) -> str:
    if not isinstance(value, str) or _HEX_32.fullmatch(value) is None:
        fail("request_id must be 32 lowercase hexadecimal characters")
    return value


def require_service(value: object) -> str:
    if not isinstance(value, str) or _SERVICE.fullmatch(value) is None:
        fail("service is not canonical")
    return value


def require_validation_endpoint(value: object) -> str:
    if not isinstance(value, str):
        fail("validation endpoint is not canonical")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        fail("validation endpoint is not canonical")
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or _PRINCIPAL.fullmatch(hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v2/"
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        fail("validation endpoint is not canonical")
    authority = hostname if port is None else f"{hostname}:{port}"
    if value != f"https://{authority}/v2/":
        fail("validation endpoint is not canonical")
    return value


def require_principal(value: object, label: str) -> str:
    if not isinstance(value, str) or _PRINCIPAL.fullmatch(value) is None:
        fail(f"{label} is not canonical")
    return value


def canonical_epoch(value: str, label: str) -> int:
    if re.fullmatch(r"0|[1-9][0-9]*", value, re.ASCII) is None:
        fail(f"{label} is not a canonical decimal epoch")
    parsed = int(value)
    if parsed <= 0:
        fail(f"{label} must be positive")
    return parsed


def parse_record(data: bytes, fields: Sequence[str], label: str) -> dict[str, str]:
    """Parse one exact ordered, LF-terminated, nonempty ASCII record."""

    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\r" in data or b"\x00" in data:
        fail(f"{label} is not canonical LF-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    if len(lines) != len(fields):
        fail(f"{label} has an unexpected field count")
    record: dict[str, str] = {}
    for expected, line in zip(fields, lines, strict=True):
        if "=" not in line:
            fail(f"{label} contains a malformed field")
        key, value = line.split("=", 1)
        if key != expected or not value or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
            fail(f"{label} contains an unexpected, empty, or unsafe field")
        record[key] = value
    return record


def serialize_record(fields: Sequence[str], values: Mapping[str, str], label: str) -> bytes:
    if set(values) != set(fields):
        fail(f"cannot serialize incomplete {label}")
    lines: list[str] = []
    for field in fields:
        value = values[field]
        if not value or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
            fail(f"cannot serialize unsafe {label}")
        lines.append(f"{field}={value}")
    return ("\n".join(lines) + "\n").encode("ascii")


def validate_reviewed_ca_bundle(data: bytes) -> None:
    matches = tuple(_CERTIFICATE_PEM.finditer(data))
    if (
        len(matches) != 2
        or b"".join(match.group(0) for match in matches) != data
    ):
        fail("reviewed CA is not the exact intermediate-plus-root PEM bundle")
    certificates: list[x509.Certificate] = []
    try:
        for match in matches:
            pem = match.group(0)
            certificate = x509.load_pem_x509_certificate(pem)
            if certificate.public_bytes(serialization.Encoding.PEM) != pem:
                fail("reviewed CA contains noncanonical PEM")
            certificates.append(certificate)
    except x509.ExtensionNotFound:
        fail("reviewed CA certificate lacks required CA extensions")
    except ValueError:
        fail("reviewed CA contains an invalid PEM certificate")
    intermediate, root = certificates
    if intermediate.issuer != root.subject or root.issuer != root.subject:
        fail("reviewed CA certificates are not ordered intermediate then root")
    for certificate, path_length, label in (
        (intermediate, 0, "intermediate"),
        (root, 1, "root"),
    ):
        try:
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            )
            usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            fail(f"reviewed CA {label} lacks required CA extensions")
        if (
            not constraints.critical
            or not constraints.value.ca
            or constraints.value.path_length != path_length
            or not usage.critical
            or not usage.value.key_cert_sign
            or not usage.value.crl_sign
            or usage.value.digital_signature
            or usage.value.key_encipherment
            or usage.value.key_agreement
        ):
            fail(f"reviewed CA {label} profile is invalid")
    for certificate, issuer, label in (
        (intermediate, root, "intermediate"),
        (root, root, "root"),
    ):
        key = issuer.public_key()
        algorithm = certificate.signature_hash_algorithm
        if isinstance(key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)) and algorithm is None:
            fail(f"reviewed CA {label} signature algorithm is unavailable")
        try:
            if isinstance(key, ec.EllipticCurvePublicKey):
                assert algorithm is not None
                key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(algorithm),
                )
            elif isinstance(key, rsa.RSAPublicKey):
                assert algorithm is not None
                key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    algorithm,
                )
            elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                key.verify(certificate.signature, certificate.tbs_certificate_bytes)
            else:
                fail(f"reviewed CA {label} uses an unsupported key")
        except ExchangeError:
            raise
        except Exception:
            fail(f"reviewed CA {label} signature verification failed")


def validate_validation_boundary(
    data: bytes,
    *,
    service: object,
    target: object,
    remote_validator: object,
    endpoint: object,
) -> None:
    expected = {
        "schema": "1",
        "kind": "pki-validation-boundary",
        "service": require_service(service),
        "target": require_principal(target, "target"),
        "local_validator": require_principal(target, "target"),
        "remote_validator": require_principal(
            remote_validator, "remote_validator"
        ),
        "endpoint": require_validation_endpoint(endpoint),
        "local_check": LOCAL_CHECK,
        "remote_check": REMOTE_CHECK,
    }
    if expected["remote_validator"] == expected["target"]:
        fail("validation boundary requires a distinct remote validator")
    boundary = parse_record(
        data, VALIDATION_BOUNDARY_FIELDS, "validation boundary"
    )
    if boundary != expected:
        fail("validation boundary differs from the exact reviewed contract")


def _identity(metadata: os.stat_result, *, mutable_times: bool = True) -> tuple[int, ...]:
    values = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
    )
    if mutable_times:
        return (*values, metadata.st_mtime_ns, metadata.st_ctime_ns)
    return values[:6]


def _trusted_ancestor_owners() -> set[int]:
    owners = {0, os.geteuid()}
    try:
        with open("/proc/self/uid_map", encoding="ascii") as stream:
            mapping = [line.split() for line in stream if line.strip()]
        if mapping != [["0", "0", "4294967295"]]:
            with open("/proc/sys/kernel/overflowuid", encoding="ascii") as stream:
                owners.add(int(stream.read().strip()))
    except (OSError, ValueError):
        pass
    return owners


def _validate_absolute_path(path: object, label: str, *, outside_repository: bool) -> str:
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if (
        not isinstance(path, str)
        or not os.path.isabs(path)
        or path == "/"
        or os.path.normpath(path) != path
        or any(_PATH_COMPONENT.fullmatch(part) is None for part in path.split("/")[1:])
    ):
        fail(f"{label} must be an absolute canonical non-root path")
    if outside_repository:
        try:
            if os.path.commonpath((REPOSITORY_ROOT, path)) == REPOSITORY_ROOT:
                fail(f"{label} must be outside the public repository")
        except ValueError:
            fail(f"cannot compare {label} with the public repository")
    return path


def _require_safe_ancestor(metadata: os.stat_result, label: str) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in _trusted_ancestor_owners():
        fail(f"{label} has an unsafe ancestor")
    if mode & 0o022 and not mode & stat.S_ISVTX:
        fail(f"{label} has an unsafely writable ancestor")


@dataclass
class PinnedDirectory:
    path: str
    descriptors: list[int]
    components: list[str]
    identities: list[tuple[int, ...]]

    @classmethod
    def open(cls, path: object, label: str, *, outside_repository: bool = True) -> "PinnedDirectory":
        canonical = _validate_absolute_path(path, label, outside_repository=outside_repository)
        components = canonical.split("/")[1:]
        descriptors: list[int] = []
        identities: list[tuple[int, ...]] = []
        try:
            descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            _require_safe_ancestor(metadata, label)
            identities.append(_identity(metadata, mutable_times=False))
            for component in components:
                descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptors[-1],
                )
                descriptors.append(descriptor)
                metadata = os.fstat(descriptor)
                _require_safe_ancestor(metadata, label)
                identities.append(_identity(metadata, mutable_times=False))
            final = os.fstat(descriptors[-1])
            if final.st_uid != os.geteuid() or stat.S_IMODE(final.st_mode) != 0o700:
                fail(f"{label} must be current-user-owned mode 0700")
            pinned = cls(canonical, descriptors, components, identities)
            pinned.recheck()
            return pinned
        except Exception:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    def fileno(self) -> int:
        return self.descriptors[-1]

    def recheck(self) -> None:
        for index, expected in enumerate(self.identities):
            if _identity(os.fstat(self.descriptors[index]), mutable_times=False) != expected:
                fail(f"protected directory identity changed: {self.path}")
            if index:
                actual = os.stat(
                    self.components[index - 1],
                    dir_fd=self.descriptors[index - 1],
                    follow_symlinks=False,
                )
                if _identity(actual, mutable_times=False) != expected:
                    fail(f"protected directory path changed: {self.path}")

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


@dataclass
class PinnedFile:
    path: str
    parent: PinnedDirectory
    name: str
    descriptor: int
    identity: tuple[int, ...]
    data: bytes

    @classmethod
    def open(
        cls,
        path: object,
        label: str,
        *,
        expected_digest: str | None = None,
        maximum: int = 65536,
        outside_repository: bool = True,
    ) -> "PinnedFile":
        canonical = _validate_absolute_path(path, label, outside_repository=outside_repository)
        parent = PinnedDirectory.open(
            os.path.dirname(canonical), f"parent of {label}", outside_repository=outside_repository
        )
        descriptor = -1
        try:
            descriptor = os.open(
                os.path.basename(canonical),
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NOATIME", 0),
                dir_fd=parent.fileno(),
            )
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > maximum
            ):
                fail(f"{label} has unsafe metadata")
            data = _read_bounded(descriptor, maximum, label)
            identity = _identity(before)
            if _identity(os.fstat(descriptor)) != identity or len(data) != before.st_size:
                fail(f"{label} changed while being read")
            if expected_digest is not None and sha256(data) != expected_digest:
                fail(f"{label} digest mismatch")
            pinned = cls(canonical, parent, os.path.basename(canonical), descriptor, identity, data)
            pinned.recheck()
            return pinned
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            parent.close()
            raise

    def recheck(self) -> None:
        self.parent.recheck()
        actual = os.stat(self.name, dir_fd=self.parent.fileno(), follow_symlinks=False)
        if _identity(actual) != self.identity or _identity(os.fstat(self.descriptor)) != self.identity:
            fail(f"protected file changed: {self.path}")

    def close(self) -> None:
        os.close(self.descriptor)
        self.parent.close()


def _read_bounded(descriptor: int, maximum: int, label: str) -> bytes:
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if not data or len(data) > maximum:
        fail(f"{label} is empty or exceeds its fixed size limit")
    return bytes(data)


@dataclass
class PinnedTree:
    directory: PinnedDirectory
    directory_identity: tuple[int, ...]
    files: dict[str, PinnedFile]
    names: frozenset[str]

    @classmethod
    def open(
        cls,
        path: object,
        names: Sequence[str],
        label: str,
        *,
        outside_repository: bool = True,
    ) -> "PinnedTree":
        directory = PinnedDirectory.open(path, label, outside_repository=outside_repository)
        files: dict[str, PinnedFile] = {}
        expected = frozenset(names)
        try:
            actual = frozenset(os.listdir(directory.fileno()))
            if actual != expected:
                fail(f"{label} does not contain the exact fixed file set")
            directory_identity = _identity(os.fstat(directory.fileno()))
            for name in names:
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NOATIME", 0),
                    dir_fd=directory.fileno(),
                )
                before = os.fstat(descriptor)
                maximum = MAX_SIZES[name]
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or before.st_size <= 0
                    or before.st_size > maximum
                ):
                    os.close(descriptor)
                    fail(f"{label} file has unsafe metadata: {name}")
                data = _read_bounded(descriptor, maximum, f"{label} file {name}")
                identity = _identity(before)
                if _identity(os.fstat(descriptor)) != identity or len(data) != before.st_size:
                    os.close(descriptor)
                    fail(f"{label} file changed while being read: {name}")
                files[name] = PinnedFile(
                    os.path.join(directory.path, name), directory, name, descriptor, identity, data
                )
            tree = cls(directory, directory_identity, files, actual)
            tree.recheck()
            return tree
        except Exception as error:
            for source in files.values():
                os.close(source.descriptor)
            directory.close()
            if isinstance(error, OSError):
                fail(f"{label} contains an unsafe or unreadable entry")
            raise

    @property
    def data(self) -> dict[str, bytes]:
        return {name: source.data for name, source in self.files.items()}

    def recheck(self) -> None:
        self.directory.recheck()
        if _identity(os.fstat(self.directory.fileno())) != self.directory_identity:
            fail(f"protected source directory changed: {self.directory.path}")
        if frozenset(os.listdir(self.directory.fileno())) != self.names:
            fail(f"protected source directory entries changed: {self.directory.path}")
        for source in self.files.values():
            actual = os.stat(source.name, dir_fd=self.directory.fileno(), follow_symlinks=False)
            if _identity(actual) != source.identity or _identity(os.fstat(source.descriptor)) != source.identity:
                fail(f"protected source file changed: {source.name}")

    def close(self) -> None:
        for source in self.files.values():
            os.close(source.descriptor)
        self.files.clear()
        self.directory.close()


def prepare_request_parent(exchange_root: object, service: str, request_id: str) -> PinnedDirectory:
    """Open/create only the canonical service/request parent below a protected root."""

    root = PinnedDirectory.open(exchange_root, "exchange root")
    current = root
    try:
        current_path = root.path
        for name in (service, request_id):
            current_path = os.path.join(current_path, name)
            try:
                os.mkdir(name, 0o700, dir_fd=current.fileno())
                os.fsync(current.fileno())
            except FileExistsError:
                pass
            child = PinnedDirectory.open(
                current_path, "exchange service/request directory"
            )
            if current is not root:
                current.close()
            current = child
        root.close()
        return current
    except Exception:
        if current is not root:
            current.close()
        root.close()
        raise


def prepare_evidence_parent(request_parent: PinnedDirectory) -> PinnedDirectory:
    """Open/create only the fixed evidence directory below a request workspace."""

    request_parent.recheck()
    try:
        os.mkdir("evidence", 0o700, dir_fd=request_parent.fileno())
        os.fsync(request_parent.fileno())
    except FileExistsError:
        pass
    evidence = PinnedDirectory.open(
        os.path.join(request_parent.path, "evidence"), "exchange evidence parent"
    )
    request_parent.recheck()
    return evidence


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    try:
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                fail("protected stage write made no progress")
            view = view[count:]
    finally:
        view.release()


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        fail("atomic no-clobber publication is unavailable")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(destination)
        fail("atomic no-clobber publication failed")


def _existing_tree_matches(parent: PinnedDirectory, name: str, data: Mapping[str, bytes]) -> bool:
    try:
        existing = PinnedTree.open(
            os.path.join(parent.path, name), tuple(data), "published exchange directory"
        )
    except (ExchangeError, OSError):
        return False
    try:
        return existing.data == dict(data)
    finally:
        existing.close()


def _remove_owned_stage(parent: PinnedDirectory, stage_name: str, identity: tuple[int, ...]) -> None:
    try:
        actual = os.stat(stage_name, dir_fd=parent.fileno(), follow_symlinks=False)
        if _identity(actual, mutable_times=False) != identity:
            return
        stage_fd = os.open(
            stage_name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent.fileno(),
        )
        try:
            for name in os.listdir(stage_fd):
                metadata = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1:
                    os.unlink(name, dir_fd=stage_fd)
                else:
                    return
        finally:
            os.close(stage_fd)
        os.rmdir(stage_name, dir_fd=parent.fileno())
        os.fsync(parent.fileno())
    except OSError:
        return


def publish_exact_tree(
    parent: PinnedDirectory,
    destination: str,
    data: Mapping[str, bytes],
    *,
    pre_publish: Callable[[], None] | None = None,
) -> bool:
    """Publish one fixed byte tree atomically; return whether it was created."""

    standard = destination in {"request", "response"} and frozenset(data) in {
        frozenset(REQUEST_PUBLICATION_NAMES),
        frozenset(RESPONSE_NAMES),
    }
    frozen_trust = (
        destination == "trust" and frozenset(data) == frozenset(TRUST_NAMES)
    )
    evidence = (
        _HEX_64.fullmatch(destination) is not None
        and os.path.basename(parent.path) == "evidence"
        and frozenset(data) == frozenset(EVIDENCE_NAMES)
    )
    if not standard and not frozen_trust and not evidence:
        fail("exchange publication destination is not allowlisted")
    try:
        os.stat(destination, dir_fd=parent.fileno(), follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        if _existing_tree_matches(parent, destination, data):
            if pre_publish is not None:
                pre_publish()
            return False
        fail("exchange publication conflicts with an existing destination")

    stage_name = f".platform-pki-{destination}.{secrets.token_hex(16)}"
    os.mkdir(stage_name, 0o700, dir_fd=parent.fileno())
    stage_fd = os.open(
        stage_name,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent.fileno(),
    )
    stage_identity = _identity(os.fstat(stage_fd), mutable_times=False)
    published = False
    try:
        for name, content in data.items():
            descriptor = os.open(
                name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=stage_fd,
            )
            try:
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(stage_fd)
        staged = PinnedTree.open(
            os.path.join(parent.path, stage_name), tuple(data), "protected exchange stage"
        )
        try:
            if staged.data != dict(data):
                fail("protected exchange stage bytes changed")
            staged.recheck()
            parent.recheck()
            if pre_publish is not None:
                pre_publish()
            try:
                _rename_noreplace(parent.fileno(), stage_name, destination)
                published = True
            except FileExistsError:
                if not _existing_tree_matches(parent, destination, data):
                    fail("exchange publication lost a no-clobber race")
            os.fsync(parent.fileno())
        finally:
            staged.close()
    finally:
        os.close(stage_fd)
        if not published:
            _remove_owned_stage(parent, stage_name, stage_identity)
    if not _existing_tree_matches(parent, destination, data):
        fail("published exchange directory failed final validation")
    return published


def _decode_ssh_string(data: bytes, offset: int, label: str) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        fail(f"{label} contains truncated SSH key data")
    length = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4
    if length > len(data) - offset:
        fail(f"{label} contains truncated SSH key data")
    return data[offset : offset + length], offset + length


def parse_allowed_signers(data: bytes, label: str) -> dict[str, tuple[str, str]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")
    if not text.endswith("\n") or text.endswith("\n\n") or "\r" in text or "\x00" in text:
        fail(f"{label} is not canonical LF-terminated text")
    records: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split(" ")
        if len(parts) != 3 or _PRINCIPAL.fullmatch(parts[0]) is None or parts[1] != "ssh-ed25519":
            fail(f"{label} contains a noncanonical signer record")
        try:
            decoded = base64.b64decode(parts[2], validate=True)
        except (binascii.Error, ValueError):
            fail(f"{label} contains invalid key data")
        algorithm, offset = _decode_ssh_string(decoded, 0, label)
        public_key, offset = _decode_ssh_string(decoded, offset, label)
        if (
            base64.b64encode(decoded).decode("ascii") != parts[2]
            or parts[0] in records
            or algorithm != b"ssh-ed25519"
            or len(public_key) != 32
            or offset != len(decoded)
        ):
            fail(f"{label} contains duplicate or noncanonical key data")
        records[parts[0]] = (parts[1], parts[2])
    if not records:
        fail(f"{label} is empty")
    return records


def validate_frozen_trust(trust: Mapping[str, PinnedFile], target: str, response_principal: str) -> dict[str, bytes]:
    if set(trust) != set(TRUST_NAMES):
        fail("frozen trust does not contain the exact five files")
    data = {name: source.data for name, source in trust.items()}
    policy = parse_record(data["policy"], POLICY_FIELDS, "frozen trust policy")
    expected = {
        "schema": "2",
        "request_namespace": REQUEST_NAMESPACE,
        "approval_namespace": "platform-pki-csr-approval-v1",
        "response_namespace": RESPONSE_NAMESPACE,
        "deployment_namespace": "platform-pki-csr-deployment-v1",
        "request_max_age_seconds": "604800",
        "sole_operator_min_delay_seconds": "86400",
        "approval_max_age_seconds": "86400",
        "deployment_max_age_seconds": "86400",
        "clock_skew_seconds": "300",
    }
    if any(policy[key] != value for key, value in expected.items()):
        fail("frozen trust policy is not the exact schema-2 policy")
    require_principal(policy["approver_principal"], "policy approver principal")
    require_principal(policy["response_principal"], "policy response principal")
    if policy["response_principal"] != response_principal:
        fail("response principal differs from frozen trust policy")
    requester = parse_allowed_signers(data["requesters.allowed_signers"], "requester trust")
    approver = parse_allowed_signers(data["approvers.allowed_signers"], "approver trust")
    responses = parse_allowed_signers(data["responses.allowed_signers"], "response trust")
    deployer = parse_allowed_signers(data["deployers.allowed_signers"], "deployer trust")
    if target not in requester or target not in deployer:
        fail("target is absent from requester or deployer trust")
    if set(approver) != {policy["approver_principal"]} or set(responses) != {response_principal}:
        fail("frozen approver or response trust has an unexpected principal set")
    return data


def pin_trust(paths: object, digests: object) -> dict[str, PinnedFile]:
    if not isinstance(paths, dict) or set(paths) != set(TRUST_NAMES):
        fail("trust_paths must contain the exact five trust names")
    if not isinstance(digests, dict) or set(digests) != set(TRUST_NAMES):
        fail("trust_sha256 must contain the exact five trust names")
    pinned: dict[str, PinnedFile] = {}
    try:
        for name in TRUST_NAMES:
            digest = require_digest(digests[name], f"trust digest for {name}")
            if not isinstance(paths[name], str) or os.path.basename(paths[name]) != name:
                fail(f"trust path basename does not match its fixed name: {name}")
            pinned[name] = PinnedFile.open(
                paths[name], f"frozen trust file {name}", expected_digest=digest
            )
        if len({source.path for source in pinned.values()}) != len(TRUST_NAMES):
            fail("frozen trust paths must be distinct")
        return pinned
    except Exception:
        for source in pinned.values():
            source.close()
        raise


def verify_ssh_signature(
    data: bytes,
    signature: PinnedFile,
    allowed_signers: PinnedFile,
    principal: str,
    namespace: str,
) -> None:
    signature.recheck()
    allowed_signers.recheck()
    try:
        result = subprocess.run(
            (
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                f"/proc/self/fd/{allowed_signers.descriptor}",
                "-I",
                principal,
                "-n",
                namespace,
                "-s",
                f"/proc/self/fd/{signature.descriptor}",
            ),
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(allowed_signers.descriptor, signature.descriptor),
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("SSH signature verification could not be completed")
    signature.recheck()
    allowed_signers.recheck()
    if result.returncode != 0:
        fail("SSH signature verification failed")


def _validate_dns(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or value.endswith(".") or not value.isascii():
        fail(f"{label} is not a canonical DNS name")
    labels = value.split(".")
    if any(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", item, re.ASCII) is None
        for item in labels
    ):
        fail(f"{label} is not a canonical DNS name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    fail(f"{label} must not be an IP address")


def validate_san_arguments(common_name: object, dns_sans: object, ip_sans: object) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    common = _validate_dns(common_name, "common_name")
    if not isinstance(dns_sans, list) or not dns_sans:
        fail("dns_sans must be a nonempty ordered list")
    if not isinstance(ip_sans, list):
        fail("ip_sans must be an ordered list")
    dns = tuple(_validate_dns(value, "DNS SAN") for value in dns_sans)
    ips: list[str] = []
    for value in ip_sans:
        if not isinstance(value, str):
            fail("IP SAN is not a canonical IPv4 address")
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            fail("IP SAN is not a canonical IPv4 address")
        if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
            fail("IP SAN is not a canonical IPv4 address")
        ips.append(value)
    if len(set(dns)) != len(dns) or len(set(ips)) != len(ips):
        fail("SAN values must not repeat")
    return common, dns, tuple(ips)


def _load_csr(data: bytes) -> x509.CertificateSigningRequest:
    if not data.endswith(b"\n") or b"\r" in data or data.count(b"-----BEGIN CERTIFICATE REQUEST-----") != 1:
        fail("CSR is not one canonical PEM object")
    try:
        csr = x509.load_pem_x509_csr(data)
    except ValueError:
        fail("CSR is invalid")
    if csr.public_bytes(serialization.Encoding.PEM) != data or not csr.is_signature_valid:
        fail("CSR encoding or self-signature is invalid")
    return csr


def validate_csr(data: bytes, common_name: str, dns_sans: Sequence[str], ip_sans: Sequence[str]) -> str:
    csr = _load_csr(data)
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP384R1):
        fail("CSR public key is not EC P-384")
    if not isinstance(csr.signature_hash_algorithm, hashes.SHA384):
        fail("CSR signature algorithm is not SHA-384")
    if csr.subject != x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, common_name),)):
        fail("CSR common name does not match the inventory binding")
    if len(csr.extensions) != 1:
        fail("CSR contains unexpected requested extensions")
    try:
        extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        fail("CSR SAN extension is missing")
    if extension.critical:
        fail("CSR SAN extension must not be critical")
    actual = tuple(extension.value)
    expected = tuple(x509.DNSName(value) for value in dns_sans) + tuple(
        x509.IPAddress(ipaddress.ip_address(value)) for value in ip_sans
    )
    if actual != expected:
        fail("CSR SANs do not exactly match the ordered inventory binding")
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sha256(spki)


def validate_request_payload(
    files: Mapping[str, bytes],
    bindings: Mapping[str, object],
    trust: Mapping[str, PinnedFile],
    signature_file: PinnedFile,
    *,
    now: int,
) -> dict[str, str]:
    if set(files) != set(REQUEST_REMOTE_NAMES):
        fail("collected request does not contain the exact three public files")
    request = parse_record(files["request"], REQUEST_FIELDS, "request")
    request_id = require_request_id(bindings["request_id"])
    service = require_service(bindings["service"])
    target = require_principal(bindings["target"], "target")
    requester = require_principal(bindings["requester_principal"], "requester_principal")
    response_principal = require_principal(bindings["response_principal"], "response_principal")
    inventory = require_digest(bindings["inventory_sha256"], "inventory_sha256")
    expected_request = require_digest(bindings["expected_request_sha256"], "expected_request_sha256")
    expected_csr = require_digest(bindings["expected_csr_sha256"], "expected_csr_sha256")
    expected_spki = require_digest(bindings["expected_csr_spki_sha256"], "expected_csr_spki_sha256")
    if bindings["profile"] != PROFILE:
        fail("profile is not the frozen server P-384 profile")
    common, dns, ips = validate_san_arguments(
        bindings["common_name"], bindings["dns_sans"], bindings["ip_sans"]
    )
    if requester != target:
        fail("requester_principal must equal target")
    if (
        request["schema"] != "1"
        or request["request_id"] != request_id
        or request["service"] != service
        or request["target"] != target
        or request["requester_principal"] != requester
        or request["response_principal"] != response_principal
        or request["inventory_sha256"] != inventory
        or request["profile"] != PROFILE
    ):
        fail("request does not match the exact controller bindings")
    if request["operation"] not in {"issue", "migrate", "renew"} or _HEX_64.fullmatch(request["nonce"]) is None:
        fail("request operation or nonce is invalid")
    if request["current_cert_sha256"] != "none" and _HEX_64.fullmatch(request["current_cert_sha256"]) is None:
        fail("request current certificate digest is invalid")
    if (request["operation"] == "issue") != (request["current_cert_sha256"] == "none"):
        fail("request operation and current certificate binding conflict")
    created = canonical_epoch(request["created_epoch"], "request created_epoch")
    expires = canonical_epoch(request["expires_epoch"], "request expires_epoch")
    if expires <= created or expires - created > 604800 or created > now + 300 or now > expires:
        fail("request lifetime is invalid or expired")
    if sha256(files["request"]) != expected_request:
        fail("request digest does not match the expected pin")
    if sha256(files["tls.csr"]) != expected_csr or request["csr_sha256"] != expected_csr:
        fail("CSR digest does not match the request and expected pin")
    spki = validate_csr(files["tls.csr"], common, dns, ips)
    if spki != expected_spki or request["csr_spki_sha256"] != expected_spki:
        fail("CSR SPKI digest does not match the request and expected pin")
    validate_frozen_trust(trust, target, response_principal)
    verify_ssh_signature(
        files["request"], signature_file, trust["requesters.allowed_signers"], requester, REQUEST_NAMESPACE
    )
    return request


def collection_receipt(
    files: Mapping[str, bytes], bindings: Mapping[str, object], trust: Mapping[str, PinnedFile], collected_epoch: int
) -> bytes:
    digests = {name: sha256(source.data) for name, source in trust.items()}
    values = {
        "schema": "1",
        "kind": "pki-request-collection",
        "service": str(bindings["service"]),
        "target": str(bindings["target"]),
        "request_id": str(bindings["request_id"]),
        "transport": str(bindings["transport"]),
        "transport_host_key_sha256": str(bindings["transport_host_key_sha256"]),
        "csr_sha256": sha256(files["tls.csr"]),
        "request_sha256": sha256(files["request"]),
        "request_signature_sha256": sha256(files["request.sig"]),
        "trust_policy_sha256": digests["policy"],
        "request_trust_sha256": digests["requesters.allowed_signers"],
        "approval_trust_sha256": digests["approvers.allowed_signers"],
        "response_trust_sha256": digests["responses.allowed_signers"],
        "deployment_trust_sha256": digests["deployers.allowed_signers"],
        "request_principal": str(bindings["requester_principal"]),
        "request_namespace": REQUEST_NAMESPACE,
        "collected_epoch": str(collected_epoch),
        "verification_result": "passed",
    }
    return serialize_record(RECEIPT_FIELDS, values, "collection receipt")


def validate_collection_receipt(
    data: bytes,
    files: Mapping[str, bytes],
    bindings: Mapping[str, object],
    trust: Mapping[str, PinnedFile],
    request: Mapping[str, str],
    *,
    now: int,
) -> None:
    receipt = parse_record(data, RECEIPT_FIELDS, "collection receipt")
    collected = canonical_epoch(receipt["collected_epoch"], "collection receipt collected_epoch")
    expected = parse_record(
        collection_receipt(files, bindings, trust, collected),
        RECEIPT_FIELDS,
        "expected collection receipt",
    )
    if receipt != expected:
        fail("collection receipt does not bind the exact request and trust")
    created = canonical_epoch(request["created_epoch"], "request created_epoch")
    expires = canonical_epoch(request["expires_epoch"], "request expires_epoch")
    if collected < created or collected > now + 300 or collected > expires:
        fail("collection receipt time is outside the request lifetime")


def validate_request_publication(
    tree: PinnedTree,
    bindings: Mapping[str, object],
    trust: Mapping[str, PinnedFile],
    *,
    now: int,
) -> dict[str, str]:
    """Authenticate the exact existing controller request publication."""

    if tree.names != frozenset(REQUEST_PUBLICATION_NAMES):
        fail("controller request publication does not contain the exact four files")
    files = tree.data
    public_files = {name: files[name] for name in REQUEST_REMOTE_NAMES}
    request = parse_record(files["request"], REQUEST_FIELDS, "published request")
    receipt = parse_record(
        files["collection-receipt"], RECEIPT_FIELDS, "published collection receipt"
    )
    if receipt["transport"] not in {"ssh", "sftp"}:
        fail("published collection receipt transport is invalid")
    require_digest(
        receipt["transport_host_key_sha256"],
        "published collection receipt transport host key digest",
    )
    derived_bindings = {
        **bindings,
        "profile": PROFILE,
        "requester_principal": bindings["target"],
        "transport": receipt["transport"],
        "transport_host_key_sha256": receipt["transport_host_key_sha256"],
        "expected_request_sha256": sha256(files["request"]),
        "expected_csr_sha256": sha256(files["tls.csr"]),
        "expected_csr_spki_sha256": request["csr_spki_sha256"],
    }
    authenticated = validate_request_payload(
        public_files,
        derived_bindings,
        trust,
        tree.files["request.sig"],
        now=now,
    )
    validate_collection_receipt(
        files["collection-receipt"],
        public_files,
        derived_bindings,
        trust,
        authenticated,
        now=now,
    )
    tree.recheck()
    for source in trust.values():
        source.recheck()
    return authenticated


def _pem_certificates(data: bytes, count: int, label: str) -> tuple[x509.Certificate, ...]:
    matches = tuple(_CERTIFICATE_PEM.finditer(data))
    if len(matches) != count or b"".join(match.group(0) for match in matches) != data:
        fail(f"{label} does not contain the exact certificate count")
    certificates: list[x509.Certificate] = []
    for match in matches:
        try:
            certificate = x509.load_pem_x509_certificate(match.group(0))
        except ValueError:
            fail(f"{label} contains an invalid certificate")
        if certificate.public_bytes(serialization.Encoding.PEM) != match.group(0):
            fail(f"{label} contains noncanonical certificate encoding")
        certificates.append(certificate)
    return tuple(certificates)


def _verify_certificate_signature(certificate: x509.Certificate, issuer: x509.Certificate, label: str) -> None:
    key = issuer.public_key()
    algorithm = certificate.signature_hash_algorithm
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            if algorithm is None:
                fail(f"{label} signature algorithm is invalid")
            key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(algorithm))
        elif isinstance(key, rsa.RSAPublicKey):
            if algorithm is None:
                fail(f"{label} signature algorithm is invalid")
            key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                algorithm,
            )
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            fail(f"{label} uses an unsupported issuer key")
    except Exception as error:
        if isinstance(error, ExchangeError):
            raise
        fail(f"{label} signature verification failed")


def _require_ca(certificate: x509.Certificate, path_length: int, label: str) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        fail(f"{label} CA extensions are missing")
    if (
        not constraints.critical
        or not constraints.value.ca
        or constraints.value.path_length != path_length
        or not usage.critical
        or not usage.value.key_cert_sign
        or not usage.value.crl_sign
        or usage.value.digital_signature
        or usage.value.key_encipherment
        or usage.value.key_agreement
    ):
        fail(f"{label} CA profile is invalid")


def _certificate_spki(certificate: x509.Certificate) -> str:
    return sha256(
        certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def validate_response_snapshot(
    tree: PinnedTree,
    request_tree: PinnedTree,
    bindings: Mapping[str, object],
    trust: Mapping[str, PinnedFile],
    *,
    now: int,
) -> dict[str, str]:
    files = tree.data
    request = validate_request_publication(request_tree, bindings, trust, now=now)
    response = parse_record(files["response"], RESPONSE_FIELDS, "response")
    artifact = parse_record(files["artifact"], ARTIFACT_FIELDS, "artifact")
    request_id = require_request_id(bindings["request_id"])
    service = require_service(bindings["service"])
    target = require_principal(bindings["target"], "target")
    principal = require_principal(bindings["response_principal"], "response_principal")
    require_digest(bindings["inventory_sha256"], "inventory_sha256")
    artifact_pin = require_digest(
        bindings["expected_artifact_sha256"], "expected_artifact_sha256"
    )
    if sha256(files["artifact"]) != artifact_pin:
        fail("artifact digest does not match the exact expected pin")
    if response["schema"] != "1" or response["operation"] not in {"issue", "migrate", "renew"}:
        fail("response schema or operation is invalid")
    if (
        response["request_id"] != request_id
        or response["request_id"] != request["request_id"]
        or response["nonce"] != request["nonce"]
        or response["operation"] != request["operation"]
        or response["service"] != request["service"]
        or response["target"] != request["target"]
        or response["response_principal"] != request["response_principal"]
        or response["request_sha256"] != sha256(request_tree.files["request"].data)
        or response["inventory_sha256"] != request["inventory_sha256"]
        or response["csr_sha256"] != request["csr_sha256"]
        or response["csr_spki_sha256"] != request["csr_spki_sha256"]
    ):
        fail("response does not match the exact request bindings")
    approval_sha = require_digest(response["approval_sha256"], "response approval_sha256")
    for field in (
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
    ):
        require_digest(response[field], f"response {field}")
    if response["certificate_spki_sha256"] != response["csr_spki_sha256"]:
        fail("response certificate and CSR SPKI bindings differ")
    if (
        _ROOT_GENERATION.fullmatch(response["issuer_root"]) is None
        or _INTERMEDIATE_GENERATION.fullmatch(response["issuer_intermediate"]) is None
        or not response["issuer_intermediate"].startswith(f"{response['issuer_root']}-i")
        or _SERIAL.fullmatch(response["serial"]) is None
        or (len(response["serial"]) > 2 and response["serial"].startswith("00"))
        or response["candidate_state"] != "pending"
    ):
        fail("response issuer, serial, or candidate state is invalid")

    response_sha = sha256(files["response"])
    signature_sha = sha256(files["response.sig"])
    certificate_sha = sha256(files["tls.crt"])
    chain_sha = sha256(files["ca-chain.crt"])
    fullchain_sha = sha256(files["fullchain.crt"])
    expected_artifact = {
        "schema": "1",
        "kind": "certificate-export",
        "service": service,
        "request_id": request_id,
        "operation": response["operation"],
        "target": target,
        "source_kind": "csr-response",
        "source_response_sha256": response_sha,
        "source_response_signature_sha256": signature_sha,
        "certificate_sha256": certificate_sha,
        "certificate_spki_sha256": response["certificate_spki_sha256"],
        "chain_sha256": chain_sha,
        "fullchain_sha256": fullchain_sha,
        "issuer_root": response["issuer_root"],
        "issuer_intermediate": response["issuer_intermediate"],
        "serial": response["serial"],
        "not_before_epoch": response["not_before_epoch"],
        "not_after_epoch": response["not_after_epoch"],
        "candidate_state": "pending",
        "deployment_state": "unfinalized",
        "response_principal": principal,
        "created_epoch": response["created_epoch"],
    }
    if artifact != expected_artifact:
        fail("artifact does not bind the exact signed response")
    if (
        response["certificate_sha256"] != certificate_sha
        or response["chain_sha256"] != chain_sha
    ):
        fail("response does not bind the exact certificate files")

    response_trust = trust["responses.allowed_signers"]
    verify_ssh_signature(
        files["response"], tree.files["response.sig"], response_trust, principal, RESPONSE_NAMESPACE
    )

    leaf = _pem_certificates(files["tls.crt"], 1, "leaf certificate")[0]
    intermediate, root = _pem_certificates(files["ca-chain.crt"], 2, "CA chain")
    if files["fullchain.crt"] != files["tls.crt"] + intermediate.public_bytes(serialization.Encoding.PEM):
        fail("full chain is not the exact leaf plus intermediate")
    _pem_certificates(files["fullchain.crt"], 2, "full chain")
    if leaf.issuer != intermediate.subject or intermediate.issuer != root.subject or root.issuer != root.subject:
        fail("certificate issuer names do not form the exact chain")
    _verify_certificate_signature(leaf, intermediate, "leaf certificate")
    _verify_certificate_signature(intermediate, root, "intermediate certificate")
    _verify_certificate_signature(root, root, "root certificate")
    _require_ca(intermediate, 0, "intermediate certificate")
    _require_ca(root, 1, "root certificate")

    common, dns, ips = validate_san_arguments(
        bindings["common_name"], bindings["dns_sans"], bindings["ip_sans"]
    )
    key = leaf.public_key()
    if (
        leaf.version is not x509.Version.v3
        or not isinstance(key, ec.EllipticCurvePublicKey)
        or not isinstance(key.curve, ec.SECP384R1)
        or not isinstance(leaf.signature_hash_algorithm, hashes.SHA384)
        or leaf.subject != x509.Name((x509.NameAttribute(NameOID.COMMON_NAME, common),))
    ):
        fail("leaf certificate is not the exact P-384 server profile")
    try:
        basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        issuer_ski = intermediate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        fail("leaf certificate is missing a required profile extension")
    expected_sans = tuple(x509.DNSName(value) for value in dns) + tuple(
        x509.IPAddress(ipaddress.ip_address(value)) for value in ips
    )
    if (
        len(leaf.extensions) != 6
        or not basic.critical
        or basic.value.ca
        or basic.value.path_length is not None
        or not usage.critical
        or not usage.value.digital_signature
        or usage.value.content_commitment
        or usage.value.key_encipherment
        or usage.value.data_encipherment
        or usage.value.key_agreement
        or usage.value.key_cert_sign
        or usage.value.crl_sign
        or eku.critical
        or tuple(eku.value) != (ExtendedKeyUsageOID.SERVER_AUTH,)
        or san.critical
        or tuple(san.value) != expected_sans
        or ski.critical
        or aki.critical
        or aki.value.key_identifier != issuer_ski.value.digest
    ):
        fail("leaf certificate extensions do not match the exact server profile")
    spki = _certificate_spki(leaf)
    if spki != response["certificate_spki_sha256"]:
        fail("leaf certificate SPKI does not match the signed response")
    serial = format(leaf.serial_number, "X")
    if len(serial) % 2:
        serial = "0" + serial
    not_before = int(leaf.not_valid_before_utc.timestamp())
    not_after = int(leaf.not_valid_after_utc.timestamp())
    response_not_before = canonical_epoch(response["not_before_epoch"], "response not_before_epoch")
    response_not_after = canonical_epoch(response["not_after_epoch"], "response not_after_epoch")
    created = canonical_epoch(response["created_epoch"], "response created_epoch")
    minimum = bindings["minimum_remaining_lifetime_seconds"]
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum <= 0:
        fail("minimum_remaining_lifetime_seconds must be a positive integer")
    if (
        serial != response["serial"]
        or (not_before, not_after) != (response_not_before, response_not_after)
        or not_after <= not_before
        or not_before > now + 300
        or now >= not_after
        or not_after - now < minimum
        or created < not_before
        or created > now + 300
        or created > not_after
    ):
        fail("leaf certificate validity or signed metadata is invalid")
    tree.recheck()
    request_tree.recheck()
    for source in trust.values():
        source.recheck()
    return {
        "request_sha256": sha256(request_tree.files["request"].data),
        "approval_sha256": approval_sha,
        "csr_sha256": request["csr_sha256"],
        "csr_spki_sha256": request["csr_spki_sha256"],
        "response_sha256": response_sha,
        "response_signature_sha256": signature_sha,
        "artifact_sha256": sha256(files["artifact"]),
        "certificate_sha256": certificate_sha,
        "certificate_spki_sha256": spki,
        "chain_sha256": chain_sha,
        "fullchain_sha256": fullchain_sha,
        "not_after_epoch": str(not_after),
    }


def validate_evidence_snapshot(
    tree: PinnedTree,
    request_tree: PinnedTree,
    response_tree: PinnedTree,
    trust_tree: PinnedTree,
    bindings: Mapping[str, object],
    *,
    now: int,
    require_current: bool = True,
) -> dict[str, str]:
    """Authenticate one exact deployment evidence attempt on the controller."""

    if tree.names != frozenset(EVIDENCE_NAMES):
        fail("evidence does not contain the exact five files")
    if trust_tree.names != frozenset(TRUST_NAMES):
        fail("controller frozen trust does not contain the exact five files")
    request_id = require_request_id(bindings["request_id"])
    service = require_service(bindings["service"])
    target = require_principal(bindings["target"], "target")
    artifact_pin = require_digest(bindings["artifact_sha256"], "artifact_sha256")
    deployment_pin = require_digest(
        bindings["deployment_sha256"], "deployment_sha256"
    )
    files = tree.data
    request_files = request_tree.data
    response_files = response_tree.data
    trust = trust_tree.files

    receipt = parse_record(
        request_files["collection-receipt"], RECEIPT_FIELDS, "collection receipt"
    )
    trust_receipt_fields = {
        "policy": "trust_policy_sha256",
        "requesters.allowed_signers": "request_trust_sha256",
        "approvers.allowed_signers": "approval_trust_sha256",
        "responses.allowed_signers": "response_trust_sha256",
        "deployers.allowed_signers": "deployment_trust_sha256",
    }
    if (
        receipt["service"] != service
        or receipt["target"] != target
        or receipt["request_id"] != request_id
        or any(
            sha256(trust[name].data) != receipt[field]
            for name, field in trust_receipt_fields.items()
        )
    ):
        fail("evidence trust differs from the collected request trust")
    policy = parse_record(trust["policy"].data, POLICY_FIELDS, "frozen trust policy")
    validate_frozen_trust(trust, target, policy["response_principal"])

    request = parse_record(request_files["request"], REQUEST_FIELDS, "evidence request")
    response = parse_record(response_files["response"], RESPONSE_FIELDS, "evidence response")
    artifact = parse_record(response_files["artifact"], ARTIFACT_FIELDS, "evidence artifact")
    if sha256(response_files["artifact"]) != artifact_pin:
        fail("evidence artifact pin differs from the controller response")
    deployment = parse_record(files["deployment"], DEPLOYMENT_FIELDS, "deployment evidence")
    validation = parse_record(
        files["validation-result"], VALIDATION_RESULT_FIELDS, "validation result"
    )
    boundary = parse_record(
        files["validation-boundary"],
        VALIDATION_BOUNDARY_FIELDS,
        "validation boundary",
    )
    if sha256(files["deployment"]) != deployment_pin:
        fail("deployment evidence digest differs from its coordinate")
    verify_ssh_signature(
        files["deployment"],
        tree.files["deployment.sig"],
        trust["deployers.allowed_signers"],
        target,
        DEPLOYMENT_NAMESPACE,
    )
    verify_ssh_signature(
        files["validation-result"],
        tree.files["validation-result.sig"],
        trust["deployers.allowed_signers"],
        target,
        DEPLOYMENT_NAMESPACE,
    )

    boundary_sha = sha256(files["validation-boundary"])
    endpoint = urllib.parse.urlsplit(boundary["endpoint"])
    if (
        boundary["schema"] != "1"
        or boundary["kind"] != "pki-validation-boundary"
        or boundary["service"] != service
        or boundary["target"] != target
        or boundary["local_validator"] != target
        or _PRINCIPAL.fullmatch(boundary["remote_validator"]) is None
        or boundary["local_check"] != LOCAL_CHECK
        or boundary["remote_check"] != REMOTE_CHECK
        or endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.path != "/v2/"
        or endpoint.query
        or endpoint.fragment
    ):
        fail("validation boundary is not the exact reviewed protocol shape")

    digest_fields = (
        "request_sha256",
        "response_sha256",
        "response_signature_sha256",
        "candidate_sha256",
        "artifact_manifest_sha256",
        "certificate_sha256",
        "certificate_spki_sha256",
        "chain_sha256",
        "fullchain_sha256",
        "local_certificate_sha256",
        "local_key_spki_sha256",
        "validation_boundary_sha256",
    )
    for field in digest_fields:
        require_digest(deployment[field], f"deployment {field}")
    if (
        deployment["schema"] != "1"
        or deployment["request_id"] != request_id
        or deployment["artifact_request_id"] != request_id
        or deployment["service"] != service
        or deployment["target"] != target
        or deployment["deployment_principal"] != target
        or deployment["nonce"] != response["nonce"]
        or deployment["operation"] != response["operation"]
        or deployment["request_sha256"] != sha256(request_files["request"])
        or deployment["request_sha256"] != response["request_sha256"]
        or deployment["response_sha256"] != sha256(response_files["response"])
        or deployment["response_signature_sha256"]
        != sha256(response_files["response.sig"])
        or deployment["artifact_manifest_sha256"] != artifact_pin
        or deployment["certificate_sha256"] != artifact["certificate_sha256"]
        or deployment["certificate_spki_sha256"]
        != artifact["certificate_spki_sha256"]
        or deployment["chain_sha256"] != artifact["chain_sha256"]
        or deployment["fullchain_sha256"] != artifact["fullchain_sha256"]
        or deployment["local_certificate_sha256"]
        != deployment["certificate_sha256"]
        or deployment["local_key_spki_sha256"]
        != deployment["certificate_spki_sha256"]
        or deployment["local_key_certificate_match"] != "true"
        or deployment["validation_boundary_sha256"] != boundary_sha
        or (deployment["action"], deployment["result"])
        not in {
            ("finalize", "activated"),
            ("abandon", "not-activated"),
            ("abandon", "rolled-back"),
        }
    ):
        fail("deployment evidence does not match controller protocol bindings")
    created = canonical_epoch(deployment["created_epoch"], "deployment created_epoch")
    expires = canonical_epoch(deployment["expires_epoch"], "deployment expires_epoch")
    if (
        expires <= created
        or expires - created > 86400
        or created > now + 300
        or (require_current and now > expires)
    ):
        fail("deployment evidence lifetime is invalid or expired")

    if (
        validation["schema"] != "1"
        or validation["kind"] != "pki-validation-result"
        or validation["service"] != service
        or validation["target"] != target
        or validation["request_id"] != request_id
        or validation["artifact_manifest_sha256"] != artifact_pin
        or validation["validation_boundary_sha256"] != boundary_sha
        or validation["action"] != deployment["action"]
        or validation["result"] != deployment["result"]
        or validation["local_validator"] != boundary["local_validator"]
        or validation["remote_validator"] != boundary["remote_validator"]
        or validation["endpoint"] != boundary["endpoint"]
        or validation["served_certificate_sha256"]
        != deployment["served_certificate_sha256"]
        or validation["served_intermediate_sha256"]
        != deployment["served_intermediate_sha256"]
        or validation["activation_epoch"] != deployment["activation_epoch"]
        or validation["validation_epoch"] != deployment["validation_epoch"]
        or validation["deployment_sha256"] != deployment_pin
    ):
        fail("validation result does not exactly bind deployment evidence")

    action_result = (deployment["action"], deployment["result"])
    observed_fields = (
        "local_service_result",
        "local_tls_result",
        "remote_tls_result",
        "remote_application_result",
    )
    if action_result == ("abandon", "not-activated"):
        not_run_fields = (*observed_fields, "remote_http_status", "remote_api_version", "remote_auth_challenge")
        if (
            any(validation[field] != "not-run" for field in not_run_fields)
            or deployment["served_certificate_sha256"] != "none"
            or deployment["served_intermediate_sha256"] != "none"
            or deployment["validation_result"] != "not-run"
            or deployment["activation_epoch"] != "none"
            or deployment["validation_epoch"] != "none"
            or deployment["rollback_state"] != "none"
            or deployment["rollback_hold_until_epoch"] != "none"
        ):
            fail("not-activated abandonment evidence is inconsistent")
    else:
        activation = canonical_epoch(
            deployment["activation_epoch"], "deployment activation_epoch"
        )
        validation_epoch = canonical_epoch(
            deployment["validation_epoch"], "deployment validation_epoch"
        )
        require_digest(
            deployment["served_certificate_sha256"],
            "deployment served_certificate_sha256",
        )
        require_digest(
            deployment["served_intermediate_sha256"],
            "deployment served_intermediate_sha256",
        )
        if (
            any(validation[field] != "passed" for field in observed_fields)
            or validation["remote_api_version"] != "registry/2.0"
            or (
                validation["remote_http_status"],
                validation["remote_auth_challenge"],
            )
            not in {("200", "not-required"), ("401", "present")}
            or deployment["validation_result"] != "passed"
            or not activation <= validation_epoch <= created + 300
        ):
            fail("observed deployment evidence is inconsistent")
        if action_result == ("finalize", "activated"):
            if deployment["served_certificate_sha256"] != deployment["certificate_sha256"]:
                fail("activated deployment serves a different certificate")
            if deployment["operation"] == "issue":
                if (
                    deployment["rollback_state"] != "none"
                    or deployment["rollback_hold_until_epoch"] != "none"
                ):
                    fail("issue evidence contains rollback state")
            else:
                hold = canonical_epoch(
                    deployment["rollback_hold_until_epoch"],
                    "deployment rollback hold",
                )
                if (
                    deployment["rollback_state"] != "retained"
                    or hold < created + MIN_ROLLBACK_SECONDS
                ):
                    fail("activated evidence rollback hold is invalid")
        else:
            hold = canonical_epoch(
                deployment["rollback_hold_until_epoch"],
                "rolled-back evidence hold",
            )
            if (
                deployment["rollback_state"] != "restored"
                or hold < created + MIN_ROLLBACK_SECONDS
            ):
                fail("rolled-back abandonment state is invalid")
    tree.recheck()
    request_tree.recheck()
    response_tree.recheck()
    trust_tree.recheck()
    return {
        "deployment_sha256": deployment_pin,
        "artifact_sha256": artifact_pin,
        "action": deployment["action"],
        "result": deployment["result"],
        "validation_boundary_sha256": boundary_sha,
        "validation_result_sha256": sha256(files["validation-result"]),
    }
