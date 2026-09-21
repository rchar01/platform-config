from __future__ import annotations

import hashlib
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from test_pki_host_local_request_helper import (
    PROTOCOL_FILES,
    REQUEST_FIELDS,
    RequestScenario,
    _assert_helper_failure,
    _json_result,
    _prepare_state,
    _sha256,
    _tree_snapshot,
    _write_private,
    request_scenario,
)


pytestmark = pytest.mark.pki
CLIENT_PROFILE = "client-p384-sha384-v1"
SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example_1"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Telemetry-2"),
    x509.NameAttribute(NameOID.COMMON_NAME, "sender.test"),
])
SUBJECT_FLAGS = {
    "--subject-cn": "sender.test",
    "--subject-ou": "Telemetry-2",
    "--subject-o": "Example_1",
    "--subject-c": "US",
}


def without(argv, *flags):
    result = list(argv)
    for flag in flags:
        while flag in result:
            index = result.index(flag)
            del result[index : index + 2]
    return result


def client_argv(scenario, **kwargs):
    argv = without(scenario.helper_argv(**kwargs), "--common-name", "--dns-san", "--ip-san")
    argv[argv.index("--profile") + 1] = CLIENT_PROFILE
    for flag, value in SUBJECT_FLAGS.items():
        argv.extend((flag, value))
    return argv


@pytest.fixture
def client_request(request_scenario: RequestScenario):
    result = _json_result(request_scenario.runner.run(client_argv(request_scenario)))
    return request_scenario, result, Path(result["pending_dir"])


def test_client_full_subject_profile_signature_and_idempotence(client_request):
    scenario, created, pending = client_request
    assert created["status"] == "created"
    assert set(path.name for path in pending.iterdir()) == PROTOCOL_FILES
    assert stat.S_IMODE(pending.stat().st_mode) == 0o700
    original = {name: (pending / name).read_bytes() for name in PROTOCOL_FILES}
    for name in PROTOCOL_FILES:
        metadata = (pending / name).stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
    csr = x509.load_pem_x509_csr(original["tls.csr"])
    key = serialization.load_pem_private_key(original["tls.key"], None)
    assert csr.is_signature_valid
    assert csr.subject == SUBJECT
    assert len(csr.subject.rdns) == 4
    assert len(csr.attributes) == len(csr.extensions) == 0
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP384R1)
    assert isinstance(csr.signature_hash_algorithm, hashes.SHA384)
    encoding, form = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    spki = csr.public_key().public_bytes(encoding, form)
    assert key.public_key().public_bytes(encoding, form) == spki
    record = dict(line.split("=", 1) for line in original["request"].decode("ascii").splitlines())
    assert tuple(record) == REQUEST_FIELDS
    assert record["schema"] == "2"
    assert record["profile"] == CLIENT_PROFILE
    assert record["operation"] == "issue"
    assert record["current_cert_sha256"] == record["predecessor_request_id"] == "none"
    assert created["request_sha256"] == hashlib.sha256(original["request"]).hexdigest()
    assert created["csr_sha256"] == record["csr_sha256"] == _sha256(pending / "tls.csr")
    assert created["csr_spki_sha256"] == record["csr_spki_sha256"] == hashlib.sha256(spki).hexdigest()
    verified = subprocess.run(
        scenario.runner.argv([
            "ssh-keygen", "-Y", "verify", "-f", scenario.trust / "requesters.allowed_signers",
            "-I", "test-target", "-n", "platform-pki-csr-request-v2", "-s", pending / "request.sig",
        ]),
        cwd=scenario.runner.command_runner.cwd,
        env=scenario.runner.environment(),
        input=original["request"], capture_output=True, timeout=30,
    )
    assert verified.returncode == 0, verified.stderr.decode(errors="replace")
    before = _tree_snapshot(scenario.work)
    for check in (True, False):
        existing = _json_result(scenario.runner.run(client_argv(scenario, check=check)))
        assert existing == {**created, "status": "existing"}
        assert _tree_snapshot(scenario.work) == before
    assert {name: (pending / name).read_bytes() for name in PROTOCOL_FILES} == original


def test_client_prepared_check_is_read_only(request_scenario):
    scenario = request_scenario
    _prepare_state(scenario)
    before = _tree_snapshot(scenario.work)
    assert _json_result(scenario.runner.run(client_argv(scenario, check=True))) == {
        "status": "would-create", "pending_dir": str(scenario.pending),
    }
    assert _tree_snapshot(scenario.work) == before
    assert not scenario.pending.exists()


def test_mixed_profiles_renewal_and_invalid_subjects_fail_before_mutation(request_scenario):
    scenario = request_scenario
    valid = client_argv(scenario)
    invalid = []
    for flag, value in (
        ("--common-name", "sender.test"), ("--dns-san", "sender.test"),
        ("--ip-san", "192.0.2.61"), ("--current-cert-sha256", "a" * 64),
        ("--current-cert-path", scenario.current_cert), ("--predecessor-request-id", "1" * 32),
        ("--profile", "alloy-client-p384-sha384-v1"),
    ):
        invalid.append([*valid, flag, value])
    invalid.append(client_argv(scenario, operation="renew", predecessor_request_id="1" * 32))
    for flag in SUBJECT_FLAGS:
        invalid.append(without(valid, flag))
        values = ("", "us", "USA", "U1", "ÜS") if flag == "--subject-c" else (
            "", "x" * 65, "space name", "a/b", "a,b", "a+b", "a=b", "$ENV", "a\nb", "é",
        )
        for value in values:
            invalid.append([*valid, f"{flag}={value}"])
        invalid.append([*scenario.helper_argv(), flag, SUBJECT_FLAGS[flag]])
        invalid.append([*scenario.helper_argv(), f"{flag}="])
    invalid.append(without(scenario.helper_argv(), "--common-name"))
    invalid.append([*scenario.helper_argv(), "--common-name", "not_a_dns_name"])
    before = _tree_snapshot(scenario.work)
    for argv in invalid:
        _assert_helper_failure(scenario.runner.run(argv))
        assert _tree_snapshot(scenario.work) == before


def test_client_subject_length_boundaries(request_scenario):
    scenario = request_scenario
    argv = client_argv(scenario)
    argv.extend(("--subject-cn", "a", "--subject-ou", "a" * 64, "--subject-o", "._-"))
    created = _json_result(scenario.runner.run(argv))
    csr = x509.load_pem_x509_csr(Path(created["pending_dir"]).joinpath("tls.csr").read_bytes())
    assert [attribute.value for attribute in csr.subject] == ["US", "._-", "a" * 64, "a"]


def replace_signed_csr(scenario, pending, csr_data):
    (pending / "tls.csr").write_bytes(csr_data)
    record = dict(line.split("=", 1) for line in (pending / "request").read_text().splitlines())
    record["csr_sha256"] = hashlib.sha256(csr_data).hexdigest()
    csr = x509.load_pem_x509_csr(csr_data)
    record["csr_spki_sha256"] = hashlib.sha256(csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()
    _write_private(pending / "request", "".join(f"{name}={record[name]}\n" for name in REQUEST_FIELDS))
    (pending / "request.sig").unlink()
    scenario.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", scenario.signing_key,
        "-n", "platform-pki-csr-request-v2", pending / "request",
    ]).assert_success()
    (pending / "request.sig").chmod(0o600)


def der_tlv(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, "big")
    # Use minimal lengths even for the short custom Attribute structures.
    if 128 <= size <= 255:
        length = bytes([0x81, size])
    return bytes([tag]) + length + content


def empty_extension_request(csr, key):
    info = csr.tbs_certrequest_bytes
    header = 2 + (info[1] & 0x7F) if info[1] & 0x80 else 2
    assert info.endswith(b"\xa0\x00")
    attribute = der_tlv(0x30, bytes.fromhex("06092a864886f70d01090e") + der_tlv(0x31, b"\x30\x00"))
    info = der_tlv(0x30, info[header:-2] + der_tlv(0xA0, attribute))
    signature = key.sign(info, ec.ECDSA(hashes.SHA384()))
    algorithm = bytes.fromhex("300a06082a8648ce3d040303")
    result = x509.load_der_x509_csr(der_tlv(0x30, info + algorithm + der_tlv(0x03, b"\x00" + signature)))
    assert result.is_signature_valid
    assert len(result.attributes) == 1
    assert len(result.extensions) == 0
    return result


@pytest.mark.parametrize("change", [
    "cn", "ou", "o", "c", "subject-order", "extra-rdn", "multi-valued-rdn", "san", "attribute",
    "empty-extension-request", "bad-self-signature", "sha256", "p256", "wrong-key",
])
def test_signed_pending_client_csr_drift_is_rejected_without_mutation(client_request, change):
    scenario, _, pending = client_request
    key = serialization.load_pem_private_key((pending / "tls.key").read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    subject = list(SUBJECT)
    if change in {"cn", "ou", "o", "c"}:
        index = {"cn": 3, "ou": 2, "o": 1, "c": 0}[change]
        subject[index] = x509.NameAttribute(subject[index].oid, "GB" if change == "c" else "other")
    if change == "subject-order":
        subject.reverse()
    if change == "extra-rdn":
        subject.append(x509.NameAttribute(NameOID.LOCALITY_NAME, "extra"))
    subject = x509.Name(subject)
    if change == "multi-valued-rdn":
        subject = x509.Name([x509.RelativeDistinguishedName(list(SUBJECT))])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if change == "san":
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("sender.test")]), False)
    if change == "attribute":
        builder = builder.add_attribute(ObjectIdentifier("1.2.840.113549.1.9.7"), b"password")
    if change in {"p256", "wrong-key"}:
        key = ec.generate_private_key(ec.SECP256R1() if change == "p256" else ec.SECP384R1())
    csr = builder.sign(key, hashes.SHA256() if change == "sha256" else hashes.SHA384())
    if change == "empty-extension-request":
        csr = empty_extension_request(csr, key)
    data = csr.public_bytes(serialization.Encoding.PEM)
    if change == "bad-self-signature":
        der = csr.public_bytes(serialization.Encoding.DER)
        csr = x509.load_der_x509_csr(der[:-1] + bytes([der[-1] ^ 1]))
        assert not csr.is_signature_valid
        data = csr.public_bytes(serialization.Encoding.PEM)
    replace_signed_csr(scenario, pending, data)
    before = _tree_snapshot(scenario.work)
    for check in (True, False):
        result = scenario.runner.run(client_argv(scenario, check=check))
        _assert_helper_failure(result)
        if change == "empty-extension-request":
            assert "zero ASN.1 attributes" in result.stderr
        assert _tree_snapshot(scenario.work) == before


def test_pending_profile_and_reviewed_subject_bindings_are_exact(client_request):
    scenario, _, _ = client_request
    before = _tree_snapshot(scenario.work)
    for argv in [scenario.helper_argv(), *[
        [*client_argv(scenario), flag, "GB" if flag == "--subject-c" else "other"]
        for flag in SUBJECT_FLAGS
    ]]:
        _assert_helper_failure(scenario.runner.run(argv))
        assert _tree_snapshot(scenario.work) == before


@pytest.mark.parametrize("point", ["after-key", "after-publication"])
def test_client_request_journal_recovery(request_scenario, point):
    scenario = request_scenario
    _assert_helper_failure(scenario.runner.run(
        client_argv(scenario), environment={"PLATFORM_PKI_REQUEST_CRASH_AT": point},
    ))
    journal = scenario.state / "request.journal"
    record = dict(line.split("=", 1) for line in journal.read_text().splitlines())
    assert record["schema"] == "2"
    pending = scenario.pending / record["request_id"]
    original = {name: (pending / name).read_bytes() for name in PROTOCOL_FILES} if pending.exists() else None
    before = _tree_snapshot(scenario.work)
    _assert_helper_failure(scenario.runner.run(client_argv(scenario, check=True)))
    assert _tree_snapshot(scenario.work) == before
    recovered = _json_result(scenario.runner.run(client_argv(scenario)))
    assert not journal.exists()
    assert {path.name for path in scenario.pending.iterdir()} == {recovered["request_id"]}
    if original is not None:
        assert recovered["status"] == "existing"
        assert recovered["request_id"] == record["request_id"]
        assert {name: (pending / name).read_bytes() for name in PROTOCOL_FILES} == original
    else:
        assert recovered["status"] == "created"
        assert recovered["request_id"] != record["request_id"]
    assert _json_result(scenario.runner.run(client_argv(scenario))) == {**recovered, "status": "existing"}


def test_retained_terminal_client_request_can_be_followed_without_active_state(client_request):
    scenario, first, _ = client_request
    terminal = {
        "schema": "2", "kind": "host-local-target-terminal", "service": "registry-test",
        "target": "test-target", "request_id": first["request_id"], "state": "not-activated",
        "artifact_manifest_sha256": "1" * 64, "response_sha256": "2" * 64,
        "response_signature_sha256": "3" * 64, "certificate_sha256": "4" * 64,
        "served_certificate_sha256": "none", "served_intermediate_sha256": "none",
        "activation_epoch": "0", "validation_epoch": "none",
    }
    _write_private(scenario.state / "target-terminal", "".join(f"{name}={value}\n" for name, value in terminal.items()))
    second = _json_result(scenario.runner.run(client_argv(scenario)))
    assert second["status"] == "created"
    assert second["request_id"] != first["request_id"]
    assert {path.name for path in scenario.pending.iterdir()} == {first["request_id"], second["request_id"]}


def test_client_issue_rejects_active_predecessor_before_pending_creation(request_scenario):
    scenario = request_scenario
    _prepare_state(scenario)
    active = {
        "schema": "2", "kind": "host-local-active", "service": "registry-test",
        "target": "test-target", "request_id": "1" * 32,
        **{name: "a" * 64 for name in (
            "artifact_manifest_sha256", "response_sha256", "response_signature_sha256",
            "certificate_sha256", "certificate_spki_sha256", "chain_sha256", "fullchain_sha256",
        )},
        "version_path": "/invalid", "version_device": "1", "version_inode": "1",
        "zot_config_sha256": "a" * 64, "activation_epoch": "1800000000",
        "rollback_deadline_epoch": "1800003600",
    }
    _write_private(scenario.state / "active", "".join(f"{name}={value}\n" for name, value in active.items()))
    before = _tree_snapshot(scenario.work)
    for check in (True, False):
        result = scenario.runner.run(client_argv(scenario, check=check))
        _assert_helper_failure(result)
        assert "issue requires no active predecessor" in result.stderr
        assert _tree_snapshot(scenario.work) == before
    assert not scenario.pending.exists()
