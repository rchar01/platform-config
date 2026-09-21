from __future__ import annotations

import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from test_pki_host_local_lifecycle_helper import (
    REQUEST_ID, SERVICE, TARGET, LifecycleCase, assert_failure, ca_usage,
    digest, leaf_usage, lifecycle_case, private_dir, private_file,
    record, result_json, tree_snapshot,
)


pytestmark = pytest.mark.pki
SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Telemetry"),
    x509.NameAttribute(NameOID.COMMON_NAME, "sender.test"),
])


def candidate() -> list[str]:
    return [
        "--trust-id", "reviewed-v1", "--subject-cn", "sender.test",
        "--subject-ou", "Telemetry", "--subject-o", "Example", "--subject-c", "US",
        "--validity-days", "397", "--minimum-remaining-lifetime-seconds", "3600",
    ]


def command(case: LifecycleCase, name: str) -> list:
    return [*case.common(name), "--service-adapter", "client-stage-v1"]


def signed(case: LifecycleCase, path: Path, namespace: str) -> None:
    signature = path.with_name(path.name + ".sig")
    signature.unlink(missing_ok=True)
    case.runner.run([
        "ssh-keygen", "-Y", "sign", "-f", case.signing_key, "-n", namespace, path,
    ]).assert_success()
    signature.chmod(0o600)


def replace_request(case: LifecycleCase, **changes) -> None:
    request = case.module.parse_record((case.pending / "request").read_bytes(), case.module.REQUEST_V2_FIELDS, "fixture request")
    request.update(changes)
    private_file(case.pending / "request", record(case.module.REQUEST_V2_FIELDS, request))
    signed(case, case.pending / "request", case.module.REQUEST_NAMESPACE_V2)


def issue_response(case: LifecycleCase, *, days=397, seconds=0, eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                   san=False, subject=SUBJECT, expired_ca=False, csr=None, ca_remaining_secs=None) -> None:
    """Real signatures and matching public records, including negative profiles."""
    module = case.module
    key = serialization.load_pem_private_key((case.pending / "tls.key").read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    if csr is None:
        csr = x509.CertificateSigningRequestBuilder().subject_name(SUBJECT).sign(key, hashes.SHA384())
    private_file(case.pending / "tls.csr", csr.public_bytes(serialization.Encoding.PEM))
    replace_request(case, profile="client-p384-sha384-v1", csr_sha256=digest(case.pending / "tls.csr"))
    before = datetime.fromtimestamp(int(time.time()) - 60, UTC)
    ca_before = before - timedelta(days=2)
    ca_after = before - timedelta(days=1) if expired_ca else before + timedelta(days=1000)
    if ca_remaining_secs is not None:
        assert not expired_ca
        ca_after = before + timedelta(seconds=60 + ca_remaining_secs)
    root_key, issuer_key = (ec.generate_private_key(ec.SECP384R1()) for _ in range(2))
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Client Test Root")])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Client Test Issuer")])
    def ca(name, issuer, public_key, signer, depth, serial):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
                .public_key(public_key).serial_number(serial)
                .not_valid_before(ca_before).not_valid_after(ca_after)
                .add_extension(x509.BasicConstraints(ca=True, path_length=depth), True)
                .add_extension(ca_usage(), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
                .sign(signer, hashes.SHA384()))
    root = ca(root_name, root_name, root_key.public_key(), root_key, 1, 1)
    issuer = ca(issuer_name, root_name, issuer_key.public_key(), root_key, 0, 2)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
               .public_key(key.public_key()).serial_number(0x1234)
               .not_valid_before(before).not_valid_after(before + timedelta(days=days, seconds=seconds))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
               .add_extension(leaf_usage(), True)
               .add_extension(x509.ExtendedKeyUsage([eku]), False)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("sender.test")]), False)
    leaf = builder.sign(issuer_key, hashes.SHA384())
    pem = serialization.Encoding.PEM
    source = case.root / "response-source"
    for name, data in {
        "tls.crt": leaf.public_bytes(pem),
        "ca-chain.crt": issuer.public_bytes(pem) + root.public_bytes(pem),
        "fullchain.crt": leaf.public_bytes(pem) + issuer.public_bytes(pem),
    }.items():
        private_file(source / name, data)
    request = module.parse_record((case.pending / "request").read_bytes(), module.REQUEST_V2_FIELDS, "request")
    response = module.parse_record((source / "response").read_bytes(), module.RESPONSE_V2_FIELDS, "response")
    response.update({
        "request_sha256": digest(case.pending / "request"),
        "request_signature_sha256": digest(case.pending / "request.sig"),
        "csr_sha256": request["csr_sha256"], "certificate_sha256": digest(source / "tls.crt"),
        "chain_sha256": digest(source / "ca-chain.crt"),
        "not_before_epoch": str(int(leaf.not_valid_before_utc.timestamp())),
        "not_after_epoch": str(int(leaf.not_valid_after_utc.timestamp())),
    })
    private_file(source / "response", record(module.RESPONSE_V2_FIELDS, response))
    signed(case, source / "response", module.RESPONSE_NAMESPACE_V2)
    artifact = module.parse_record((source / "artifact").read_bytes(), module.ARTIFACT_FIELDS, "artifact")
    for name in ("certificate_sha256", "chain_sha256", "not_before_epoch", "not_after_epoch"):
        artifact[name] = response[name]
    artifact.update({
        "source_response_sha256": digest(source / "response"),
        "source_response_signature_sha256": digest(source / "response.sig"),
        "fullchain_sha256": digest(source / "fullchain.crt"),
    })
    private_file(source / "artifact", record(module.ARTIFACT_FIELDS, artifact))


@pytest.fixture
def client_case(lifecycle_case):
    issue_response(lifecycle_case)
    return lifecycle_case


def prepare_import(case):
    exchange = private_dir(case.root / "exchange")
    source = private_dir(exchange / SERVICE / "responses" / REQUEST_ID)
    for name in case.module.RESPONSE_NAMES:
        private_file(source / name, (case.root / "response-source" / name).read_bytes())
    prepared = result_json(case.run([
        *command(case, "target-response-prepare"), "--trust-id", "reviewed-v1",
    ]))
    argv = [*command(case, "target-response-import"), "--trust-id", "reviewed-v1",
            "--exchange-root", exchange, "--input-owner-uid", "0"]
    return argv, Path(prepared["ingress_dir"])


def install(case, **kwargs):
    return case.run([*command(case, "target-response-install"), *candidate()], **kwargs)


def status(case):
    return case.run([*command(case, "target-stage-status"), *candidate()])


def test_client_export_import_stage_and_readonly_reauthentication(client_case):
    case = client_case
    original_pending = tree_snapshot(case.pending)
    output = private_dir(case.root / "request-export")
    result_json(case.run([*command(case, "target-request-export"), "--trust-id", "reviewed-v1",
                          "--output-dir", output, "--output-owner-uid", "0"]))
    assert {p.name for p in output.iterdir()} == {"tls.csr", "request", "request.sig"}
    assert result_json(status(case))["status"] == "request-pending"
    argv, ingress = prepare_import(case)
    before = tree_snapshot(case.root)
    empty = result_json(status(case))
    assert empty["status"] == "response-partial" and empty["required_action"] == "await-response"
    assert result_json(case.run([*argv, "--check"]))["status"] == "would-import"
    assert tree_snapshot(case.root) == before
    # A partially imported response is resumable before version publication.
    private_file(ingress / "tls.crt", (case.root / "response-source/tls.crt").read_bytes())
    before = tree_snapshot(case.root)
    partial = result_json(status(case))
    assert partial["status"] == "response-partial" and partial["required_action"] == "await-response"
    assert set(partial) == {"schema", "kind", "status", "service", "target", "request_id", "required_action"}
    assert_failure(install(case))
    assert tree_snapshot(case.root) == before
    assert result_json(case.run(argv))["status"] == "imported"
    assert result_json(case.run(argv))["status"] == "existing"
    before = tree_snapshot(case.root)
    assert result_json(status(case))["required_action"] == "install-response"
    assert result_json(case.run([*command(case, "target-response-install"), *candidate(), "--check"]))["status"] == "would-install"
    assert tree_snapshot(case.root) == before
    installed = result_json(install(case))
    install_keys = {"status", "request_id", "version_path", "artifact_sha256",
                    "certificate_sha256", "certificate_spki_sha256"}
    assert set(installed) == install_keys
    assert installed["status"] == "staged"
    assert not ingress.exists()
    version = case.versions_root / REQUEST_ID
    assert set(p.name for p in version.iterdir()) == set(case.module.VERSION_NAMES)
    assert stat.S_IMODE(version.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 and p.stat().st_nlink == 1 for p in version.iterdir())
    before = tree_snapshot(case.root)
    value = result_json(status(case))
    assert value["status"] == "staged" and value["required_action"] == "none"
    replay = result_json(install(case))
    assert set(replay) == install_keys
    assert replay == installed
    assert tree_snapshot(case.root) == before
    assert tree_snapshot(case.pending) == original_pending
    assert {p.name for p in case.state.iterdir()} == {"lock", "trust"}
    assert not case.service_log.exists()


@pytest.mark.parametrize("tamper", ["unexpected-name", "mode", "symlink", "hardlink", "directory"])
def test_client_partial_status_rejects_unsafe_entries_without_mutation(client_case, tamper):
    case = client_case
    _, ingress = prepare_import(case)
    source = case.root / "response-source/tls.crt"
    entry = ingress / "tls.crt"
    if tamper == "unexpected-name":
        private_file(ingress / "unexpected", b"retain\n")
    elif tamper == "mode":
        private_file(entry, source.read_bytes(), 0o644)
    elif tamper == "symlink":
        entry.symlink_to(source)
    elif tamper == "hardlink":
        entry.hardlink_to(source)
    else:
        private_dir(entry)
    before = tree_snapshot(case.root)
    assert_failure(status(case))
    assert tree_snapshot(case.root) == before


@pytest.mark.parametrize("point", ["before-version-publication", "after-version-publication"])
def test_client_crash_retains_unknown_stage_or_resumes_authenticated_publication(client_case, point):
    case = client_case
    argv, ingress = prepare_import(case)
    result_json(case.run(argv))
    pending = tree_snapshot(case.pending)
    assert_failure(install(case, environment={"PLATFORM_PKI_LIFECYCLE_CRASH_AT": point}))
    before = tree_snapshot(case.root)
    if point == "before-version-publication":
        assert any(p.name.startswith(".stage-") for p in case.versions_root.iterdir())
        for result in (install(case), status(case), case.run(argv), case.run([
            *command(case, "target-response-prepare"), "--trust-id", "reviewed-v1",
        ])):
            assert_failure(result)
        assert tree_snapshot(case.root) == before
    else:
        value = result_json(status(case))
        assert value["status"] == "staged-pending" and value["required_action"] == "install-response"
        assert tree_snapshot(case.root) == before
        assert result_json(install(case))["status"] == "staged"
        assert not ingress.exists()
        assert result_json(status(case))["status"] == "staged"
    assert tree_snapshot(case.pending) == pending
    assert not case.service_log.exists()


@pytest.mark.parametrize("tamper", ["partial-ingress", "conflict", "response-signature", "pending-signature", "version-key", "mode", "link", "extra-stage", "active"])
def test_client_retained_publication_never_trusts_presence(client_case, tamper):
    case = client_case
    argv, ingress = prepare_import(case)
    result_json(case.run(argv))
    assert_failure(install(case, environment={"PLATFORM_PKI_LIFECYCLE_FAIL_AT": "after-version-publication"}))
    version = case.versions_root / REQUEST_ID
    if tamper == "partial-ingress":
        (ingress / "artifact").unlink()
    elif tamper == "conflict":
        private_file(ingress / "response", b"untrusted\n")
    elif tamper == "response-signature":
        for directory in (ingress, version):
            private_file(directory / "response.sig", b"invalid\n")
    elif tamper == "pending-signature":
        private_file(case.pending / "request.sig", b"invalid\n")
    elif tamper == "version-key":
        private_file(version / "tls.key", b"invalid\n")
    elif tamper == "mode":
        (version / "tls.crt").chmod(0o644)
    elif tamper == "link":
        (version / "tls.crt").unlink()
        (version / "tls.crt").symlink_to(ingress / "tls.crt")
    elif tamper == "extra-stage":
        private_dir(case.versions_root / ".stage-unknown")
    else:
        private_file(case.state / "active", b"unknown\n")
    before, pending = tree_snapshot(case.root), (case.pending / "tls.key").read_bytes()
    assert_failure(install(case))
    assert_failure(status(case))
    assert tree_snapshot(case.root) == before
    assert (case.pending / "tls.key").read_bytes() == pending


@pytest.mark.parametrize("change", [
    {"days": 396}, {"seconds": 1}, {"eku": ExtendedKeyUsageOID.SERVER_AUTH},
    {"san": True}, {"subject": x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong")])},
    {"expired_ca": True},
])
def test_client_signed_response_must_match_subject_profile_days_and_chain(client_case, change):
    case = client_case
    issue_response(case, **change)
    argv, _ = prepare_import(case)
    result_json(case.run(argv))
    before = tree_snapshot(case.root)
    assert_failure(install(case))
    assert_failure(status(case))
    assert tree_snapshot(case.root) == before


@pytest.mark.parametrize("mutation", ["renew", "server-profile", "attribute", "san", "wrong-subject", "wrong-key", "second-pending"])
def test_client_pending_boundaries_reject_before_ingress_mutation(client_case, mutation):
    case = client_case
    if mutation in {"renew", "server-profile"}:
        replace_request(case, **({"operation": "renew"} if mutation == "renew" else {"profile": case.module.PROFILE}))
    elif mutation in {"attribute", "san", "wrong-subject"}:
        key = serialization.load_pem_private_key((case.pending / "tls.key").read_bytes(), None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            SUBJECT if mutation != "wrong-subject" else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong")]))
        if mutation == "attribute":
            builder = builder.add_attribute(ObjectIdentifier("1.2.840.113549.1.9.7"), b"challenge")
        elif mutation == "san":
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("sender.test")]), False)
        issue_response(case, csr=builder.sign(key, hashes.SHA384()))
    elif mutation == "wrong-key":
        private_file(case.pending / "tls.key", ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    else:
        private_dir(case.pending_root / ("f" * 32))
    before = tree_snapshot(case.root)
    assert_failure(case.run([*command(case, "target-response-prepare"), "--trust-id", "reviewed-v1"]))
    assert tree_snapshot(case.root) == before


def test_client_arguments_and_active_function_boundaries(client_case):
    case, module = client_case, client_case.module
    parser = module.build_parser()
    good = [str(value) for value in [*command(case, "target-response-install")[1:], *candidate()]]
    args = parser.parse_args(good)
    module.validate_arguments(args)
    for days in (None, True, 0, -1, 365001, 1.5, "397"):
        args.validity_days = days
        with pytest.raises(module.LifecycleError):
            module.validate_arguments(args)
    for days in (1, 397, 365000):
        args.validity_days = days
        module.validate_arguments(args)
    for extra in (["--common-name", "server.test"], ["--dns-san", "server.test"],
                  ["--ip-san", "192.0.2.1"], ["--subject-cn", "bad/name"],
                  ["--subject-c", "us"], ["--service-unit", "alloy.service"],
                  ["--service-adapter", "zot-v1"]):
        with pytest.raises(module.LifecycleError):
            module.validate_arguments(parser.parse_args([*good, *extra]))
    for extra in (["--request-id", REQUEST_ID], ["--artifact-sha256", "a" * 64], ["--validity-days", "1.5"]):
        with pytest.raises(SystemExit):
            parser.parse_args([*good, *extra])
    before = tree_snapshot(case.root)
    # Direct active functions reject before using any paths, even with valid
    # issue bytes available; CLI rejection alone is not the mutation boundary.
    for name in ("activate_start", "target_activate_start", "target_activate_complete",
                 "target_recover", "target_status", "active_paths", "zot_custody", "openbao_custody"):
        with pytest.raises(module.LifecycleError, match="server adapter"):
            getattr(module, name)(SimpleNamespace(service_adapter="client-stage-v1"))
    assert tree_snapshot(case.root) == before
    assert not case.service_log.exists()


def test_client_creates_private_versions_root_and_rejects_unexpected_ingress(client_case):
    case = client_case
    case.versions_root.rmdir()
    argv = [*command(case, "target-response-prepare"), "--trust-id", "reviewed-v1"]
    before = tree_snapshot(case.root)
    assert_failure(case.run([*argv, "--check"]))
    assert tree_snapshot(case.root) == before
    value = result_json(case.run(argv))
    assert stat.S_IMODE(case.versions_root.stat().st_mode) == 0o700
    assert case.run(["stat", "-c", "%u:%g", case.versions_root]).assert_success().stdout.strip() == "0:0"
    private_file(Path(value["ingress_dir"]) / "unexpected", b"retain for review\n")
    output = private_dir(case.root / "export")
    before = tree_snapshot(case.root)
    assert_failure(case.run([*command(case, "target-request-export"), "--trust-id", "reviewed-v1",
                             "--output-dir", output, "--output-owner-uid", "0"]))
    assert_failure(case.run(argv))
    assert_failure(status(case))
    assert tree_snapshot(case.root) == before


@pytest.mark.parametrize("tamper", ["response-signature", "version-key"])
def test_clean_client_staging_reauthenticates_expected_subject_days_and_signature(client_case, tamper):
    case = client_case
    argv, _ = prepare_import(case)
    result_json(case.run(argv))
    result_json(install(case))
    before = tree_snapshot(case.root)
    for change in (["--subject-cn", "other"], ["--validity-days", "396"],
                   ["--minimum-remaining-lifetime-seconds", str(398 * 86400)]):
        assert_failure(case.run([*command(case, "target-stage-status"), *candidate(), *change]))
    assert tree_snapshot(case.root) == before
    version = case.versions_root / REQUEST_ID
    if tamper == "response-signature":
        private_file(version / "response.sig", b"invalid\n")
    else:
        private_file(version / "tls.key", ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    before = tree_snapshot(case.root)
    assert_failure(status(case))
    assert_failure(install(case))
    assert tree_snapshot(case.root) == before
