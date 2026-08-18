from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import runpy
import shutil
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from conftest import CommandResult, NamespaceRootRunner


pytestmark = pytest.mark.pki


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
PROTOCOL_FILES = {"tls.key", "tls.csr", "request", "request.sig"}
TRUST_NAMES = (
    "policy",
    "requesters.allowed_signers",
    "approvers.allowed_signers",
    "responses.allowed_signers",
    "deployers.allowed_signers",
)


@dataclass(frozen=True)
class RequestScenario:
    runner: NamespaceRootRunner
    helper: Path
    work: Path
    trust: Path
    state: Path
    pending: Path
    signing_key: Path
    current_cert: Path
    current_digest: str
    trust_digests: dict[str, str]

    def helper_argv(
        self,
        *,
        check: bool = False,
        ttl: int = 3600,
        state: Path | None = None,
        pending: Path | None = None,
    ) -> list[str | Path]:
        argv: list[str | Path] = [
            self.helper,
            "request",
            "--service",
            "registry-test",
            "--target",
            "test-target",
            "--requester-principal",
            "test-target",
            "--operation",
            "migrate",
            "--profile",
            "server-p384-sha384-v1",
            "--inventory-sha256",
            "a" * 64,
            "--current-cert-sha256",
            self.current_digest,
            "--current-cert-path",
            self.current_cert,
            "--common-name",
            "registry.test.example",
            "--dns-san",
            "registry.test.example",
            "--dns-san",
            "test-target",
            "--ip-san",
            "192.0.2.61",
            "--response-principal",
            "test-response",
            "--request-ttl-seconds",
            str(ttl),
            "--request-signing-key",
            self.signing_key,
            "--request-namespace",
            "platform-pki-csr-request-v1",
        ]
        for name in TRUST_NAMES:
            argv.extend(
                (
                    "--trust-binding",
                    name,
                    self.trust / name,
                    self.trust_digests[name],
                )
            )
        argv.extend(
            (
                "--state-root",
                state or self.state,
                "--pending-root",
                pending or self.pending,
            )
        )
        if check:
            argv.append("--check")
        return argv

    def run(
        self,
        *,
        check: bool = False,
        ttl: int = 3600,
        state: Path | None = None,
        pending: Path | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> CommandResult:
        return self.runner.run(
            self.helper_argv(
                check=check,
                ttl=ttl,
                state=state,
                pending=pending,
            ),
            environment=environment,
            timeout=timeout,
        )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="ascii")
    path.chmod(0o600)


def _mkdir_private(path: Path, *, parents: bool = False) -> None:
    path.mkdir(parents=parents)
    path.chmod(0o700)


@pytest.fixture
def request_scenario(
    repo_root: Path,
    isolated_test_dir: Path,
    namespace_root_runner: NamespaceRootRunner,
) -> RequestScenario:
    work = isolated_test_dir / "request-helper"
    _mkdir_private(work)
    trust_parent = work / "trust"
    trust = trust_parent / "reviewed-v1"
    _mkdir_private(trust_parent)
    _mkdir_private(trust)
    signing_key = work / "request-key"

    namespace_root_runner.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", signing_key]
    ).assert_success()
    signing_key.chmod(0o600)
    algorithm, payload, *_ = (signing_key.with_suffix(".pub")).read_text(
        encoding="ascii"
    ).split()
    assert algorithm == "ssh-ed25519"

    signer_principals = {
        "requesters.allowed_signers": "test-target",
        "approvers.allowed_signers": "test-approver",
        "responses.allowed_signers": "test-response",
        "deployers.allowed_signers": "test-target",
    }
    for name, principal in signer_principals.items():
        _write_private(trust / name, f"{principal} {algorithm} {payload}\n")
    _write_private(
        trust / "policy",
        "\n".join(
            (
                "schema=2",
                "request_namespace=platform-pki-csr-request-v1",
                "approval_namespace=platform-pki-csr-approval-v1",
                "response_namespace=platform-pki-csr-response-v1",
                "deployment_namespace=platform-pki-csr-deployment-v1",
                "request_max_age_seconds=604800",
                "sole_operator_min_delay_seconds=86400",
                "approval_max_age_seconds=86400",
                "deployment_max_age_seconds=86400",
                "clock_skew_seconds=300",
                "approver_principal=test-approver",
                "response_principal=test-response",
                "",
            )
        ),
    )

    current_cert = work / "current.crt"
    namespace_root_runner.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=old.test.example",
            "-keyout",
            work / "current.key",
            "-out",
            current_cert,
        ]
    ).assert_success()
    current_cert.chmod(0o600)

    return RequestScenario(
        runner=namespace_root_runner,
        helper=(
            repo_root
            / "roles/pki_host_local_certificate/files/platform-pki-host-local-request"
        ),
        work=work,
        trust=trust,
        state=work / "state",
        pending=work / "pending",
        signing_key=signing_key,
        current_cert=current_cert,
        current_digest=_sha256(current_cert),
        trust_digests={name: _sha256(trust / name) for name in TRUST_NAMES},
    )


def _prepare_state(scenario: RequestScenario, state: Path | None = None) -> Path:
    state = state or scenario.state
    _mkdir_private(state)
    lock = state / "lock"
    lock.touch()
    lock.chmod(0o600)
    return state


def _assert_helper_failure(result: CommandResult) -> None:
    result.assert_failure()
    assert result.stdout == "", result.diagnostics()


def _json_result(result: CommandResult) -> dict[str, Any]:
    result.assert_success()
    assert result.stderr == "", result.diagnostics()
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return value


@pytest.fixture
def created_request(request_scenario: RequestScenario) -> tuple[RequestScenario, dict[str, Any]]:
    return request_scenario, _json_result(request_scenario.run())


def _tree_snapshot(root: Path) -> str:
    records: list[list[int | str]] = []
    for current, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        for name in directories + files:
            path = Path(current) / name
            metadata = path.lstat()
            record: list[int | str] = [
                str(path.relative_to(root)),
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
                metadata.st_nlink,
                metadata.st_size,
            ]
            if stat.S_ISREG(metadata.st_mode):
                descriptor = os.open(
                    path, os.O_RDONLY | getattr(os, "O_NOATIME", 0)
                )
                try:
                    content = b""
                    while chunk := os.read(descriptor, 65536):
                        content += chunk
                finally:
                    os.close(descriptor)
                record.extend(
                    (metadata.st_atime_ns, hashlib.sha256(content).hexdigest())
                )
            records.append(record)
    return json.dumps(records, sort_keys=True, separators=(",", ":"))


def _start_helper(
    scenario: RequestScenario,
    *,
    state: Path,
    pending: Path,
    environment: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        scenario.runner.argv(
            scenario.helper_argv(state=state, pending=pending)
        ),
        cwd=scenario.runner.command_runner.cwd,
        env=scenario.runner.environment(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def _finish_process(
    process: subprocess.Popen[str], *, timeout: float = 10.0
) -> tuple[int, str, str]:
    stdout, stderr = process.communicate(timeout=timeout)
    assert process.returncode is not None
    return process.returncode, stdout, stderr


def _assert_process_failure(outcome: tuple[int, str, str]) -> None:
    returncode, stdout, stderr = outcome
    assert returncode != 0, f"race helper unexpectedly succeeded\nstderr:\n{stderr}"
    assert stdout == "", f"failed race helper emitted stdout: {stdout!r}"


def _private_key_lines(scenario: RequestScenario) -> list[bytes]:
    return [
        line
        for line in scenario.signing_key.read_bytes().splitlines()
        if len(line) >= 16
    ]


def _assert_private_material_absent(
    scenario: RequestScenario, output: str | bytes
) -> None:
    encoded = output.encode("utf-8") if isinstance(output, str) else output
    assert b"PRIVATE KEY" not in encoded
    assert not any(line in encoded for line in _private_key_lines(scenario))


def _cleanup_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=2)


def _wait_for_glob(root: Path, pattern: str, process: subprocess.Popen[str]) -> Path:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        matches = list(root.glob(pattern))
        if matches:
            return matches[0]
        if process.poll() is not None:
            break
        time.sleep(0.02)
    raise AssertionError(f"helper did not create expected race artifact: {pattern}")


def _wait_for_pause(process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 4
    wchan = Path(f"/proc/{process.pid}/wchan")
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            if wchan.read_text(encoding="ascii").strip() == "hrtimer_nanosleep":
                return
        except (FileNotFoundError, PermissionError):
            pass
        time.sleep(0.02)
    raise AssertionError("helper did not reach the injected pause")


def _crash_after_publication(
    scenario: RequestScenario, state: Path, pending: Path
) -> None:
    _assert_helper_failure(
        scenario.run(
            state=state,
            pending=pending,
            environment={"PLATFORM_PKI_REQUEST_CRASH_AT": "after-publication"},
        )
    )
    assert (state / "request.journal").is_file()


def test_absent_check_mode_is_non_mutating_and_fails(
    request_scenario: RequestScenario,
) -> None:
    before = _tree_snapshot(request_scenario.work)
    _assert_helper_failure(request_scenario.run(check=True))
    assert _tree_snapshot(request_scenario.work) == before
    assert not os.path.lexists(request_scenario.state)
    assert not os.path.lexists(request_scenario.pending)


def test_prepared_check_mode_is_non_mutating_and_reports_would_create(
    request_scenario: RequestScenario,
) -> None:
    _prepare_state(request_scenario)
    before = _tree_snapshot(request_scenario.work)
    output = _json_result(request_scenario.run(check=True))
    assert _tree_snapshot(request_scenario.work) == before
    assert not os.path.lexists(request_scenario.pending)
    assert output == {
        "status": "would-create",
        "pending_dir": str(request_scenario.pending),
    }


def test_creation_result_json_is_canonical(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    assert set(output) == {
        "status",
        "request_id",
        "request_sha256",
        "csr_sha256",
        "csr_spki_sha256",
        "pending_dir",
    }
    assert output["status"] == "created"
    assert re.fullmatch(r"[0-9a-f]{32}", output["request_id"])
    assert output["pending_dir"] == str(scenario.pending / output["request_id"])
    for name in ("request_sha256", "csr_sha256", "csr_spki_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", output[name])


def test_created_protocol_files_have_exact_names_and_metadata(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    pending_dir = scenario.pending / output["request_id"]
    metadata = pending_dir.lstat()
    assert stat.S_ISDIR(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o700
    assert metadata.st_uid == os.geteuid()
    assert {entry.name for entry in pending_dir.iterdir()} == PROTOCOL_FILES
    for name in PROTOCOL_FILES:
        metadata = (pending_dir / name).lstat()
        assert stat.S_ISREG(metadata.st_mode), name
        assert stat.S_IMODE(metadata.st_mode) == 0o600, name
        assert metadata.st_uid == os.geteuid(), name
        assert metadata.st_nlink == 1, name


def test_created_request_record_is_canonical_and_digest_bound(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    pending_dir = scenario.pending / output["request_id"]
    data = (pending_dir / "request").read_bytes()
    assert data.endswith(b"\n")
    assert b"\r" not in data
    lines = data.decode("ascii").splitlines()
    assert len(lines) == len(REQUEST_FIELDS)
    record: dict[str, str] = {}
    for expected, line in zip(REQUEST_FIELDS, lines, strict=True):
        key, value = line.split("=", 1)
        assert key == expected
        record[key] = value
    assert {
        key: record[key]
        for key in (
            "schema",
            "request_id",
            "operation",
            "service",
            "target",
            "requester_principal",
            "inventory_sha256",
            "current_cert_sha256",
            "profile",
            "response_principal",
        )
    } == {
        "schema": "1",
        "request_id": output["request_id"],
        "operation": "migrate",
        "service": "registry-test",
        "target": "test-target",
        "requester_principal": "test-target",
        "inventory_sha256": "a" * 64,
        "current_cert_sha256": scenario.current_digest,
        "profile": "server-p384-sha384-v1",
        "response_principal": "test-response",
    }
    assert int(record["expires_epoch"]) - int(record["created_epoch"]) == 3600
    assert record["csr_sha256"] == _sha256(pending_dir / "tls.csr")
    assert output["request_sha256"] == hashlib.sha256(data).hexdigest()
    assert output["csr_sha256"] == record["csr_sha256"]
    assert output["csr_spki_sha256"] == record["csr_spki_sha256"]


def test_request_binds_canonical_leaf_from_current_fullchain(
    request_scenario: RequestScenario,
) -> None:
    leaf = request_scenario.current_cert.read_bytes()
    with request_scenario.current_cert.open("ab") as stream:
        stream.write(leaf)
    request_scenario.current_cert.chmod(0o600)
    assert _sha256(request_scenario.current_cert) != request_scenario.current_digest

    output = _json_result(request_scenario.run())
    request = dict(
        line.split("=", 1)
        for line in (
            request_scenario.pending / output["request_id"] / "request"
        ).read_text(encoding="ascii").splitlines()
    )

    assert request["current_cert_sha256"] == request_scenario.current_digest


def test_created_request_signature_verifies(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    pending_dir = scenario.pending / output["request_id"]
    result = subprocess.run(
        scenario.runner.argv(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                scenario.trust / "requesters.allowed_signers",
                "-I",
                "test-target",
                "-n",
                "platform-pki-csr-request-v1",
                "-s",
                pending_dir / "request.sig",
            ]
        ),
        cwd=scenario.runner.command_runner.cwd,
        env=scenario.runner.environment(),
        input=(pending_dir / "request").read_bytes(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_created_csr_is_valid_and_matches_private_key_spki(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    pending_dir = scenario.pending / output["request_id"]
    scenario.runner.run(
        ["openssl", "req", "-in", pending_dir / "tls.csr", "-verify", "-noout"]
    ).assert_success()
    key_spki = scenario.work / "key-spki.der"
    csr_public = scenario.work / "csr-public.pem"
    csr_spki = scenario.work / "csr-spki.der"
    scenario.runner.run(
        [
            "openssl",
            "pkey",
            "-in",
            pending_dir / "tls.key",
            "-pubout",
            "-outform",
            "DER",
            "-out",
            key_spki,
        ]
    ).assert_success()
    scenario.runner.run(
        [
            "openssl",
            "req",
            "-in",
            pending_dir / "tls.csr",
            "-pubkey",
            "-noout",
            "-out",
            csr_public,
        ]
    ).assert_success()
    scenario.runner.run(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-in",
            csr_public,
            "-outform",
            "DER",
            "-out",
            csr_spki,
        ]
    ).assert_success()
    assert key_spki.read_bytes() == csr_spki.read_bytes()
    assert output["csr_spki_sha256"] == _sha256(csr_spki)


def test_idempotent_rerun_selects_existing_request(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, created = created_request
    existing = _json_result(scenario.run())
    assert existing["status"] == "existing"
    assert existing["request_id"] == created["request_id"]


def test_completed_lifecycle_state_preserves_existing_request(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, created = created_request
    for name, content in (
        ("active", "active\n"),
        ("rollback", "rollback\n"),
        ("validation-boundary", "boundary\n"),
    ):
        _write_private(scenario.state / name, content)
    evidence = (
        scenario.state
        / "evidence/0123456789abcdef0123456789abcdef"
        / ("a" * 64)
    )
    _mkdir_private(evidence.parent.parent)
    _mkdir_private(evidence.parent)
    _mkdir_private(evidence)
    for name in (
        "deployment",
        "deployment.sig",
        "validation-boundary",
        "validation-result",
        "validation-result.sig",
    ):
        _write_private(evidence / name, f"{name}\n")
    output = _json_result(scenario.run())
    assert output["status"] == "existing"
    assert output["request_id"] == created["request_id"]


def test_unresolved_activation_journal_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, _ = created_request
    _write_private(scenario.state / "activation-journal", "unresolved\n")
    _assert_helper_failure(scenario.run())


def test_state_lock_contention_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, _ = created_request
    descriptor = os.open(scenario.state / "lock", os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _assert_helper_failure(scenario.run())
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def test_changed_request_ttl_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, _ = created_request
    _assert_helper_failure(scenario.run(ttl=7200))


def test_symlinked_protocol_file_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    signature = scenario.pending / output["request_id"] / "request.sig"
    saved = scenario.work / "request.sig.saved"
    signature.rename(saved)
    signature.symlink_to(saved)
    _assert_helper_failure(scenario.run())


def test_hard_linked_protocol_file_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    csr = scenario.pending / output["request_id"] / "tls.csr"
    saved = scenario.work / "tls.csr.saved"
    csr.rename(saved)
    os.link(saved, csr)
    _assert_helper_failure(scenario.run())


def test_unexpected_protocol_entry_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    _write_private(
        scenario.pending / output["request_id"] / "unexpected", "unexpected\n"
    )
    _assert_helper_failure(scenario.run())


def test_corrupt_pending_request_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    request = scenario.pending / output["request_id"] / "request"
    request.unlink()
    _write_private(request, "malformed\n")
    _assert_helper_failure(scenario.run())


def test_multiple_pending_requests_are_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, output = created_request
    shutil.copytree(
        scenario.pending / output["request_id"],
        scenario.pending / ("0" * 32),
    )
    _assert_helper_failure(scenario.run())


def test_symlinked_state_root_is_rejected(
    created_request: tuple[RequestScenario, dict[str, Any]],
) -> None:
    scenario, _ = created_request
    state_link = scenario.work / "state-link"
    state_link.symlink_to(scenario.state)
    _assert_helper_failure(scenario.run(state=state_link))


def test_expired_pending_request_is_rejected(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "expired-state"
    pending = request_scenario.work / "expired-pending"
    _json_result(request_scenario.run(state=state, pending=pending, ttl=1))
    time.sleep(2)
    _assert_helper_failure(request_scenario.run(state=state, pending=pending, ttl=1))


def test_pending_request_is_not_current_at_exact_expiry(
    request_scenario: RequestScenario,
) -> None:
    helper = runpy.run_path(os.fspath(request_scenario.helper))
    is_current = helper["pending_request_lifetime_is_current"]
    expires = 1_800_000_000

    assert is_current(expires - 3600, expires, expires - 1, 3600) is True
    assert is_current(expires - 3600, expires, expires, 3600) is False
    assert is_current(expires - 3600, expires, expires + 1, 3600) is False


def test_prepublication_crash_check_is_non_mutating_and_apply_recovers(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "crash-state"
    pending = request_scenario.work / "crash-pending"
    _assert_helper_failure(
        request_scenario.run(
            state=state,
            pending=pending,
            environment={"PLATFORM_PKI_REQUEST_CRASH_AT": "after-key"},
        )
    )
    assert (state / "request.journal").is_file()
    assert list(pending.glob(".stage-*"))
    before = _tree_snapshot(request_scenario.work)
    _assert_helper_failure(
        request_scenario.run(check=True, state=state, pending=pending)
    )
    assert _tree_snapshot(request_scenario.work) == before
    recovered = _json_result(request_scenario.run(state=state, pending=pending))
    assert recovered["status"] == "created"
    assert not os.path.lexists(state / "request.journal")
    assert len([path for path in pending.iterdir() if re.fullmatch(r"[0-9a-f]{32}", path.name)]) == 1


def test_postpublication_crash_check_is_non_mutating_and_apply_recovers(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "published-state"
    pending = request_scenario.work / "published-pending"
    _crash_after_publication(request_scenario, state, pending)
    before = _tree_snapshot(request_scenario.work)
    _assert_helper_failure(
        request_scenario.run(check=True, state=state, pending=pending)
    )
    assert _tree_snapshot(request_scenario.work) == before
    recovered = _json_result(request_scenario.run(state=state, pending=pending))
    assert recovered["status"] == "existing"
    assert not os.path.lexists(state / "request.journal")


@pytest.mark.serial
def test_recovery_rejects_replaced_pending_root(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "published-state"
    pending = request_scenario.work / "published-pending"
    validated = request_scenario.work / "published-pending.validated"
    _crash_after_publication(request_scenario, state, pending)
    process = _start_helper(
        request_scenario,
        state=state,
        pending=pending,
        environment={
            "PLATFORM_PKI_REQUEST_PAUSE_AT": "before-recovery-journal-removal"
        },
    )
    try:
        _wait_for_pause(process)
        pending.rename(validated)
        shutil.copytree(validated, pending)
        _assert_process_failure(_finish_process(process))
        assert (state / "request.journal").is_file()
    finally:
        _cleanup_process(process)
    shutil.rmtree(pending)
    validated.rename(pending)
    assert _json_result(request_scenario.run(state=state, pending=pending))["status"] == "existing"


@pytest.mark.serial
def test_recovery_rejects_replaced_journal(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "published-state"
    pending = request_scenario.work / "published-pending"
    journal = state / "request.journal"
    validated = state / "request.journal.validated"
    _crash_after_publication(request_scenario, state, pending)
    process = _start_helper(
        request_scenario,
        state=state,
        pending=pending,
        environment={
            "PLATFORM_PKI_REQUEST_PAUSE_AT": "before-recovery-journal-removal"
        },
    )
    try:
        _wait_for_pause(process)
        journal.rename(validated)
        shutil.copyfile(validated, journal)
        journal.chmod(0o600)
        _assert_process_failure(_finish_process(process))
        assert journal.is_file()
    finally:
        _cleanup_process(process)
    journal.unlink()
    validated.rename(journal)
    assert _json_result(request_scenario.run(state=state, pending=pending))["status"] == "existing"


@pytest.mark.serial
def test_concurrent_publication_creates_exactly_one_request(
    request_scenario: RequestScenario,
) -> None:
    pending = request_scenario.work / "race-pending"
    processes: list[subprocess.Popen[str]] = []
    try:
        for index in (1, 2):
            processes.append(
                _start_helper(
                    request_scenario,
                    state=request_scenario.work / f"race-state-{index}",
                    pending=pending,
                )
            )
        outcomes = [_finish_process(process, timeout=30) for process in processes]
    finally:
        for process in processes:
            _cleanup_process(process)
    successes = [outcome for outcome in outcomes if outcome[0] == 0]
    assert successes
    request_dirs = [
        path
        for path in pending.iterdir()
        if path.is_dir() and re.fullmatch(r"[0-9a-f]{32}", path.name)
    ]
    assert len(request_dirs) == 1
    statuses = []
    for returncode, stdout, stderr in outcomes:
        if returncode == 0:
            statuses.append(json.loads(stdout)["status"])
        else:
            assert stdout == "", f"failed concurrent helper emitted stdout: {stdout!r}"
            assert "another operation holds the pending-root parent lock" in stderr
    assert statuses.count("created") == 1
    assert all(status in {"created", "existing"} for status in statuses)
    assert len(statuses) in {1, 2}


@pytest.mark.serial
def test_publication_rejects_replaced_state_lock(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "binding-state"
    pending = request_scenario.work / "binding-pending"
    lock = state / "lock"
    validated = state / "lock.validated"
    process = _start_helper(
        request_scenario,
        state=state,
        pending=pending,
        environment={"PLATFORM_PKI_REQUEST_PAUSE_AT": "before-publication"},
    )
    try:
        _wait_for_glob(pending, ".stage-*/request.sig", process)
        _wait_for_pause(process)
        lock.rename(validated)
        lock.touch()
        lock.chmod(0o600)
        _assert_process_failure(_finish_process(process))
    finally:
        _cleanup_process(process)
    lock.unlink()
    validated.rename(lock)
    _json_result(request_scenario.run(state=state, pending=pending))


@pytest.mark.serial
def test_publication_rejects_replaced_pending_root(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "pending-binding-state"
    pending = request_scenario.work / "pending-binding-root"
    validated = request_scenario.work / "pending-binding-root.validated"
    process = _start_helper(
        request_scenario,
        state=state,
        pending=pending,
        environment={"PLATFORM_PKI_REQUEST_PAUSE_AT": "before-publication"},
    )
    try:
        _wait_for_glob(pending, ".stage-*/request.sig", process)
        _wait_for_pause(process)
        pending.rename(validated)
        _mkdir_private(pending)
        _assert_process_failure(_finish_process(process))
    finally:
        _cleanup_process(process)
    pending.rmdir()
    validated.rename(pending)
    _json_result(request_scenario.run(state=state, pending=pending))


@pytest.mark.serial
def test_publication_rejects_replaced_journal(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "publication-journal-state"
    pending = request_scenario.work / "publication-journal-pending"
    journal = state / "request.journal"
    validated = state / "request.journal.validated"
    process = _start_helper(
        request_scenario,
        state=state,
        pending=pending,
        environment={
            "PLATFORM_PKI_REQUEST_PAUSE_AT": "before-publication-journal-removal"
        },
    )
    try:
        _wait_for_pause(process)
        journal.rename(validated)
        shutil.copyfile(validated, journal)
        journal.chmod(0o600)
        _assert_process_failure(_finish_process(process))
        assert journal.is_file()
    finally:
        _cleanup_process(process)
    journal.unlink()
    validated.rename(journal)
    _json_result(request_scenario.run(state=state, pending=pending))


@pytest.mark.serial
def test_signing_rejects_replaced_private_key(
    request_scenario: RequestScenario,
) -> None:
    state = request_scenario.work / "replacement-state"
    pending = request_scenario.work / "replacement-pending"
    validated = request_scenario.work / "request-key.validated"
    process = _start_helper(
        request_scenario,
        state=state,
        pending=pending,
        environment={"PLATFORM_PKI_REQUEST_PAUSE_AT": "before-signing"},
    )
    try:
        _wait_for_glob(pending, ".stage-*/request", process)
        _wait_for_pause(process)
        request_scenario.signing_key.rename(validated)
        request_scenario.runner.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                request_scenario.signing_key,
            ]
        ).assert_success()
        request_scenario.signing_key.chmod(0o600)
        _assert_process_failure(_finish_process(process))
    finally:
        _cleanup_process(process)
    request_scenario.signing_key.unlink()
    request_scenario.signing_key.with_suffix(".pub").unlink()
    validated.rename(request_scenario.signing_key)
    _json_result(request_scenario.run(state=state, pending=pending))


def test_helper_stdout_redacts_private_signing_key(
    request_scenario: RequestScenario,
) -> None:
    _prepare_state(request_scenario)
    outputs = [_json_result(request_scenario.run(check=True))]
    outputs.append(_json_result(request_scenario.run()))
    outputs.append(_json_result(request_scenario.run()))

    expired_state = request_scenario.work / "expired-state"
    expired_pending = request_scenario.work / "expired-pending"
    outputs.append(
        _json_result(
            request_scenario.run(
                state=expired_state,
                pending=expired_pending,
            )
        )
    )

    crash_state = request_scenario.work / "crash-state"
    crash_pending = request_scenario.work / "crash-pending"
    _assert_helper_failure(
        request_scenario.run(
            state=crash_state,
            pending=crash_pending,
            environment={"PLATFORM_PKI_REQUEST_CRASH_AT": "after-key"},
        )
    )
    outputs.append(
        _json_result(request_scenario.run(state=crash_state, pending=crash_pending))
    )

    published_state = request_scenario.work / "published-state"
    published_pending = request_scenario.work / "published-pending"
    _crash_after_publication(
        request_scenario, published_state, published_pending
    )
    outputs.append(
        _json_result(
            request_scenario.run(state=published_state, pending=published_pending)
        )
    )

    for output in outputs:
        _assert_private_material_absent(
            request_scenario, json.dumps(output, sort_keys=True)
        )

    failure = request_scenario.run(ttl=7200)
    _assert_helper_failure(failure)
    _assert_private_material_absent(
        request_scenario, failure.stdout + failure.stderr
    )


@dataclass(frozen=True)
class RoleScenario:
    request: RequestScenario
    variables: Path
    state: Path
    pending: Path
    helper: Path
    lifecycle_helper: Path
    playbook: Path
    pythonpath: Path
    helper_digest: str

    def run(self, *, check: bool = False) -> CommandResult:
        playbook_argv: list[str | Path] = ["ansible-playbook"]
        if check:
            playbook_argv.append("--check")
        playbook_argv.extend(
            (
                "-i",
                "localhost,",
                "-e",
                f"@{self.variables}",
                self.playbook,
            )
        )
        return self.request.runner.run(
            [
                "unshare",
                "-m",
                "--",
                "sh",
                "-c",
                'mount --bind "$1" /usr/local/libexec && shift && exec "$@"',
                "sh",
                self.lifecycle_helper.parent,
                *playbook_argv,
            ],
            environment={"PYTHONPATH": str(self.pythonpath)},
            timeout=60,
        )


@pytest.fixture
def role_scenario(
    request_scenario: RequestScenario, repo_root: Path
) -> RoleScenario:
    request = request_scenario
    public = request.runner.run(
        ["ssh-keygen", "-y", "-f", request.signing_key]
    ).assert_success().stdout.strip().split()
    assert len(public) >= 2
    for name in ("requesters.allowed_signers", "deployers.allowed_signers"):
        _write_private(request.trust / name, f"localhost {public[0]} {public[1]}\n")

    state = request.work / "role-state"
    pending = request.work / "tls-pending"
    versions = request.work / "tls-versions"
    exchange = request.work / "exchange"
    helper = request.work / "bin/platform-pki-host-local-request"
    lifecycle_helper = request.work / "bin/platform-pki-host-local-lifecycle"
    role_trust = state / "trust/reviewed-v1"
    _mkdir_private(state)
    _mkdir_private(state / "trust")
    _mkdir_private(role_trust)
    _mkdir_private(exchange)
    for name in TRUST_NAMES:
        shutil.copyfile(request.trust / name, role_trust / name)
        (role_trust / name).chmod(0o600)
    (state / "lock").touch()
    (state / "lock").chmod(0o600)
    helper.parent.mkdir()
    helper.parent.chmod(0o755)
    shutil.copyfile(request.helper, helper)
    helper.chmod(0o755)
    shutil.copyfile(
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle",
        lifecycle_helper,
    )
    lifecycle_helper.chmod(0o755)

    variables = request.work / "role-vars.json"
    trust_digests = {name: _sha256(request.trust / name) for name in TRUST_NAMES}
    role_variables = {
        "ansible_remote_tmp": f"{state}-ansible-tmp",
        "pki_host_local_certificate_service": "registry-test",
        "pki_host_local_certificate_target": "localhost",
        "pki_host_local_certificate_operation": "migrate",
        "pki_host_local_certificate_inventory_sha256": "a" * 64,
        "pki_host_local_certificate_current_cert_sha256": request.current_digest,
        "pki_host_local_certificate_current_cert_path": str(request.current_cert),
        "pki_host_local_certificate_requester_principal": "localhost",
        "pki_host_local_certificate_response_principal": "test-response",
        "pki_host_local_certificate_common_name": "registry.test.example",
        "pki_host_local_certificate_dns_sans": [
            "registry.test.example",
            "localhost",
        ],
        "pki_host_local_certificate_ip_sans": ["192.0.2.61"],
        "pki_host_local_certificate_validity_days": 397,
        "pki_host_local_certificate_request_ttl_seconds": 3600,
        "pki_host_local_certificate_request_signing_key_path": str(
            request.signing_key
        ),
        "pki_host_local_certificate_trust_id": "reviewed-v1",
        "pki_host_local_certificate_state_root": str(state),
        "pki_host_local_certificate_pending_root": str(pending),
        "pki_host_local_certificate_versions_root": str(versions),
        "pki_host_local_certificate_request_helper_path": str(helper),
        "pki_host_local_certificate_lifecycle_helper_path": (
            "/usr/local/libexec/platform-pki-host-local-lifecycle"
        ),
        "pki_host_local_certificate_controller_exchange_root": str(
            exchange
        ),
        "pki_host_local_certificate_transport": "sftp",
        "pki_host_local_certificate_transport_host_key_sha256": "b" * 64,
        "pki_host_local_certificate_trust_paths": {
            name: str(role_trust / name) for name in TRUST_NAMES
        },
        "pki_host_local_certificate_trust_sources": {
            name: str(request.trust / name) for name in TRUST_NAMES
        },
        "pki_host_local_certificate_trust_sha256": trust_digests,
    }
    variables.write_text(
        json.dumps(role_variables, sort_keys=True), encoding="utf-8"
    )
    variables.chmod(0o600)
    return RoleScenario(
        request=request,
        variables=variables,
        state=state,
        pending=pending,
        helper=helper,
        lifecycle_helper=lifecycle_helper,
        playbook=(
            repo_root / "tests/fixtures/pki-host-local-request-role/integration.yml"
        ),
        pythonpath=repo_root,
        helper_digest=_sha256(helper),
    )


def test_ansible_role_check_mode_is_non_mutating(
    role_scenario: RoleScenario,
) -> None:
    role_scenario.run(check=True).assert_success()
    assert not os.path.lexists(role_scenario.pending)
    assert _sha256(role_scenario.helper) == role_scenario.helper_digest
    assert {path.name for path in role_scenario.state.iterdir()} == {"lock", "trust"}


def test_ansible_role_apply_creates_one_protected_request(
    role_scenario: RoleScenario,
) -> None:
    result = role_scenario.run().assert_success()
    _assert_private_material_absent(
        role_scenario.request, result.stdout + result.stderr
    )
    assert os.access(role_scenario.helper, os.X_OK)
    requests = [
        path
        for path in role_scenario.pending.iterdir()
        if path.is_dir() and re.fullmatch(r"[0-9a-f]{32}", path.name)
    ]
    assert len(requests) == 1
    assert (requests[0] / "tls.key").is_file()
    assert not os.path.lexists(role_scenario.request.work / "tls.key")


def test_ansible_role_second_apply_is_idempotent(
    role_scenario: RoleScenario,
) -> None:
    role_scenario.run().assert_success()
    result = role_scenario.run().assert_success()
    _assert_private_material_absent(
        role_scenario.request, result.stdout + result.stderr
    )
    assert re.search(r"changed=0.*failed=0", result.stdout)
