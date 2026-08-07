from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from conftest import NamespaceRootRunner


pytestmark = pytest.mark.pki


TRUST_NAMES = (
    "policy",
    "requesters.allowed_signers",
    "approvers.allowed_signers",
    "responses.allowed_signers",
    "deployers.allowed_signers",
)


def tree_snapshot(root: Path) -> tuple[tuple[Any, ...], ...]:
    result: list[tuple[Any, ...]] = []
    if not os.path.lexists(root):
        return ()
    for current, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        for name in directories + files:
            path = Path(current) / name
            metadata = path.lstat()
            record: tuple[Any, ...] = (
                str(path.relative_to(root)),
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_ino,
            )
            if stat.S_ISREG(metadata.st_mode):
                record += (hashlib.sha256(path.read_bytes()).hexdigest(),)
            result.append(record)
    return tuple(result)


def stop_owned_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=2)


@dataclass
class TrustCase:
    repo_root: Path
    work: Path
    runner: NamespaceRootRunner
    helper: Path
    request_helper: Path
    source: Path
    key: Path
    key_algorithm: str
    key_payload: str
    digests: dict[str, str]

    def prepare(self, state: Path) -> None:
        result = self.runner.run(
            [
                self.helper,
                "prepare",
                "--state-root",
                state,
                "--trust-id",
                "reviewed-v1",
            ]
        ).assert_success()
        assert json.loads(result.stdout)["status"] in {"prepared", "existing"}

    def populate_ingress(self, state: Path) -> None:
        ingress = state / "trust/.ingress-reviewed-v1"
        for source in self.source.iterdir():
            shutil.copy2(source, ingress / source.name)
            (ingress / source.name).chmod(0o600)

    def prepare_ingress(self, state: Path) -> None:
        self.prepare(state)
        self.populate_ingress(state)

    def install_argv(
        self,
        state: Path,
        *,
        check: bool = False,
        trust_id: str = "reviewed-v1",
        digests: dict[str, str] | None = None,
    ) -> list[str | Path]:
        selected_digests = digests or self.digests
        target = state / "trust" / trust_id
        argv: list[str | Path] = [self.helper, "install"]
        if check:
            argv.append("--check")
        argv.extend(
            [
                "--state-root",
                state,
                "--trust-id",
                trust_id,
                "--requester-principal",
                "test-target",
                "--response-principal",
                "test-response",
            ]
        )
        for name in TRUST_NAMES:
            argv.extend(
                [
                    "--trust-binding",
                    name,
                    target / name,
                    selected_digests[name],
                ]
            )
        return argv

    def install(
        self,
        state: Path,
        *,
        check: bool = False,
        trust_id: str = "reviewed-v1",
        digests: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
    ):
        return self.runner.run(
            self.install_argv(
                state,
                check=check,
                trust_id=trust_id,
                digests=digests,
            ),
            environment=environment,
        )

    def request_argv(self, state: Path, pending: Path) -> list[str | Path]:
        target = state / "trust/reviewed-v1"
        argv: list[str | Path] = [
            self.request_helper,
            "request",
            "--service",
            "registry-test",
            "--target",
            "test-target",
            "--requester-principal",
            "test-target",
            "--operation",
            "issue",
            "--profile",
            "server-p384-sha384-v1",
            "--inventory-sha256",
            "a" * 64,
            "--current-cert-sha256",
            "none",
            "--common-name",
            "registry.test.example",
            "--dns-san",
            "registry.test.example",
            "--response-principal",
            "test-response",
            "--request-ttl-seconds",
            "3600",
            "--request-signing-key",
            self.key,
            "--request-namespace",
            "platform-pki-csr-request-v1",
            "--state-root",
            state,
            "--pending-root",
            pending,
        ]
        for name in TRUST_NAMES:
            argv.extend(
                [
                    "--trust-binding",
                    name,
                    target / name,
                    self.digests[name],
                ]
            )
        return argv

    def request(self, state: Path, pending: Path):
        return self.runner.run(self.request_argv(state, pending), timeout=45)

    def digest_tree(self, root: Path) -> dict[str, str]:
        return {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in TRUST_NAMES
        }

    def start_install(
        self,
        state: Path,
        *,
        environment: dict[str, str],
    ) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.runner.argv(self.install_argv(state)),
            cwd=self.repo_root,
            env=self.runner.environment(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )


@pytest.fixture
def trust_case(
    repo_root: Path,
    isolated_test_dir: Path,
    namespace_root_runner: NamespaceRootRunner,
) -> TrustCase:
    source = isolated_test_dir / "reviewed-source"
    source.mkdir(mode=0o700)
    key = isolated_test_dir / "request-key"
    namespace_root_runner.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key]
    ).assert_success()
    key.chmod(0o600)
    algorithm, payload, *_ = (key.with_suffix(".pub")).read_text(
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
        (source / name).write_text(
            f"{principal} {algorithm} {payload}\n", encoding="ascii"
        )
    (source / "policy").write_text(
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
        encoding="ascii",
    )
    for path in source.iterdir():
        path.chmod(0o600)

    digests = {
        name: hashlib.sha256((source / name).read_bytes()).hexdigest()
        for name in TRUST_NAMES
    }
    return TrustCase(
        repo_root=repo_root,
        work=isolated_test_dir,
        runner=namespace_root_runner,
        helper=repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-trust",
        request_helper=repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-request",
        source=source,
        key=key,
        key_algorithm=algorithm,
        key_payload=payload,
        digests=digests,
    )


def assert_helper_failure(result) -> None:
    result.assert_failure()
    assert result.stdout == "", result.diagnostics()


def install_trust(case: TrustCase, state: Path) -> Path:
    case.prepare_ingress(state)
    result = case.install(state).assert_success()
    assert json.loads(result.stdout)["status"] == "installed"
    return state / "trust/reviewed-v1"


def wait_for_stage(state: Path, timeout: float = 5) -> Path:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = sorted((state / "trust").glob(".stage-*"))
        if candidates:
            assert len(candidates) == 1
            return candidates[0]
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for trust stage: {state}")


def wait_for_pause(process: subprocess.Popen[str], timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
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


def assert_background_helper_failure(process: subprocess.Popen[str]) -> None:
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode != 0, f"helper succeeded\nstdout:\n{stdout}\nstderr:\n{stderr}"
    assert stdout == "", f"failed helper emitted stdout:\n{stdout}\nstderr:\n{stderr}"


def test_check_mode_rejects_absent_prerequisites_without_mutation(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "absent-state"
    before = tree_snapshot(state)

    assert_helper_failure(trust_case.install(state, check=True))

    assert tree_snapshot(state) == before
    assert not os.path.lexists(state)


def test_check_mode_rejects_incomplete_ingress_without_mutation(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "incomplete-state"
    trust_case.prepare(state)
    before = tree_snapshot(state)

    assert_helper_failure(trust_case.install(state, check=True))

    assert tree_snapshot(state) == before


def test_check_mode_reports_complete_ingress_without_mutation(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "ready-state"
    trust_case.prepare_ingress(state)
    before = tree_snapshot(state)

    result = trust_case.install(state, check=True).assert_success()

    assert json.loads(result.stdout)["status"] == "would-install"
    assert tree_snapshot(state) == before


def test_request_fails_before_trust_bootstrap(trust_case: TrustCase) -> None:
    state = trust_case.work / "request-before-state"
    trust_case.prepare_ingress(state)

    assert_helper_failure(
        trust_case.request(state, trust_case.work / "request-before-pending")
    )


def test_install_enforces_metadata_and_is_idempotent(trust_case: TrustCase) -> None:
    state = trust_case.work / "installed-state"
    target = install_trust(trust_case, state)
    target_inode = target.stat().st_ino
    metadata_check = r"""
import os
import stat
import sys

state = sys.argv[1]
if set(os.listdir(state)) != {"lock", "trust"}:
    raise SystemExit("unexpected post-install state")
for path in (state, os.path.join(state, "trust"), os.path.join(state, "trust", "reviewed-v1")):
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != 0 or metadata.st_gid != 0:
        raise SystemExit(f"unsafe directory metadata: {path}")
for name in ("lock", "trust/reviewed-v1/policy", "trust/reviewed-v1/requesters.allowed_signers", "trust/reviewed-v1/approvers.allowed_signers", "trust/reviewed-v1/responses.allowed_signers", "trust/reviewed-v1/deployers.allowed_signers"):
    metadata = os.lstat(os.path.join(state, name))
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != 0 or metadata.st_gid != 0 or metadata.st_nlink != 1:
        raise SystemExit(f"unsafe file metadata: {name}")
"""
    trust_case.runner.run(
        [sys.executable, "-c", metadata_check, state]
    ).assert_success()

    result = trust_case.install(state, check=True).assert_success()

    assert json.loads(result.stdout)["status"] == "existing"
    assert target.stat().st_ino == target_inode


def test_request_succeeds_after_trust_bootstrap(trust_case: TrustCase) -> None:
    state = trust_case.work / "request-after-state"
    install_trust(trust_case, state)

    result = trust_case.request(
        state, trust_case.work / "request-after-pending"
    ).assert_success()

    assert json.loads(result.stdout)["status"] == "created"


@pytest.mark.serial
def test_lock_contention_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "lock-state"
    install_trust(trust_case, state)
    ready = trust_case.work / "lock-ready"
    lock_script = r"""
import fcntl
import pathlib
import sys
import time

with open(sys.argv[1], "rb") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    pathlib.Path(sys.argv[2]).write_text("ready", encoding="ascii")
    time.sleep(30)
"""
    process = subprocess.Popen(
        trust_case.runner.argv(
            [sys.executable, "-c", lock_script, state / "lock", ready]
        ),
        cwd=trust_case.repo_root,
        env=trust_case.runner.environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.02)
        assert ready.exists()
        assert_helper_failure(trust_case.install(state, check=True))
    finally:
        stop_owned_process(process)


def test_destination_symlink_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "destination-symlink-state"
    target = install_trust(trust_case, state)
    saved = trust_case.work / "policy.saved"
    (target / "policy").rename(saved)
    (target / "policy").symlink_to(saved)

    assert_helper_failure(trust_case.install(state, check=True))


def test_destination_hardlink_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "destination-hardlink-state"
    target = install_trust(trust_case, state)
    saved = trust_case.work / "requesters.saved"
    (target / "requesters.allowed_signers").rename(saved)
    os.link(saved, target / "requesters.allowed_signers")

    assert_helper_failure(trust_case.install(state, check=True))


def test_destination_extra_file_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "destination-extra-state"
    target = install_trust(trust_case, state)
    (target / "extra").write_text("unexpected\n", encoding="ascii")

    assert_helper_failure(trust_case.install(state, check=True))


def test_destination_unsafe_metadata_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "destination-mode-state"
    target = install_trust(trust_case, state)
    (target / "responses.allowed_signers").chmod(0o644)

    assert_helper_failure(trust_case.install(state, check=True))


def test_unexpected_state_root_entry_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "unexpected-state"
    install_trust(trust_case, state)
    (state / "unexpected").write_text("unexpected\n", encoding="ascii")

    assert_helper_failure(trust_case.install(state, check=True))


def test_trust_rotation_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "rotation-state"
    install_trust(trust_case, state)
    rotated = dict(trust_case.digests)
    rotated["policy"] = "b" * 64

    assert_helper_failure(trust_case.install(state, check=True, digests=rotated))


def test_other_trust_id_is_rejected(trust_case: TrustCase) -> None:
    state = trust_case.work / "other-trust-state"
    install_trust(trust_case, state)

    assert_helper_failure(
        trust_case.install(state, check=True, trust_id="reviewed-v2")
    )


def test_installed_trust_accepts_lifecycle_state_without_mutation(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "lifecycle-state"
    install_trust(trust_case, state)
    for name, content in (
        ("active", "active\n"),
        ("rollback", "rollback\n"),
        ("validation-boundary", "boundary\n"),
    ):
        (state / name).write_text(content, encoding="ascii")
        (state / name).chmod(0o600)
    deployment = (
        state
        / "evidence/0123456789abcdef0123456789abcdef"
        / ("a" * 64)
    )
    deployment.mkdir(parents=True, mode=0o700)
    (state / "evidence").chmod(0o700)
    deployment.parent.chmod(0o700)
    for name in (
        "deployment",
        "deployment.sig",
        "validation-boundary",
        "validation-result",
        "validation-result.sig",
    ):
        (deployment / name).write_text(f"{name}\n", encoding="ascii")
        (deployment / name).chmod(0o600)
    before = tree_snapshot(state)

    result = trust_case.install(state, check=True).assert_success()

    assert json.loads(result.stdout)["status"] == "existing"
    assert tree_snapshot(state) == before


INVALID_CASES = (
    "schema",
    "principal",
    "key",
    "requester",
    "approver",
    "response",
    "deployer",
    "digest",
    "symlink",
    "hardlink",
    "mode",
    "extra",
)


@pytest.mark.parametrize("mutation", INVALID_CASES, ids=INVALID_CASES)
def test_invalid_ingress_is_rejected(
    trust_case: TrustCase,
    mutation: str,
) -> None:
    state = trust_case.work / f"invalid-{mutation}"
    trust_case.prepare_ingress(state)
    ingress = state / "trust/.ingress-reviewed-v1"
    semantic_mutation = mutation in {
        "schema",
        "principal",
        "key",
        "requester",
        "approver",
        "response",
        "deployer",
    }
    if mutation == "schema":
        policy = ingress / "policy"
        policy.write_text(
            policy.read_text(encoding="ascii").replace("schema=2", "schema=1"),
            encoding="ascii",
        )
    elif mutation == "principal":
        (ingress / "requesters.allowed_signers").write_text(
            f"Test-target {trust_case.key_algorithm} {trust_case.key_payload}\n",
            encoding="ascii",
        )
    elif mutation == "key":
        (ingress / "requesters.allowed_signers").write_text(
            "test-target ssh-ed25519 AAAA\n", encoding="ascii"
        )
    elif mutation == "requester":
        (ingress / "requesters.allowed_signers").write_text(
            f"other-target {trust_case.key_algorithm} {trust_case.key_payload}\n",
            encoding="ascii",
        )
    elif mutation == "approver":
        with (ingress / "approvers.allowed_signers").open(
            "a", encoding="ascii"
        ) as stream:
            stream.write(
                f"other {trust_case.key_algorithm} {trust_case.key_payload}\n"
            )
    elif mutation == "response":
        with (ingress / "responses.allowed_signers").open(
            "a", encoding="ascii"
        ) as stream:
            stream.write(
                f"other {trust_case.key_algorithm} {trust_case.key_payload}\n"
            )
    elif mutation == "deployer":
        (ingress / "deployers.allowed_signers").write_text(
            f"other-target {trust_case.key_algorithm} {trust_case.key_payload}\n",
            encoding="ascii",
        )
    elif mutation == "digest":
        with (ingress / "deployers.allowed_signers").open(
            "a", encoding="ascii"
        ) as stream:
            stream.write("extra\n")
    elif mutation == "symlink":
        saved = trust_case.work / "symlink.saved"
        (ingress / "policy").rename(saved)
        (ingress / "policy").symlink_to(saved)
    elif mutation == "hardlink":
        os.link(ingress / "policy", trust_case.work / "hardlink.link")
    elif mutation == "mode":
        (ingress / "policy").chmod(0o644)
    elif mutation == "extra":
        (ingress / "extra").write_text("unexpected\n", encoding="ascii")
    else:
        raise AssertionError(f"unknown invalid case: {mutation}")

    digests = (
        trust_case.digest_tree(ingress)
        if semantic_mutation
        else trust_case.digests
    )
    assert_helper_failure(trust_case.install(state, digests=digests))


def test_check_mode_does_not_recover_crash_after_journal(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "journal-check-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={"PLATFORM_PKI_TRUST_CRASH_AT": "after-journal"},
        )
    )
    assert (state / "trust-install.journal").is_file()
    before = tree_snapshot(state)

    assert_helper_failure(trust_case.install(state, check=True))

    assert tree_snapshot(state) == before


def test_apply_recovers_crash_after_journal(trust_case: TrustCase) -> None:
    state = trust_case.work / "journal-recovery-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={"PLATFORM_PKI_TRUST_CRASH_AT": "after-journal"},
        )
    )

    result = trust_case.install(state).assert_success()

    assert json.loads(result.stdout)["status"] == "installed"


def test_apply_recovers_crash_after_publication(trust_case: TrustCase) -> None:
    state = trust_case.work / "publication-crash-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={"PLATFORM_PKI_TRUST_CRASH_AT": "after-publication"},
        )
    )
    assert (state / "trust/reviewed-v1").is_dir()
    assert (state / "trust-install.journal").is_file()

    result = trust_case.install(state).assert_success()

    assert json.loads(result.stdout)["status"] == "existing"
    assert {path.name for path in state.iterdir()} == {"lock", "trust"}


@pytest.mark.parametrize(
    "crash_point",
    ("after-ingress-cleanup-file", "after-ingress-cleanup"),
    ids=("after-file", "after-directory"),
)
def test_apply_recovers_crash_during_ingress_cleanup(
    trust_case: TrustCase,
    crash_point: str,
) -> None:
    state = trust_case.work / f"{crash_point}-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={"PLATFORM_PKI_TRUST_CRASH_AT": crash_point},
        )
    )
    assert (state / "trust/reviewed-v1").is_dir()
    assert (state / "trust-install.journal").is_file()

    result = trust_case.install(state).assert_success()

    assert json.loads(result.stdout)["status"] == "existing"
    assert {path.name for path in state.iterdir()} == {"lock", "trust"}


def test_apply_recovers_empty_unjournaled_stage(trust_case: TrustCase) -> None:
    state = trust_case.work / "empty-orphan-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={
                "PLATFORM_PKI_TRUST_CRASH_AT": "after-stage-create-before-journal"
            },
        )
    )
    assert not os.path.lexists(state / "trust-install.journal")
    assert len(list((state / "trust").glob(".stage-*"))) == 1

    result = trust_case.install(state).assert_success()

    assert json.loads(result.stdout)["status"] == "installed"


def test_nonempty_unjournaled_stage_is_rejected_and_preserved(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "nonempty-orphan-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={
                "PLATFORM_PKI_TRUST_CRASH_AT": "after-stage-create-before-journal"
            },
        )
    )
    orphan = wait_for_stage(state)
    (orphan / "foreign").write_text("foreign\n", encoding="ascii")
    (orphan / "foreign").chmod(0o600)
    orphan_inode = orphan.stat().st_ino

    assert_helper_failure(trust_case.install(state))

    assert orphan.stat().st_ino == orphan_inode
    assert (orphan / "foreign").read_text(encoding="ascii") == "foreign\n"


def test_ambiguous_unjournaled_stage_is_rejected_and_preserved(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "ambiguous-orphan-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={
                "PLATFORM_PKI_TRUST_CRASH_AT": "after-stage-create-before-journal"
            },
        )
    )
    orphan = wait_for_stage(state)
    foreign = state / "trust/unexpected"
    foreign.mkdir(mode=0o700)
    orphan_inode = orphan.stat().st_ino
    foreign_inode = foreign.stat().st_ino

    assert_helper_failure(trust_case.install(state))

    assert orphan.stat().st_ino == orphan_inode
    assert foreign.stat().st_ino == foreign_inode


@pytest.mark.serial
def test_ingress_mutation_publication_race_is_rejected(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "ingress-race-state"
    trust_case.prepare_ingress(state)
    process = trust_case.start_install(
        state,
        environment={"PLATFORM_PKI_TRUST_PAUSE_AT": "before-publication"},
    )
    try:
        wait_for_stage(state)
        wait_for_pause(process)
        with (state / "trust/.ingress-reviewed-v1/requesters.allowed_signers").open(
            "a", encoding="ascii"
        ) as stream:
            stream.write("changed\n")
        assert_background_helper_failure(process)
        assert not os.path.lexists(state / "trust/reviewed-v1")
    finally:
        stop_owned_process(process)


@pytest.mark.serial
def test_destination_conflict_publication_race_is_rejected(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "destination-race-state"
    trust_case.prepare_ingress(state)
    process = trust_case.start_install(
        state,
        environment={"PLATFORM_PKI_TRUST_PAUSE_AT": "before-publication"},
    )
    try:
        wait_for_stage(state)
        wait_for_pause(process)
        target = state / "trust/reviewed-v1"
        target.mkdir(mode=0o700)
        (target / "foreign").write_text("foreign\n", encoding="ascii")
        assert_background_helper_failure(process)
        assert (target / "foreign").read_text(encoding="ascii") == "foreign\n"
    finally:
        stop_owned_process(process)


@pytest.mark.serial
def test_lock_replacement_publication_race_is_rejected(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "lock-race-state"
    trust_case.prepare_ingress(state)
    process = trust_case.start_install(
        state,
        environment={"PLATFORM_PKI_TRUST_PAUSE_AT": "before-publication"},
    )
    try:
        wait_for_stage(state)
        wait_for_pause(process)
        (state / "lock").rename(state / "lock.validated")
        (state / "lock").touch(mode=0o600)
        (state / "lock").chmod(0o600)
        assert_background_helper_failure(process)
        assert not os.path.lexists(state / "trust/reviewed-v1")
    finally:
        stop_owned_process(process)


REPLACEMENT_CASES = ("state", "trust", "ingress", "stage", "journal")


@pytest.mark.parametrize("replacement", REPLACEMENT_CASES, ids=REPLACEMENT_CASES)
@pytest.mark.serial
def test_target_replacement_publication_race_is_rejected(
    trust_case: TrustCase,
    replacement: str,
) -> None:
    state = trust_case.work / f"{replacement}-replacement-state"
    trust_case.prepare_ingress(state)
    process = trust_case.start_install(
        state,
        environment={"PLATFORM_PKI_TRUST_PAUSE_AT": "before-publication"},
    )
    try:
        stage = wait_for_stage(state)
        wait_for_pause(process)
        deadline = time.monotonic() + 5
        while not (state / "trust-install.journal").is_file() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.02)
        assert (state / "trust-install.journal").is_file()
        if replacement == "state":
            state.rename(Path(f"{state}.validated"))
            state.mkdir(mode=0o700)
        elif replacement == "trust":
            (state / "trust").rename(state / "trust.validated")
            (state / "trust").mkdir(mode=0o700)
        elif replacement == "ingress":
            ingress = state / "trust/.ingress-reviewed-v1"
            ingress.rename(state / "trust/.ingress-reviewed-v1.validated")
            ingress.mkdir(mode=0o700)
        elif replacement == "stage":
            stage.rename(Path(f"{stage}.validated"))
            stage.mkdir(mode=0o700)
        elif replacement == "journal":
            journal = state / "trust-install.journal"
            validated = state / "trust-install.journal.validated"
            journal.rename(validated)
            shutil.copy2(validated, journal)
            journal.chmod(0o600)
        else:
            raise AssertionError(f"unknown replacement case: {replacement}")

        assert_background_helper_failure(process)
        if replacement == "state":
            target = Path(f"{state}.validated") / "trust/reviewed-v1"
        elif replacement == "trust":
            target = state / "trust.validated/reviewed-v1"
        else:
            target = state / "trust/reviewed-v1"
        assert not os.path.lexists(target)
    finally:
        stop_owned_process(process)


def test_journaled_stage_identity_mismatch_is_rejected_and_preserved(
    trust_case: TrustCase,
) -> None:
    state = trust_case.work / "stage-mismatch-state"
    trust_case.prepare_ingress(state)
    assert_helper_failure(
        trust_case.install(
            state,
            environment={"PLATFORM_PKI_TRUST_CRASH_AT": "after-journal"},
        )
    )
    stage = wait_for_stage(state)
    stage.rename(Path(f"{stage}.journaled"))
    stage.mkdir(mode=0o700)
    replacement_inode = stage.stat().st_ino

    assert_helper_failure(trust_case.install(state))

    assert stage.stat().st_ino == replacement_inode
    assert (state / "trust-install.journal").is_file()


PLUGIN_PROBE = r"""
import hashlib
import importlib.util
import os
import shutil
import sys

plugin_path, source, work, case = sys.argv[1:]
spec = importlib.util.spec_from_file_location("platform_pki_trust_ingress_test", plugin_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

if case == "repository":
    try:
        module.pin_source(plugin_path, "0" * 64)
    except module.AnsibleActionFail as exc:
        if "outside the public repository" not in str(exc):
            raise
    else:
        raise SystemExit("controller source inside the public repository was accepted")
    raise SystemExit(0)

case_root = os.path.join(work, f"controller-{case}-source")
shutil.copytree(source, case_root)
path = os.path.join(case_root, "requesters.allowed_signers" if case == "file" else "policy")
with open(path, "rb") as stream:
    digest = hashlib.sha256(stream.read()).hexdigest()
pinned = module.pin_source(path, digest)
try:
    if case == "file":
        os.rename(path, f"{path}.validated")
        shutil.copy2(f"{path}.validated", path)
        os.chmod(path, 0o600)
    elif case == "ancestor":
        os.rename(case_root, f"{case_root}.validated")
        os.mkdir(case_root, 0o700)
        shutil.copy2(f"{case_root}.validated/policy", os.path.join(case_root, "policy"))
        os.chmod(os.path.join(case_root, "policy"), 0o600)
    else:
        raise SystemExit(f"unknown probe case: {case}")
    try:
        pinned.recheck()
    except module.AnsibleActionFail:
        pass
    else:
        raise SystemExit(f"controller {case} replacement was accepted")
finally:
    pinned.close()
"""


@pytest.mark.parametrize(
    "probe_case",
    ("file", "ancestor", "repository"),
    ids=("file-recheck", "ancestor-recheck", "public-repository-rejection"),
)
def test_action_plugin_pinned_source_recheck(
    trust_case: TrustCase,
    probe_case: str,
) -> None:
    plugin = trust_case.repo_root / "plugins/action/platform_pki_trust_ingress.py"

    trust_case.runner.run(
        [
            sys.executable,
            "-c",
            PLUGIN_PROBE,
            plugin,
            trust_case.source,
            trust_case.work,
            probe_case,
        ]
    ).assert_success()


def role_inputs(case: TrustCase) -> tuple[Path, Path, Path]:
    for name in ("requesters.allowed_signers", "deployers.allowed_signers"):
        (case.source / name).write_text(
            f"localhost {case.key_algorithm} {case.key_payload}\n",
            encoding="ascii",
        )
        (case.source / name).chmod(0o600)
    case.digests.update(case.digest_tree(case.source))

    state = case.work / "role-state"
    helper = case.work / "bin/platform-pki-host-local-trust"
    variables_path = case.work / "role-vars.json"
    target = state / "trust/reviewed-v1"
    variables = {
        "ansible_remote_tmp": f"{state}-ansible-tmp",
        "pki_host_local_certificate_target": "localhost",
        "pki_host_local_certificate_requester_principal": "localhost",
        "pki_host_local_certificate_response_principal": "test-response",
        "pki_host_local_certificate_trust_id": "reviewed-v1",
        "pki_host_local_certificate_state_root": str(state),
        "pki_host_local_certificate_trust_helper_path": str(helper),
        "pki_host_local_certificate_trust_sources": {
            name: str(case.source / name) for name in TRUST_NAMES
        },
        "pki_host_local_certificate_trust_paths": {
            name: str(target / name) for name in TRUST_NAMES
        },
        "pki_host_local_certificate_trust_sha256": case.digests,
    }
    variables_path.write_text(
        json.dumps(variables, sort_keys=True), encoding="ascii"
    )
    return state, helper, variables_path


def run_role(
    case: TrustCase,
    variables: Path,
    *,
    check: bool = False,
):
    playbook = (
        case.repo_root
        / "tests/fixtures/pki-host-local-trust-role/integration.yml"
    )
    argv: list[str | Path] = ["ansible-playbook"]
    if check:
        argv.append("--check")
    argv.extend(["-i", "localhost,", "-e", f"@{variables}", playbook])
    return case.runner.run(argv, timeout=90)


def test_ansible_role_check_rejects_absent_prerequisites_without_mutation(
    trust_case: TrustCase,
) -> None:
    state, helper, variables = role_inputs(trust_case)
    before = tree_snapshot(state)

    run_role(trust_case, variables, check=True).assert_failure()

    assert tree_snapshot(state) == before
    assert not os.path.lexists(helper)


def test_ansible_role_apply_installs_trust(trust_case: TrustCase) -> None:
    state, helper, variables = role_inputs(trust_case)

    run_role(trust_case, variables).assert_success()

    assert helper.is_file()
    assert stat.S_IMODE(helper.stat().st_mode) == 0o755
    assert (state / "trust/reviewed-v1").is_dir()


def test_ansible_role_check_validates_installed_trust_without_replacement(
    trust_case: TrustCase,
) -> None:
    state, _helper, variables = role_inputs(trust_case)
    run_role(trust_case, variables).assert_success()
    target = state / "trust/reviewed-v1"
    target_inode = target.stat().st_ino

    run_role(trust_case, variables, check=True).assert_success()

    assert target.stat().st_ino == target_inode


def test_ansible_role_second_apply_is_exact_noop(trust_case: TrustCase) -> None:
    state, _helper, variables = role_inputs(trust_case)
    run_role(trust_case, variables).assert_success()
    target = state / "trust/reviewed-v1"
    target_inode = target.stat().st_ino

    result = run_role(trust_case, variables).assert_success()

    assert target.stat().st_ino == target_inode
    recap = next(line for line in result.stdout.splitlines() if "failed=" in line)
    assert "changed=0" in recap
    assert "failed=0" in recap
