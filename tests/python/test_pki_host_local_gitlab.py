from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from conftest import NamespaceRootRunner


REQUEST_ID = "0123456789abcdef0123456789abcdef"
ACTIVE_ID = "fedcba9876543210fedcba9876543210"
DIGEST = "a" * 64
TOKEN = "target-project-token-do-not-disclose"
RESPONSE_FILES = (
    "artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response",
    "response.sig",
)
DOWNLOAD_FILES = (*RESPONSE_FILES, "stage-manifest")


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def private_file(path: Path, data: str, mode: int = 0o600) -> Path:
    path.write_text(data, encoding="ascii")
    path.chmod(mode)
    return path


@dataclass
class Result:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class GitLabCase:
    runner: NamespaceRootRunner
    facade: Path
    root: Path
    config_path: Path
    config: dict[str, Any]
    control_path: Path
    log_path: Path
    spool: Path
    versions: Path
    pending: Path

    def write_config(self) -> None:
        private_file(
            self.config_path,
            json.dumps(self.config, sort_keys=True, separators=(",", ":")) + "\n",
        )

    def control(self, **updates: Any) -> None:
        current = json.loads(self.control_path.read_text(encoding="ascii"))
        current.update(updates)
        private_file(
            self.control_path,
            json.dumps(current, sort_keys=True, separators=(",", ":")) + "\n",
        )

    def calls(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="ascii").splitlines()]

    def run(self, command: str, *extra: str) -> Result:
        result = self.runner.run(
            (self.facade, command, "--config", self.config_path, *extra),
            timeout=20,
        )
        return Result(result.returncode, result.stdout, result.stderr)


FAKE_PROGRAM = r'''#!__PYTHON__
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

REQUEST_ID = "0123456789abcdef0123456789abcdef"
ACTIVE_ID = "fedcba9876543210fedcba9876543210"
DIGEST = "a" * 64
TOKEN = "target-project-token-do-not-disclose"
RESPONSE_FILES = (
    "artifact", "tls.crt", "ca-chain.crt", "fullchain.crt", "response",
    "response.sig",
)
CONTROL = Path(__CONTROL__)
LOG = Path(__LOG__)
VERSIONS = Path(__VERSIONS__)
PENDING = Path(__PENDING__)
CERT = Path(__CERT__)

argv = sys.argv[1:]
if argv and argv[0] == "request":
    role = "request-helper"
elif argv and argv[0] == "gitlab-package":
    role = "platform-pki"
else:
    role = "lifecycle-helper"
control = json.loads(CONTROL.read_text(encoding="ascii"))
with LOG.open("a", encoding="ascii") as stream:
    stream.write(json.dumps({"role": role, "argv": argv}, sort_keys=True) + "\n")

selected = argv[0] if argv else ""
if role == "platform-pki":
    selected = argv[1] if len(argv) > 1 else ""
if control.get("fail") in {role, selected, f"{role}:{selected}"}:
    print(f"secret={TOKEN} project=/private/project id={REQUEST_ID} digest={DIGEST}")
    print(f"failed secret={TOKEN} project=/private/project id={REQUEST_ID} digest={DIGEST}", file=sys.stderr)
    raise SystemExit(23)

def options(tokens):
    result = {}
    index = 0
    while index < len(tokens):
        if tokens[index].startswith("--") and index + 1 < len(tokens):
            result.setdefault(tokens[index], []).append(tokens[index + 1])
            index += 2
        else:
            index += 1
    return result

def mutate_result(output, mutation):
    if mutation == "stage":
        output["stage"] = "approval"
    elif mutation == "version":
        output["package_version"] = ACTIVE_ID
    elif mutation == "name":
        output["package_name"] = "pki-exchange-approval-registry-test"
    elif mutation == "destination":
        output["destination_dir"] = "/wrong/destination"
    elif mutation == "project-id":
        output["project_id"] = 43
    elif mutation == "project-path":
        output["project_path"] = "private/wrong"
    elif mutation == "package-id-invalid":
        output["package_id"] = 0
    elif mutation == "package-id-type":
        output["package_id"] = "7"
    elif mutation == "digest-missing":
        del output["file_sha256"][next(iter(output["file_sha256"]))]
    elif mutation == "digest-extra":
        output["file_sha256"]["unexpected"] = DIGEST
    elif mutation == "digest-malformed":
        first = next(iter(output["file_sha256"]))
        output["file_sha256"][first] = "not-a-sha256"
    elif mutation == "digest-wrong":
        first = next(iter(output["file_sha256"]))
        output["file_sha256"][first] = DIGEST
    elif mutation == "missing":
        del output["package_id"]
    elif mutation == "extra":
        output["unexpected"] = "value"
    return output

if role == "request-helper":
    values = options(argv[1:])
    output = {
        "status": control.get("request_status", "created"),
        "request_id": REQUEST_ID,
        "request_sha256": DIGEST,
        "csr_sha256": DIGEST,
        "csr_spki_sha256": DIGEST,
        "pending_dir": str(PENDING / REQUEST_ID),
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
elif role == "lifecycle-helper":
    command = argv[0]
    values = options(argv[1:])
    if command == "active-paths":
        print(json.dumps({
            "request_id": ACTIVE_ID, "cert_path": str(CERT),
            "key_path": str(CERT.parent / "tls.key"),
            "artifact_sha256": DIGEST, "certificate_sha256": DIGEST,
            "spki_sha256": DIGEST, "chain_sha256": DIGEST,
            "fullchain_sha256": DIGEST, "zot_config_sha256": DIGEST,
        }, sort_keys=True, separators=(",", ":")))
    elif command == "target-request-export":
        output = Path(values["--output-dir"][0])
        csr = b"FAKE CSR\n"
        fields = (
            "schema", "request_id", "nonce", "created_epoch", "expires_epoch",
            "operation", "service", "target", "requester_principal",
            "inventory_sha256", "csr_sha256", "csr_spki_sha256",
            "current_cert_sha256", "predecessor_request_id", "profile",
            "response_principal",
        )
        record = {
            "schema": "2", "request_id": REQUEST_ID, "nonce": "b" * 64,
            "created_epoch": "100", "expires_epoch": "200",
            "operation": control.get("operation", "issue"),
            "service": "registry-test", "target": "target.test",
            "requester_principal": "target.test", "inventory_sha256": DIGEST,
            "csr_sha256": hashlib.sha256(csr).hexdigest(),
            "csr_spki_sha256": DIGEST,
            "current_cert_sha256": control.get("current_digest", "none"),
            "predecessor_request_id": control.get("predecessor", "none"),
            "profile": "server-p384-sha384-v1",
            "response_principal": "response.test",
        }
        for name, data in {
            "tls.csr": csr,
            "request": "".join(f"{name}={record[name]}\n" for name in fields).encode(),
            "request.sig": b"FAKE SIGNATURE\n",
        }.items():
            (output / name).write_bytes(data)
            (output / name).chmod(0o600)
        if control.get("request_extra"):
            (output / "extra").write_text("extra\n", encoding="ascii")
            (output / "extra").chmod(0o600)
        print(json.dumps({
            "status": "collected", "request_id": REQUEST_ID,
            "request_sha256": DIGEST, "csr_sha256": DIGEST,
            "request_signature_sha256": DIGEST,
        }, sort_keys=True, separators=(",", ":")))
    elif command == "target-response-prepare":
        marker = VERSIONS / ".installed"
        if marker.exists():
            print(json.dumps({
                "status": "installed", "request_id": REQUEST_ID,
                "ingress_dir": "none",
            }, sort_keys=True, separators=(",", ":")))
        else:
            VERSIONS.mkdir(mode=0o700, exist_ok=True)
            VERSIONS.chmod(0o700)
            ingress = VERSIONS / f".ingress-{REQUEST_ID}"
            status = "existing" if ingress.exists() else "prepared"
            ingress.mkdir(mode=0o700, exist_ok=True)
            ingress.chmod(0o700)
            metadata = ingress.stat()
            print(json.dumps({
                "status": status, "request_id": REQUEST_ID,
                "ingress_dir": str(ingress), "ingress_device": metadata.st_dev,
                "ingress_inode": metadata.st_ino,
            }, sort_keys=True, separators=(",", ":")))
    elif command == "target-response-install":
        ingress = VERSIONS / f".ingress-{REQUEST_ID}"
        if set(item.name for item in ingress.iterdir()) != set(RESPONSE_FILES):
            raise SystemExit(31)
        if control.get("fail_install"):
            print(f"install failure {TOKEN} {REQUEST_ID} {DIGEST}", file=sys.stderr)
            raise SystemExit(32)
        for item in ingress.iterdir():
            item.unlink()
        ingress.rmdir()
        (VERSIONS / ".installed").write_text("installed\n", encoding="ascii")
        (VERSIONS / ".installed").chmod(0o600)
        print(json.dumps({
            "status": "installed", "request_id": REQUEST_ID,
            "version_path": str(VERSIONS / REQUEST_ID),
            "artifact_sha256": DIGEST, "certificate_sha256": DIGEST,
            "certificate_spki_sha256": DIGEST,
        }, sort_keys=True, separators=(",", ":")))
    else:
        raise SystemExit(33)
elif role == "platform-pki":
    command = argv[1]
    values = options(argv[2:])
    if command == "publish":
        source = Path(values["--source-dir"][0])
        payloads = {name: (source / name).read_bytes() for name in ("tls.csr", "request", "request.sig")}
        manifest = [
            "schema=2", "kind=pki-exchange-stage", "stage=request",
            "service=registry-test", f"request_id={REQUEST_ID}",
            f"package_version={REQUEST_ID}", "payload_count=3",
            *(f"payload={name} sha256={hashlib.sha256(payloads[name]).hexdigest()}" for name in ("tls.csr", "request", "request.sig")),
        ]
        package_files = {
            **payloads,
            "stage-manifest": ("\n".join(manifest) + "\n").encode(),
        }
        output = {
            "status": control.get("publish_status", "published"),
            "stage": "request", "project_id": 42,
            "project_path": "private/exchange", "package_id": 7,
            "package_name": "pki-exchange-request-registry-test",
            "package_version": REQUEST_ID,
            "file_sha256": {
                name: hashlib.sha256(data).hexdigest()
                for name, data in package_files.items()
            },
        }
        print(json.dumps(
            mutate_result(output, control.get("publish_result")),
            sort_keys=True, separators=(",", ":"),
        ))
    elif command == "download":
        destination = Path(values["--destination-dir"][0])
        existing = destination.exists()
        destination.mkdir(mode=0o700, exist_ok=True)
        destination.chmod(0o700)
        payloads = {name: f"payload:{name}\n".encode() for name in RESPONSE_FILES}
        for name, data in payloads.items():
            path = destination / name
            if not path.exists():
                path.write_bytes(data)
                path.chmod(0o600)
        manifest = [
            "schema=2", "kind=pki-exchange-stage", "stage=response",
            "service=registry-test", f"request_id={REQUEST_ID}",
            f"package_version={REQUEST_ID}", "payload_count=6",
            *(f"payload={name} sha256={hashlib.sha256(payloads[name]).hexdigest()}" for name in RESPONSE_FILES),
        ]
        manifest_path = destination / "stage-manifest"
        if not manifest_path.exists():
            manifest_path.write_text("\n".join(manifest) + "\n", encoding="ascii")
            manifest_path.chmod(0o600)
        if control.get("malformed_manifest"):
            manifest_path.write_text("schema=broken\n", encoding="ascii")
            manifest_path.chmod(0o600)
        if control.get("download_extra"):
            (destination / "extra").write_text("extra\n", encoding="ascii")
            (destination / "extra").chmod(0o600)
        output = {
            "status": "existing" if existing else "downloaded",
            "stage": "response", "project_id": 42,
            "project_path": "private/exchange", "package_id": 8,
            "package_name": "pki-exchange-response-registry-test",
            "package_version": REQUEST_ID, "destination_dir": str(destination),
            "file_sha256": {
                name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                for name in (*RESPONSE_FILES, "stage-manifest")
            },
            "gitlab_authority_claimed": False,
        }
        print(json.dumps(
            mutate_result(output, control.get("download_result")),
            sort_keys=True, separators=(",", ":"),
        ))
    else:
        raise SystemExit(34)
else:
    raise SystemExit(35)
'''


@pytest.fixture
def gitlab_case(
    repo_root: Path, tmp_path: Path, namespace_root_runner: NamespaceRootRunner,
) -> GitLabCase:
    root = private_dir(tmp_path / "gitlab-facade")
    state = private_dir(root / "state")
    trust = private_dir(private_dir(state / "trust") / "reviewed-v2")
    for name in (
        "policy", "requesters.allowed_signers", "approvers.allowed_signers",
        "responses.allowed_signers",
    ):
        private_file(trust / name, f"{name}\n")
    tls = private_dir(root / "tls")
    pending = tls / "tls-pending"
    versions = tls / "tls-versions"
    spool = private_dir(root / "spool")
    control_path = private_file(root / "control.json", "{}\n")
    log_path = root / "calls.jsonl"
    cert = private_file(root / "current.crt", "CERTIFICATE\n", 0o644)
    replacements = {
        "__PYTHON__": sys.executable,
        "__CONTROL__": repr(str(control_path)),
        "__LOG__": repr(str(log_path)),
        "__VERSIONS__": repr(str(versions)),
        "__PENDING__": repr(str(pending)),
        "__CERT__": repr(str(cert)),
    }
    program = FAKE_PROGRAM
    for old, new in replacements.items():
        program = program.replace(old, new)
    executables: dict[str, Path] = {}
    for name in ("request-helper", "lifecycle-helper", "platform-pki"):
        executables[name] = private_file(root / name, program, 0o755)
    project = private_file(
        root / "project-record",
        "schema=1\n"
        "kind=pki-exchange-project\n"
        "origin=https://gitlab.test\n"
        "project_id=42\n"
        "project_path=private/exchange\n"
        "gitlab_version=18.11.3-ce.0\n",
    )
    token = private_file(root / "token", TOKEN + "\n")
    ca = private_file(root / "ca.pem", "CA\n", 0o644)
    signing = private_file(root / "signing-key", "KEY\n")
    zot = private_file(root / "zot.json", "{}\n", 0o644)
    config = {
        "schema": 2,
        "kind": "platform-config-target-local-gitlab",
        "service": "registry-test",
        "target": "target.test",
        "operation": "issue",
        "profile": "server-p384-sha384-v1",
        "inventory_sha256": DIGEST,
        "current_cert_sha256": "none",
        "current_cert_path": "none",
        "common_name": "registry.test",
        "dns_sans": ["registry.test"],
        "ip_sans": ["192.0.2.1"],
        "response_principal": "response.test",
        "request_ttl_seconds": 3600,
        "request_signing_key": str(signing),
        "trust_id": "reviewed-v2",
        "state_root": str(state),
        "pending_root": str(pending),
        "versions_root": str(versions),
        "zot_config": str(zot),
        "minimum_remaining_lifetime_seconds": 60,
        "project_record": str(project),
        "token_file": str(token),
        "ca_file": str(ca),
        "spool_root": str(spool),
        "request_helper": str(executables["request-helper"]),
        "lifecycle_helper": str(executables["lifecycle-helper"]),
        "platform_pki": str(executables["platform-pki"]),
        "timeout": 5,
        "processing_attempts": 2,
        "processing_interval": 0,
    }
    config_path = root / "config.json"
    case = GitLabCase(
        runner=namespace_root_runner,
        facade=repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-gitlab",
        root=root, config_path=config_path, config=config,
        control_path=control_path, log_path=log_path, spool=spool,
        versions=versions, pending=pending,
    )
    case.write_config()
    return case


def assert_bounded(result: Result, command: str, status: str) -> None:
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "schema": 2,
        "kind": "platform-config-target-local-gitlab-status",
        "command": command,
        "status": status,
    }
    for secret in (TOKEN, REQUEST_ID, ACTIVE_ID, DIGEST, "/private/project"):
        assert secret not in result.stdout
        assert secret not in result.stderr


def assert_redacted_failure(result: Result) -> None:
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "platform-pki-host-local-gitlab: operation failed\n"
    for secret in (TOKEN, REQUEST_ID, ACTIVE_ID, DIGEST, "/private/project"):
        assert secret not in result.stdout + result.stderr


def call(case: GitLabCase, role: str, command: str) -> dict[str, Any]:
    return next(
        item for item in case.calls()
        if item["role"] == role and item["argv"] and item["argv"][0 if role != "platform-pki" else 1] == command
    )


def option(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


def test_gitlab_process_timeout_covers_maximum_retry_schedule(
    repo_root: Path,
) -> None:
    facade = (
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-gitlab"
    )
    namespace = runpy.run_path(str(facade))

    timeout = namespace["gitlab_process_timeout"]({
        "timeout": 120,
        "processing_attempts": 20,
        "processing_interval": 60,
    })

    assert timeout == 22590


def test_request_publish_uses_schema_2_transport_and_cleans_export(
    gitlab_case: GitLabCase,
) -> None:
    result = gitlab_case.run("request-publish")

    assert_bounded(result, "request-publish", "published")
    request_call = call(gitlab_case, "request-helper", "request")
    assert option(request_call["argv"], "--request-namespace") == "platform-pki-csr-request-v2"
    assert option(request_call["argv"], "--predecessor-request-id") == "none"
    assert option(request_call["argv"], "--current-cert-sha256") == "none"
    assert "--current-cert-path" not in request_call["argv"]
    publish = call(gitlab_case, "platform-pki", "publish")
    assert option(publish["argv"], "--token-type") == "private"
    assert option(publish["argv"], "--token-file") == gitlab_case.config["token_file"]
    assert not {"--inventory-record", "--trust-dir", "--transport-host-key-sha256"} & set(publish["argv"])
    assert set(item.name for item in gitlab_case.spool.iterdir()) == {"lock"}


def test_request_publish_is_idempotent(gitlab_case: GitLabCase) -> None:
    first = gitlab_case.run("request-publish")
    gitlab_case.control(request_status="existing", publish_status="existing")
    second = gitlab_case.run("request-publish")

    assert_bounded(first, "request-publish", "published")
    assert_bounded(second, "request-publish", "existing")
    assert len([item for item in gitlab_case.calls() if item["role"] == "platform-pki"]) == 2
    assert set(item.name for item in gitlab_case.spool.iterdir()) == {"lock"}


@pytest.mark.parametrize(
    "mutation",
    (
        "stage", "version", "name", "project-id", "project-path",
        "package-id-invalid", "package-id-type", "digest-missing",
        "digest-extra", "digest-malformed", "digest-wrong", "missing",
        "extra",
    ),
)
def test_request_publish_rejects_unbound_or_inexact_client_result(
    gitlab_case: GitLabCase, mutation: str,
) -> None:
    gitlab_case.control(publish_result=mutation)

    result = gitlab_case.run("request-publish")

    assert_redacted_failure(result)
    assert set(item.name for item in gitlab_case.spool.iterdir()) == {"lock"}


def test_request_export_with_extra_file_fails_and_is_cleaned(
    gitlab_case: GitLabCase,
) -> None:
    gitlab_case.control(request_extra=True)

    result = gitlab_case.run("request-publish")

    assert_redacted_failure(result)
    assert set(item.name for item in gitlab_case.spool.iterdir()) == {"lock"}


def test_renew_derives_authenticated_predecessor_and_leaf(
    gitlab_case: GitLabCase,
) -> None:
    gitlab_case.config.update(
        operation="renew", current_cert_sha256="derived", current_cert_path="derived"
    )
    gitlab_case.write_config()
    gitlab_case.control(
        operation="renew", current_digest=DIGEST, predecessor=ACTIVE_ID
    )

    result = gitlab_case.run("request-publish")

    assert_bounded(result, "request-publish", "published")
    active = call(gitlab_case, "lifecycle-helper", "active-paths")
    request_call = call(gitlab_case, "request-helper", "request")
    assert active
    assert option(request_call["argv"], "--predecessor-request-id") == ACTIVE_ID
    assert option(request_call["argv"], "--current-cert-sha256") == DIGEST
    assert option(request_call["argv"], "--current-cert-path") == str(gitlab_case.root / "current.crt")


def test_response_download_copies_only_payloads_installs_and_cleans(
    gitlab_case: GitLabCase,
) -> None:
    result = gitlab_case.run("response-download")

    assert_bounded(result, "response-download", "installed")
    download = call(gitlab_case, "platform-pki", "download")
    assert option(download["argv"], "--token-type") == "private"
    assert option(download["argv"], "--request-id") == REQUEST_ID
    assert not (gitlab_case.spool / "response-download").exists()
    assert not (gitlab_case.versions / f".ingress-{REQUEST_ID}").exists()
    assert (gitlab_case.versions / ".installed").is_file()


def test_response_download_resumes_matching_ingress(gitlab_case: GitLabCase) -> None:
    ingress = private_dir(gitlab_case.versions / f".ingress-{REQUEST_ID}")
    for name in RESPONSE_FILES[:2]:
        private_file(ingress / name, f"payload:{name}\n")

    result = gitlab_case.run("response-download")

    assert_bounded(result, "response-download", "installed")
    assert not (gitlab_case.spool / "response-download").exists()


def test_response_download_is_idempotent_without_second_network_call(
    gitlab_case: GitLabCase,
) -> None:
    first = gitlab_case.run("response-download")
    second = gitlab_case.run("response-download")

    assert_bounded(first, "response-download", "installed")
    assert_bounded(second, "response-download", "existing")
    downloads = [
        item for item in gitlab_case.calls()
        if item["role"] == "platform-pki" and item["argv"][1] == "download"
    ]
    assert len(downloads) == 1


@pytest.mark.parametrize(
    "mutation",
    (
        "stage", "version", "name", "destination", "project-id",
        "project-path", "package-id-invalid", "package-id-type",
        "digest-missing", "digest-extra", "digest-malformed",
        "digest-wrong", "missing", "extra",
    ),
)
def test_response_download_rejects_unbound_or_inexact_client_result(
    gitlab_case: GitLabCase, mutation: str,
) -> None:
    gitlab_case.control(download_result=mutation)

    result = gitlab_case.run("response-download")

    assert_redacted_failure(result)
    assert (gitlab_case.spool / "response-download").is_dir()
    assert not any(
        item["role"] == "lifecycle-helper"
        and item["argv"][0] == "target-response-install"
        for item in gitlab_case.calls()
    )


def test_failed_install_preserves_transport_and_ingress_then_resumes(
    gitlab_case: GitLabCase,
) -> None:
    gitlab_case.control(fail_install=True)
    failed = gitlab_case.run("response-download")

    assert_redacted_failure(failed)
    download = gitlab_case.spool / "response-download"
    ingress = gitlab_case.versions / f".ingress-{REQUEST_ID}"
    assert set(item.name for item in download.iterdir()) == set(DOWNLOAD_FILES)
    assert set(item.name for item in ingress.iterdir()) == set(RESPONSE_FILES)

    gitlab_case.control(fail_install=False)
    resumed = gitlab_case.run("response-download")
    assert_bounded(resumed, "response-download", "installed")
    assert not download.exists()


@pytest.mark.parametrize("failure", ["request-helper", "platform-pki:publish"])
def test_request_subprocess_failures_are_redacted_and_export_is_cleaned(
    gitlab_case: GitLabCase, failure: str,
) -> None:
    gitlab_case.control(fail=failure)

    result = gitlab_case.run("request-publish")

    assert_redacted_failure(result)
    assert set(item.name for item in gitlab_case.spool.iterdir()) == {"lock"}


@pytest.mark.parametrize("failure", ["lifecycle-helper:target-response-prepare", "platform-pki:download"])
def test_response_subprocess_failures_are_redacted(
    gitlab_case: GitLabCase, failure: str,
) -> None:
    gitlab_case.control(fail=failure)

    result = gitlab_case.run("response-download")

    assert_redacted_failure(result)


@pytest.mark.parametrize("mutation", ["missing", "extra", "schema", "path", "token-mode"])
def test_malformed_config_and_pins_fail_closed(
    gitlab_case: GitLabCase, mutation: str,
) -> None:
    if mutation == "missing":
        del gitlab_case.config["timeout"]
    elif mutation == "extra":
        gitlab_case.config["project_id"] = 42
    elif mutation == "schema":
        gitlab_case.config["schema"] = 1
    elif mutation == "path":
        gitlab_case.config["spool_root"] += "/../spool"
    elif mutation == "token-mode":
        Path(gitlab_case.config["token_file"]).chmod(0o644)
    gitlab_case.write_config()

    assert_redacted_failure(gitlab_case.run("request-publish"))


@pytest.mark.parametrize("mutation", ["extra", "manifest"])
def test_malformed_download_is_preserved_and_never_installed(
    gitlab_case: GitLabCase, mutation: str,
) -> None:
    gitlab_case.control(
        download_extra=mutation == "extra", malformed_manifest=mutation == "manifest"
    )

    result = gitlab_case.run("response-download")

    assert_redacted_failure(result)
    assert (gitlab_case.spool / "response-download").is_dir()
    assert not any(
        item["role"] == "lifecycle-helper"
        and item["argv"][0] == "target-response-install"
        for item in gitlab_case.calls()
    )


def test_conflicting_ingress_is_not_clobbered(gitlab_case: GitLabCase) -> None:
    ingress = private_dir(gitlab_case.versions / f".ingress-{REQUEST_ID}")
    conflict = private_file(ingress / "artifact", "conflicting bytes\n")

    result = gitlab_case.run("response-download")

    assert_redacted_failure(result)
    assert conflict.read_text(encoding="ascii") == "conflicting bytes\n"
    assert (gitlab_case.spool / "response-download").is_dir()


@pytest.mark.parametrize("target", ["config", "token", "spool"])
def test_symlinked_protected_inputs_fail_closed(
    gitlab_case: GitLabCase, target: str,
) -> None:
    if target == "config":
        actual = gitlab_case.root / "actual-config"
        gitlab_case.config_path.rename(actual)
        gitlab_case.config_path.symlink_to(actual)
    elif target == "token":
        path = Path(gitlab_case.config["token_file"])
        actual = gitlab_case.root / "actual-token"
        path.rename(actual)
        path.symlink_to(actual)
    else:
        actual = gitlab_case.root / "actual-spool"
        gitlab_case.spool.rename(actual)
        gitlab_case.spool.symlink_to(actual, target_is_directory=True)

    assert_redacted_failure(gitlab_case.run("request-publish"))


@pytest.mark.parametrize("target", ["config", "token", "platform"])
def test_hardlinked_protected_files_fail_closed(
    gitlab_case: GitLabCase, target: str,
) -> None:
    path = {
        "config": gitlab_case.config_path,
        "token": Path(gitlab_case.config["token_file"]),
        "platform": Path(gitlab_case.config["platform_pki"]),
    }[target]
    os.link(path, gitlab_case.root / f"{target}-hardlink")

    assert_redacted_failure(gitlab_case.run("request-publish"))


def test_extra_operator_coordinates_are_rejected_without_disclosure(
    gitlab_case: GitLabCase,
) -> None:
    result = gitlab_case.run("request-publish", "--request-id", REQUEST_ID)

    assert_redacted_failure(result)
    assert gitlab_case.calls() == []


def test_existing_installed_response_cleans_only_valid_retained_download(
    gitlab_case: GitLabCase,
) -> None:
    first = gitlab_case.run("response-download")
    assert_bounded(first, "response-download", "installed")
    gitlab_case.control(fail_install=True)
    # Recreate a valid interrupted transport directory without invoking install.
    marker = gitlab_case.versions / ".installed"
    marker.unlink()
    failed = gitlab_case.run("response-download")
    assert_redacted_failure(failed)
    ingress = gitlab_case.versions / f".ingress-{REQUEST_ID}"
    for item in ingress.iterdir():
        item.unlink()
    ingress.rmdir()
    marker.write_text("installed\n", encoding="ascii")
    marker.chmod(0o600)

    resumed = gitlab_case.run("response-download")

    assert_bounded(resumed, "response-download", "existing")
    assert not (gitlab_case.spool / "response-download").exists()


def test_source_files_are_root_owned_single_link_regular_files(
    gitlab_case: GitLabCase,
) -> None:
    for field in (
        "request_helper", "lifecycle_helper", "platform_pki", "project_record",
        "token_file", "ca_file", "request_signing_key",
    ):
        metadata = Path(gitlab_case.config[field]).stat()
        assert metadata.st_uid == os.geteuid()
        assert metadata.st_nlink == 1
        assert stat.S_ISREG(metadata.st_mode)
