from __future__ import annotations

import base64
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
import yaml


pytestmark = pytest.mark.pki
REQUEST_ID = "0123456789abcdef0123456789abcdef"
ARTIFACT_SHA = "a" * 64
DEPLOYMENT_SHA = "b" * 64


def load_script(path: Path, name: str) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


@pytest.fixture
def facade(repo_root: Path) -> ModuleType:
    return load_script(
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-exchange",
        "platform_pki_host_local_exchange",
    )


@pytest.fixture
def controller(repo_root: Path) -> ModuleType:
    return load_script(
        repo_root / "scripts/platform-pki-direct-exchange",
        "platform_pki_direct_exchange",
    )


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def private_file(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def record(**values: str) -> bytes:
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")


def target_config(module: ModuleType, root: Path) -> Any:
    setattr(module, "ROOT_UID", os.geteuid())
    setattr(module, "ROOT_GID", os.getegid())
    state = private_dir(root / "state")
    private_file(state / "lock", b"lock\n")
    return module.Config(
        lifecycle_helper="/usr/local/libexec/platform-pki-host-local-lifecycle",
        pending_root=os.fspath(private_dir(root / "tls-pending")),
        service="registry-test",
        spool_root=os.fspath(private_dir(root / "spool")),
        state_root=os.fspath(state),
        target="target.test",
        trust_id="reviewed-v1",
        versions_root=os.fspath(private_dir(root / "tls-versions")),
        zot_config="/etc/zot/config.json",
    )


def response_files(module: ModuleType) -> tuple[dict[str, bytes], str]:
    artifact = record(
        schema="1", service="registry-test", target="target.test",
        request_id=REQUEST_ID,
    )
    response = record(
        schema="1", request_id=REQUEST_ID, service="registry-test",
        target="target.test",
    )
    files = {
        "artifact": artifact,
        "tls.crt": b"certificate\n",
        "ca-chain.crt": b"chain\n",
        "fullchain.crt": b"fullchain\n",
        "response": response,
        "response.sig": b"signature\n",
    }
    assert tuple(files) == module.RESPONSE_NAMES
    return files, module.sha256(artifact)


def outcome_files(module: ModuleType) -> tuple[dict[str, bytes], dict[str, str]]:
    deployment = record(
        schema="1", service="registry-test", target="target.test",
        request_id=REQUEST_ID, artifact_manifest_sha256=ARTIFACT_SHA,
    )
    deployment_sha = module.sha256(deployment)
    outcome = record(
        schema="1", service="registry-test", target="target.test",
        request_id=REQUEST_ID, artifact_manifest_sha256=ARTIFACT_SHA,
        deployment_sha256=deployment_sha,
    )
    files = {
        "outcome": outcome,
        "outcome.sig": b"outcome signature\n",
        "deployment": deployment,
        "deployment.sig": b"deployment signature\n",
        "deployers.allowed_signers": b"target.test ssh-ed25519 AAAA\n",
        "decision": record(
            schema="1", service="registry-test", target="target.test",
            request_id=REQUEST_ID,
        ),
    }
    assert tuple(files) == module.OUTCOME_NAMES
    coordinates = {
        "request_id": REQUEST_ID,
        "artifact_sha256": ARTIFACT_SHA,
        "deployment_sha256": deployment_sha,
        "outcome_sha256": module.sha256(outcome),
    }
    return files, coordinates


def test_facade_command_grammar_is_exact(facade: ModuleType) -> None:
    parser = facade.build_parser()
    assert parser.parse_args(["export-request", REQUEST_ID]).command == "export-request"
    assert parser.parse_args(
        ["export-evidence", REQUEST_ID, ARTIFACT_SHA, DEPLOYMENT_SHA]
    ).command == "export-evidence"
    assert parser.parse_args(
        ["stage-response", REQUEST_ID, ARTIFACT_SHA]
    ).command == "stage-response"
    full = [REQUEST_ID, ARTIFACT_SHA, DEPLOYMENT_SHA, "c" * 64]
    assert parser.parse_args(["stage-outcome", *full]).command == "stage-outcome"
    assert parser.parse_args(["cleanup-outcome", *full]).command == "cleanup-outcome"
    with pytest.raises(SystemExit):
        parser.parse_args(["get", "/etc/shadow"])
    with pytest.raises(SystemExit):
        parser.parse_args(["export-request", REQUEST_ID, "--config", "/tmp/config"])


def test_controller_command_grammar_is_exact(controller: ModuleType) -> None:
    parser = controller.build_parser()
    endpoint = "/protected/endpoint.json"
    assert parser.parse_args(
        ["request-pull", endpoint, REQUEST_ID, "/protected/request"]
    ).command == "request-pull"
    assert parser.parse_args(
        [
            "evidence-pull", endpoint, REQUEST_ID, ARTIFACT_SHA,
            DEPLOYMENT_SHA, "/protected/evidence",
        ]
    ).command == "evidence-pull"
    assert parser.parse_args(
        ["response-push", endpoint, REQUEST_ID, ARTIFACT_SHA, "/protected/response"]
    ).command == "response-push"
    assert parser.parse_args(
        [
            "outcome-push", endpoint, REQUEST_ID, ARTIFACT_SHA,
            DEPLOYMENT_SHA, "c" * 64, "/protected/outcome",
        ]
    ).command == "outcome-push"
    with pytest.raises(SystemExit):
        parser.parse_args(["cleanup-outcome", endpoint, REQUEST_ID])


def test_allowlists_are_exact_and_exclude_private_key_name(
    facade: ModuleType, controller: ModuleType, repo_root: Path
) -> None:
    expected = {
        "request": 3,
        "response": 6,
        "evidence": 5,
        "outcome": 6,
    }
    for module in (facade, controller):
        assert {kind: len(names) for kind, names in module.NAMES_BY_KIND.items()} == expected
        assert all("tls" + ".key" not in names for names in module.NAMES_BY_KIND.values())
    for path in (
        repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-exchange",
        repo_root / "scripts/platform-pki-direct-exchange",
    ):
        assert "tls" + ".key" not in path.read_text(encoding="utf-8")


def test_canonical_frame_rejects_trailing_and_unsafe_metadata(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, artifact_sha = response_files(facade)
    values = {"request_id": REQUEST_ID, "artifact_sha256": artifact_sha}
    encoded = facade.encode_frame("response", files, values, config)
    assert facade.decode_frame(encoded, "response", values, config) == files
    with pytest.raises(facade.ExchangeError, match="trailing"):
        facade.decode_frame(encoded + b"x", "response", values, config)
    header, payload = encoded.split(b"\n", 1)
    value = json.loads(header)
    value["files"][0]["size"] = facade.MAX_SIZES["artifact"] + 1
    unsafe = facade.canonical_json(value) + b"\n" + payload
    with pytest.raises(facade.ExchangeError, match="unsafe"):
        facade.decode_frame(unsafe, "response", values, config)


def test_response_stage_is_idempotent_and_conflict_safe(
    facade: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = target_config(facade, tmp_path)
    files, artifact_sha = response_files(facade)
    values = {"request_id": REQUEST_ID, "artifact_sha256": artifact_sha}
    frame = facade.encode_frame("response", files, values, config)

    def prepare(_config: object, command: str, arguments: list[str]) -> dict[str, object]:
        assert command == "response-prepare"
        assert arguments == ["--request-id", REQUEST_ID]
        ingress = Path(config.versions_root) / f".ingress-{REQUEST_ID}"
        if not ingress.exists():
            private_dir(ingress)
            status_value = "prepared"
        else:
            status_value = "existing"
        return {"status": status_value, "request_id": REQUEST_ID}

    monkeypatch.setattr(facade, "run_lifecycle", prepare)
    assert facade.stage_response(config, REQUEST_ID, artifact_sha, frame)["status"] == "staged"
    assert facade.stage_response(config, REQUEST_ID, artifact_sha, frame)["status"] == "existing"
    ingress = Path(config.versions_root) / f".ingress-{REQUEST_ID}"
    (ingress / "response.sig").write_bytes(b"conflict\n")
    (ingress / "response.sig").chmod(0o600)
    before = {path.name: path.read_bytes() for path in ingress.iterdir()}
    with pytest.raises(facade.ExchangeError, match="conflicts"):
        facade.stage_response(config, REQUEST_ID, artifact_sha, frame)
    assert {path.name: path.read_bytes() for path in ingress.iterdir()} == before


def test_response_stage_rejects_unsafe_existing_metadata(
    facade: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = target_config(facade, tmp_path)
    files, artifact_sha = response_files(facade)
    values = {"request_id": REQUEST_ID, "artifact_sha256": artifact_sha}
    frame = facade.encode_frame("response", files, values, config)
    ingress = private_dir(Path(config.versions_root) / f".ingress-{REQUEST_ID}")
    private_file(ingress / "artifact", files["artifact"]).chmod(0o644)
    monkeypatch.setattr(
        facade,
        "run_lifecycle",
        lambda *_args: {"status": "existing", "request_id": REQUEST_ID},
    )
    with pytest.raises(facade.ExchangeError, match="unsafe metadata"):
        facade.stage_response(config, REQUEST_ID, artifact_sha, frame)


def test_outcome_stage_is_logical_idempotent_and_no_clobber(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, values = outcome_files(facade)
    frame = facade.encode_frame("outcome", files, values, config)
    first = facade.publish_outcome(config, values, frame)
    assert first["status"] == "staged"
    assert first["stage_id"] == facade.outcome_stage_id(**values)
    assert config.spool_root not in first["stage_id"]
    assert facade.publish_outcome(config, values, frame)["status"] == "existing"
    stage = Path(config.spool_root) / "outcomes" / REQUEST_ID / values["outcome_sha256"]
    (stage / "outcome.sig").write_bytes(b"conflict\n")
    (stage / "outcome.sig").chmod(0o600)
    with pytest.raises(facade.ExchangeError, match="conflicts"):
        facade.publish_outcome(config, values, frame)


def test_outcome_cleanup_requires_accepted_matching_history(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, values = outcome_files(facade)
    frame = facade.encode_frame("outcome", files, values, config)
    facade.publish_outcome(config, values, frame)
    history = private_dir(
        Path(config.state_root) / "outcomes" / REQUEST_ID / values["outcome_sha256"]
    )
    for name, data in files.items():
        private_file(history / name, data)
    pointer = record(
        schema="1",
        kind="host-local-accepted-signer-outcome",
        service=config.service,
        target=config.target,
        request_id=REQUEST_ID,
        artifact_manifest_sha256=values["artifact_sha256"],
        deployment_sha256=values["deployment_sha256"],
        outcome_sha256=values["outcome_sha256"],
        decision_sha256=facade.sha256(files["decision"]),
        action="finalize",
        state="finalized",
        resulting_active_request_id=REQUEST_ID,
    )
    private_file(Path(config.state_root) / "accepted-outcome", pointer)
    assert facade.cleanup_outcome(config, values)["status"] == "cleaned"
    assert facade.cleanup_outcome(config, values)["status"] == "absent"
    assert not (
        Path(config.spool_root) / "outcomes" / REQUEST_ID / values["outcome_sha256"]
    ).exists()


def test_export_revalidates_then_removes_exact_stage(
    facade: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = target_config(facade, tmp_path)
    files = {
        "tls.csr": b"csr\n",
        "request": b"request\n",
        "request.sig": b"signature\n",
    }
    calls: list[str] = []

    def lifecycle(_config: object, command: str, arguments: list[str]) -> dict[str, object]:
        assert command == "collection-prepare"
        output = Path(arguments[arguments.index("--output-dir") + 1])
        if not calls:
            for name, data in files.items():
                private_file(output / name, data)
            status_value = "collected"
        else:
            status_value = "existing"
        calls.append(status_value)
        return {
            "status": status_value,
            "request_id": REQUEST_ID,
            "request_sha256": facade.sha256(files["request"]),
            "csr_sha256": facade.sha256(files["tls.csr"]),
            "request_signature_sha256": facade.sha256(files["request.sig"]),
        }

    output = io.BytesIO()
    monkeypatch.setattr(facade, "run_lifecycle", lifecycle)
    monkeypatch.setattr(facade.sys, "stdout", SimpleNamespace(buffer=output))
    values = {"request_id": REQUEST_ID}
    facade.export_files(
        config, "request", values, "collection-prepare",
        ["--trust-id", config.trust_id, "--request-id", REQUEST_ID],
    )
    assert calls == ["collected", "existing"]
    assert facade.decode_frame(output.getvalue(), "request", values, config) == files
    assert list(Path(config.spool_root).iterdir()) == []


def endpoint_fixture(controller: ModuleType, root: Path, *, expected: str | None = None) -> tuple[Path, Any]:
    identity = private_file(root / "identity", b"private identity\n")
    algorithm = b"ssh-ed25519"
    public = b"k" * 32
    blob = len(algorithm).to_bytes(4, "big") + algorithm + len(public).to_bytes(4, "big") + public
    encoded = base64.b64encode(blob).decode("ascii")
    digest = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    known_hosts = private_file(
        root / "known_hosts", f"target.test ssh-ed25519 {encoded}\n".encode("ascii")
    )
    value = {
        "expected_host_key_sha256": expected or digest,
        "host": "target.test",
        "identity_path": os.fspath(identity),
        "known_hosts_path": os.fspath(known_hosts),
        "port": 22,
        "remote_helper_path": "/usr/local/libexec/platform-pki-host-local-exchange",
        "schema": 1,
        "user": "admin",
    }
    endpoint_path = private_file(
        root / "endpoint.json", controller.canonical_json(value) + b"\n"
    )
    return endpoint_path, controller.load_endpoint(os.fspath(endpoint_path))


def test_pinned_ssh_argv_and_no_shell_use(
    controller: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint_path, endpoint = endpoint_fixture(controller, tmp_path)
    known_host_blob = base64.b64decode(endpoint.known_hosts_data.decode("ascii").split()[2])
    assert endpoint.transport_host_key_sha256 == hashlib.sha256(
        known_host_blob
    ).hexdigest()
    observed: dict[str, object] = {}

    def fake_run(
        argv: list[str], input_data: bytes | None
    ) -> tuple[int, bytes, bytes]:
        observed["argv"] = argv
        observed["input_data"] = input_data
        identity_path = Path(argv[argv.index("-i") + 1])
        known_hosts_option = next(
            value for value in argv if value.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = Path(known_hosts_option.split("=", 1)[1])
        observed["identity_path"] = identity_path
        observed["known_hosts_path"] = known_hosts_path
        assert identity_path.read_bytes() == endpoint.identity_data
        assert known_hosts_path.read_bytes() == endpoint.known_hosts_data
        return 0, b"frame", b""

    monkeypatch.setattr(controller, "run_bounded", fake_run)
    assert controller.invoke(endpoint, "export-request", [REQUEST_ID], None) == b"frame"
    argv = observed["argv"]
    assert isinstance(argv, list)
    required = {
        "BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null", "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no", "ForwardAgent=no", "ForwardX11=no",
        "ClearAllForwardings=yes", "PermitLocalCommand=no",
        "ProxyCommand=none", "ProxyJump=none", "CanonicalizeHostname=no",
    }
    assert required.issubset(set(argv))
    assert endpoint.identity_path not in argv
    assert f"UserKnownHostsFile={endpoint.known_hosts_path}" not in argv
    proc_prefix = f"/proc/{os.getpid()}/fd/"
    assert os.fspath(cast(Path, observed["identity_path"])).startswith(proc_prefix)
    assert os.fspath(cast(Path, observed["known_hosts_path"])).startswith(proc_prefix)
    assert argv[-6:] == [
        "sudo", "-n", "--", endpoint.remote_helper_path, "export-request", REQUEST_ID
    ]
    assert observed["input_data"] is None
    assert os.fspath(endpoint_path) not in argv
    assert not cast(Path, observed["identity_path"]).exists()
    assert not cast(Path, observed["known_hosts_path"]).exists()


def test_controller_rejects_openssh_path_tokens(
    controller: ModuleType, tmp_path: Path
) -> None:
    endpoint_path, _endpoint = endpoint_fixture(controller, tmp_path)
    value = json.loads(endpoint_path.read_bytes())
    value["known_hosts_path"] = "/outside-git/ssh/%h.known_hosts"
    private_file(endpoint_path, controller.canonical_json(value) + b"\n")

    with pytest.raises(controller.DirectExchangeError, match="canonical non-root path"):
        controller.load_endpoint(os.fspath(endpoint_path))


def test_ssh_uses_validated_bytes_after_source_replacement(
    controller: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _endpoint_path, endpoint = endpoint_fixture(controller, tmp_path)
    private_file(Path(endpoint.identity_path), b"replacement identity\n")
    private_file(Path(endpoint.known_hosts_path), b"replacement known hosts\n")

    def fake_run(
        argv: list[str], _input_data: bytes | None
    ) -> tuple[int, bytes, bytes]:
        identity_path = Path(argv[argv.index("-i") + 1])
        known_hosts_option = next(
            value for value in argv if value.startswith("UserKnownHostsFile=")
        )
        known_hosts_path = Path(known_hosts_option.split("=", 1)[1])
        assert identity_path.read_bytes() == endpoint.identity_data
        assert known_hosts_path.read_bytes() == endpoint.known_hosts_data
        return 0, b"frame", b""

    monkeypatch.setattr(controller, "run_bounded", fake_run)
    assert controller.invoke(endpoint, "export-request", [REQUEST_ID], None) == b"frame"


@pytest.mark.parametrize(
    ("stream", "limit", "message"),
    (("stdout", "MAX_FRAME", "output"), ("stderr", "HEADER_LIMIT", "diagnostics")),
)
def test_controller_bounds_ssh_process_output(
    controller: ModuleType, stream: str, limit: str, message: str
) -> None:
    size = getattr(controller, limit) + 1
    script = f"import sys; sys.{stream}.buffer.write(b'x' * {size})"

    with pytest.raises(controller.DirectExchangeError, match=f"{message} exceeded"):
        controller.run_bounded([sys.executable, "-c", script], None)


def test_bounded_process_times_out_under_stdin_backpressure(
    controller: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(controller, "SSH_TIMEOUT_SECONDS", 0.1)

    with pytest.raises(controller.subprocess.TimeoutExpired):
        controller.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            b"x" * controller.MAX_FRAME,
        )


def test_openssh_loads_parent_memfd_identity(
    controller: ModuleType, tmp_path: Path
) -> None:
    identity = tmp_path / "probe-identity"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", identity],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    identity_data = identity.read_bytes()
    identity.unlink()
    identity.with_suffix(".pub").unlink()
    descriptor = controller.sealed_memfd("platform-pki-probe", identity_data)
    identity_path = f"/proc/{os.getpid()}/fd/{descriptor}"
    try:
        result = subprocess.run(
            [
                "ssh", "-vvv", "-F", "/dev/null", "-T",
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "ProxyCommand=/bin/false",
                "-o", "CanonicalizeHostname=no",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-i", identity_path, "probe.invalid", "true",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    finally:
        os.close(descriptor)

    assert result.returncode == 255
    diagnostics = result.stderr.decode("utf-8")
    assert re.search(
        rf"identity file {re.escape(identity_path)} type [0-9]+", diagnostics
    )
    assert f"Identity file {identity_path} not accessible" not in diagnostics


def test_request_pull_reports_receipt_compatible_host_key_digest(
    controller: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint_path, endpoint = endpoint_fixture(controller, tmp_path)
    output_dir = tmp_path / "request-output"
    files = {
        "tls.csr": b"csr\n",
        "request": b"request\n",
        "request.sig": b"signature\n",
    }
    values = {"request_id": REQUEST_ID}
    frame = controller.encode_frame(
        "request", files, values, "registry-test", "target.test"
    )
    output = io.BytesIO()
    monkeypatch.setattr(controller, "load_endpoint", lambda _path: endpoint)
    monkeypatch.setattr(controller, "invoke", lambda *_args: frame)
    monkeypatch.setattr(
        controller.sys,
        "argv",
        [
            "platform-pki-direct-exchange",
            "request-pull",
            os.fspath(endpoint_path),
            REQUEST_ID,
            os.fspath(output_dir),
        ],
    )
    monkeypatch.setattr(controller.sys, "stdout", SimpleNamespace(buffer=output))

    controller.main()

    result = json.loads(output.getvalue())
    assert result["transport_host_key_sha256"] == endpoint.transport_host_key_sha256
    assert set(result) == {
        "request_id",
        "service",
        "status",
        "target",
        "transport_host_key_sha256",
    }


def test_wrong_known_host_digest_is_rejected_before_ssh(
    controller: ModuleType, tmp_path: Path
) -> None:
    endpoint_path, _endpoint = endpoint_fixture(controller, tmp_path)
    value = json.loads(endpoint_path.read_bytes())
    value["expected_host_key_sha256"] = "SHA256:" + "A" * 43
    private_file(endpoint_path, controller.canonical_json(value) + b"\n")
    with pytest.raises(controller.DirectExchangeError, match="digest differs"):
        controller.load_endpoint(os.fspath(endpoint_path))


def test_controller_rejects_unsafe_local_file_metadata(
    controller: ModuleType, tmp_path: Path
) -> None:
    path = private_file(tmp_path / "unsafe", b"data\n")
    path.chmod(0o644)
    with pytest.raises(controller.DirectExchangeError, match="unsafe metadata"):
        controller.protected_file(os.fspath(path), "unsafe file", maximum=32)


def test_role_wiring_installs_fixed_config_and_private_spool(repo_root: Path) -> None:
    role = repo_root / "roles/pki_host_local_certificate"
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text(encoding="utf-8"))
    assert defaults["pki_host_local_certificate_exchange_helper_path"] == (
        "/usr/local/libexec/platform-pki-host-local-exchange"
    )
    assert defaults["pki_host_local_certificate_exchange_config_path"] == (
        "/etc/platform-config/pki-host-local-exchange.json"
    )
    tasks = yaml.safe_load((role / "tasks/exchange_helper.yml").read_text(encoding="utf-8"))
    copies = [task["ansible.builtin.copy"] for task in tasks if "ansible.builtin.copy" in task]
    assert copies[0]["src"] == "platform-pki-host-local-exchange"
    assert copies[0]["mode"] == "0755"
    assert copies[1]["mode"] == "0600"
    directory_task = next(task for task in tasks if task["name"] == "Create fixed host-local certificate exchange directories")
    assert {item["mode"] for item in directory_task["loop"]} == {"0755", "0700"}
