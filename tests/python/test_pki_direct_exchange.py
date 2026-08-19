from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

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


def publish_evidence(
    module: ModuleType,
    config: Any,
    files: dict[str, bytes],
    coordinates: dict[str, str],
) -> None:
    evidence = private_dir(Path(config.state_root) / "evidence")
    request = private_dir(evidence / coordinates["request_id"])
    deployment = private_dir(request / coordinates["deployment_sha256"])
    evidence_files = {
        "deployment": files["deployment"],
        "deployment.sig": files["deployment.sig"],
        "validation-boundary": b"validation boundary\n",
        "validation-result": b"validation result\n",
        "validation-result.sig": b"validation signature\n",
    }
    assert tuple(evidence_files) == module.EVIDENCE_NAMES
    for name, data in evidence_files.items():
        private_file(deployment / name, data)


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


def test_allowlists_are_exact_and_exclude_private_key_name(
    facade: ModuleType, repo_root: Path
) -> None:
    expected = {
        "request": 3,
        "response": 6,
        "evidence": 5,
        "outcome": 6,
    }
    assert {kind: len(names) for kind, names in facade.NAMES_BY_KIND.items()} == expected
    assert all("tls" + ".key" not in names for names in facade.NAMES_BY_KIND.values())
    path = repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-exchange"
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
        assert arguments == [
            "--trust-id",
            "reviewed-v1",
            "--request-id",
            REQUEST_ID,
        ]
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
    publish_evidence(facade, config, files, values)
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


def test_outcome_stage_requires_published_evidence(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, values = outcome_files(facade)
    frame = facade.encode_frame("outcome", files, values, config)

    with pytest.raises(facade.ExchangeError):
        facade.publish_outcome(config, values, frame)
    assert not (Path(config.spool_root) / "outcomes").exists()


def test_outcome_stage_allows_only_one_candidate_per_request(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, values = outcome_files(facade)
    publish_evidence(facade, config, files, values)
    first_frame = facade.encode_frame("outcome", files, values, config)
    facade.publish_outcome(config, values, first_frame)

    second_files = dict(files)
    second_files["outcome"] = files["outcome"] + b"note=second\n"
    second_values = dict(values)
    second_values["outcome_sha256"] = facade.sha256(second_files["outcome"])
    second_frame = facade.encode_frame("outcome", second_files, second_values, config)
    with pytest.raises(facade.ExchangeError, match="different outcome"):
        facade.publish_outcome(config, second_values, second_frame)


def test_outcome_stage_recovers_exact_interrupted_private_stage(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, values = outcome_files(facade)
    publish_evidence(facade, config, files, values)
    outcomes = private_dir(Path(config.spool_root) / "outcomes")
    request = private_dir(outcomes / REQUEST_ID)
    interrupted = private_dir(request / f".stage-{values['outcome_sha256']}")
    private_file(interrupted / "outcome", files["outcome"])
    frame = facade.encode_frame("outcome", files, values, config)

    assert facade.publish_outcome(config, values, frame)["status"] == "staged"
    assert not interrupted.exists()
    assert (request / values["outcome_sha256"]).is_dir()


def test_outcome_cleanup_requires_accepted_matching_history(
    facade: ModuleType, tmp_path: Path
) -> None:
    config = target_config(facade, tmp_path)
    files, values = outcome_files(facade)
    frame = facade.encode_frame("outcome", files, values, config)
    publish_evidence(facade, config, files, values)
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
