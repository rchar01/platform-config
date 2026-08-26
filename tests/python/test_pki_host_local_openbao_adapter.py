from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


pytestmark = pytest.mark.pki
REQUEST_ID = "0123456789abcdef0123456789abcdef"


def load_helper(repo_root: Path) -> ModuleType:
    path = (
        repo_root
        / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"
    )
    loader = importlib.machinery.SourceFileLoader(
        "platform_pki_host_local_openbao_adapter", str(path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def adapter_args(**changes: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "service_adapter": "openbao-pristine-v1",
        "service_unit": "openbao.service",
        "service_config": "/etc/openbao/listener.hcl",
        "node_dns": "bao-1.test",
        "node_address": "192.0.2.10",
        "backend_port": 18200,
        "cluster_port": 8201,
        "container_versions_root": "/openbao/config/tls-versions",
        "base_config_dir": "/openbao/config",
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_parser_rejects_unknown_adapter_and_openbao_url(repo_root: Path) -> None:
    helper = load_helper(repo_root)
    parser = helper.build_parser()
    common = [
        "--state-root", "/state", "--pending-root", "/tls-pending",
        "--versions-root", "/tls-versions", "--service", "openbao-test-01",
        "--target", "bao-1.test",
    ]
    with pytest.raises(SystemExit):
        parser.parse_args([
            "target-status", *common, "--service-adapter", "shell-v1",
        ])

    parsed = parser.parse_args([
        "target-activate-complete", *common,
        "--service-adapter", "openbao-pristine-v1",
        "--service-unit", "openbao.service",
        "--service-config", "/etc/openbao/listener.hcl",
        "--node-dns", "bao-1.test", "--node-address", "192.0.2.10",
        "--backend-port", "18200", "--cluster-port", "8201",
        "--container-versions-root", "/openbao/config/tls-versions",
        "--base-config-dir", "/openbao/config",
        "--raft-data-dir", "/var/lib/openbao",
        "--bootstrap-marker-path", "/var/lib/platform-config/openbao-bootstrap.json",
        "--trust-id", "reviewed-v1", "--common-name", "bao-1.test",
        "--dns-san", "bao-1.test",
        "--minimum-remaining-lifetime-seconds", "1",
        "--reviewed-ca", "/etc/openbao/tls/ca.crt",
        "--endpoint", "https://bao-1.test:18200/v1/sys/health",
    ])
    with pytest.raises(helper.LifecycleError, match="does not accept an endpoint URL"):
        helper.validate_arguments(parsed)
    parsed.endpoint = None
    parsed.container_versions_root = "/openbao/certificates/tls-versions"
    with pytest.raises(helper.LifecycleError, match="exact /openbao/config/tls-versions"):
        helper.validate_arguments(parsed)

    wrong_zot_path = parser.parse_args([
        "active-paths", *common, "--zot-config", "/tmp/zot.json",
    ])
    with pytest.raises(helper.LifecycleError, match="exact /etc/zot/config.json"):
        helper.validate_arguments(wrong_zot_path)
    zot_openbao_custody = parser.parse_args([
        "openbao-custody", *common, "--zot-config", "/etc/zot/config.json",
    ])
    with pytest.raises(helper.LifecycleError, match="supports openbao-pristine-v1 only"):
        helper.validate_arguments(zot_openbao_custody)
    accepted_custody = parser.parse_args([
        "openbao-custody", *common,
        "--service-adapter", "openbao-pristine-v1",
        "--service-unit", "openbao.service",
        "--service-config", "/etc/openbao/listener.hcl",
        "--node-dns", "bao-1.test", "--node-address", "192.0.2.10",
        "--backend-port", "18200", "--cluster-port", "8201",
        "--container-versions-root", "/openbao/config/tls-versions",
        "--base-config-dir", "/openbao/config",
        "--raft-data-dir", "/var/lib/openbao",
        "--bootstrap-marker-path", "/var/lib/platform-config/openbao-bootstrap.json",
    ])
    helper.validate_arguments(accepted_custody)
    assert accepted_custody.function is helper.openbao_custody


def test_exact_listener_rendering_and_container_path_translation(
    repo_root: Path,
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()
    certificate, key = helper.selected_version_paths(args, REQUEST_ID)
    rendered = helper.openbao_listener_bytes(args, certificate, key)

    assert certificate == (
        f"/openbao/config/tls-versions/{REQUEST_ID}/fullchain.crt"
    )
    assert key == f"/openbao/config/tls-versions/{REQUEST_ID}/tls.key"
    assert rendered == (
        'listener "tcp" {\n'
        '  address = "192.0.2.10:18200"\n'
        '  cluster_address = "192.0.2.10:8201"\n'
        f'  tls_cert_file = "{certificate}"\n'
        f'  tls_key_file = "{key}"\n'
        '  tls_min_version = "tls12"\n'
        '  tls_max_version = "tls13"\n'
        '  tls_disable_client_certs = true\n'
        '  disable_unauthed_rekey_endpoints = true\n'
        '  disable_unauthed_generate_root_endpoints = true\n'
        '}\n'
    ).encode("ascii")
    assert helper.parse_openbao_listener(rendered, args)[1:] == (certificate, key)
    with pytest.raises(helper.LifecycleError, match="exact adapter-owned HCL"):
        helper.parse_openbao_listener(rendered + b"\n", args)


def test_openbao_served_chain_rejects_extra_certificate(repo_root: Path) -> None:
    helper = load_helper(repo_root)
    leaf = b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n"
    intermediate = b"-----BEGIN CERTIFICATE-----\nQg==\n-----END CERTIFICATE-----\n"
    extra = b"-----BEGIN CERTIFICATE-----\nQw==\n-----END CERTIFICATE-----\n"

    assert helper.validate_openbao_served_chain(
        leaf + intermediate, helper.sha256(leaf), helper.sha256(intermediate)
    ) == (leaf, intermediate)
    with pytest.raises(helper.LifecycleError, match="exactly leaf and intermediate"):
        helper.validate_openbao_served_chain(
            leaf + intermediate + extra,
            helper.sha256(leaf), helper.sha256(intermediate),
        )


@pytest.mark.parametrize("validator_fails", (False, True))
def test_candidate_validation_uses_fixed_helper_and_always_cleans_up(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    validator_fails: bool,
) -> None:
    helper = load_helper(repo_root)
    listener = tmp_path / "listener.hcl"
    original = b"original listener\n"
    listener.write_bytes(original)
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)

    class Parent:
        path = str(tmp_path)
        fd = parent_fd

        @staticmethod
        def close() -> None:
            os.close(parent_fd)

    monkeypatch.setattr(helper.PinnedDirectory, "open", lambda *_args, **_kwargs: Parent())
    monkeypatch.setattr(helper.os, "fchown", lambda *_args, **_kwargs: None)
    candidate = helper.openbao_listener_bytes(
        adapter_args(),
        f"/openbao/config/tls-versions/{REQUEST_ID}/fullchain.crt",
        f"/openbao/config/tls-versions/{REQUEST_ID}/tls.key",
    )

    def fixed_validator(
        arguments: Sequence[str], label: str, **_kwargs: object
    ) -> SimpleNamespace:
        argv = tuple(arguments)
        assert argv[0] == "/usr/local/libexec/platform/openbao-validate-config"
        assert argv[1] == "listener"
        assert Path(argv[2]).parent == tmp_path
        assert Path(argv[2]).read_bytes() == candidate
        assert label == "fixed OpenBao candidate configuration validation"
        if validator_fails:
            raise helper.LifecycleError("validator rejected candidate")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(helper, "run", fixed_validator)
    args = adapter_args(service_config=str(listener))
    if validator_fails:
        with pytest.raises(helper.LifecycleError, match="validator rejected"):
            helper.validate_openbao_candidate_config(args, candidate)
    else:
        helper.validate_openbao_candidate_config(args, candidate)

    assert listener.read_bytes() == original
    assert {path.name for path in tmp_path.iterdir()} == {"listener.hcl"}


def test_openbao_pristine_preconditions(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper(repo_root)
    raft = tmp_path / "raft"
    raft.mkdir(mode=0o750)
    raft.chmod(0o750)
    marker = tmp_path / "bootstrap.json"
    args = adapter_args(raft_data_dir=str(raft), bootstrap_marker_path=str(marker))
    prior = helper.openbao_listener_bytes(
        args, "/openbao/config/tls/tls.crt", "/openbao/config/tls/tls.key"
    )
    request = {
        "operation": "issue", "current_cert_sha256": "none",
        "predecessor_request_id": "none",
    }
    service = {"state": "inactive"}
    monkeypatch.setattr(helper, "service_state", lambda _args: service["state"])
    monkeypatch.setattr(helper, "service_enabled_state", lambda _args: "disabled")
    monkeypatch.setattr(helper, "validate_openbao_raft_directory", lambda _args: None)

    assert helper.validate_openbao_preconditions(
        args, request, None, None, prior
    ) == ("/openbao/config/tls/tls.crt", "/openbao/config/tls/tls.key")

    marker.write_text("{}\n", encoding="ascii")
    with pytest.raises(helper.LifecycleError, match="absent bootstrap marker"):
        helper.validate_openbao_preconditions(args, request, None, None, prior)
    marker.unlink()
    service["state"] = "active"
    with pytest.raises(helper.LifecycleError, match="inactive, unmasked"):
        helper.validate_openbao_preconditions(args, request, None, None, prior)
    service["state"] = "inactive"
    with pytest.raises(helper.LifecycleError, match="issue only"):
        helper.validate_openbao_preconditions(
            args, {**request, "operation": "renew"}, None, None, prior
        )


def test_openbao_immutable_version_metadata(repo_root: Path) -> None:
    helper = load_helper(repo_root)
    modes = helper.version_modes(helper.OPENBAO_ADAPTER)
    gids = helper.version_owner_gids(helper.OPENBAO_ADAPTER)

    assert helper.version_directory_metadata(helper.OPENBAO_ADAPTER) == (0o750, 1000)
    assert modes["tls.key"] == 0o640
    assert gids["tls.key"] == 1000
    assert all(modes[name] == 0o644 for name in helper.CERTIFICATE_NAMES)
    assert all(gids[name] == 0 for name in helper.CERTIFICATE_NAMES)
    assert helper.version_directory_metadata(helper.ZOT_ADAPTER) == (0o700, 0)
    assert helper.version_modes(helper.ZOT_ADAPTER)["tls.key"] == 0o600


def test_openbao_raft_service_owner_is_final_directory_only(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)
    observed: dict[str, object] = {}

    class Directory:
        fd = 1

        def close(self) -> None:
            return None

    def open_directory(_path: str, _label: str, **options: object) -> Directory:
        observed.update(options)
        return Directory()

    metadata = SimpleNamespace(st_uid=100, st_gid=1000, st_mode=0o40750)
    monkeypatch.setattr(helper.PinnedDirectory, "open", open_directory)
    monkeypatch.setattr(helper.os, "fstat", lambda _fd: metadata)
    monkeypatch.setattr(helper, "scan", lambda *_args: {})

    helper.validate_openbao_raft_directory(adapter_args(raft_data_dir="/raft"))

    assert "allowed_owner_uids" not in observed
    assert observed["allowed_final_owner_uids"] == {100}
    assert observed["allowed_final_owner_gids"] == {1000}


def test_openbao_health_status_and_native_boolean_contract(repo_root: Path) -> None:
    helper = load_helper(repo_root)
    body = json.dumps({
        "initialized": False,
        "sealed": True,
        "standby": True,
        "replication_performance_mode": "unknown",
        "replication_dr_mode": "unknown",
        "server_time_utc": 1,
        "version": "2.6.1",
    }).encode("ascii")
    helper.validate_openbao_health_response(501, body)

    with pytest.raises(helper.LifecycleError, match="exact HTTP 501"):
        helper.validate_openbao_health_response(503, body)
    with pytest.raises(helper.LifecycleError, match="pristine 2.6.1 contract"):
        helper.validate_openbao_health_response(
            501, body.replace(b'"initialized": false', b'"initialized": 0')
        )
    with pytest.raises(helper.LifecycleError, match="pristine 2.6.1 contract"):
        helper.validate_openbao_health_response(
            501, body.replace(b'"version": "2.6.1"', b'"version": "2.6.2"')
        )
    with pytest.raises(helper.LifecycleError, match="fixed limit"):
        helper.validate_openbao_health_response(
            501, b" " * (helper.OPENBAO_BODY_MAX_SIZE + 1)
        )


def test_openbao_validation_cycle_returns_inactive_disabled(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()
    state = {"active": False, "enabled": False}
    actions: list[str] = []
    monkeypatch.setattr(
        helper, "service_state",
        lambda _args: "active" if state["active"] else "inactive",
    )
    monkeypatch.setattr(
        helper, "service_enabled_state",
        lambda _args: "enabled" if state["enabled"] else "disabled",
    )

    def action(_args: object, name: str) -> None:
        actions.append(name)
        if name == "start":
            state["active"] = True
        elif name == "stop":
            state["active"] = False

    monkeypatch.setattr(helper, "service_action", action)
    monkeypatch.setattr(
        helper, "strict_local_validation",
        lambda *_args: {
            "served_certificate_sha256": "a" * 64,
            "served_intermediate_sha256": "b" * 64,
        },
    )

    result = helper.openbao_validation_cycle(args, "a" * 64, "b" * 64)

    assert actions == ["start", "stop"]
    assert state == {"active": False, "enabled": False}
    assert result["served_certificate_sha256"] == "a" * 64


def test_openbao_validation_authenticates_generated_quadlet(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()
    state = {"active": False}
    provenance = (
        b"LoadState=loaded\nUnitFileState=generated\n"
        b"FragmentPath=/run/systemd/generator/openbao.service\n"
        b"SourcePath=/etc/containers/systemd/openbao.container\n"
    )
    sources: list[tuple[str, str, int]] = []
    monkeypatch.setattr(
        helper,
        "read_path",
        lambda path, label, *, mode: (
            sources.append((path, label, mode)) or (b"[Container]\n", ())
        ),
    )

    def systemctl(
        arguments: object, _label: str, **_kwargs: object
    ) -> SimpleNamespace:
        assert isinstance(arguments, tuple)
        if arguments[1] == "is-active":
            return SimpleNamespace(
                returncode=0 if state["active"] else 3,
                stdout=b"active\n" if state["active"] else b"inactive\n",
                stderr=b"",
            )
        if arguments[1] == "is-enabled":
            return SimpleNamespace(returncode=0, stdout=b"generated\n", stderr=b"")
        assert arguments == (
            "/usr/bin/systemctl", "show", "--property=LoadState",
            "--property=UnitFileState", "--property=FragmentPath",
            "--property=SourcePath",
            "openbao.service",
        )
        return SimpleNamespace(returncode=0, stdout=provenance, stderr=b"")

    monkeypatch.setattr(helper, "run", systemctl)
    helper.require_openbao_inactive_disabled(args)
    state["active"] = True
    helper.require_openbao_active_disabled(args)
    assert sources == [
        (
            "/etc/containers/systemd/openbao.container",
            "OpenBao Quadlet source",
            0o644,
        ),
        (
            "/etc/containers/systemd/openbao.container",
            "OpenBao Quadlet source",
            0o644,
        ),
    ]


@pytest.mark.parametrize(
    "provenance",
    (
        b"LoadState=not-found\nUnitFileState=generated\nFragmentPath=/run/systemd/generator/openbao.service\nSourcePath=/etc/containers/systemd/openbao.container\n",
        b"LoadState=loaded\nUnitFileState=disabled\nFragmentPath=/run/systemd/generator/openbao.service\nSourcePath=/etc/containers/systemd/openbao.container\n",
        b"LoadState=loaded\nUnitFileState=generated\nFragmentPath=/etc/systemd/system/openbao.service\nSourcePath=/etc/containers/systemd/openbao.container\n",
        b"LoadState=loaded\nUnitFileState=generated\nFragmentPath=/run/systemd/generator/openbao.service\nSourcePath=/tmp/openbao.container\n",
        b"LoadState=loaded\nUnitFileState=generated\nFragmentPath=/run/systemd/generator/openbao.service\nSourcePath=\n",
        b"LoadState=loaded\nUnitFileState=generated\nFragmentPath=/run/systemd/generator/openbao.service\nSourcePath=/etc/containers/systemd/openbao.container\nUnexpected=value\n",
        b"LoadState=loaded\nUnitFileState=generated\nFragmentPath=/run/systemd/generator/openbao.service\nSourcePath=/etc/containers/systemd/openbao.container",
    ),
)
def test_openbao_validation_rejects_wrong_generated_unit_provenance(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    provenance: bytes,
) -> None:
    helper = load_helper(repo_root)
    monkeypatch.setattr(
        helper,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=provenance, stderr=b""
        ),
    )

    with pytest.raises(helper.LifecycleError, match="provenance is not canonical"):
        helper.require_openbao_generated_unit(adapter_args())


def test_openbao_validation_rejects_failed_start_and_still_stops(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()
    actions: list[str] = []
    monkeypatch.setattr(helper, "service_state", lambda _args: "inactive")
    monkeypatch.setattr(helper, "service_enabled_state", lambda _args: "disabled")
    monkeypatch.setattr(
        helper, "service_action", lambda _args, action: actions.append(action)
    )
    monkeypatch.setattr(
        helper, "strict_local_validation",
        lambda *_args: pytest.fail("validation must not run after a failed start"),
    )

    with pytest.raises(helper.LifecycleError, match="active, unmasked"):
        helper.openbao_validation_cycle(args, "a" * 64, "b" * 64)
    assert actions == ["start", "stop"]


def test_openbao_restore_attempts_stop_before_journal_authentication(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)
    events: list[str] = []
    monkeypatch.setattr(
        helper, "service_action",
        lambda _args, action: events.append(action),
    )
    monkeypatch.setattr(
        helper, "require_openbao_inactive_disabled",
        lambda _args: events.append("inactive-disabled"),
    )

    def reject_journal(_data: bytes, _args: object) -> dict[str, str]:
        events.append("journal")
        raise helper.LifecycleError("invalid journal")

    monkeypatch.setattr(helper, "journal_record", reject_journal)
    with pytest.raises(helper.LifecycleError, match="invalid journal"):
        helper.restore_from_journal(object(), b"invalid", (), adapter_args())
    assert events == ["stop", "inactive-disabled", "journal"]


class CustodyState:
    def close(self) -> None:
        pass


def test_openbao_custody_dormant_and_unresolved_state(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args(
        state_root="/state", pending_root="/tls-pending",
        versions_root="/etc/openbao/tls-versions", service="openbao",
        target="bao-1.test", bootstrap_marker_path="/bootstrap.json",
        raft_data_dir="/var/lib/openbao",
    )
    lock = os.open("/dev/null", os.O_RDONLY)
    monkeypatch.setattr(helper, "common_open", lambda *_args, **_kwargs: (CustodyState(), lock))
    monkeypatch.setattr(helper, "state_entries", lambda _state: {"lock"})
    monkeypatch.setattr(helper, "authenticate_active", lambda _state, _args: None)
    dormant = helper.openbao_listener_bytes(
        args, "/openbao/config/tls/tls.crt", "/openbao/config/tls/tls.key"
    )
    monkeypatch.setattr(helper, "read_service_config", lambda *_args, **_kwargs: (dormant, ()))
    custody_states: list[bool] = []
    monkeypatch.setattr(
        helper,
        "require_openbao_inactive_custody_state",
        lambda _args, *, allow_absent=False: custody_states.append(allow_absent),
    )
    monkeypatch.setattr(helper, "validate_openbao_raft_directory", lambda _args: None)

    helper.openbao_custody(args)
    result = json.loads(capsys.readouterr().out)
    assert custody_states == [True]
    assert result == {
        "schema": "2", "kind": "platform-config-openbao-tls-custody",
        "custody": "dormant", "request_id": "none",
        "host_cert_path": "/etc/openbao/tls/tls.crt",
        "host_key_path": "/etc/openbao/tls/tls.key",
        "container_cert_path": "/openbao/config/tls/tls.crt",
        "container_key_path": "/openbao/config/tls/tls.key",
        "artifact_sha256": "none", "certificate_sha256": "none",
        "spki_sha256": "none", "chain_sha256": "none",
        "fullchain_sha256": "none", "listener_sha256": helper.sha256(dormant),
    }

    second_lock = os.open("/dev/null", os.O_RDONLY)
    monkeypatch.setattr(
        helper, "common_open",
        lambda *_args, **_kwargs: (CustodyState(), second_lock),
    )
    monkeypatch.setattr(
        helper, "state_entries", lambda _state: {"lock", "activation-journal"}
    )
    with pytest.raises(helper.LifecycleError, match="unresolved lifecycle state"):
        helper.openbao_custody(args)


def test_openbao_custody_accepts_masked_but_not_enabled_service(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper(repo_root)
    monkeypatch.setattr(helper, "service_state", lambda _args: "inactive")
    monkeypatch.setattr(helper, "service_enabled_state", lambda _args: "masked")

    helper.require_openbao_inactive_custody_state(object())

    monkeypatch.setattr(helper, "service_enabled_state", lambda _args: "enabled")
    with pytest.raises(helper.LifecycleError, match="inactive, disabled or masked"):
        helper.require_openbao_inactive_custody_state(object())


def test_openbao_dormant_custody_accepts_only_absent_service_unit(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()

    def absent_service(
        arguments: object, label: str, **kwargs: object
    ) -> SimpleNamespace:
        accepted = kwargs.get("accepted", frozenset((0,)))
        assert isinstance(accepted, frozenset)
        assert isinstance(arguments, tuple)
        if arguments[1] == "is-active":
            return SimpleNamespace(returncode=3, stdout=b"inactive\n", stderr=b"")
        assert arguments[1] == "is-enabled"
        if 4 not in accepted:
            raise helper.LifecycleError(f"{label} failed")
        return SimpleNamespace(returncode=4, stdout=b"not-found\n", stderr=b"")

    monkeypatch.setattr(helper, "run", absent_service)

    helper.require_openbao_inactive_custody_state(args, allow_absent=True)
    with pytest.raises(helper.LifecycleError, match="service enablement query failed"):
        helper.require_openbao_inactive_custody_state(args)


@pytest.mark.parametrize("active_output", (b"unknown\n", b"inactive\n"))
def test_openbao_dormant_custody_accepts_fully_absent_service_unit(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_output: bytes,
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()
    calls: list[str] = []

    def absent_service(
        arguments: object, label: str, **kwargs: object
    ) -> SimpleNamespace:
        assert isinstance(arguments, tuple)
        calls.append(arguments[1])
        accepted = kwargs.get("accepted", frozenset((0,)))
        assert isinstance(accepted, frozenset)
        if 4 not in accepted:
            raise helper.LifecycleError(f"{label} failed")
        return SimpleNamespace(returncode=4, stdout=active_output, stderr=b"")

    monkeypatch.setattr(helper, "run", absent_service)

    helper.require_openbao_inactive_custody_state(args, allow_absent=True)
    assert calls == ["is-active"]
    with pytest.raises(helper.LifecycleError, match="service-state query failed"):
        helper.require_openbao_inactive_custody_state(args)


@pytest.mark.parametrize(
    ("command", "returncode", "stdout", "message"),
    (
        ("is-active", 4, b"active\n", "service state is not canonical"),
        ("is-active", 3, b"unknown\n", "service state is not canonical"),
        ("is-active", 0, b" active\n", "service state is not canonical"),
        ("is-active", 0, b"active", "service state is not canonical"),
        ("is-active", 0, b"active\n\n", "service state is not canonical"),
        ("is-enabled", 4, b"disabled\n", "enablement state is not canonical"),
        ("is-enabled", 1, b"generated\n", "enablement state is not canonical"),
        ("is-enabled", 1, b" disabled\n", "enablement state is not canonical"),
        ("is-enabled", 1, b"disabled", "enablement state is not canonical"),
        ("is-enabled", 1, b"disabled\n\n", "enablement state is not canonical"),
    ),
)
def test_openbao_service_state_rejects_noncanonical_result_pairs(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    returncode: int,
    stdout: bytes,
    message: str,
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args()
    monkeypatch.setattr(
        helper,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr=b""
        ),
    )

    query = helper.service_state if command == "is-active" else helper.service_enabled_state
    with pytest.raises(helper.LifecycleError, match=message):
        query(args, allow_absent=True)


def test_openbao_staging_preflight_accepts_absent_state(
    repo_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = load_helper(repo_root)
    monkeypatch.setattr(
        helper, "trusted_ancestor_owners", lambda: {0, os.getuid(), os.getgid()}
    )
    args = adapter_args(
        state_root=str(tmp_path / "state"),
        pending_root=str(tmp_path / "tls-pending"),
        versions_root=str(tmp_path / "tls-versions"),
        service_config=str(tmp_path / "listener.hcl"),
        service="openbao-test-01",
        target="bao-1.test",
    )
    args.trust_id = "openbao-test-v1"

    helper.openbao_staging_preflight(args)

    assert json.loads(capsys.readouterr().out) == {
        "schema": "1",
        "kind": "platform-config-openbao-staging-preflight",
        "status": "absent",
        "service": "openbao-test-01",
        "target": "bao-1.test",
    }


def test_openbao_staging_preflight_authenticates_exact_trust_only_state(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = load_helper(repo_root)

    class Directory:
        path = "/state"

        def recheck(self, _label: str) -> None:
            return None

        def close(self) -> None:
            return None

    state = Directory()
    trust_root = Directory()
    lock = os.open("/dev/null", os.O_RDONLY)
    monkeypatch.setattr(
        helper, "require_absent_canonical_path", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(helper.os.path, "lexists", lambda _path: True)
    monkeypatch.setattr(helper, "common_open", lambda *_args, **_kwargs: (state, lock))
    monkeypatch.setattr(helper, "state_entries", lambda _state: {"lock", "trust"})
    monkeypatch.setattr(helper.PinnedDirectory, "open", lambda *_args, **_kwargs: trust_root)
    monkeypatch.setattr(helper, "scan", lambda *_args: {"openbao-test-v1": object()})
    loaded: list[tuple[str, str]] = []
    monkeypatch.setattr(
        helper,
        "load_trust",
        lambda _state, trust_id, target: loaded.append((trust_id, target)),
    )
    args = adapter_args(
        state_root="/state",
        service="openbao-test-01",
        target="bao-1.test",
    )
    args.trust_id = "openbao-test-v1"

    helper.openbao_staging_preflight(args)

    assert loaded == [("openbao-test-v1", "bao-1.test")]
    assert json.loads(capsys.readouterr().out)["status"] == "trust-only"


def test_openbao_staging_preflight_allows_fixed_listener_parent_gid(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = load_helper(repo_root)
    observed: list[tuple[str, int | None]] = []

    def require_absent(
        path: str, _label: str, *, allowed_ancestor_gid: int | None = None
    ) -> None:
        observed.append((path, allowed_ancestor_gid))

    monkeypatch.setattr(helper, "require_absent_canonical_path", require_absent)
    monkeypatch.setattr(helper.os.path, "lexists", lambda _path: False)
    args = adapter_args(
        state_root="/state",
        service_config="/etc/openbao/listener.hcl",
        service="openbao-test-01",
        target="bao-1.test",
    )
    args.trust_id = "openbao-test-v1"

    helper.openbao_staging_preflight(args)

    assert observed == [
        ("/etc/openbao/listener.hcl", 1000),
        ("/state", None),
    ]
    assert json.loads(capsys.readouterr().out)["status"] == "absent"


def test_openbao_pending_root_allows_only_fixed_container_gid_ancestors(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)

    class Directory:
        def close(self) -> None:
            return None

    observed: dict[str, object] = {}

    def open_directory(_path: str, _label: str, **options: object) -> Directory:
        observed.update(options)
        return Directory()

    monkeypatch.setattr(helper.PinnedDirectory, "open", open_directory)
    monkeypatch.setattr(helper, "scan", lambda *_args: {})
    monkeypatch.setattr(helper, "target_excluded_request_ids", lambda _args: set())
    monkeypatch.setattr(helper, "trusted_ancestor_owners", lambda: {0})
    args = adapter_args(pending_root="/etc/openbao/tls-pending")

    assert helper.target_pending_request_ids(args) == ()
    assert "allowed_owner_uids" not in observed
    assert observed["allowed_owner_gids"] == {0, 1000}


def test_openbao_container_gid_does_not_trust_matching_host_uid(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper(repo_root)
    monkeypatch.setattr(helper, "trusted_ancestor_owners", lambda: {0})

    with tempfile.TemporaryDirectory(
        prefix="platform-pki-uid-boundary-", dir="/tmp"
    ) as temporary:
        if os.geteuid() == 0:
            os.chown(temporary, 1000, 1000)
        elif os.geteuid() != 1000:
            pytest.skip("test requires root or UID 1000")

        with pytest.raises(helper.LifecycleError, match="unsafe ancestor"):
            helper.PinnedDirectory.open(
                temporary,
                "OpenBao GID boundary",
                allowed_owner_gids={0, 1000},
            )

        directory = helper.PinnedDirectory.open(
            temporary,
            "explicit final owner boundary",
            allowed_final_owner_uids={1000},
            final_owner_uid=1000,
            final_owner_uid_only=True,
        )
        directory.close()


def test_openbao_custody_active_emits_host_and_container_paths(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = load_helper(repo_root)
    args = adapter_args(
        state_root="/state", pending_root="/tls-pending",
        versions_root="/etc/openbao/tls-versions", service="openbao",
        target="bao-1.test", bootstrap_marker_path="/bootstrap.json",
        raft_data_dir="/var/lib/openbao",
    )
    lock = os.open("/dev/null", os.O_RDONLY)
    active = {
        "request_id": REQUEST_ID,
        "version_path": f"/etc/openbao/tls-versions/{REQUEST_ID}",
        "artifact_manifest_sha256": "a" * 64,
        "certificate_sha256": "b" * 64,
        "certificate_spki_sha256": "c" * 64,
        "chain_sha256": "d" * 64,
        "fullchain_sha256": "e" * 64,
        "zot_config_sha256": "f" * 64,
    }
    monkeypatch.setattr(helper, "common_open", lambda *_args, **_kwargs: (CustodyState(), lock))
    monkeypatch.setattr(helper, "state_entries", lambda _state: {"lock", "active", "rollback"})
    monkeypatch.setattr(
        helper, "authenticate_active",
        lambda _state, _args: {"record": active},
    )
    monkeypatch.setattr(helper, "require_active_rollback", lambda *_args: {})
    monkeypatch.setattr(
        helper, "require_openbao_inactive_custody_state", lambda _args: None
    )

    helper.openbao_custody(args)
    result = json.loads(capsys.readouterr().out)
    assert result["custody"] == "host-local"
    assert result["host_cert_path"] == (
        f"/etc/openbao/tls-versions/{REQUEST_ID}/fullchain.crt"
    )
    assert result["container_cert_path"] == (
        f"/openbao/config/tls-versions/{REQUEST_ID}/fullchain.crt"
    )
    assert result["listener_sha256"] == "f" * 64
