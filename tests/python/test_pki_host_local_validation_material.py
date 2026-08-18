from __future__ import annotations

import datetime
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from conftest import CommandRunner
from plugins.action import platform_pki_validation_material as validation_action
from plugins.module_utils.platform_pki_exchange import (
    ExchangeError,
    LOCAL_CHECK,
    REMOTE_CHECK,
    VALIDATION_BOUNDARY_FIELDS,
    serialize_record,
    validate_reviewed_ca_bundle,
    validate_validation_boundary,
)
from plugins.module_utils.platform_pki_secure_source import (
    SourcePinError,
    pin_controller_source,
)


SERVICE = "registry-dev"
TARGET = "registry-one.test"
RUNNER = "runner-one.test"
ENDPOINT = "https://registry.test/v2/"


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _certificate(*, ca: bool = True, constraints: bool = True, critical: bool = True) -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Validation Test CA")])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=critical
        )
    certificate = builder.sign(key, hashes.SHA384())
    return certificate.public_bytes(serialization.Encoding.PEM)


def _reviewed_ca_certificates() -> tuple[bytes, bytes]:
    now = datetime.datetime.now(datetime.UTC)
    root_key = ec.generate_private_key(ec.SECP384R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Validation Root CA")])
    usage = x509.KeyUsage(
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
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(usage, critical=True)
        .sign(root_key, hashes.SHA384())
    )
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Validation Intermediate CA")]
    )
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(2)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(usage, critical=True)
        .sign(root_key, hashes.SHA384())
    )
    return (
        intermediate.public_bytes(serialization.Encoding.PEM),
        root.public_bytes(serialization.Encoding.PEM),
    )


def _reviewed_ca() -> bytes:
    return b"".join(_reviewed_ca_certificates())


def _boundary(**overrides: str) -> bytes:
    values = {
        "schema": "1",
        "kind": "pki-validation-boundary",
        "service": SERVICE,
        "target": TARGET,
        "local_validator": TARGET,
        "remote_validator": RUNNER,
        "endpoint": ENDPOINT,
        "local_check": LOCAL_CHECK,
        "remote_check": REMOTE_CHECK,
    }
    values.update(overrides)
    return serialize_record(VALIDATION_BOUNDARY_FIELDS, values, "test boundary")


def _source(path: Path, data: bytes) -> tuple[str, str]:
    path.write_bytes(data)
    path.chmod(0o600)
    return str(path), hashlib.sha256(data).hexdigest()


def _arguments(source: str, digest: str, *, material: str = "reviewed-ca") -> dict[str, str]:
    filename = "reviewed-ca.pem" if material == "reviewed-ca" else "validation-boundary"
    return {
        "material": material,
        "source": source,
        "destination": f"/etc/platform-pki/{SERVICE}/validation-material/{filename}",
        "sha256": digest,
        "mode": "0644" if material == "reviewed-ca" else "0600",
        "service": SERVICE,
        "target": TARGET,
        "remote_validator": RUNNER,
        "endpoint": ENDPOINT,
    }


def test_validation_material_content_is_exact() -> None:
    intermediate, root = _reviewed_ca_certificates()
    ca = intermediate + root
    validate_reviewed_ca_bundle(ca)
    validate_validation_boundary(
        _boundary(),
        service=SERVICE,
        target=TARGET,
        remote_validator=RUNNER,
        endpoint=ENDPOINT,
    )

    for invalid_ca in (
        b"",
        intermediate,
        ca + root,
        root + intermediate,
        ca + b"\n",
        ca.replace(b"\n", b"\r\n"),
    ):
        with pytest.raises(ExchangeError):
            validate_reviewed_ca_bundle(invalid_ca)
    for non_ca in (
        _certificate(ca=False),
        _certificate(constraints=False),
        _certificate(critical=False),
    ):
        with pytest.raises(ExchangeError):
            validate_reviewed_ca_bundle(non_ca + root)
    for override in (
        {"schema": "2"},
        {"kind": "other"},
        {"service": "other-service"},
        {"target": RUNNER},
        {"local_validator": RUNNER},
        {"remote_validator": TARGET},
        {"endpoint": "https://registry.test/v2"},
        {"local_check": "other"},
        {"remote_check": "other"},
    ):
        with pytest.raises(ExchangeError):
            validate_validation_boundary(
                _boundary(**override),
                service=SERVICE,
                target=TARGET,
                remote_validator=RUNNER,
                endpoint=ENDPOINT,
            )
    lines = _boundary().splitlines(keepends=True)
    with pytest.raises(ExchangeError):
        validate_validation_boundary(
            b"".join((lines[1], lines[0], *lines[2:])),
            service=SERVICE,
            target=TARGET,
            remote_validator=RUNNER,
            endpoint=ENDPOINT,
        )


def test_shared_source_pin_rejects_unsafe_metadata_and_replacement(
    isolated_test_dir: Path,
) -> None:
    source_path = isolated_test_dir / "reviewed.pem"
    source, digest = _source(source_path, _reviewed_ca())
    pinned = pin_controller_source(source, digest, label="reviewed test source")
    try:
        replacement = isolated_test_dir / "replacement.pem"
        replacement.write_bytes(source_path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(source_path)
        with pytest.raises(SourcePinError, match="changed during transfer"):
            pinned.recheck()
    finally:
        pinned.close()

    source_path.chmod(0o644)
    with pytest.raises(SourcePinError, match="metadata is unsafe"):
        pin_controller_source(source, digest, label="reviewed test source")
    source_path.chmod(0o600)
    hardlink = isolated_test_dir / "reviewed-hardlink.pem"
    os.link(source_path, hardlink)
    with pytest.raises(SourcePinError, match="metadata is unsafe"):
        pin_controller_source(source, digest, label="reviewed test source")
    hardlink.unlink()
    with pytest.raises(SourcePinError, match="digest mismatch"):
        pin_controller_source(source, "0" * 64, label="reviewed test source")
    with pytest.raises(SourcePinError, match="not canonical SHA-256"):
        pin_controller_source(source, "A" * 64, label="reviewed test source")

    symlink = isolated_test_dir / "reviewed-link.pem"
    symlink.symlink_to(source_path)
    with pytest.raises(OSError):
        pin_controller_source(str(symlink), digest, label="reviewed test source")

    unsafe_parent = isolated_test_dir / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o777)
    unsafe_parent.chmod(0o777)
    unsafe_source, unsafe_digest = _source(
        unsafe_parent / "reviewed.pem", _reviewed_ca()
    )
    with pytest.raises(SourcePinError, match="unsafely writable"):
        pin_controller_source(
            unsafe_source, unsafe_digest, label="reviewed test source"
        )


@pytest.mark.parametrize(
    ("change", "message"),
    (
        ({"extra": "forbidden"}, "exact structured argument set"),
        ({"destination": "relative/reviewed-ca.pem"}, "absolute, canonical"),
        ({"destination": "/srv/pki/../reviewed-ca.pem"}, "absolute, canonical"),
        ({"destination": "/srv/pki/bad name.pem"}, "absolute, canonical"),
        ({"destination": "/srv/pki/current/reviewed-ca.pem"}, "absolute, canonical"),
        ({"source": f"/etc/platform-pki/{SERVICE}/validation-material/reviewed-ca.pem"}, "must be separate"),
        ({"mode": "0666"}, "destination mode"),
        ({"remote_validator": TARGET}, "distinct remote validator"),
        ({"endpoint": "http://registry.test/v2/"}, "endpoint is not canonical"),
    ),
)
def test_action_argument_allowlist(change: dict[str, str], message: str) -> None:
    arguments = _arguments("/outside-git/reviewed-ca.pem", "a" * 64)
    arguments.update(change)
    with pytest.raises(validation_action.ExchangeError, match=message):
        validation_action.validate_arguments(arguments)


def test_action_reuses_canonical_lifecycle_destination() -> None:
    arguments = _arguments("/outside-git/reviewed-ca.pem", "a" * 64)
    arguments["destination"] = "/srv/platform-pki/frozen/reviewed-ca.pem"

    assert validation_action.validate_arguments(arguments)["destination"] == arguments["destination"]


class _FakeAction(validation_action.ActionModule):
    def __init__(self, args: dict[str, str], *, check_mode: bool) -> None:
        self._task = SimpleNamespace(args=args, check_mode=check_mode)
        self._connection = SimpleNamespace(
            _shell=SimpleNamespace(join_path=os.path.join)
        )
        self.parent: dict[str, object] = {
            "exists": True,
            "isdir": True,
            "islnk": False,
            "uid": 0,
            "gid": 0,
            "mode": "0700",
            "dev": 1,
            "inode": 1,
            "mtime": 1.0,
            "ctime": 1.0,
        }
        self.destination: dict[str, object] = {"exists": False}
        self.remote: dict[str, bytes] = {}
        self.transfer_count = 0
        self.mutate_destination_during_transfer = False
        self.mutate_source_during_transfer: Path | None = None

    def _make_tmp_path(self) -> str:
        return "/remote/action-tmp"

    def _remove_tmp_path(self, remote_tmp: str) -> None:
        self.remote.clear()

    def _transfer_data(self, remote_path: str, data: bytes) -> None:
        self.transfer_count += 1
        self.remote[remote_path] = data
        if self.mutate_destination_during_transfer:
            self.destination = {
                "exists": True,
                "isreg": True,
                "islnk": False,
                "uid": 0,
                "gid": 0,
                "nlink": 1,
                "mode": "0600",
                "checksum": "0" * 64,
                "dev": 1,
                "inode": 99,
                "size": 1,
                "mtime": 2.0,
                "ctime": 2.0,
            }
        if self.mutate_source_during_transfer is not None:
            self.mutate_source_during_transfer.write_bytes(b"changed\n")

    def _execute_module(
        self,
        *,
        module_name: str,
        module_args: dict[str, object],
        task_vars: dict[str, object],
    ) -> dict[str, object]:
        del task_vars
        if module_name == "ansible.legacy.stat":
            if str(module_args["path"]).endswith("/validation-material"):
                return {"changed": False, "stat": dict(self.parent)}
            return {"changed": False, "stat": dict(self.destination)}
        if module_name != "ansible.legacy.copy":
            raise AssertionError(f"unexpected module: {module_name}")
        data = self.remote[str(module_args["src"])]
        self.destination = {
            "exists": True,
            "isreg": True,
            "islnk": False,
            "uid": 0,
            "gid": 0,
            "nlink": 1,
            "mode": module_args["mode"],
            "checksum": hashlib.sha256(data).hexdigest(),
            "dev": 1,
            "inode": 2,
            "size": len(data),
            "mtime": 1.0,
            "ctime": 1.0,
        }
        return {"changed": True}


def test_action_check_mode_and_idempotency(
    isolated_test_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, digest = _source(isolated_test_dir / "reviewed-ca.pem", _reviewed_ca())
    arguments = _arguments(source, digest)
    monkeypatch.setattr(
        ActionBase, "run", lambda self, tmp=None, task_vars=None: {}
    )
    action = _FakeAction(arguments, check_mode=True)

    check = action.run(task_vars={})
    assert check["changed"] is True
    assert check["status"] == "would-deploy"
    assert action.transfer_count == 0
    assert action.destination == {"exists": False}

    action._task.check_mode = False
    first = action.run(task_vars={})
    assert first["changed"] is True
    assert first["status"] == "deployed"
    assert action.transfer_count == 1

    second = action.run(task_vars={})
    assert second["changed"] is False
    assert second["status"] == "existing"
    assert action.transfer_count == 1

    action._task.check_mode = True
    action.destination["islnk"] = True
    action.destination["isreg"] = False
    with pytest.raises(AnsibleActionFail, match="metadata is unsafe"):
        action.run(task_vars={})

    action.destination = {"exists": False}
    action.parent["islnk"] = True
    action.parent["isdir"] = False
    with pytest.raises(AnsibleActionFail, match="directory metadata is unsafe"):
        action.run(task_vars={})


@pytest.mark.parametrize(
    "unsafe",
    (
        {"isreg": False, "islnk": True},
        {"uid": 1},
        {"gid": 1},
        {"nlink": 2},
    ),
)
def test_action_refuses_unsafe_existing_destination(
    unsafe: dict[str, object],
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, digest = _source(isolated_test_dir / "reviewed-ca.pem", _reviewed_ca())
    monkeypatch.setattr(ActionBase, "run", lambda self, tmp=None, task_vars=None: {})
    action = _FakeAction(_arguments(source, digest), check_mode=False)
    action.destination = {
        "exists": True,
        "isreg": True,
        "islnk": False,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "mode": "0600",
        "checksum": "0" * 64,
        "dev": 1,
        "inode": 2,
        "size": 1,
        "mtime": 1.0,
        "ctime": 1.0,
    }
    action.destination.update(unsafe)

    with pytest.raises(AnsibleActionFail, match="metadata is unsafe"):
        action.run(task_vars={})
    assert action.transfer_count == 0


def test_action_rejects_destination_change_during_transfer(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, digest = _source(isolated_test_dir / "reviewed-ca.pem", _reviewed_ca())
    monkeypatch.setattr(ActionBase, "run", lambda self, tmp=None, task_vars=None: {})
    action = _FakeAction(_arguments(source, digest), check_mode=False)
    action.mutate_destination_during_transfer = True

    with pytest.raises(AnsibleActionFail, match="changed during transfer"):
        action.run(task_vars={})
    assert action.transfer_count == 1


def test_action_rejects_source_change_during_transfer(
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = isolated_test_dir / "reviewed-ca.pem"
    source, digest = _source(source_path, _reviewed_ca())
    monkeypatch.setattr(ActionBase, "run", lambda self, tmp=None, task_vars=None: {})
    action = _FakeAction(_arguments(source, digest), check_mode=False)
    action.mutate_source_during_transfer = source_path

    with pytest.raises(AnsibleActionFail, match="changed during transfer"):
        action.run(task_vars={})
    assert action.transfer_count == 1


def test_validation_material_role_and_playbook_are_isolated(repo_root: Path) -> None:
    role_dir = repo_root / "roles/pki_host_local_validation_material"
    defaults = _load_yaml(role_dir / "defaults/main.yml")
    assert defaults == {
        "pki_host_local_validation_material_reviewed_ca_src": "",
        "pki_host_local_validation_material_boundary_src": "",
    }

    playbook_path = repo_root / "playbooks/registry-pki-validation-material.yml"
    plays = _load_yaml(playbook_path)
    assert len(plays) == 1
    assert set(plays[0]) == {"name", "hosts", "become", "gather_facts", "tasks"}
    assert plays[0]["hosts"] == "registry"
    assert plays[0]["become"] is True
    assert plays[0]["gather_facts"] is False
    assert plays[0]["tasks"][0]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_validation_material"
    }

    for path in (
        repo_root / "playbooks/site.yml",
        repo_root / "playbooks/registry.yml",
        repo_root / "roles/pki_host_local_certificate/tasks/main.yml",
    ):
        text = path.read_text(encoding="utf-8")
        assert "pki_host_local_validation_material" not in text
        assert "registry-pki-validation-material.yml" not in text

    tasks = _load_yaml(role_dir / "tasks/main.yml")
    contract = tasks[0]["ansible.builtin.assert"]["that"]
    assert "ansible_play_hosts_all == [inventory_hostname]" in contract
    assert any("remote_validator) | list | length == 1" in item for item in contract)
    for variable in (
        "pki_host_local_certificate_reviewed_ca_target_path",
        "pki_host_local_certificate_reviewed_ca_runner_path",
        "pki_host_local_certificate_validation_boundary_target_path",
        "pki_host_local_certificate_validation_boundary_runner_path",
    ):
        assert f"{variable} is not search('(^|/)\\.\\.?(/|$)')" in contract
        assert f"{variable} is not search('(^|/)(latest|current)(/|$)')" in contract
    action_tasks = [task for task in tasks if "platform_pki_validation_material" in task]
    assert len(action_tasks) == 4
    assert [task.get("delegate_to") for task in action_tasks] == [
        None,
        None,
        "{{ pki_host_local_certificate_remote_validator }}",
        "{{ pki_host_local_certificate_remote_validator }}",
    ]
    assert all(
        set(task["platform_pki_validation_material"])
        == set(validation_action.ACTION_ARGUMENTS)
        for task in action_tasks
    )
    file_tasks = [task for task in tasks if "ansible.builtin.file" in task]
    assert len(file_tasks) == 2
    assert all(task["ansible.builtin.file"]["mode"] == "0700" for task in file_tasks)
    stat_paths = [
        task["ansible.builtin.stat"]["path"]
        for task in tasks
        if "ansible.builtin.stat" in task
    ]
    assert "{{ item }}" in stat_paths
    assert stat_paths.count("{{ item }}") == 4


@pytest.mark.parametrize(
    "arguments",
    (
        ("ENV=", "LIMIT=registry-one.test", "RUNNER_LIMIT=runner-one.test"),
        ("ENV=dev", "LIMIT=", "RUNNER_LIMIT=runner-one.test"),
        ("ENV=dev", "LIMIT=registry-one.test", "RUNNER_LIMIT="),
        ("ENV=Dev", "LIMIT=registry-one.test", "RUNNER_LIMIT=runner-one.test"),
        ("ENV=dev", "LIMIT=registry,other", "RUNNER_LIMIT=runner-one.test"),
        ("ENV=dev", "LIMIT=registry-one.test", "RUNNER_LIMIT=registry-one.test"),
    ),
)
def test_validation_material_make_target_rejects_inexact_coordinates(
    arguments: tuple[str, ...], repo_root: Path, command_runner: CommandRunner
) -> None:
    command_runner.run(
        ("make", "registry-pki-validation-material", *arguments), cwd=repo_root
    ).assert_failure()


def test_validation_material_make_target_pins_play_and_runner(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run(
        (
            "make",
            "-n",
            "registry-pki-validation-material",
            "ENV=dev",
            "LIMIT=registry-one.test",
            "RUNNER_LIMIT=runner-one.test",
        ),
        cwd=repo_root,
    ).assert_success()
    assert "PLAYBOOK=playbooks/registry-pki-validation-material.yml" in result.stdout
    assert "LIMIT='registry-one.test'" in result.stdout
    assert "pki_host_local_certificate_remote_validator=runner-one.test" in result.stdout


def test_request_playbook_pins_typed_request_phase_values(repo_root: Path) -> None:
    play = yaml.safe_load(
        (repo_root / "playbooks/registry-pki-request.yml").read_text(encoding="utf-8")
    )[0]

    assert play["vars"] == {
        "registry_pki_request_ttl_seconds": 3600,
        "pki_host_local_certificate_request_ttl_seconds": (
            "{{ registry_pki_request_ttl_seconds | int }}"
        ),
        "pki_host_local_certificate_validation_boundary_sha256": "",
        "pki_host_local_certificate_rollback_seconds": 0,
    }


def test_request_make_target_passes_explicit_bounded_ttl(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run(
        (
            "make",
            "-n",
            "registry-pki-request",
            "ENV=dev",
            "LIMIT=registry-one.test",
            "REQUEST_TTL_SECONDS=604800",
        ),
        cwd=repo_root,
    ).assert_success()

    assert "registry_pki_request_ttl_seconds=604800" in result.stdout


def test_cancel_make_target_passes_exact_request_coordinates(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    request_id = "0123456789abcdef0123456789abcdef"
    request_sha256 = "a" * 64
    result = command_runner.run(
        (
            "make",
            "-n",
            "registry-pki-cancel-request",
            "ENV=dev",
            "LIMIT=registry-one.test",
            f"REQUEST_ID={request_id}",
            f"REQUEST_SHA256={request_sha256}",
        ),
        cwd=repo_root,
    ).assert_success()

    assert "playbooks/registry-pki-cancel-request.yml" in result.stdout
    assert f"pki_host_local_certificate_request_id={request_id}" in result.stdout
    assert (
        f"pki_host_local_certificate_request_sha256={request_sha256}"
        in result.stdout
    )
