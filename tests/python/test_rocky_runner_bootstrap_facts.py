from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import json
import os
import pwd
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


SCRIPT = Path("scripts/rocky-runner-bootstrap-facts")


@pytest.fixture(scope="module")
def collector_module(repo_root: Path) -> ModuleType:
    path = repo_root / SCRIPT
    loader = importlib.machinery.SourceFileLoader(
        "rocky_runner_bootstrap_facts", str(path)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_collector_is_executable_and_has_valid_cli(
    tmp_path: Path, repo_root: Path, command_runner
) -> None:
    script = repo_root / SCRIPT

    assert script.is_file()
    assert script.stat().st_mode & 0o111
    assert script.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3\n")
    command_runner.run(
        ["python3", "-m", "py_compile", script],
        environment={"PYTHONPYCACHEPREFIX": str(tmp_path / "pycache")},
    ).assert_success()
    help_result = command_runner.run([script, "--help"]).assert_success()
    assert "--controller-user" in help_result.stdout
    assert "keep the report outside Git" in help_result.stdout


def test_documented_vm_invocation_keeps_report_private(repo_root: Path) -> None:
    documentation = (repo_root / "docs/gitlab-runner-self-bootstrap.md").read_text(
        encoding="utf-8"
    )

    assert "umask 077" in documentation
    assert "sudo python3 ./scripts/rocky-runner-bootstrap-facts" in documentation
    assert "--controller-user ansible" in documentation
    assert "python3 -m json.tool" in documentation
    assert "Keep the report outside Git" in documentation


def test_collector_rejects_unsafe_user_before_collection(
    repo_root: Path, command_runner
) -> None:
    result = command_runner.run(
        [repo_root / SCRIPT, "--controller-user", "../ansible"]
    ).assert_failure()

    assert result.returncode == 2
    assert "one literal Linux account name" in result.stderr
    assert result.stdout == ""


def test_collector_requires_root(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(collector_module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        collector_module,
        "collect_report",
        lambda _username: pytest.fail("collection must not run without root"),
    )

    assert collector_module.main(["--controller-user", "ansible"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "run this collector with sudo" in captured.err


def test_url_and_text_redaction_removes_credentials(
    collector_module: ModuleType,
) -> None:
    secret_url = "https://alice:s3cr3t@repo.example.test/rocky?token=qwerty#internal"

    sanitized, components = collector_module.sanitize_url(secret_url)
    text = collector_module.sanitize_text(
        f"origin={secret_url} password=hunter2 token=abcd"
    )

    assert sanitized == (
        "https://<redacted-auth>@repo.example.test/rocky?"
        "<redacted>#<redacted>"
    )
    assert components == ["userinfo", "query", "fragment"]
    for secret in ("alice", "s3cr3t", "qwerty", "internal", "hunter2", "abcd"):
        assert secret not in text
    assert "password=<redacted>" in text
    assert "token=<redacted>" in text


@pytest.mark.parametrize(
    ("value", "secret"),
    (
        ("access_token=access-value", "access-value"),
        ("bearer_token=bearer-value", "bearer-value"),
        ("api_key=api-value", "api-value"),
        ("Authorization: Bearer header-value", "header-value"),
        ("https://repo.example.test/token/path-value", "path-value"),
        ("https://repo.example.test/access_token=segment-value", "segment-value"),
        ("https://repo.example.test/path?bearer_token=query-value", "query-value"),
        ('token="quoted secret value" trailing', "quoted secret value"),
        ("access_token='comma,secret,value' trailing", "comma,secret,value"),
        ('bearer "escaped \\"secret\\" value" trailing', 'escaped \\"secret\\" value'),
    ),
)
def test_redaction_covers_common_credential_forms(
    value: str, secret: str, collector_module: ModuleType
) -> None:
    assert secret not in collector_module.sanitize_text(value)


def test_command_output_is_redacted(
    tmp_path: Path,
    collector_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "facts-output"
    executable.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'https://alice:s3cr3t@repo.example.test/path?token=qwerty'\n"
        "printf '%s\\n' 'password=stderr-secret' >&2\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setattr(
        collector_module,
        "COMMAND_PATH",
        f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
    )

    result = collector_module.command_result([executable.name])

    serialized = json.dumps(result)
    for secret in ("alice", "s3cr3t", "qwerty", "stderr-secret"):
        assert secret not in serialized
    assert "<redacted-auth>" in result["stdout"]
    assert result["stderr"] == "password=<redacted>"


def test_missing_command_is_reported_without_failure(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_module, "COMMAND_PATH", "")

    result = collector_module.command_result(["definitely-not-installed"])

    assert result == {
        "argv": ["definitely-not-installed"],
        "returncode": None,
        "stderr": "required executable not found: definitely-not-installed",
        "stdout": "",
    }


def test_command_errors_and_invalid_bytes_are_structured(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_module.shutil, "which", lambda *_args, **_kwargs: "/bin/tool")
    monkeypatch.setattr(
        collector_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("exec failed")),
    )

    failed = collector_module.command_result(["tool"])

    assert failed["returncode"] is None
    assert failed["stderr"] == "OSError: exec failed"

    monkeypatch.setattr(
        collector_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b"value=\xff access_token=private-value\n",
            stderr=b"warning=\xfe",
        ),
    )
    decoded = collector_module.command_result(["tool"])

    assert "\ufffd" in decoded["stdout"]
    assert "private-value" not in decoded["stdout"]


def test_fstab_collection_is_targeted_and_redacts_sensitive_options(
    tmp_path: Path, collector_module: ModuleType
) -> None:
    fstab = tmp_path / "fstab"
    fstab.write_text(
        "UUID=root / xfs defaults 0 0\n"
        "UUID=var /var xfs rw,nodev,password=secret 0 0\n"
        "//server/share /mnt/private cifs credentials=/root/creds 0 0\n",
        encoding="utf-8",
    )

    result = collector_module.collect_fstab(
        fstab, (Path("/"), Path("/var"))
    )

    assert result["entries"] == [
        {
            "filesystem": "xfs",
            "line": 1,
            "options": "defaults",
            "source": "UUID=root",
            "target": "/",
        },
        {
            "filesystem": "xfs",
            "line": 2,
            "options": "rw,nodev,password=<redacted>",
            "source": "UUID=var",
            "target": "/var",
        },
    ]
    assert "server" not in json.dumps(result)
    assert "secret" not in json.dumps(result)


def test_key_collection_emits_fingerprints_not_public_key_material(
    tmp_path: Path, collector_module: ModuleType
) -> None:
    key_blob = base64.b64encode(b"public-key-fixture").decode()
    key_file = tmp_path / "authorized_keys"
    key_file.write_text(
        f'from="192.0.2.1" ssh-ed25519 {key_blob} operator@example.test\n',
        encoding="utf-8",
    )

    result = collector_module.key_file_fingerprints_beneath(
        tmp_path, Path("authorized_keys")
    )
    serialized = json.dumps(result)

    assert result["exists"] is True
    assert result["keys"][0]["type"] == "ssh-ed25519"
    assert result["keys"][0]["fingerprint"].startswith("SHA256:")
    assert key_blob not in serialized
    assert "operator@example.test" not in serialized
    assert "192.0.2.1" not in serialized


def test_storage_config_collection_is_bounded(
    tmp_path: Path, collector_module: ModuleType
) -> None:
    config = tmp_path / "storage.conf"
    config.write_text(
        "[storage]\n"
        'driver = "overlay"\n'
        'runroot = "/run/user/1000/containers"\n'
        'graphroot = "/srv/bootstrap/containers"\n'
        "[storage.options.overlay]\n"
        'mountopt = "nodev"\n'
        "[engine]\n"
        'authfile = "/secret/registry-auth.json"\n',
        encoding="utf-8",
    )

    result = collector_module.collect_storage_config(config)

    assert result == {
        "driver": "overlay",
        "exists": True,
        "graphroot": "/srv/bootstrap/containers",
        "mountopt": "nodev",
        "path": str(config),
        "runroot": "/run/user/1000/containers",
        "size_bytes": config.stat().st_size,
    }
    assert "authfile" not in json.dumps(result)


def test_storage_config_selected_values_are_redacted(
    tmp_path: Path, collector_module: ModuleType
) -> None:
    config = tmp_path / "storage.conf"
    config.write_text(
        "[storage]\n"
        'driver = "overlay access_token=driver-value"\n'
        'runroot = "https://alice:s3cr3t@run.example/path"\n'
        'graphroot = "/srv/token/graph-value"\n'
        "[storage.options.overlay]\n"
        'mountopt = "nodev,bearer_token=mount-value"\n',
        encoding="utf-8",
    )

    serialized = json.dumps(collector_module.collect_storage_config(config))

    for secret in (
        "driver-value",
        "alice",
        "s3cr3t",
        "graph-value",
        "mount-value",
    ):
        assert secret not in serialized


def test_descendant_mounts_are_skipped_before_user_file_open(
    tmp_path: Path, collector_module: ModuleType
) -> None:
    home = tmp_path / "home"
    ssh = home / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "authorized_keys").write_text("private-value", encoding="utf-8")
    mount_table = {
        "command": {},
        "records": [
            {"fstype": "xfs", "target": "/"},
            {"fstype": "fuse.sshfs", "target": str(ssh)},
        ],
    }

    result = collector_module.key_file_fingerprints_beneath(
        home, Path(".ssh/authorized_keys"), mount_table
    )

    assert "crosses descendant mount" in result["inspection_skipped"]
    assert "private-value" not in json.dumps(result)


def test_user_controlled_key_paths_skip_symlinks_special_files_and_large_files(
    tmp_path: Path, collector_module: ModuleType
) -> None:
    root = tmp_path / "home"
    ssh = root / ".ssh"
    ssh.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("private-value", encoding="utf-8")
    (ssh / "linked").symlink_to(outside)
    os.mkfifo(ssh / "fifo")
    (ssh / "large").write_bytes(b"x" * 9)

    linked = collector_module.key_file_fingerprints_beneath(
        root, Path(".ssh/linked")
    )
    fifo = collector_module.key_file_fingerprints_beneath(root, Path(".ssh/fifo"))
    content, large = collector_module.read_regular_file_beneath(
        root, Path(".ssh/large"), maximum_bytes=8
    )

    assert "inspection_skipped" in linked
    assert "private-value" not in json.dumps(linked)
    assert fifo["inspection_skipped"] == "path is not a regular file"
    assert content is None
    assert "exceeds 8 byte" in large["inspection_skipped"]


def test_relative_account_home_is_not_inspected(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    account = pwd.struct_passwd(
        ("ansible", "x", 1000, 1000, "", "relative/home", "/bin/bash")
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(collector_module.pwd, "getpwnam", lambda _user: account)
    monkeypatch.setattr(collector_module, "subordinate_ids", lambda path, user: {})
    monkeypatch.setattr(
        collector_module,
        "command_result",
        lambda argv, **_kwargs: calls.append(argv)
        or {"argv": argv, "returncode": 0, "stderr": "", "stdout": ""},
    )

    result = collector_module.collect_access(
        "ansible", {"command": {}, "records": [{"fstype": "xfs", "target": "/"}]}
    )

    assert "absolute normalized path" in result["home"]["inspection_skipped"]
    assert not any(argv[0] == "runuser" for argv in calls)


def test_remote_and_automount_paths_are_not_dereferenced(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    mount_table = {
        "command": {},
        "records": [
            {"fstype": "xfs", "target": "/"},
            {"fstype": "nfs4", "target": "/home"},
            {"fstype": "autofs", "target": "/var/lib/containers"},
        ],
    }
    inspected: list[Path] = []
    monkeypatch.setattr(
        collector_module,
        "file_metadata",
        lambda path: inspected.append(path) or {"path": str(path)},
    )

    home = collector_module.local_path_metadata(Path("/home/ansible"), mount_table)
    containers = collector_module.local_path_metadata(
        Path("/var/lib/containers"), mount_table
    )
    local = collector_module.local_path_metadata(Path("/var"), mount_table)

    assert "inspection_skipped" in home
    assert home["containing_filesystem"] == "nfs4"
    assert "inspection_skipped" in containers
    assert containers["containing_filesystem"] == "autofs"
    assert local == {"path": "/var"}
    assert inspected == [Path("/var")]


def test_observational_command_set_excludes_network_and_mutation(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def record(argv: list[str], *, timeout: int = 30) -> dict[str, object]:
        calls.append(argv)
        stdout = ""
        if argv[0] == "findmnt":
            stdout = json.dumps(
                {
                    "filesystems": [
                        {
                            "fstype": "xfs",
                            "fsroot": "/",
                            "options": "rw",
                            "source": "/dev/mapper/system-root",
                            "target": "/",
                        }
                    ]
                }
            )
        return {"argv": argv, "returncode": 0, "stderr": "", "stdout": stdout}

    account = pwd.struct_passwd(("ansible", "x", 1000, 1000, "", "/home/ansible", "/bin/bash"))
    monkeypatch.setattr(collector_module, "command_result", record)
    monkeypatch.setattr(collector_module, "collect_disk_links", lambda: [])
    monkeypatch.setattr(collector_module, "collect_fstab", lambda: {})
    monkeypatch.setattr(
        collector_module,
        "file_metadata",
        lambda path: {"kind": "directory", "path": str(path)},
    )
    monkeypatch.setattr(
        collector_module, "collect_storage_config", lambda path, *_args: {}
    )
    monkeypatch.setattr(
        collector_module,
        "collect_storage_config_beneath",
        lambda root, path, *_args: {},
    )
    monkeypatch.setattr(
        collector_module,
        "key_file_fingerprints_beneath",
        lambda root, path, *_args: {},
    )
    monkeypatch.setattr(collector_module, "subordinate_ids", lambda path, user: {})
    monkeypatch.setattr(collector_module.pwd, "getpwnam", lambda _user: account)

    collector_module.collect_report("ansible")

    allowed_commands = {
        "blkid",
        "df",
        "findmnt",
        "getenforce",
        "hostnamectl",
        "id",
        "ip",
        "lsblk",
        "lvs",
        "pvs",
        "rpm",
        "runuser",
        "systemctl",
        "timedatectl",
        "update-crypto-policies",
        "vgs",
    }
    assert calls
    assert {argv[0] for argv in calls} <= allowed_commands
    assert ["runuser", "--user", "ansible", "--", "sudo", "-n", "true"] in calls
    assert not {
        "curl",
        "dnf",
        "du",
        "lvcreate",
        "lvextend",
        "mkfs",
        "mount",
        "podman",
        "reboot",
        "ssh",
        "wget",
    } & {argv[0] for argv in calls}
    for argv in calls:
        if argv[0] == "systemctl":
            assert argv[1] in {"--failed", "show"}


def test_dnf_inspection_does_not_load_repository_metadata(
    repo_root: Path,
) -> None:
    source = (repo_root / SCRIPT).read_text(encoding="utf-8")

    assert "base.read_all_repos()" in source
    assert "fill_sack" not in source
    assert "repoquery" not in source
    assert "subprocess.run(" in source
    assert "shell=True" not in source


def test_root_run_emits_one_json_report(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(collector_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        collector_module,
        "collect_report",
        lambda username: {
            "collection": {"controller_user": username},
            "schema": collector_module.SCHEMA,
        },
    )

    assert collector_module.main(["--controller-user", "ansible"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "collection": {"controller_user": "ansible"},
        "schema": "platform.rocky-runner-bootstrap-facts.v1",
    }
    assert collector_module.WARNING in captured.err


def test_collection_failure_still_emits_valid_json(
    collector_module: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(collector_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        collector_module,
        "collect_report",
        lambda _username: (_ for _ in ()).throw(RuntimeError("token=private-value")),
    )

    assert collector_module.main(["--controller-user", "ansible"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["schema"] == "platform.rocky-runner-bootstrap-facts.v1"
    assert report["collection"]["controller_user"] == "ansible"
    assert "private-value" not in captured.out
    assert "token=<redacted>" in report["collection"]["collection_error"]
    assert "Traceback" not in captured.err
