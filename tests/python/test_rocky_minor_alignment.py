from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

from ansible_test_helpers import run_playbook
from conftest import CommandRunner


def _helper(repo_root: Path):
    path = repo_root / "migrations/files/platform-rocky-minor-alignment"
    loader = SourceFileLoader("platform_rocky_minor_alignment", str(path))
    spec = importlib.util.spec_from_loader(
        "platform_rocky_minor_alignment", loader
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Rocky alignment helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_rocky_alignment_playbook_syntax_and_isolation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    migration = repo_root / "migrations/2026-08-rocky-10.1-to-10.2.yml"
    run_playbook(
        command_runner,
        migration,
        inventory=repo_root / "tests/fixtures/rocky-minor-alignment/inventory.yml",
        syntax_check=True,
    ).assert_success()

    for path in (repo_root / "playbooks").rglob("*.yml"):
        assert "2026-08-rocky-10.1-to-10.2" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ([], "Usage:"),
        (["unknown"], "unsupported operation"),
        (["preflight"], "--env"),
        (["preflight", "--env", "DEV", "--limit", "host"], "literal environment"),
        (["preflight", "--env", "dev", "--limit", ""], "one literal"),
        (["preflight", "--env", "dev", "--limit", "*"], "one literal"),
        (["preflight", "--env", "dev", "--limit", "group:host"], "one literal"),
        (["preflight", "--env", "dev", "--limit", "host,other"], "one literal"),
        (["preflight", "--env", "dev", "--limit", "-host"], "one literal"),
    ],
)
def test_rocky_alignment_launcher_rejects_unsafe_arguments(
    repo_root: Path,
    command_runner: CommandRunner,
    argv: list[str],
    message: str,
) -> None:
    result = command_runner.run([repo_root / "scripts/rocky-minor-alignment", *argv])
    result.assert_failure()
    assert message in result.stderr


def test_rocky_alignment_has_fixed_transition_and_private_gate(repo_root: Path) -> None:
    playbook = (
        repo_root / "migrations/2026-08-rocky-10.1-to-10.2.yml"
    ).read_text(encoding="utf-8")
    preflight = (
        repo_root / "migrations/tasks/rocky-10.1-to-10.2-preflight.yml"
    ).read_text(encoding="utf-8")

    assert 'rocky_alignment_source_version: "10.1"' in playbook
    assert 'rocky_alignment_target_version: "10.2"' in playbook
    assert "rocky_10_1_to_10_2_enabled | default(false) | bool" in playbook
    assert "Rocky 10.0 and every other release fail closed" in preflight
    assert "--allowerasing" not in preflight
    assert "distro-sync" not in preflight


def test_rocky_alignment_binds_transaction_and_installed_state(repo_root: Path) -> None:
    upgrade = (
        repo_root / "migrations/tasks/rocky-10.1-to-10.2-upgrade.yml"
    ).read_text(encoding="utf-8")

    helper = (
        repo_root / "migrations/files/platform-rocky-minor-alignment"
    ).read_text(encoding="utf-8")

    assert "download_packages" in helper
    assert 'staging / "manifest.json"' in helper
    assert "sha256_file" in helper
    assert "installed_state()" in helper
    assert "qualified_rpmdb_lock" in helper
    assert "local-only DNF action set differs" in helper
    assert "releasever.unlink()" in helper
    assert helper.index("installed RPM state changed after approval") < helper.index(
        "releasever.unlink()"
    )
    assert "load_available_repos=False" in helper
    assert "allow_erasing=False" in helper
    assert "--allowerasing" not in upgrade
    assert "distro-sync" not in upgrade


def test_rocky_alignment_marker_follows_verification(repo_root: Path) -> None:
    verify = (
        repo_root / "migrations/tasks/rocky-10.1-to-10.2-verify.yml"
    ).read_text(encoding="utf-8")

    marker = verify.index("Publish and validate the migration completion marker exclusively")
    assert verify.index("Require the Rocky 10.2 target release") < marker
    assert verify.index("Recheck installed RPM dependency state") < marker
    assert verify.index("Verify the running kernel package") < marker
    assert verify.index("Require no failed units after Rocky alignment") < marker
    helper = (
        repo_root / "migrations/files/platform-rocky-minor-alignment"
    ).read_text(encoding="utf-8")
    assert "os.O_EXCL" in helper
    assert "os.O_NOFOLLOW" in helper
    assert "os.fsync" in helper


def test_rocky_alignment_launcher_uses_isolated_inventory(repo_root: Path) -> None:
    launcher = (repo_root / "scripts/rocky-minor-alignment").read_text(
        encoding="utf-8"
    )

    assert '$environment-rocky-alignment/hosts.yml' in launcher
    assert "--inventory" not in launcher
    assert "rocky_alignment_hosts must contain exactly one member" in launcher
    assert "HOST_KEY_CHECKING must be true" in launcher
    assert "accept-new" in launcher
    assert "ssh_g_output=" in launcher


def test_rocky_alignment_launcher_passes_effective_ssh_arguments(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    private_root = isolated_test_dir / "platform-private"
    inventory = private_root / "config/inventories/dev-rocky-alignment/hosts.yml"
    inventory.parent.mkdir(parents=True)
    inventory.write_text("---\n", encoding="utf-8")
    env_file = private_root / "config/dev.ansible.env"
    env_file.write_text("# Mock environment.\n", encoding="utf-8")
    bin_dir = isolated_test_dir / "bin"
    bin_dir.mkdir()
    playbook_log = isolated_test_dir / "playbook.log"
    inventory_data = {
        "rocky_alignment_hosts": {"hosts": ["rocky-alignment-example"]},
        "_meta": {
            "hostvars": {
                "rocky-alignment-example": {
                    "ansible_connection": "ansible.builtin.ssh",
                    "ansible_host": "192.0.2.90",
                    "ansible_port": 2222,
                    "ansible_user": "rocky",
                    "ansible_ssh_common_args": (
                        "-F /etc/ssh/ssh_config "
                        "-o HostKeyAlias=runner-rebuilt "
                        "-o StrictHostKeyChecking=yes "
                        "-o UserKnownHostsFile=/tmp/known_hosts"
                    ),
                    "rocky_10_1_to_10_2_enabled": True,
                    "rocky_10_1_to_10_2_repositories": {"baseos": {}},
                }
            }
        },
    }
    _write_executable(
        bin_dir / "ansible-inventory",
        "#!/bin/sh\nprintf '%s\\n' '" + json.dumps(inventory_data) + "'\n",
    )
    _write_executable(
        bin_dir / "ansible-config",
        """#!/bin/sh
case " $* " in
  *" --type connection "*)
    printf '%s\n' '[{"ssh":[{"name":"ssh_args","value":"-C"},{"name":"ssh_common_args","value":""},{"name":"ssh_executable","value":"/usr/bin/ssh"},{"name":"ssh_extra_args","value":""}]}]'
    ;;
  *) printf '%s\n' '[{"name":"HOST_KEY_CHECKING","value":true}]' ;;
esac
""",
    )
    _write_executable(
        bin_dir / "ansible",
        """#!/bin/sh
printf '%s\n' '  hosts (1):' '    rocky-alignment-example'
""",
    )
    _write_executable(
        bin_dir / "ansible-playbook",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$ROCKY_PLAYBOOK_LOG\"\n",
    )
    environment = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PLATFORM_CONFIG_PRIVATE_ROOT": str(private_root),
        "ROCKY_PLAYBOOK_LOG": str(playbook_log),
    }

    result = command_runner.run(
        [
            repo_root / "scripts/rocky-minor-alignment",
            "preflight",
            "--env",
            "dev",
            "--limit",
            "rocky-alignment-example",
        ],
        environment=environment,
    )
    result.assert_success()
    playbook_arguments = playbook_log.read_text(encoding="utf-8").splitlines()
    assert str(inventory) in playbook_arguments
    assert "rocky_alignment_target_host=rocky-alignment-example" in playbook_arguments


@pytest.mark.parametrize(
    ("connection", "ssh_executable", "message"),
    [
        ("local", "", "ansible_connection must be ansible.builtin.ssh"),
        (
            "ansible.builtin.ssh",
            "unreviewed-ssh",
            "must resolve to /usr/bin/ssh",
        ),
    ],
)
def test_rocky_alignment_launcher_rejects_unvalidated_connection(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
    connection: str,
    ssh_executable: str,
    message: str,
) -> None:
    private_root = isolated_test_dir / "platform-private"
    inventory = private_root / "config/inventories/dev-rocky-alignment/hosts.yml"
    inventory.parent.mkdir(parents=True)
    inventory.write_text("---\n", encoding="utf-8")
    (private_root / "config/dev.ansible.env").write_text(
        "# Mock environment.\n", encoding="utf-8"
    )
    bin_dir = isolated_test_dir / "bin"
    bin_dir.mkdir()
    inventory_data = {
        "rocky_alignment_hosts": {"hosts": ["rocky-alignment-example"]},
        "_meta": {
            "hostvars": {
                "rocky-alignment-example": {
                    "ansible_connection": connection,
                    "ansible_ssh_executable": ssh_executable,
                    "rocky_10_1_to_10_2_enabled": True,
                    "rocky_10_1_to_10_2_repositories": {"baseos": {}},
                }
            }
        },
    }
    _write_executable(
        bin_dir / "ansible-inventory",
        "#!/bin/sh\nprintf '%s\\n' '" + json.dumps(inventory_data) + "'\n",
    )
    for executable in ("ansible", "ansible-playbook", "unreviewed-ssh"):
        _write_executable(bin_dir / executable, "#!/bin/sh\nexit 0\n")
    _write_executable(
        bin_dir / "ansible-config",
        """#!/bin/sh
case " $* " in
  *" --type connection "*)
    printf '%s\n' '[{"ssh":[{"name":"ssh_args","value":""},{"name":"ssh_common_args","value":""},{"name":"ssh_executable","value":"/usr/bin/ssh"},{"name":"ssh_extra_args","value":""}]}]'
    ;;
  *) printf '%s\n' '[{"name":"HOST_KEY_CHECKING","value":true}]' ;;
esac
""",
    )
    environment = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PLATFORM_CONFIG_PRIVATE_ROOT": str(private_root),
    }

    result = command_runner.run(
        [
            repo_root / "scripts/rocky-minor-alignment",
            "preflight",
            "--env",
            "dev",
            "--limit",
            "rocky-alignment-example",
        ],
        environment=environment,
    )
    result.assert_failure()
    assert message in result.stderr


def test_rocky_alignment_repository_policy_binds_origins(repo_root: Path) -> None:
    helper = _helper(repo_root)
    record = {
        "baseurl": [],
        "gpgcheck": True,
        "gpgkey": ["file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10"],
        "metalink": None,
        "mirrorlist": "https://mirrors.rockylinux.org/mirrorlist?repo=BaseOS-10",
        "repo_gpgcheck": False,
    }
    repo = SimpleNamespace(id="baseos", enabled=True, **record)
    base = SimpleNamespace(repos=SimpleNamespace(values=lambda: [repo]))

    assert helper.validate_repositories(base, {"baseos": record}) == {
        "baseos": record
    }
    malicious = dict(record, mirrorlist="https://mirror.example.test/rocky")
    with pytest.raises(helper.AlignmentError, match="differ from the reviewed policy"):
        helper.validate_repositories(base, {"baseos": malicious})
    unqualified_key = dict(record, gpgkey=["file:///tmp/unqualified-key"])
    unqualified_repo = SimpleNamespace(
        id="baseos", enabled=True, **unqualified_key
    )
    unqualified_base = SimpleNamespace(
        repos=SimpleNamespace(values=lambda: [unqualified_repo])
    )
    with pytest.raises(helper.AlignmentError, match="qualified Rocky 10 signing key"):
        helper.validate_repositories(unqualified_base, {"baseos": unqualified_key})


def test_rocky_alignment_rejects_unqualified_dnf_packages(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    qualified = """dnf-0:4.20.0-18.el10.rocky.0.1.noarch
python3-dnf-0:4.20.0-18.el10.rocky.0.1.noarch
libdnf-0:0.73.1-12.el10.rocky.0.1.x86_64
"""
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=qualified),
    )
    assert helper.qualified_dnf_packages() == helper.QUALIFIED_DNF_PACKAGES[0]

    unqualified = qualified.replace("libdnf-0:0.73.1-12", "libdnf-0:0.73.1-13")
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=unqualified),
    )
    with pytest.raises(helper.AlignmentError, match="differ from the qualified"):
        helper.qualified_dnf_packages()


def test_rocky_alignment_rejects_duplicate_dnf_packages(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    duplicate = """dnf-0:4.20.0-18.el10.rocky.0.1.noarch
dnf-0:4.20.0-18.el10.rocky.0.1.noarch
libdnf-0:0.73.1-12.el10.rocky.0.1.x86_64
"""
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=duplicate),
    )
    with pytest.raises(helper.AlignmentError, match="exactly one installed build"):
        helper.qualified_dnf_packages()


def test_rocky_alignment_checks_capacity_before_download(
    repo_root: Path,
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _helper(repo_root)
    cache = isolated_test_dir / "cache"
    staging = isolated_test_dir / "staging"
    staging.mkdir()
    base = SimpleNamespace(conf=SimpleNamespace(cachedir=str(cache)))
    packages = [SimpleNamespace(downloadsize=1024)]
    filesystem = SimpleNamespace(f_bavail=1, f_frsize=1)
    monkeypatch.setattr(helper.os, "statvfs", lambda path: filesystem)

    with pytest.raises(helper.AlignmentError, match="insufficient free space"):
        helper.require_download_capacity(base, packages, staging)


def test_rocky_alignment_rejects_destructive_transaction_actions(repo_root: Path) -> None:
    helper = _helper(repo_root)
    transaction_module = SimpleNamespace(
        PKG_INSTALL=1,
        PKG_DOWNGRADE=2,
        PKG_DOWNGRADED=3,
        PKG_OBSOLETE=4,
        PKG_OBSOLETED=5,
        PKG_UPGRADE=6,
        PKG_UPGRADED=7,
        PKG_REMOVE=8,
        PKG_REINSTALL=9,
        PKG_REINSTALLED=10,
    )
    erase = SimpleNamespace(
        action=8,
        name="unsafe",
        nevra="unsafe-0:1-1.x86_64",
        from_repo="@System",
        version="1",
    )

    with pytest.raises(helper.AlignmentError, match="prohibited actions: erase"):
        helper.transaction_rows([erase], transaction_module)


def test_rocky_alignment_exclusive_write_rejects_overwrite(
    repo_root: Path, isolated_test_dir: Path
) -> None:
    helper = _helper(repo_root)
    target = isolated_test_dir / "exclusive.json"

    helper.write_exclusive(target, b"first\n", 0o600)
    with pytest.raises(FileExistsError):
        helper.write_exclusive(target, b"second\n", 0o600)
    assert target.read_bytes() == b"first\n"
