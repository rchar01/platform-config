from __future__ import annotations

import importlib.util
import json
import os
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace

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
    for name in (
        "2026-08-rocky-10.0-to-10.2.yml",
        "2026-08-rocky-10.1-to-10.2.yml",
    ):
        run_playbook(
            command_runner,
            repo_root / "migrations" / name,
            inventory=repo_root / "tests/fixtures/rocky-minor-alignment/inventory.yml",
            syntax_check=True,
        ).assert_success()

    for path in (repo_root / "playbooks").rglob("*.yml"):
        assert "2026-08-rocky-10.1-to-10.2" not in path.read_text(encoding="utf-8")
        assert "2026-08-rocky-10.0-to-10.2" not in path.read_text(encoding="utf-8")


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
        (
            ["preflight", "--env", "dev", "--limit", "host", "--transition", "rocky-10.0-to-10.1"],
            "unsupported Rocky transition",
        ),
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

    migration_10_0 = (
        repo_root / "migrations/2026-08-rocky-10.0-to-10.2.yml"
    ).read_text(encoding="utf-8")
    preflight_10_0 = (
        repo_root / "migrations/tasks/rocky-10.0-to-10.2-preflight.yml"
    ).read_text(encoding="utf-8")
    assert 'rocky_alignment_source_version: "10.0"' in migration_10_0
    assert "rocky_alignment_transition | default('') == 'rocky-10.0-to-10.2'" in migration_10_0
    assert "rocky_10_0_to_10_2_enabled | default(false) | bool" in migration_10_0
    assert "/etc/dnf/vars/releasever" in preflight_10_0
    assert "/etc/yum/vars/releasever" in preflight_10_0
    assert "Rocky 10.1 and every other release fail closed" in preflight_10_0
    verify = (
        repo_root / "migrations/tasks/rocky-minor-alignment-verify.yml"
    ).read_text(encoding="utf-8")
    assert "/etc/dnf/vars/releasever" in verify
    assert "/etc/yum/vars/releasever" in verify
    assert "rocky_alignment_transition == 'rocky-10.0-to-10.2'" in verify


def test_rocky_alignment_capacity_matches_qualified_template(repo_root: Path) -> None:
    preflight = (
        repo_root / "migrations/tasks/rocky-minor-alignment-preflight.yml"
    ).read_text(encoding="utf-8")

    assert "/boot: 536870912" in preflight
    assert "/boot/efi: 134217728" in preflight
    assert "/boot/efi: 268435456" not in preflight


def test_rocky_alignment_binds_transaction_and_installed_state(repo_root: Path) -> None:
    upgrade = (
        repo_root / "migrations/tasks/rocky-minor-alignment-upgrade.yml"
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
        repo_root / "migrations/tasks/rocky-minor-alignment-verify.yml"
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
    assert "eligibility_var=rocky_10_1_to_10_2_enabled" in launcher
    assert "eligibility_var=rocky_10_0_to_10_2_enabled" in launcher
    assert "repositories_var=rocky_10_1_to_10_2_repositories" in launcher
    assert "repositories_var=rocky_10_0_to_10_2_repositories" in launcher


@pytest.mark.parametrize(
    ("transition", "playbook_name"),
    [
        (None, "2026-08-rocky-10.1-to-10.2.yml"),
        ("rocky-10.0-to-10.2", "2026-08-rocky-10.0-to-10.2.yml"),
    ],
)
def test_rocky_alignment_launcher_passes_effective_ssh_arguments(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
    transition: str | None,
    playbook_name: str,
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
    if transition is None:
        transition_vars = {
            "rocky_10_1_to_10_2_enabled": True,
            "rocky_10_1_to_10_2_repositories": {"baseos": {}},
        }
    else:
        transition_vars = {
            "rocky_10_0_to_10_2_enabled": True,
            "rocky_10_0_to_10_2_repositories": {"baseos": {}},
        }
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
                    **transition_vars,
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

    argv = [
        repo_root / "scripts/rocky-minor-alignment",
        "preflight",
        "--env",
        "dev",
        "--limit",
        "rocky-alignment-example",
    ]
    if transition is not None:
        argv.extend(["--transition", transition])
    result = command_runner.run(argv, environment=environment)
    result.assert_success()
    playbook_arguments = playbook_log.read_text(encoding="utf-8").splitlines()
    assert str(inventory) in playbook_arguments
    assert str(repo_root / "migrations" / playbook_name) in playbook_arguments
    assert "rocky_alignment_target_host=rocky-alignment-example" in playbook_arguments
    assert f"rocky_alignment_transition={transition or 'rocky-10.1-to-10.2'}" in playbook_arguments


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


def test_rocky_10_0_alignment_accepts_only_reviewed_credential_free_https(
    repo_root: Path,
) -> None:
    helper = _helper(repo_root)
    profile = helper.transition("rocky-10.0-to-10.2")
    record = {
        "baseurl": ["https://rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/"],
        "gpgcheck": True,
        "gpgkey": ["file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10"],
        "metalink": None,
        "mirrorlist": None,
        "repo_gpgcheck": False,
    }

    def base(value: dict[str, object]) -> SimpleNamespace:
        repo = SimpleNamespace(id="baseos", enabled=True, **value)
        return SimpleNamespace(repos=SimpleNamespace(values=lambda: [repo]))

    assert helper.validate_repositories(base(record), {"baseos": record}, profile) == {
        "baseos": record
    }
    with pytest.raises(helper.AlignmentError, match="unapproved baseurl origin"):
        helper.validate_repositories(base(record), {"baseos": record})
    for origin in (
        "http://rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/",
        "https://user:password@rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/",
        "https://@rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/",
        "https://:@rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/",
        "https://rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/\n",
        "https://rocky-mirror.example.test:invalid/rocky/10/BaseOS/x86_64/os/",
        "https://rocky-mirror.example.test/rocky/10/BaseOS/x86_64/os/#fragment",
        "https://[broken/rocky/10/BaseOS/x86_64/os/",
    ):
        unsafe = dict(record, baseurl=[origin])
        with pytest.raises(helper.AlignmentError, match="unapproved"):
            helper.validate_repositories(base(unsafe), {"baseos": unsafe}, profile)


def test_rocky_10_0_alignment_qualifies_local_signing_key(
    repo_root: Path,
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _helper(repo_root)
    profile = helper.transition("rocky-10.0-to-10.2")
    key = SimpleNamespace(
        is_symlink=lambda: False,
        lstat=lambda: SimpleNamespace(
            st_gid=0,
            st_mode=helper.stat.S_IFREG | 0o644,
            st_uid=0,
        ),
    )
    expected = profile["signing_key_sha256"]
    monkeypatch.setattr(helper, "sha256_file", lambda path: expected)

    helper.validate_signing_key(profile, key)
    monkeypatch.setattr(helper, "sha256_file", lambda path: "0" * 64)
    with pytest.raises(helper.AlignmentError, match="digest differs"):
        helper.validate_signing_key(profile, key)
    with pytest.raises(FileNotFoundError):
        helper.validate_signing_key(profile, isolated_test_dir / "missing-key")
    unsafe_metadata = (
        (helper.stat.S_IFDIR | 0o755, 0, 0, False),
        (helper.stat.S_IFREG | 0o644, 1, 0, False),
        (helper.stat.S_IFREG | 0o644, 0, 1, False),
        (helper.stat.S_IFREG | 0o666, 0, 0, False),
        (helper.stat.S_IFREG | 0o644, 0, 0, True),
    )
    for mode, uid, gid, symlink in unsafe_metadata:
        unsafe_key = SimpleNamespace(
            is_symlink=lambda value=symlink: value,
            lstat=lambda value=(mode, uid, gid): SimpleNamespace(
                st_gid=value[2],
                st_mode=value[0],
                st_uid=value[1],
            ),
        )
        with pytest.raises(helper.AlignmentError, match="ownership or mode"):
            helper.validate_signing_key(profile, unsafe_key)

    helper.validate_signing_key(
        helper.transition("rocky-10.1-to-10.2"), unsafe_key
    )


def test_rocky_10_0_apply_revalidates_signing_key_before_mutation(
    repo_root: Path,
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _helper(repo_root)
    events: list[str] = []
    profile = helper.transition("rocky-10.0-to-10.2")
    manifest = {
        "dnf_version": "4.20.0",
        "download_size": 1,
        "install_size": 1,
        "installed_state_sha256": "a" * 64,
        "migration_id": profile["migration_id"],
        "payloads": [],
        "repositories": {"baseos": {}},
        "schema": 1,
        "source": profile["source"],
        "target": profile["target"],
        "transaction": [],
    }
    lock_base = SimpleNamespace(
        close=lambda: None,
        conf=SimpleNamespace(read=lambda: None, exit_on_lock=False),
    )
    local_base = SimpleNamespace(
        close=lambda: None,
        do_transaction=lambda: events.append("transaction"),
    )
    dnf = SimpleNamespace(Base=lambda: lock_base)
    monkeypatch.setattr(helper, "os_release_version", lambda selected: "10.0")
    monkeypatch.setattr(helper, "load_dnf", lambda release, selected: (dnf, object()))
    monkeypatch.setattr(helper, "load_manifest", lambda staging, digest: manifest)
    monkeypatch.setattr(helper, "installed_state", lambda: ([], "a" * 64))
    monkeypatch.setattr(helper, "verify_payloads", lambda staging, payloads: [])
    monkeypatch.setattr(
        helper,
        "local_transaction",
        lambda loaded_dnf, transaction_module, paths: (local_base, []),
    )
    monkeypatch.setattr(
        helper,
        "qualified_rpmdb_lock",
        lambda loaded_dnf, base: helper.contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        helper,
        "validate_signing_key",
        lambda selected: events.append("key"),
    )
    monkeypatch.setattr(helper, "source_releasever_path", lambda selected: None)
    monkeypatch.setattr(
        helper,
        "write_exclusive",
        lambda path, payload, mode: events.append("phase"),
    )
    args = SimpleNamespace(
        installed_state_sha256="a" * 64,
        manifest_sha256="b" * 64,
        staging=str(isolated_test_dir),
        transition="rocky-10.0-to-10.2",
    )

    assert helper.command_apply(args)["applied"] is True
    assert events == ["key", "phase", "transaction", "phase"]

    events.clear()

    def fail_signing_key(selected: dict[str, object]) -> None:
        raise helper.AlignmentError("signing key changed")

    monkeypatch.setattr(helper, "validate_signing_key", fail_signing_key)
    with pytest.raises(helper.AlignmentError, match="signing key changed"):
        helper.command_apply(args)
    assert events == []


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
    profile = helper.transition("rocky-10.1-to-10.2")
    expected = frozenset(qualified.splitlines())
    assert helper.qualified_dnf_packages("10.1", profile) == expected
    assert helper.qualified_dnf_packages("10.2", profile) == expected
    with pytest.raises(helper.AlignmentError, match="current Rocky release"):
        helper.qualified_dnf_packages(
            "10.2", helper.transition("rocky-10.0-to-10.2")
        )

    unqualified = qualified.replace("libdnf-0:0.73.1-12", "libdnf-0:0.73.1-13")
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=unqualified),
    )
    with pytest.raises(helper.AlignmentError, match="differ from the qualified"):
        helper.qualified_dnf_packages("10.1", profile)


def test_rocky_alignment_qualifies_exact_10_0_dnf_packages(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    qualified = """dnf-0:4.20.0-14.el10_0.rocky.0.1.noarch
python3-dnf-0:4.20.0-14.el10_0.rocky.0.1.noarch
libdnf-0:0.73.1-9.el10_0.rocky.0.1.x86_64
"""
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=qualified),
    )

    profile = helper.transition("rocky-10.0-to-10.2")
    packages = helper.qualified_dnf_packages("10.0", profile)
    assert packages == frozenset(qualified.splitlines())
    assert helper.DNF_QUALIFICATIONS[packages]["do_transaction_sha256"] == (
        "046c279ebcc9f7fc207fa513300889dd6be5cd1c2583b4041900c89b602a278c"
    )
    with pytest.raises(helper.AlignmentError, match="current Rocky release"):
        helper.qualified_dnf_packages("10.1", profile)


def test_rocky_alignment_enforces_10_0_dnf_source_digest(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    qualified = """dnf-0:4.20.0-14.el10_0.rocky.0.1.noarch
python3-dnf-0:4.20.0-14.el10_0.rocky.0.1.noarch
libdnf-0:0.73.1-9.el10_0.rocky.0.1.x86_64
"""
    monkeypatch.setattr(
        helper.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=qualified),
    )
    dnf = ModuleType("dnf")
    dnf.__path__ = []
    dnf.VERSION = "4.20.0"
    dnf.Base = type("Base", (), {"do_transaction": lambda self: None})
    lock = ModuleType("dnf.lock")
    transaction = ModuleType("dnf.transaction")
    dnf.lock = lock
    dnf.transaction = transaction
    monkeypatch.setitem(sys.modules, "dnf", dnf)
    monkeypatch.setitem(sys.modules, "dnf.lock", lock)
    monkeypatch.setitem(sys.modules, "dnf.transaction", transaction)
    monkeypatch.setattr(helper.inspect, "getsource", lambda function: "qualified")
    expected_digest = (
        "046c279ebcc9f7fc207fa513300889dd6be5cd1c2583b4041900c89b602a278c"
    )
    monkeypatch.setattr(helper, "sha256_bytes", lambda payload: expected_digest)
    profile = helper.transition("rocky-10.0-to-10.2")

    assert helper.load_dnf("10.0", profile) == (dnf, transaction)
    monkeypatch.setattr(helper, "sha256_bytes", lambda payload: "0" * 64)
    with pytest.raises(helper.AlignmentError, match="implementation differs"):
        helper.load_dnf("10.0", profile)


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
        helper.qualified_dnf_packages(
            "10.1", helper.transition("rocky-10.1-to-10.2")
        )


def test_rocky_alignment_manifest_is_bound_to_selected_transition(
    repo_root: Path,
) -> None:
    helper = _helper(repo_root)
    profile = helper.transition("rocky-10.0-to-10.2")
    manifest = {
        "dnf_version": "4.20.0",
        "download_size": 1,
        "install_size": 1,
        "installed_state_sha256": "a" * 64,
        "migration_id": "2026-08-rocky-10.0-to-10.2",
        "payloads": [],
        "repositories": {"baseos": {}},
        "schema": 1,
        "source": "10.0",
        "target": "10.2",
        "transaction": [],
    }

    helper.validate_manifest_identity(manifest, profile)
    with pytest.raises(helper.AlignmentError, match="transition identity"):
        helper.validate_manifest_identity(
            manifest,
            helper.transition("rocky-10.1-to-10.2"),
        )


def test_rocky_alignment_marker_is_bound_to_selected_transition(
    repo_root: Path,
) -> None:
    helper = _helper(repo_root)
    marker = {
        "completed_at": "2026-08-24T12:00:00Z",
        "manifest_sha256": "a" * 64,
        "migration_id": "2026-08-rocky-10.0-to-10.2",
        "running_kernel": "6.12.0-test",
        "schema": 1,
        "source": "10.0",
        "target": "10.2",
    }

    helper.validate_marker_identity(
        marker, helper.transition("rocky-10.0-to-10.2")
    )
    with pytest.raises(helper.AlignmentError, match="transition identity"):
        helper.validate_marker_identity(
            marker, helper.transition("rocky-10.1-to-10.2")
        )


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
