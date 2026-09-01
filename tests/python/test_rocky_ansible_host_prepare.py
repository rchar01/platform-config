from __future__ import annotations

import base64
import importlib.util
import os
import stat
import struct
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _helper(repo_root: Path) -> ModuleType:
    path = repo_root / "scripts/rocky-ansible-host-prepare"
    loader = SourceFileLoader("platform_rocky_ansible_host_prepare", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Rocky Ansible host preparer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _public_key(comment: str = "opl test") -> bytes:
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes(range(32)))
    encoded = base64.b64encode(blob).decode("ascii")
    return f"ssh-ed25519 {encoded} {comment}\n".encode("ascii")


def test_argument_contract_requires_explicit_apply_confirmation(repo_root: Path) -> None:
    helper = _helper(repo_root)
    common = [
        "--expected-hostname",
        "node.example",
        "--public-key-file",
        "/root/node.pub",
        "--controller-address",
        "192.0.2.20",
        "--controller-hostname",
        "controller.example",
        "--server-address",
        "192.0.2.30",
        "--server-port",
        "22",
    ]

    checked = helper.parse_arguments(["check", *common])
    assert checked.operation == "check"
    with pytest.raises(SystemExit):
        helper.parse_arguments(["apply", *common])

    applied = helper.parse_arguments(
        ["apply", *common, "--confirm", "node.example:rocky"]
    )
    assert applied.confirm == "node.example:rocky"


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"ssh-rsa invalid\n",
        _public_key() + _public_key("second"),
        _public_key().replace(b"\n", b"\r\n"),
        _public_key().rstrip(b"\n"),
    ],
)
def test_public_key_parser_rejects_noncanonical_input(
    repo_root: Path, content: bytes
) -> None:
    helper = _helper(repo_root)
    with pytest.raises(helper.PreparationError):
        helper.parse_ed25519_public_key(content)


def test_public_key_parser_returns_only_fingerprint(repo_root: Path) -> None:
    helper = _helper(repo_root)
    content = _public_key()

    parsed = helper.parse_ed25519_public_key(content)

    assert parsed.content == content
    assert parsed.fingerprint.startswith("SHA256:")
    assert content.decode("ascii").split()[1] not in parsed.fingerprint
    assert parsed.value == " ".join(content.decode("ascii").split()[:2])


@pytest.mark.parametrize(
    ("address", "port", "prefix"),
    [
        ("192.0.2.30", 22, "192.0.2.30 "),
        ("192.0.2.30", 2222, "[192.0.2.30]:2222 "),
        ("2001:db8::30", 22, "2001:db8::30 "),
        ("2001:db8::30", 2222, "[2001:db8::30]:2222 "),
    ],
)
def test_known_hosts_entry_uses_server_address_and_port(
    repo_root: Path, address: str, port: int, prefix: str
) -> None:
    helper = _helper(repo_root)
    settings = helper.Settings(
        operation="check",
        expected_hostname="node.example",
        public_key_file=Path("/root/node.pub"),
        controller_address="192.0.2.20",
        controller_hostname="controller.example",
        server_address=address,
        server_port=port,
        confirm=None,
    )
    key = helper.parse_ed25519_public_key(_public_key("ignored comment"))

    entry = helper.known_hosts_entry(settings, key)

    assert entry == f"{prefix}{key.value}"
    assert "ignored comment" not in entry


def test_check_ready_requests_one_key_summary(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    settings = helper.Settings(
        operation="check",
        expected_hostname="node.example",
        public_key_file=Path("/root/node.pub"),
        controller_address="192.0.2.20",
        controller_hostname="controller.example",
        server_address="192.0.2.30",
        server_port=22,
        confirm=None,
    )
    key = helper.parse_ed25519_public_key(_public_key())
    summaries: list[bool] = []

    def fake_check_base(
        _settings: object,
        _key: object,
        *,
        check_effective_ssh: bool = True,
        print_key_summary: bool = True,
    ) -> None:
        assert check_effective_ssh
        summaries.append(print_key_summary)

    monkeypatch.setattr(helper, "check_base", fake_check_base)
    monkeypatch.setattr(helper, "check_account", lambda _key: None)

    helper.check_ready(settings, key)

    assert summaries == [True]


def test_public_key_file_rejects_symlink_and_unsafe_mode(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    monkeypatch.setattr(helper, "validate_root_controlled_ancestors", lambda _path: None)
    key = tmp_path / "node.pub"
    key.write_bytes(_public_key())
    key.chmod(0o644)

    assert helper.load_public_key(key, expected_uid=os.geteuid()).fingerprint

    link = tmp_path / "link.pub"
    link.symlink_to(key)
    with pytest.raises(helper.PreparationError):
        helper.load_public_key(link, expected_uid=os.geteuid())

    key.chmod(0o666)
    with pytest.raises(helper.PreparationError):
        helper.load_public_key(key, expected_uid=os.geteuid())


def test_public_key_file_rejects_untrusted_ancestor(
    repo_root: Path, tmp_path: Path
) -> None:
    helper = _helper(repo_root)
    key = tmp_path / "node.pub"
    key.write_bytes(_public_key())
    key.chmod(0o644)

    with pytest.raises(helper.PreparationError, match="ancestor"):
        helper.load_public_key(key, expected_uid=os.geteuid())


def test_effective_sshd_policy_is_fail_closed(repo_root: Path) -> None:
    helper = _helper(repo_root)
    valid = helper.parse_effective_sshd(
        "\n".join(
            (
                "pubkeyauthentication yes",
                "passwordauthentication no",
                "kbdinteractiveauthentication no",
                "authorizedkeyscommand none",
                "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
                "trustedusercakeys none",
                "hostbasedauthentication no",
                "gssapiauthentication no",
                "kerberosauthentication no",
            )
        )
    )
    helper.validate_effective_sshd(valid)

    for name, value in (
        ("pubkeyauthentication", "no"),
        ("passwordauthentication", "yes"),
        ("kbdinteractiveauthentication", "yes"),
        ("authorizedkeyscommand", "/usr/local/bin/keys"),
        ("authorizedkeysfile", ".ssh/other_keys"),
        ("trustedusercakeys", "/etc/ssh/ca.pub"),
        ("hostbasedauthentication", "yes"),
        ("gssapiauthentication", "yes"),
        ("kerberosauthentication", "yes"),
        (
            "authorizedkeysfile",
            ".ssh/authorized_keys /etc/ssh/authorized_keys/%u",
        ),
    ):
        invalid = valid.copy()
        invalid[name] = value
        with pytest.raises(helper.PreparationError):
            helper.validate_effective_sshd(invalid)


def test_effective_sshd_uses_source_and_destination_context(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    settings = helper.Settings(
        operation="check",
        expected_hostname="node.example",
        public_key_file=Path("/root/node.pub"),
        controller_address="192.0.2.20",
        controller_hostname="controller.example",
        server_address="192.0.2.30",
        server_port=2222,
        confirm=None,
    )
    calls: list[tuple[str, ...]] = []
    output = "\n".join(
        (
            "pubkeyauthentication yes",
            "passwordauthentication no",
            "kbdinteractiveauthentication no",
            "authorizedkeyscommand none",
            "authorizedkeysfile .ssh/authorized_keys",
            "trustedusercakeys none",
            "hostbasedauthentication no",
            "gssapiauthentication no",
            "kerberosauthentication no",
        )
    )

    def fake_run(name: str, *arguments: str) -> str:
        calls.append((name, *arguments))
        return output

    monkeypatch.setattr(helper, "run_command", fake_run)
    helper.check_effective_ssh_policy(settings)

    assert calls == [
        (
            "sshd",
            "-T",
            "-C",
            "user=rocky,host=controller.example,addr=192.0.2.20,"
            "laddr=192.0.2.30,lport=2222",
        )
    ]


def test_atomic_publication_is_idempotent_and_refuses_replacement(
    repo_root: Path, tmp_path: Path
) -> None:
    helper = _helper(repo_root)
    target = tmp_path / "authorized_keys"
    content = _public_key()

    helper.publish_file(
        target,
        content,
        uid=os.geteuid(),
        gid=os.getegid(),
        mode=0o600,
    )
    helper.publish_file(
        target,
        content,
        uid=os.geteuid(),
        gid=os.getegid(),
        mode=0o600,
    )

    assert target.read_bytes() == content
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.stat().st_nlink == 1
    with pytest.raises(helper.PreparationError):
        helper.publish_file(
            target,
            _public_key("different"),
            uid=os.geteuid(),
            gid=os.getegid(),
            mode=0o600,
        )


def test_atomic_publication_removes_failed_new_file(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    target = tmp_path / "authorized_keys"

    def fail_write(_descriptor: int, _content: bytes) -> None:
        raise OSError("injected write failure")

    monkeypatch.setattr(helper, "write_all", fail_write)
    with pytest.raises(OSError, match="injected"):
        helper.publish_file(
            target,
            _public_key(),
            uid=os.geteuid(),
            gid=os.getegid(),
            mode=0o600,
        )

    assert not target.exists()


def test_atomic_publication_anchors_destination_directory(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    destination = tmp_path / "ssh"
    moved = tmp_path / "ssh-original"
    decoy = tmp_path / "decoy"
    staging = tmp_path / "staging"
    destination.mkdir(mode=0o700)
    decoy.mkdir(mode=0o700)
    staging.mkdir(mode=0o700)
    target = destination / "authorized_keys"
    original_link = helper.os.link

    def swap_then_link(
        source: str,
        target_name: str,
        *,
        dst_dir_fd: int,
        follow_symlinks: bool,
    ) -> None:
        destination.rename(moved)
        destination.symlink_to(decoy, target_is_directory=True)
        original_link(
            source,
            target_name,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(helper.os, "link", swap_then_link)
    helper.publish_file(
        target,
        _public_key(),
        uid=os.geteuid(),
        gid=os.getegid(),
        mode=0o600,
        staging_directory=staging,
    )

    assert (moved / "authorized_keys").read_bytes() == _public_key()
    assert not (decoy / "authorized_keys").exists()


def test_apply_checks_effective_ssh_before_granting_access(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    events: list[str] = []
    lock_descriptor = os.open("/dev/null", os.O_RDONLY)
    settings = helper.Settings(
        operation="apply",
        expected_hostname="node.example",
        public_key_file=Path("/root/node.pub"),
        controller_address="192.0.2.20",
        controller_hostname="controller.example",
        server_address="192.0.2.30",
        server_port=22,
        confirm="node.example:rocky",
    )
    public_key = helper.parse_ed25519_public_key(_public_key())
    user = SimpleNamespace(pw_uid=1000, pw_gid=1000)
    primary = SimpleNamespace(gr_gid=1000)

    monkeypatch.setattr(helper, "acquire_lock", lambda: lock_descriptor)
    monkeypatch.setattr(
        helper,
        "check_base",
        lambda *_args, **_kwargs: events.append("base"),
    )
    monkeypatch.setattr(
        helper,
        "ensure_account_state_before_apply",
        lambda: (None, None),
    )
    monkeypatch.setattr(
        helper,
        "preflight_managed_files",
        lambda _key: events.append("managed-files"),
    )
    monkeypatch.setattr(
        helper,
        "run_command",
        lambda name, *_args: events.append(name) or "",
    )
    monkeypatch.setattr(helper, "account", lambda: user)
    monkeypatch.setattr(helper, "check_account_identity", lambda _user: primary)
    monkeypatch.setattr(
        helper.grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=2000),
    )
    monkeypatch.setattr(helper, "account_groups", lambda _user: {1000})
    monkeypatch.setattr(helper, "path_exists", lambda _path: False)

    def reject_ssh(_settings: object) -> None:
        events.append("effective-ssh")
        raise helper.PreparationError("injected SSH policy failure")

    monkeypatch.setattr(helper, "check_effective_ssh_policy", reject_ssh)
    monkeypatch.setattr(
        helper,
        "publish_file",
        lambda *_args, **_kwargs: events.append("published-key"),
    )
    monkeypatch.setattr(
        helper,
        "publish_sudoers",
        lambda: events.append("published-sudoers"),
    )

    with pytest.raises(helper.PreparationError, match="injected"):
        helper.apply(settings, public_key)

    assert events == [
        "base",
        "managed-files",
        "useradd",
        "passwd",
        "usermod",
        "effective-ssh",
    ]


def test_apply_refuses_group_grant_after_access_files_exist(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    lock_descriptor = os.open("/dev/null", os.O_RDONLY)
    settings = helper.Settings(
        operation="apply",
        expected_hostname="node.example",
        public_key_file=Path("/root/node.pub"),
        controller_address="192.0.2.20",
        controller_hostname="controller.example",
        server_address="192.0.2.30",
        server_port=22,
        confirm="node.example:rocky",
    )
    public_key = helper.parse_ed25519_public_key(_public_key())
    user = SimpleNamespace(pw_uid=1000, pw_gid=1000)
    primary = SimpleNamespace(gr_gid=1000)

    monkeypatch.setattr(helper, "acquire_lock", lambda: lock_descriptor)
    monkeypatch.setattr(helper, "check_base", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        helper,
        "ensure_account_state_before_apply",
        lambda: (user, primary),
    )
    monkeypatch.setattr(helper, "preflight_managed_files", lambda _key: None)
    monkeypatch.setattr(
        helper.grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=2000),
    )
    monkeypatch.setattr(helper, "account_groups", lambda _user: {1000})
    monkeypatch.setattr(
        helper,
        "path_exists",
        lambda path: path == helper.AUTHORIZED_KEYS,
    )

    with pytest.raises(helper.PreparationError, match="after key or sudo"):
        helper.apply(settings, public_key)


def test_home_staging_directory_is_root_only(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    staging = tmp_path / "staging"
    monkeypatch.setattr(helper, "HOME_STAGING_DIRECTORY", staging)
    original_lstat = Path.lstat

    def root_owned_lstat(path: Path) -> os.stat_result:
        values = list(original_lstat(path))
        values[4] = 0
        values[5] = 0
        return os.stat_result(values)

    monkeypatch.setattr(helper.Path, "lstat", root_owned_lstat)

    helper.ensure_home_staging_directory()
    assert stat.S_IMODE(staging.stat().st_mode) == 0o700

    staging.chmod(0o755)
    with pytest.raises(helper.PreparationError, match="0700"):
        helper.ensure_home_staging_directory()


def test_apply_resumes_exact_key_only_partial_state(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    home = tmp_path / "rocky"
    ssh_directory = home / ".ssh"
    authorized_keys = ssh_directory / "authorized_keys"
    sudoers = tmp_path / "sudoers"
    staging = tmp_path / "staging"
    home.mkdir(mode=0o700)
    ssh_directory.mkdir(mode=0o700)
    authorized_keys.write_bytes(_public_key())
    authorized_keys.chmod(0o600)

    monkeypatch.setattr(helper, "AUTOMATION_HOME", home)
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS", authorized_keys)
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS_2", ssh_directory / "authorized_keys2")
    monkeypatch.setattr(helper, "SUDOERS_FILE", sudoers)
    monkeypatch.setattr(helper, "HOME_STAGING_DIRECTORY", staging)
    monkeypatch.setattr(
        helper,
        "ensure_home_staging_directory",
        lambda: staging.mkdir(mode=0o700),
    )

    lock_descriptor = os.open("/dev/null", os.O_RDONLY)
    user = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    primary = SimpleNamespace(gr_gid=os.getegid())
    access = SimpleNamespace(gr_gid=2000)
    settings = helper.Settings(
        operation="apply",
        expected_hostname="node.example",
        public_key_file=Path("/root/node.pub"),
        controller_address="192.0.2.20",
        controller_hostname="controller.example",
        server_address="192.0.2.30",
        server_port=22,
        confirm="node.example:rocky",
    )
    public_key = helper.parse_ed25519_public_key(_public_key())
    events: list[str] = []

    monkeypatch.setattr(helper, "acquire_lock", lambda: lock_descriptor)
    def fake_check_base(
        _settings: object,
        _key: object,
        *,
        check_effective_ssh: bool = True,
        print_key_summary: bool = True,
    ) -> None:
        assert not check_effective_ssh
        events.append("printed-key" if print_key_summary else "silent-preflight")

    monkeypatch.setattr(helper, "check_base", fake_check_base)
    monkeypatch.setattr(
        helper,
        "ensure_account_state_before_apply",
        lambda: (user, primary),
    )
    monkeypatch.setattr(helper.grp, "getgrnam", lambda _name: access)
    monkeypatch.setattr(helper, "account_groups", lambda _user: {primary.gr_gid, access.gr_gid})
    monkeypatch.setattr(
        helper,
        "check_effective_ssh_policy",
        lambda _settings: events.append("effective-ssh"),
    )
    monkeypatch.setattr(
        helper,
        "publish_sudoers",
        lambda: events.append("published-sudoers"),
    )
    monkeypatch.setattr(
        helper,
        "run_command",
        lambda name, *_args: events.append(name) or "",
    )
    def final_check(_settings: object, _key: object) -> None:
        events.append("printed-key")
        events.append("ready")

    monkeypatch.setattr(helper, "check_ready", final_check)

    helper.apply(settings, public_key)

    assert authorized_keys.read_bytes() == public_key.content
    assert events == [
        "silent-preflight",
        "effective-ssh",
        "published-sudoers",
        "restorecon",
        "printed-key",
        "ready",
    ]
    assert events.count("printed-key") == 1
    assert not staging.exists()


def test_helper_keeps_access_only_boundary(repo_root: Path) -> None:
    source = (repo_root / "scripts/rocky-ansible-host-prepare").read_text(
        encoding="utf-8"
    )

    assert "dnf" not in source
    assert "yum" not in source
    assert "ssh-keygen" not in source
    assert "shell=True" not in source
    assert "users_manage_ansible_user" not in source
