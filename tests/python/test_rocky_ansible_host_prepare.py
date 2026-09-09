from __future__ import annotations

import base64
import errno
import importlib.util
import json
import os
import pty
import select
import signal
import stat
import struct
import subprocess
import sys
import time
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


def _file_state(path: Path) -> tuple[int, ...]:
    info = os.stat(path, follow_symlinks=False)
    # Reads may update atime; inode, metadata and nanosecond write/change times
    # must survive refusals and idempotent runs unchanged.
    return (
        info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def test_run_command_detaches_from_real_controlling_terminal(repo_root: Path) -> None:
    # forkpty gives the helper's caller a real controlling terminal, even in CI.
    script = r'''
import json
import os
import runpy
import signal
import subprocess
import sys

signal.alarm(20)
helper = runpy.run_path(sys.argv[1])
tty = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
os.close(tty)
probe = """
import json
import os
import signal
signal.alarm(5)
try:
    tty = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
except OSError as error:
    tty_error = error.errno
else:
    os.close(tty)
    tty_error = None
print(json.dumps({'tty_error': tty_error, 'stdio_ttys': [os.isatty(fd) for fd in (0, 1, 2)]}))
"""
detached = json.loads(helper["run_command"](sys.executable, "-c", probe))
original_run = subprocess.run
def undetached_run(*args, **kwargs):
    kwargs.pop("start_new_session", None)
    return original_run(*args, **kwargs)
subprocess.run = undetached_run
try:
    control = json.loads(helper["run_command"](sys.executable, "-c", probe))
finally:
    subprocess.run = original_run
print(json.dumps({'caller_has_ctty': True, 'detached': detached, 'control': control}), flush=True)
'''
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execv(sys.executable, [
                sys.executable, "-c", script,
                str(repo_root / "scripts/rocky-ansible-host-prepare"),
            ])
        finally:
            os._exit(127)

    output = bytearray()
    status = None
    eof = False
    deadline = time.monotonic() + 25
    try:
        while status is None or not eof:
            assert time.monotonic() < deadline, f"PTY probe timed out: {output!r}"
            readable, _, _ = select.select([] if eof else [master], [], [], 0.05)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                    output.extend(chunk)
                    eof = not chunk
                except OSError as error:
                    if error.errno != errno.EIO:  # Linux PTY slave has closed.
                        raise
                    eof = True
            if status is None:
                waited, child_status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = child_status
        assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
        result = json.loads(output)
        assert result["caller_has_ctty"] is True
        assert result["control"] == {"tty_error": None, "stdio_ttys": [False] * 3}
        assert result["detached"] == {"tty_error": errno.ENXIO, "stdio_ttys": [False] * 3}
    finally:
        os.close(master)
        # Only signal our unreaped forkpty child/session. Detached probes also
        # have their own alarm, bounding their lifetime if the caller is interrupted.
        if status is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                os.kill(pid, signal.SIGKILL)
            cleanup_deadline = time.monotonic() + 2
            while not os.waitpid(pid, os.WNOHANG)[0]:
                if time.monotonic() >= cleanup_deadline:
                    pytest.fail("PTY child did not exit after SIGKILL")
                time.sleep(0.01)


@pytest.fixture
def sudoers_environment(repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    helper = _helper(repo_root)
    directory = tmp_path / "sudoers.d"
    directory.mkdir(mode=0o755)
    target = directory / "90-platform-ansible-rocky"
    owners: dict[Path, tuple[int, int]] = {}
    original_lstat = Path.lstat
    original_fstat = os.fstat

    def root_owned_lstat(path: Path) -> os.stat_result:
        info = original_lstat(path)
        if not (path.is_relative_to(directory) or path in directory.parents):
            return info
        values = list(info)
        values[4:6] = owners.get(path, (0, 0))
        # Model the trusted system ancestors above our sandbox only;
        # permissions/types inside it still come from the real filesystem.
        if path in tmp_path.parents:
            values[0] = int(values[0]) & ~0o022
        return os.stat_result(values)

    def root_owned_fstat(descriptor: int) -> os.stat_result:
        values = list(original_fstat(descriptor))
        path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        if path.is_relative_to(directory):
            values[4:6] = owners.get(path, (0, 0))
        return os.stat_result(values)

    def root_fchown(descriptor: int, uid: int, gid: int) -> None:
        assert (uid, gid) == (0, 0)
        assert Path(os.readlink(f"/proc/self/fd/{descriptor}")).is_relative_to(directory)

    monkeypatch.setattr(Path, "lstat", root_owned_lstat)
    # Keep identity emulation local to the helper; writes, modes, links, rename,
    # fsync and all validation functions execute normally without root.
    monkeypatch.setattr(helper, "os", SimpleNamespace(
        **(vars(os) | {"fstat": root_owned_fstat, "fchown": root_fchown}),
    ))
    monkeypatch.setattr(helper, "SUDOERS_FILE", target)
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS", tmp_path / "authorized_keys")
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS_2", tmp_path / "authorized_keys2")
    monkeypatch.setattr(helper, "run_command", lambda *_args: pytest.fail("unexpected host command"))
    return helper, owners


@pytest.mark.parametrize("initial", [None, "legacy", "current"])
def test_sudoers_publication_validates_candidate_and_is_idempotent(
    sudoers_environment, monkeypatch: pytest.MonkeyPatch, initial: str | None,
) -> None:
    helper, _ = sudoers_environment
    target = helper.SUDOERS_FILE
    old = b"rocky ALL=(ALL) NOPASSWD: ALL\n"
    current = b"Defaults:rocky !requiretty\n" + old
    assert helper.LEGACY_SUDOERS_CONTENT == old
    assert helper.SUDOERS_CONTENT == current
    previous = {None: None, "legacy": old, "current": current}[initial]
    if previous is not None:
        target.write_bytes(previous)
        target.chmod(0o440)
    validated: list[Path] = []
    events: list[str] = []
    original_replace = helper.os.replace
    original_fsync = helper.os.fsync

    def validate(name: str, flag: str, filename: str) -> str:
        assert (name, flag) == ("visudo", "-cf")
        candidate = Path(filename)
        assert candidate != target and candidate.parent == target.parent
        assert candidate.read_bytes() == current
        helper.check_path(candidate, uid=0, gid=0, mode=0o440, directory=False)
        assert (target.read_bytes() if target.exists() else None) == previous
        validated.append(candidate)
        events.append("validated")
        return ""

    def replace(source, destination, *, src_dir_fd, dst_dir_fd):
        assert events[-1] == "validated"
        assert source == validated[0].name and destination == target.name
        assert src_dir_fd == dst_dir_fd
        assert os.fstat(src_dir_fd).st_ino == target.parent.stat().st_ino
        original_replace(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        events.append("replaced")

    def fsync(descriptor: int) -> None:
        original_fsync(descriptor)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            events.append("directory-synced")

    monkeypatch.setattr(helper, "run_command", validate)
    monkeypatch.setattr(helper.os, "replace", replace)
    monkeypatch.setattr(helper.os, "fsync", fsync)
    helper.preflight_managed_files(helper.parse_ed25519_public_key(_public_key()))
    before = _file_state(target) if target.exists() else None
    helper.publish_sudoers()
    assert target.read_bytes() == current
    helper.check_path(target, uid=0, gid=0, mode=0o440, directory=False)
    assert list(target.parent.iterdir()) == [target]
    if initial == "legacy":
        assert events == ["validated", "replaced", "directory-synced"]
        assert before is not None
        assert target.stat().st_ino != before[0]
    assert len(validated) == (0 if initial == "current" else 1)
    if initial == "current":
        assert _file_state(target) == before

    before = _file_state(target)
    monkeypatch.setattr(helper, "run_command", lambda *_args: pytest.fail("idempotent run invoked visudo"))
    monkeypatch.setattr(helper.tempfile, "mkstemp", lambda **_kwargs: pytest.fail("idempotent run staged a file"))
    helper.publish_sudoers()
    assert _file_state(target) == before
    assert target.read_bytes() == current


@pytest.mark.parametrize("content", [
    b"rocky ALL=(ALL) NOPASSWD: ALL\n\n",
    b"rocky ALL=(ALL) NOPASSWD: ALL\n# local policy\n",
    b"Defaults !requiretty\nrocky ALL=(ALL) NOPASSWD: ALL\n",
    b"somebody ALL=(ALL) ALL\n",
])
def test_sudoers_rejects_unknown_policy_without_rewriting(sudoers_environment, content: bytes) -> None:
    helper, _ = sudoers_environment
    target = helper.SUDOERS_FILE
    target.write_bytes(content)
    target.chmod(0o440)
    before = _file_state(target)
    with pytest.raises(helper.PreparationError, match="different sudoers policy"):
        helper.preflight_managed_files(helper.parse_ed25519_public_key(_public_key()))
    with pytest.raises(helper.PreparationError, match="different sudoers policy"):
        helper.publish_sudoers()
    assert target.read_bytes() == content
    assert _file_state(target) == before
    assert list(target.parent.iterdir()) == [target]


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("defect, message", [
    ("owner", "ownership"), ("group", "ownership"),
    (0o400, "mode"), (0o644, "mode"), (0o460, "mode"),
    ("hardlink", "exactly one link"), ("symlink", "type"),
    ("directory", "type"), ("fifo", "type"),
])
def test_sudoers_rejects_bad_metadata_before_staging(
    sudoers_environment, monkeypatch: pytest.MonkeyPatch, defect, message: str, legacy: bool,
) -> None:
    helper, owners = sudoers_environment
    target = helper.SUDOERS_FILE
    content = helper.LEGACY_SUDOERS_CONTENT if legacy else helper.SUDOERS_CONTENT
    target.write_bytes(content)
    target.chmod(0o440)
    if defect in ("owner", "group"):
        owners[target] = (1000, 0) if defect == "owner" else (0, 1000)
    elif isinstance(defect, int):
        target.chmod(defect)
    elif defect == "hardlink":
        os.link(target, target.parent / "other")
    else:
        target.rename(target.parent / "other")
        if defect == "symlink":
            target.symlink_to(target.parent / "other")
        elif defect == "directory":
            target.mkdir(mode=0o440)
        else:
            os.mkfifo(target, 0o440)
    before = _file_state(target)
    entries = set(target.parent.iterdir())
    monkeypatch.setattr(helper.tempfile, "mkstemp", lambda **_kwargs: pytest.fail("unsafe policy staged"))
    with pytest.raises(helper.PreparationError, match=message):
        helper.preflight_managed_files(helper.parse_ed25519_public_key(_public_key()))
    with pytest.raises(helper.PreparationError, match=message):
        helper.publish_sudoers()
    assert _file_state(target) == before
    assert set(target.parent.iterdir()) == entries
    if stat.S_ISREG(target.lstat().st_mode):
        assert target.read_bytes() == content


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("defect, message", [
    ("owner", "not root-owned"), ("writable", "writable"),
    ("symlink", "not a directory"), ("missing", "absent"),
])
def test_sudoers_requires_root_controlled_ancestors(
    sudoers_environment, tmp_path: Path, existing: bool, defect: str, message: str,
) -> None:
    helper, owners = sudoers_environment
    target = helper.SUDOERS_FILE
    if existing:
        target.write_bytes(helper.LEGACY_SUDOERS_CONTENT)
        target.chmod(0o440)
    if defect == "owner":
        owners[target.parent] = (1000, 0)
    elif defect == "writable":
        target.parent.chmod(0o775)
    else:
        moved = tmp_path / "moved"
        target.parent.rename(moved)
        if defect == "symlink":
            target.parent.symlink_to(moved, target_is_directory=True)
    with pytest.raises(helper.PreparationError, match=f"ancestor.*{message}"):
        helper.preflight_managed_files(helper.parse_ed25519_public_key(_public_key()))
    with pytest.raises(helper.PreparationError, match=f"ancestor.*{message}"):
        helper.publish_sudoers()


@pytest.mark.parametrize("failure", ["visudo", "replace"])
def test_sudoers_upgrade_failure_preserves_legacy_and_cleans_candidate(
    sudoers_environment, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    helper, _ = sudoers_environment
    target = helper.SUDOERS_FILE
    target.write_bytes(helper.LEGACY_SUDOERS_CONTENT)
    target.chmod(0o440)
    before = _file_state(target)
    validated: list[Path] = []

    def validate(name: str, flag: str, filename: str) -> str:
        assert (name, flag) == ("visudo", "-cf")
        candidate = Path(filename)
        assert candidate.parent == target.parent and candidate != target
        assert candidate.read_bytes() == helper.SUDOERS_CONTENT
        assert target.read_bytes() == helper.LEGACY_SUDOERS_CONTENT
        validated.append(candidate)
        if failure == "visudo":
            raise helper.PreparationError("injected visudo failure")
        return ""

    def fail_replace(*_args, **_kwargs):
        assert failure == "replace" and len(validated) == 1
        raise OSError("injected replace failure")

    monkeypatch.setattr(helper, "run_command", validate)
    monkeypatch.setattr(helper.os, "replace", fail_replace)
    error = helper.PreparationError if failure == "visudo" else OSError
    with pytest.raises(error, match=f"injected {failure} failure"):
        helper.publish_sudoers()
    assert len(validated) == 1
    assert target.read_bytes() == helper.LEGACY_SUDOERS_CONTENT
    assert _file_state(target) == before
    assert list(target.parent.iterdir()) == [target]


@pytest.mark.parametrize("change", ["current", "unknown", "missing", "mode"])
def test_sudoers_upgrade_rechecks_legacy_after_validation(
    sudoers_environment, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    helper, _ = sudoers_environment
    target = helper.SUDOERS_FILE
    target.write_bytes(helper.LEGACY_SUDOERS_CONTENT)
    target.chmod(0o440)
    changed = None
    changed_stat = None

    def validate(name: str, flag: str, filename: str) -> str:
        nonlocal changed, changed_stat
        assert (name, flag) == ("visudo", "-cf")
        assert Path(filename).read_bytes() == helper.SUDOERS_CONTENT
        if change == "missing":
            target.unlink()
        elif change == "mode":
            target.chmod(0o640)
        else:
            target.chmod(0o600)
            target.write_bytes(helper.SUDOERS_CONTENT if change == "current" else b"local policy\n")
            target.chmod(0o440)
        if target.exists():
            changed = target.read_bytes()
            changed_stat = _file_state(target)
        return ""

    monkeypatch.setattr(helper, "run_command", validate)
    monkeypatch.setattr(helper.os, "replace", lambda *_args, **_kwargs: pytest.fail("replaced changed policy"))
    message = {"current": "changed during", "unknown": "different sudoers", "missing": "changed during", "mode": "mode"}[change]
    with pytest.raises(helper.PreparationError, match=message):
        helper.publish_sudoers()
    assert (target.read_bytes() if target.exists() else None) == changed
    assert (_file_state(target) if target.exists() else None) == changed_stat
    assert list(target.parent.iterdir()) == ([] if change == "missing" else [target])


@pytest.mark.parametrize("legacy", [False, True])
def test_check_mode_requires_current_sudoers_without_rewriting(
    sudoers_environment, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, legacy: bool,
) -> None:
    helper, _ = sudoers_environment
    home = tmp_path / "rocky"
    home.mkdir(mode=0o700)
    (home / ".ssh").mkdir(mode=0o700)
    key = home / ".ssh/authorized_keys"
    key.write_bytes(_public_key())
    key.chmod(0o600)
    target = helper.SUDOERS_FILE
    content = helper.LEGACY_SUDOERS_CONTENT if legacy else helper.SUDOERS_CONTENT
    target.write_bytes(content)
    target.chmod(0o440)
    before = _file_state(target)
    user = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(helper, "AUTOMATION_HOME", home)
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS", key)
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: user)
    monkeypatch.setattr(helper, "check_account_identity", lambda _user: SimpleNamespace(gr_gid=user.pw_gid))
    monkeypatch.setattr(helper.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=2000))
    monkeypatch.setattr(helper, "account_groups", lambda _user: {user.pw_gid, 2000})
    monkeypatch.setattr(helper, "password_is_locked", lambda: True)
    monkeypatch.setattr(helper, "load_public_key", lambda _path: helper.parse_ed25519_public_key(_public_key()))
    monkeypatch.setattr(helper, "check_base", lambda *_args, **_kwargs: (True, set()))
    monkeypatch.setattr(helper, "check_effective_ssh_policy", lambda _settings: None)
    monkeypatch.setattr(helper, "command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "run_command", lambda *args: calls.append(args) or "")
    result = helper.main([
        "check", "--expected-hostname", "node.example", "--public-key-file", str(key),
        "--controller-address", "192.0.2.20", "--controller-hostname", "controller.example",
        "--server-address", "192.0.2.30", "--server-port", "22",
    ])
    output = capsys.readouterr()
    assert result == (1 if legacy else 0)
    if legacy:
        assert "managed sudoers policy differs" in output.out
        assert "Result: NOT READY" in output.err
        assert "Result: READY" not in output.out
        assert not calls
    else:
        assert "Result: READY FOR ANSIBLE TRANSPORT" in output.out
        assert calls[0] == ("runuser", "-u", "rocky", "--", "/usr/bin/sudo", "-n", "true")
    assert target.read_bytes() == content
    assert _file_state(target) == before
    assert list(target.parent.iterdir()) == [target]


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


@pytest.fixture
def readiness_environment(repo_root: Path, monkeypatch: pytest.MonkeyPatch):
    helper = _helper(repo_root)
    arguments = [
        "check", "--expected-hostname", "node.example",
        "--public-key-file", "/root/node.pub",
        "--controller-address", "192.0.2.20",
        "--controller-hostname", "controller.example",
        "--server-address", "192.0.2.30", "--server-port", "22",
    ]
    calls: list[tuple[str, ...]] = []
    user = SimpleNamespace(
        pw_uid=1000, pw_gid=1000, pw_gecos=helper.AUTOMATION_COMMENT,
        pw_dir="/home/rocky", pw_shell="/bin/bash",
    )
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper, "command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper.platform, "freedesktop_os_release", lambda: {"ID": "rocky", "VERSION_ID": "10.0"})
    monkeypatch.setattr(helper.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(helper.sys, "version_info", (3, 12))
    monkeypatch.setattr(helper.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=2000))
    monkeypatch.setattr(helper.grp, "getgrgid", lambda _gid: SimpleNamespace(gr_name="rocky"))
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: user)
    monkeypatch.setattr(helper.pwd, "getpwall", lambda: [user])
    monkeypatch.setattr(helper, "load_public_key", lambda _path: helper.parse_ed25519_public_key(_public_key()))
    monkeypatch.setattr(helper, "check_account", lambda _key: calls.append(("account-check",)))
    monkeypatch.setattr(helper, "check_effective_ssh_policy", lambda _settings: calls.append(("effective-ssh",)))

    def run_command(name: str, *args: str) -> str:
        calls.append((name, *args))
        return {"hostnamectl": "node.example", "getenforce": "Enforcing"}.get(name, "")

    monkeypatch.setattr(helper, "run_command", run_command)
    return helper, arguments, calls


@pytest.mark.parametrize("missing", ["account", "group"])
def test_check_reports_missing_prerequisite_and_skips_dependents(
    readiness_environment, monkeypatch: pytest.MonkeyPatch, capsys, missing: str
) -> None:
    helper, arguments, calls = readiness_environment

    def absent(_name: str):
        raise KeyError(_name)

    if missing == "account":
        monkeypatch.setattr(helper.pwd, "getpwnam", absent)
    else:
        monkeypatch.setattr(helper.grp, "getgrnam", absent)

    assert helper.main(arguments) == 1
    captured = capsys.readouterr()
    assert "Summary: 1 failed, 2 skipped" in captured.out
    assert "[SKIPPED] effective SSH policy" in captured.out
    if missing == "account":
        assert "[NEEDS PREPARATION] automation account is absent: rocky" in captured.out
    assert "Result: NOT READY" in captured.err
    assert "Result: READY" not in captured.out
    assert ("systemctl", "is-active", "sshd") in calls
    assert ("visudo", "-cf", "/etc/sudoers") in calls
    assert captured.out.count("192.0.2.30 ssh-ed25519 ") == 1
    assert ("account-check",) not in calls
    assert ("effective-ssh",) not in calls


def test_check_collects_independent_errors_and_continues(
    readiness_environment, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    helper, arguments, calls = readiness_environment
    original_run = helper.run_command
    original_load = helper.load_public_key

    def run_command(name: str, *args: str) -> str:
        if name == "sshd":
            raise subprocess.TimeoutExpired("sshd", 15)
        if name == "getenforce":
            raise OSError("injected SELinux failure")
        return original_run(name, *args)

    def load_key(path: Path):
        if path == Path("/root/node.pub"):
            raise helper.PreparationError("invalid automation public key")
        return original_load(path)

    monkeypatch.setattr(helper, "run_command", run_command)
    monkeypatch.setattr(helper, "load_public_key", load_key)

    assert helper.main(arguments) == 1
    captured = capsys.readouterr()
    assert "invalid automation public key" in captured.out
    assert "injected SELinux failure" in captured.out
    assert "[ERROR] SSH configuration:" in captured.out
    assert "Summary: 3 failed, 1 skipped" in captured.out
    assert ("visudo", "-cf", "/etc/sudoers") in calls
    assert ("effective-ssh",) in calls
    assert ("account-check",) not in calls
    assert captured.out.count("192.0.2.30 ssh-ed25519 ") == 1


@pytest.mark.parametrize("missing_tool,skip_count", [("sshd", 2), ("systemctl", 2), ("getenforce", 1)])
def test_check_skips_missing_command_dependents(
    readiness_environment, monkeypatch, capsys, missing_tool, skip_count
) -> None:
    helper, arguments, calls = readiness_environment
    original_path = helper.command_path

    def command_path(name):
        if name == missing_tool:
            raise helper.PreparationError(f"required command is unavailable: {name}")
        return original_path(name)

    monkeypatch.setattr(helper, "command_path", command_path)
    assert helper.main(arguments) == 1
    output = capsys.readouterr().out
    assert f"Summary: 1 failed, {skip_count} skipped" in output
    assert not any(call[0] == missing_tool for call in calls)
    assert ("visudo", "-cf", "/etc/sudoers") in calls
    assert ("account-check",) in calls


def test_check_skips_invalid_account_without_claiming_it_is_absent(
    readiness_environment, capsys
) -> None:
    helper, arguments, calls = readiness_environment
    helper.pwd.getpwnam("rocky").pw_shell = "/bin/false"

    assert helper.main(arguments) == 1
    output = capsys.readouterr().out
    assert "shell must be /bin/bash" in output
    assert "NEEDS PREPARATION" not in output
    assert "Summary: 1 failed, 2 skipped" in output
    assert ("account-check",) not in calls
    assert ("effective-ssh",) not in calls
    assert ("visudo", "-cf", "/etc/sudoers") in calls


def test_check_ready_summary_and_nonroot_guard(readiness_environment, monkeypatch, capsys) -> None:
    helper, arguments, calls = readiness_environment
    assert helper.main(arguments) == 0
    captured = capsys.readouterr()
    assert "Summary: 0 failed, 0 skipped" in captured.out
    assert "Result: READY FOR ANSIBLE TRANSPORT" in captured.out
    assert captured.out.count("192.0.2.30 ssh-ed25519 ") == 1
    assert ("account-check",) in calls
    assert ("effective-ssh",) in calls

    calls.clear()
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    assert helper.main(arguments) == 1
    assert not calls
    assert "run this helper as root" in capsys.readouterr().err


def test_apply_base_checks_still_fail_fast(readiness_environment, monkeypatch, capsys) -> None:
    helper, arguments, calls = readiness_environment
    arguments[0] = "apply"
    arguments.extend(["--confirm", "node.example:rocky"])
    monkeypatch.setattr(helper, "acquire_lock", lambda: os.open("/dev/null", os.O_RDONLY))
    monkeypatch.setattr(helper.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(helper, "ensure_account_state_before_apply", lambda: pytest.fail("apply continued after base failure"))

    assert helper.main(arguments) == 1
    assert ("visudo", "-cf", "/etc/sudoers") not in calls
    assert ("getenforce",) not in calls
    assert "architecture is not x86_64" in capsys.readouterr().err


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


@pytest.mark.parametrize("gssapi", ["yes", "no", None])
def test_effective_sshd_policy_is_fail_closed(
    repo_root: Path, gssapi: str | None
) -> None:
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
                "kerberosauthentication no",
            )
        )
    )
    if gssapi is not None:
        valid["gssapiauthentication"] = gssapi
    helper.validate_effective_sshd(valid)

    for name, value in (
        ("pubkeyauthentication", "no"),
        ("passwordauthentication", "yes"),
        ("kbdinteractiveauthentication", "yes"),
        ("authorizedkeyscommand", "/usr/local/bin/keys"),
        ("authorizedkeysfile", ".ssh/other_keys"),
        ("trustedusercakeys", "/etc/ssh/ca.pub"),
        ("hostbasedauthentication", "yes"),
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
            "gssapiauthentication yes",
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
    def record_command(name: str, *arguments: str) -> str:
        events.append(name)
        if name == "useradd":
            comment_index = arguments.index("--comment")
            assert arguments[comment_index + 1] == helper.AUTOMATION_COMMENT
        return ""

    monkeypatch.setattr(helper, "run_command", record_command)
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


def test_account_identity_requires_automation_comment(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    user = SimpleNamespace(
        pw_uid=1000,
        pw_gid=1000,
        pw_gecos=helper.AUTOMATION_COMMENT,
        pw_dir="/home/rocky",
        pw_shell="/bin/bash",
    )
    primary = SimpleNamespace(gr_name="rocky")
    monkeypatch.setattr(helper.grp, "getgrgid", lambda _gid: primary)
    monkeypatch.setattr(helper.pwd, "getpwall", lambda: [user])

    assert helper.check_account_identity(user) is primary

    user.pw_gecos = ""
    with pytest.raises(helper.PreparationError, match="comment"):
        helper.check_account_identity(user)


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


def test_existing_account_preflight_rejects_ssh_startup_files(
    repo_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = _helper(repo_root)
    home = tmp_path / "rocky"
    ssh_directory = home / ".ssh"
    home.mkdir(mode=0o700)
    ssh_directory.mkdir()
    authorized_keys = ssh_directory / "authorized_keys"
    authorized_keys.write_bytes(_public_key())
    (ssh_directory / "rc").write_text("exit 0\n", encoding="ascii")
    user = SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    primary = SimpleNamespace(gr_gid=os.getegid())

    monkeypatch.setattr(helper, "AUTOMATION_HOME", home)
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS", authorized_keys)
    monkeypatch.setattr(helper, "AUTHORIZED_KEYS_2", ssh_directory / "authorized_keys2")
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: user)
    monkeypatch.setattr(helper, "check_account_identity", lambda _user: primary)
    monkeypatch.setattr(helper, "password_is_locked", lambda: True)
    monkeypatch.setattr(helper.grp, "getgrnam", lambda _name: primary)
    monkeypatch.setattr(helper, "account_groups", lambda _user: {primary.gr_gid})

    with pytest.raises(helper.PreparationError, match="unexpected entries"):
        helper.ensure_account_state_before_apply()


def test_apply_resumes_exact_key_only_partial_state(
    sudoers_environment, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, _ = sudoers_environment
    home = tmp_path / "rocky"
    ssh_directory = home / ".ssh"
    authorized_keys = ssh_directory / "authorized_keys"
    sudoers = helper.SUDOERS_FILE
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
    assert source.count('check_ssh_directory_entries(AUTOMATION_HOME / ".ssh")') == 2
