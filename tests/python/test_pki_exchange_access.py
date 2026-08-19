from __future__ import annotations

import os
import runpy
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml


REQUEST_ID = "1" * 32
ARTIFACT = "2" * 64
DEPLOYMENT = "3" * 64
OUTCOME = "4" * 64
HELPER = "/usr/local/libexec/platform-pki-host-local-exchange"
ROOT_DISPATCH = "/usr/local/libexec/platform-pki-host-local-exchange-root-dispatch"
PREFIX = f"sudo -n -- {HELPER}"


@pytest.fixture
def dispatcher(repo_root: Path) -> dict[str, Any]:
    return runpy.run_path(
        os.fspath(
            repo_root
            / "roles/pki_host_local_exchange_access/files/"
            "platform-pki-host-local-exchange-ssh-dispatch"
        )
    )


@pytest.fixture
def root_dispatcher(repo_root: Path) -> dict[str, Any]:
    return runpy.run_path(
        os.fspath(
            repo_root
            / "roles/pki_host_local_exchange_access/files/"
            "platform-pki-host-local-exchange-root-dispatch"
        )
    )


@pytest.mark.parametrize(
    ("command", "expected"),
    (
        (f"{PREFIX} export-request {REQUEST_ID}", ("export-request", REQUEST_ID)),
        (
            f"{PREFIX} export-evidence {REQUEST_ID} {ARTIFACT} {DEPLOYMENT}",
            ("export-evidence", REQUEST_ID, ARTIFACT, DEPLOYMENT),
        ),
        (
            f"{PREFIX} stage-response {REQUEST_ID} {ARTIFACT}",
            ("stage-response", REQUEST_ID, ARTIFACT),
        ),
        (
            f"{PREFIX} stage-outcome {REQUEST_ID} {ARTIFACT} {DEPLOYMENT} {OUTCOME}",
            ("stage-outcome", REQUEST_ID, ARTIFACT, DEPLOYMENT, OUTCOME),
        ),
    ),
)
def test_dispatcher_accepts_only_controller_commands(
    dispatcher: dict[str, Any], command: str, expected: tuple[str, ...]
) -> None:
    assert dispatcher["parse_original_command"](command) == expected


@pytest.mark.parametrize(
    "command",
    (
        "",
        f"{PREFIX} cleanup-outcome {REQUEST_ID} {ARTIFACT} {DEPLOYMENT} {OUTCOME}",
        f"{PREFIX} export-request {REQUEST_ID} extra",
        f"{PREFIX}  export-request {REQUEST_ID}",
        f"{PREFIX}\texport-request\t{REQUEST_ID}",
        f"{PREFIX} export-request {REQUEST_ID}\n",
        f"{PREFIX} export-request {'A' * 32}",
        f"{PREFIX} stage-response {REQUEST_ID} {'2' * 63}",
        f"{PREFIX} stage-response {REQUEST_ID} {ARTIFACT};id",
        f"sudo -n -- /bin/sh -c {REQUEST_ID}",
        f"/usr/bin/sudo -n -- {HELPER} export-request {REQUEST_ID}",
        f"{HELPER} export-request {REQUEST_ID}",
        "sftp-server",
        "scp -f /etc/passwd",
    ),
)
def test_dispatcher_rejects_noncanonical_commands(
    dispatcher: dict[str, Any], command: str
) -> None:
    with pytest.raises(dispatcher["DispatchError"]):
        dispatcher["parse_original_command"](command)


def test_dispatcher_reconstructs_fixed_broker_execve(
    dispatcher: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    command = f"{PREFIX} export-request {REQUEST_ID}"
    observed: dict[str, object] = {}
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", command)
    monkeypatch.setenv("UNTRUSTED", "discarded")
    monkeypatch.setattr(
        dispatcher["pwd"],
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="exchange-operator"),
    )

    def fake_execve(path: str, argv: tuple[str, ...], environment: dict[str, str]) -> None:
        observed.update(path=path, argv=argv, environment=environment)
        raise RuntimeError("execve observed")

    monkeypatch.setattr(dispatcher["os"], "execve", fake_execve)
    with pytest.raises(RuntimeError, match="execve observed"):
        dispatcher["main"]()

    assert observed["path"] == "/usr/bin/sudo"
    assert observed["argv"] == (
        "/usr/bin/sudo",
        "-n",
        "--",
        ROOT_DISPATCH,
        "export-request",
        REQUEST_ID,
    )
    assert observed["environment"] == {
        "HOME": "/var/lib/platform-config/pki-exchange-operator",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }


def test_dispatcher_rejects_wrong_local_account(
    dispatcher: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"{PREFIX} export-request {REQUEST_ID}")
    monkeypatch.setattr(
        dispatcher["pwd"],
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="ansible"),
    )
    with pytest.raises(SystemExit) as error:
        dispatcher["main"]()
    assert error.value.code == 126


def test_root_dispatcher_rejects_cleanup_and_malformed_coordinates(
    root_dispatcher: dict[str, Any],
) -> None:
    with pytest.raises(root_dispatcher["DispatchError"]):
        root_dispatcher["parse_arguments"](
            ("cleanup-outcome", REQUEST_ID, ARTIFACT, DEPLOYMENT, OUTCOME)
        )
    with pytest.raises(root_dispatcher["DispatchError"]):
        root_dispatcher["parse_arguments"](("stage-response", REQUEST_ID, "2" * 63))


def test_root_dispatcher_revalidates_sudo_provenance_and_executes_pinned_fd(
    root_dispatcher: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv("SUDO_USER", "exchange-operator")
    monkeypatch.setenv("SUDO_UID", "991")
    monkeypatch.setattr(root_dispatcher["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(root_dispatcher["os"], "getegid", lambda: 0)
    monkeypatch.setattr(
        root_dispatcher["pwd"],
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="exchange-operator"),
    )
    monkeypatch.setattr(root_dispatcher["sys"], "argv", [ROOT_DISPATCH, "export-request", REQUEST_ID])
    monkeypatch.setitem(
        root_dispatcher["main"].__globals__, "open_protected_helper", lambda: 9
    )

    def fake_execve(path: str, argv: tuple[str, ...], environment: dict[str, str]) -> None:
        observed.update(path=path, argv=argv, environment=environment)
        raise RuntimeError("execve observed")

    monkeypatch.setattr(root_dispatcher["os"], "execve", fake_execve)
    with pytest.raises(RuntimeError, match="execve observed"):
        root_dispatcher["main"]()

    assert observed["path"] == "/usr/bin/python3"
    assert observed["argv"] == (
        "/usr/bin/python3",
        "-I",
        "/proc/self/fd/9",
        "export-request",
        REQUEST_ID,
    )
    assert isinstance(observed["environment"], dict)
    assert "SUDO_USER" not in observed["environment"]


def test_root_dispatcher_rejects_non_sudo_invocation(
    root_dispatcher: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(root_dispatcher["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(root_dispatcher["os"], "getegid", lambda: 0)
    with pytest.raises(root_dispatcher["DispatchError"]):
        root_dispatcher["require_sudo_provenance"]({})


def test_root_dispatcher_validates_helper_chain(
    root_dispatcher: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    directories = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755,
        st_uid=0,
        st_gid=0,
    )
    helper = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o755,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
    )
    inherited: list[tuple[int, bool]] = []
    monkeypatch.setattr(root_dispatcher["os"], "lstat", lambda _path: directories)
    monkeypatch.setattr(root_dispatcher["os"], "open", lambda *_args: 7)
    monkeypatch.setattr(root_dispatcher["os"], "fstat", lambda _fd: helper)
    monkeypatch.setattr(
        root_dispatcher["os"],
        "set_inheritable",
        lambda descriptor, value: inherited.append((descriptor, value)),
    )
    assert root_dispatcher["open_protected_helper"]() == 7
    assert inherited == [(7, True)]

    directories.st_mode = stat.S_IFDIR | 0o775
    with pytest.raises(root_dispatcher["DispatchError"]):
        root_dispatcher["open_protected_helper"]()


def task_named(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(task for task in tasks if task["name"] == name)


def test_access_role_is_fixed_owned_and_fail_closed(repo_root: Path) -> None:
    role = repo_root / "roles/pki_host_local_exchange_access"
    defaults = yaml.safe_load((role / "defaults/main.yml").read_text(encoding="utf-8"))
    assert defaults["pki_host_local_exchange_access_state"] == "absent"
    assert defaults["pki_host_local_exchange_access_user"] == "exchange-operator"
    assert defaults["pki_host_local_exchange_access_group"] == "exchange-operator"
    assert defaults["pki_host_local_exchange_access_marker_path"].endswith(".managed")
    assert defaults["pki_host_local_exchange_access_root_dispatch_path"] == ROOT_DISPATCH
    assert defaults["pki_host_local_exchange_access_helper_path"] == HELPER

    present = yaml.safe_load((role / "tasks/present.yml").read_text(encoding="utf-8"))
    collision = task_named(
        present, "Refuse unmanaged host-local PKI exchange identity collisions"
    )["ansible.builtin.assert"]
    assert "Refusing to adopt" in collision["fail_msg"]
    helper_check = task_named(present, "Require a protected root-owned exchange facade")
    assert "ansible.builtin.assert" in helper_check
    user = task_named(present, "Create locked host-local PKI exchange account")[
        "ansible.builtin.user"
    ]
    assert user["system"] is True
    assert user["create_home"] is False
    assert user["password_lock"] is True
    assert user["groups"] == ""
    assert user["append"] is False
    key = task_named(present, "Install root-controlled forced exchange public key")
    assert "not ansible_check_mode" in key["when"][0]

    dispatchers = task_named(
        present, "Install fixed host-local PKI exchange dispatchers"
    )["ansible.builtin.copy"]
    assert dispatchers["mode"] == "0755"
    sudo = task_named(present, "Install fixed host-local PKI exchange sudo policy")[
        "ansible.builtin.copy"
    ]
    assert sudo["mode"] == "0440"
    assert sudo["validate"] == "/usr/sbin/visudo -cf %s"
    assert "NOSETENV:" in sudo["content"]
    assert "root_dispatch_path" in sudo["content"]
    assert "helper_path" not in sudo["content"]
    sshd = task_named(present, "Install account-wide host-local PKI exchange SSH policy")[
        "ansible.builtin.copy"
    ]
    for directive in (
        "Match User",
        "AuthenticationMethods publickey",
        "AuthorizedKeysFile",
        "AuthorizedKeysCommand none",
        "ForceCommand",
        "DisableForwarding yes",
        "PermitTTY no",
        "Match all",
    ):
        assert directive in sshd["content"]
    assert sshd["validate"] == (
        "{{ pki_host_local_exchange_access_sshd_validate_path }} %s"
    )
    sshd_task = task_named(
        present, "Install account-wide host-local PKI exchange SSH policy"
    )
    assert "not ansible_check_mode" in sshd_task["when"]
    marker = task_named(
        present, "Claim converged host-local PKI exchange account ownership"
    )
    assert "'uid':" in marker["ansible.builtin.copy"]["content"]
    assert "'gid':" in marker["ansible.builtin.copy"]["content"]
    assert present.index(marker) < present.index(
        task_named(present, "Install fixed host-local PKI exchange sudo policy")
    )


def test_absent_role_only_revokes_owned_identity_and_removes_sudo_first(
    repo_root: Path,
) -> None:
    absent = yaml.safe_load(
        (
            repo_root
            / "roles/pki_host_local_exchange_access/tasks/absent.yml"
        ).read_text(encoding="utf-8")
    )
    revoke = task_named(absent, "Revoke managed host-local PKI exchange access")
    assert "marker.stat.exists" in revoke["when"]
    ownership = task_named(
        absent, "Validate exact managed identity ownership before revocation"
    )["ansible.builtin.assert"]
    assert any("marker_record.uid" in check for check in ownership["that"])
    assert any("marker_record.gid" in check for check in ownership["that"])
    block = revoke["block"]
    assert block[0]["name"] == "Remove host-local PKI exchange sudo policy first"
    assert block[-1]["name"] == "Release host-local PKI exchange account ownership"


def test_registry_playbooks_order_exchange_access(repo_root: Path) -> None:
    registry = yaml.safe_load((repo_root / "playbooks/registry.yml").read_text(encoding="utf-8"))
    play = registry[0]
    assert play["pre_tasks"][0]["when"].endswith("== 'absent'")
    assert play["roles"] == ["firewalld", "podman_host", "zot_registry"]
    assert play["post_tasks"][0]["when"].endswith("== 'present'")
    focused = yaml.safe_load(
        (repo_root / "playbooks/registry-pki-exchange-access.yml").read_text(
            encoding="utf-8"
        )
    )
    assert focused[0]["roles"] == ["pki_host_local_exchange_access"]


def test_dispatchers_use_no_shell_or_subprocess(repo_root: Path) -> None:
    root = repo_root / "roles/pki_host_local_exchange_access/files"
    for name in (
        "platform-pki-host-local-exchange-ssh-dispatch",
        "platform-pki-host-local-exchange-root-dispatch",
    ):
        source = (root / name).read_text(encoding="utf-8")
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=" not in source
        assert "eval(" not in source
        assert "os.execve(" in source


def test_sshd_validator_checks_complete_config(repo_root: Path) -> None:
    source = (
        repo_root
        / "roles/pki_host_local_exchange_access/files/"
        "platform-pki-host-local-exchange-sshd-validate"
    ).read_text(encoding="utf-8")
    assert 'MAIN_CONFIG = "/etc/ssh/sshd_config"' in source
    assert 'DROPIN_PATTERN = "/etc/ssh/sshd_config.d/*.conf"' in source
    assert '"-T"' in source
    assert "EXPECTED.issubset" in source
    assert "shell=True" not in source
