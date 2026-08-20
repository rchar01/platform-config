from __future__ import annotations

import os
import runpy
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from conftest import CommandRunner


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
    assert "pki_host_local_exchange_access_state" not in defaults
    assert defaults["pki_host_local_exchange_access_user"] == "exchange-operator"
    assert defaults["pki_host_local_exchange_access_group"] == "exchange-operator"
    assert defaults["pki_host_local_exchange_access_marker_path"].endswith(".managed")
    assert defaults["pki_host_local_exchange_access_root_dispatch_path"] == ROOT_DISPATCH
    assert defaults["pki_host_local_exchange_access_helper_path"] == HELPER
    assert defaults["pki_host_local_exchange_access_lease_path"] == (
        "/var/lib/platform-pki-exchange-access.lease"
    )
    assert defaults["pki_host_local_exchange_access_operation_token"] == ""

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
    assert present.index(marker) < present.index(
        task_named(present, "Create root-controlled exchange account directories")
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
    home = task_named(block, "Remove host-local PKI exchange account home")
    assert home["when"] == (
        "pki_host_local_exchange_access_absent_marker_record.state == 'managed'"
    )
    assert block[-1]["name"] == "Release host-local PKI exchange account ownership"


def test_registry_playbooks_order_exchange_access(repo_root: Path) -> None:
    registry = yaml.safe_load((repo_root / "playbooks/registry.yml").read_text(encoding="utf-8"))
    play = registry[0]
    assert play["pre_tasks"] == [
        {
            "name": "Revoke host-local PKI exchange access before service convergence",
            "ansible.builtin.include_role": {
                "name": "pki_host_local_exchange_access",
                "tasks_from": "revoke",
            },
        }
    ]
    assert play["roles"] == ["firewalld", "podman_host", "zot_registry"]
    assert "post_tasks" not in play
    assert "pki_host_local_exchange_access_state" not in yaml.safe_dump(play)

    focused = yaml.safe_load(
        (repo_root / "playbooks/registry-pki-exchange-access.yml").read_text(
            encoding="utf-8"
        )
    )
    tasks = focused[0]["tasks"]
    assert [task["name"] for task in tasks] == [
        "Require one exact registry target for exchange access enablement",
        "Require owned host-local PKI exchange operation lease",
        "Install host-local PKI lifecycle helper for enabled exchange access",
        "Install host-local PKI exchange endpoint for enabled access",
        "Run fixed enabled host-local PKI exchange access boundary",
    ]
    assert tasks[0]["ansible.builtin.assert"]["that"] == [
        "ansible_play_hosts_all == [inventory_hostname]",
        (
            "groups.get('registry', []) | select('equalto', inventory_hostname) "
            "| list | length == 1"
        ),
    ]
    assert tasks[1]["ansible.builtin.include_role"]["tasks_from"] == "require_lease"
    assert tasks[2]["ansible.builtin.include_role"]["tasks_from"] == "lifecycle_helper"
    assert tasks[3]["ansible.builtin.include_role"]["tasks_from"] == "exchange_helper"
    assert tasks[4]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_exchange_access",
        "tasks_from": "enable_access",
    }
    assert "pki_host_local_exchange_access_state" not in yaml.safe_dump(focused)

    role = repo_root / "roles/pki_host_local_exchange_access/tasks"
    enable_entry = yaml.safe_load((role / "enable.yml").read_text(encoding="utf-8"))
    assert enable_entry[0] == {
        "name": "Load fixed host-local PKI exchange access validation",
        "ansible.builtin.import_tasks": "validate.yml",
    }
    assert "ansible.builtin.assert" in enable_entry[1]
    claim = task_named(
        task_named(enable_entry, "Claim fixed host-local PKI exchange operation lease")[
            "block"
        ],
        "Atomically create empty host-local PKI exchange operation lease",
    )
    claim_source = claim["ansible.builtin.command"]["argv"][2]
    assert "os.mkdir(path, 0o700)" in claim_source
    assert "os.setxattr(" in claim_source
    assert "user.platform_config_operation" in claim_source
    assert "flock" not in yaml.safe_dump(enable_entry)
    claim_block = task_named(
        enable_entry, "Claim fixed host-local PKI exchange operation lease"
    )
    cleanup_claim = task_named(
        claim_block["rescue"],
        "Release incomplete owned host-local PKI exchange lease claim",
    )
    assert cleanup_claim["when"][-1].endswith("lease_claim.rc == 0")

    enable_access = yaml.safe_load(
        (role / "enable_access.yml").read_text(encoding="utf-8")
    )
    assert enable_access[0] == {
        "name": "Require fixed host-local PKI exchange operation lease",
        "ansible.builtin.import_tasks": "require_lease.yml",
    }
    assert enable_access[2] == {
        "name": "Enable fixed host-local PKI exchange access",
        "ansible.builtin.import_tasks": "present.yml",
    }
    assert [task["name"] for task in enable_access[-4:]] == [
        "Read fixed host-local PKI exchange public key after enablement",
        "Inspect fixed host-local PKI exchange account after enablement",
        "Inspect fixed host-local PKI exchange group after enablement",
        "Require fixed host-local PKI exchange access to be enabled",
    ]
    enabled = enable_access[-1]["ansible.builtin.assert"]["that"]
    assert "pki_host_local_exchange_access_enabled_user.rc == 0" in enabled
    assert "pki_host_local_exchange_access_enabled_group.rc == 0" in enabled
    assert any("enabled_key.content" in condition for condition in enabled)
    assert "pki_host_local_exchange_access_state" not in yaml.safe_dump(
        enable_entry + enable_access
    )

    lease_validation = (role / "validate_lease.yml").read_text(encoding="utf-8")
    for required in (
        "os.O_NOFOLLOW",
        "metadata.st_uid != 0",
        "stat.S_IMODE(metadata.st_mode) != 0o700",
        "os.listdir(descriptor)",
        "user.platform_config_operation",
        "lease belongs to another operation",
    ):
        assert required in lease_validation

    claim_play = yaml.safe_load(
        (
            repo_root / "playbooks/registry-pki-exchange-access-claim.yml"
        ).read_text(encoding="utf-8")
    )[0]
    assert claim_play["tasks"][1]["ansible.builtin.include_role"] == {
        "name": "pki_host_local_exchange_access",
        "tasks_from": "enable",
    }

    revoke = yaml.safe_load(
        (repo_root / "playbooks/registry-pki-exchange-access-revoke.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    assert revoke["hosts"] == "registry"
    assert "vars" not in revoke
    assert revoke["tasks"][0]["ansible.builtin.assert"]["that"] == [
        "ansible_play_hosts_all == [inventory_hostname]",
        (
            "groups.get('registry', []) | select('equalto', inventory_hostname) "
            "| list | length == 1"
        ),
    ]
    assert revoke["tasks"][1] == {
        "name": "Run fixed absent host-local PKI exchange access boundary",
        "ansible.builtin.include_role": {
            "name": "pki_host_local_exchange_access",
            "tasks_from": "revoke",
        },
    }

    revoke_entry = yaml.safe_load((role / "revoke.yml").read_text(encoding="utf-8"))
    assert revoke_entry[0] == {
        "name": "Load fixed host-local PKI exchange access validation",
        "ansible.builtin.import_tasks": "validate.yml",
    }
    revoke_access = task_named(
        revoke_entry, "Revoke fixed host-local PKI exchange access"
    )
    assert revoke_access["ansible.builtin.import_tasks"] == "absent.yml"
    postcondition_task = task_named(
        revoke_entry, "Require fixed host-local PKI exchange access to be absent"
    )
    postcondition = postcondition_task["ansible.builtin.assert"]["that"]
    assert "pki_host_local_exchange_access_revoked_user.rc == 2" in postcondition
    assert "pki_host_local_exchange_access_revoked_group.rc == 2" in postcondition
    release = task_named(
        revoke_entry,
        "Release empty host-local PKI exchange operation lease after revocation",
    )
    assert release["ansible.builtin.command"]["argv"][:2] == [
        "/usr/bin/rmdir",
        "--",
    ]
    assert revoke_entry.index(postcondition_task) < revoke_entry.index(release)
    assert task_named(
        revoke_entry,
        "Validate host-local PKI exchange operation lease before revocation",
    )["when"].endswith("lease.stat.exists")
    assert task_named(
        revoke_entry,
        "Require token-bound cleanup to retain its operation lease",
    )["when"] == "pki_host_local_exchange_access_operation_token != ''"
    assert revoke_entry[-1]["name"] == (
        "Require fixed host-local PKI exchange operation lease to be absent"
    )
    assert "pki_host_local_exchange_access_state" not in yaml.safe_dump(revoke_entry)
    assert "pki_host_local_exchange_access_state" not in (
        role / "validate.yml"
    ).read_text(encoding="utf-8")
    assert "pki_host_local_exchange_access_state" not in (
        role / "absent.yml"
    ).read_text(encoding="utf-8")
    main = yaml.safe_load((role / "main.yml").read_text(encoding="utf-8"))
    assert main == [
        {
            "name": "Run fixed absent host-local PKI exchange access boundary",
            "ansible.builtin.import_tasks": "revoke.yml",
        }
    ]


def test_revoke_make_target_uses_only_the_fixed_revoke_entry_point(
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("registry-pki-exchange-access-revoke:", 1)[1].split(
        "\n\n", 1
    )[0]
    assert "_guard-pki-limit" in target
    assert "PLAYBOOK=playbooks/registry-pki-exchange-access-revoke.yml" in target
    assert "pki_host_local_exchange_access_state" not in target
    playbook = yaml.safe_load(
        (repo_root / "playbooks/registry-pki-exchange-access-revoke.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    dispatch = playbook["tasks"][1]["ansible.builtin.include_role"]
    assert dispatch["tasks_from"] == "revoke"
    assert "pki_host_local_exchange_access_state" not in yaml.safe_dump(playbook)
    dry_run = command_runner.run(
        (
            "make",
            "-n",
            "registry-pki-exchange-access-revoke",
            "ENV=dev",
            "LIMIT=registry-one.test",
            "EXTRA_ARGS=-e pki_host_local_exchange_access_state=present",
        ),
        cwd=repo_root,
    ).assert_success()
    assert "pki_host_local_exchange_access_state=present" in dry_run.stdout
    assert "pki_host_local_exchange_access_state=absent" not in dry_run.stdout
    assert "PLAYBOOK=playbooks/registry-pki-exchange-access-revoke.yml" in (
        dry_run.stdout
    )


def test_operation_lease_mkdir_rejects_overlap_without_replacing_owner(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
) -> None:
    tasks = yaml.safe_load(
        (
            repo_root / "roles/pki_host_local_exchange_access/tasks/enable.yml"
        ).read_text(encoding="utf-8")
    )
    claim_block = task_named(
        tasks, "Claim fixed host-local PKI exchange operation lease"
    )["block"]
    claim = task_named(
        claim_block, "Atomically create empty host-local PKI exchange operation lease"
    )["ansible.builtin.command"]["argv"]
    lease = tmp_path / "exchange.lease"
    first_token = "a" * 64
    second_token = "b" * 64

    assert claim[0] == "/usr/bin/python3"
    command_runner.run(
        (sys.executable, claim[1], claim[2], lease, first_token)
    ).assert_success()
    command_runner.run(
        (sys.executable, claim[1], claim[2], lease, second_token)
    ).assert_failure()

    assert list(lease.iterdir()) == []
    assert os.getxattr(lease, "user.platform_config_operation") == first_token.encode()


def _write_direct_exchange_test_tools(bin_dir: Path, log: Path) -> None:
    bin_dir.mkdir()
    make = bin_dir / "make"
    make.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'make' >>\"$EXCHANGE_TEST_LOG\"\n"
        "printf '|%s' \"$@\" >>\"$EXCHANGE_TEST_LOG\"\n"
        "printf '\\n' >>\"$EXCHANGE_TEST_LOG\"\n"
        "target=\"\"\n"
        "operation_token=\"\"\n"
        "for argument in \"$@\"; do\n"
        "  case \"$argument\" in\n"
        "    registry-pki-exchange-access-claim|registry-pki-exchange-access|registry-pki-exchange-access-revoke)\n"
        "      target=$argument ;;\n"
        "    OPERATION_TOKEN=*) operation_token=${argument#OPERATION_TOKEN=} ;;\n"
        "  esac\n"
        "done\n"
        "case \"$target\" in\n"
        "  registry-pki-exchange-access-claim)\n"
        "    if [[ -n ${EXCHANGE_TEST_LEASE_DIR:-} ]]; then\n"
        "      mkdir \"$EXCHANGE_TEST_LEASE_DIR\" || exit \"${EXCHANGE_TEST_CLAIM_STATUS:-31}\"\n"
        "      printf '%s\\n' \"$operation_token\" >\"$EXCHANGE_TEST_LEASE_DIR.token\"\n"
        "    fi\n"
        "    if [[ -n ${EXCHANGE_TEST_SIGNAL_DURING_CLAIM:-} ]]; then\n"
        "      kill -\"$EXCHANGE_TEST_SIGNAL_DURING_CLAIM\" \"$PPID\"\n"
        "      sleep 0.05\n"
        "    fi\n"
        "    exit \"${EXCHANGE_TEST_CLAIM_STATUS:-0}\" ;;\n"
        "  registry-pki-exchange-access)\n"
        "    exit \"${EXCHANGE_TEST_ENABLE_STATUS:-0}\" ;;\n"
        "  registry-pki-exchange-access-revoke)\n"
        "    if [[ -n ${EXCHANGE_TEST_LEASE_DIR:-} ]]; then\n"
        "      [[ -d $EXCHANGE_TEST_LEASE_DIR ]] || exit 44\n"
        "      [[ $(<\"$EXCHANGE_TEST_LEASE_DIR.token\") == \"$operation_token\" ]] || exit 44\n"
        "      rmdir \"$EXCHANGE_TEST_LEASE_DIR\"\n"
        "      rm \"$EXCHANGE_TEST_LEASE_DIR.token\"\n"
        "    fi\n"
        "    exit \"${EXCHANGE_TEST_REVOKE_STATUS:-0}\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    platform_pki = bin_dir / "platform-pki"
    platform_pki.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'platform-pki' >>\"$EXCHANGE_TEST_LOG\"\n"
        "printf '|%s' \"$@\" >>\"$EXCHANGE_TEST_LOG\"\n"
        "printf '\\n' >>\"$EXCHANGE_TEST_LOG\"\n"
        "if [[ -n ${EXCHANGE_TEST_SIGNAL_PARENT:-} ]]; then\n"
        "  kill -\"$EXCHANGE_TEST_SIGNAL_PARENT\" \"$PPID\"\n"
        "  exit 0\n"
        "fi\n"
        "exit \"${EXCHANGE_TEST_PLATFORM_STATUS:-0}\"\n",
        encoding="utf-8",
    )
    make.chmod(0o755)
    platform_pki.chmod(0o755)
    log.write_text("", encoding="utf-8")


@pytest.mark.parametrize(
    ("route", "route_arguments"),
    (
        ("request-pull", ("/endpoint.json", REQUEST_ID, "/request")),
        ("response-push", ("/endpoint.json", REQUEST_ID, ARTIFACT, "/response")),
        (
            "evidence-pull",
            ("/endpoint.json", REQUEST_ID, ARTIFACT, DEPLOYMENT, "/evidence"),
        ),
        (
            "outcome-push",
            (
                "/endpoint.json",
                REQUEST_ID,
                ARTIFACT,
                DEPLOYMENT,
                OUTCOME,
                "/outcome",
            ),
        ),
    ),
)
def test_direct_exchange_wrapper_fixes_route_and_access_boundaries(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
    route: str,
    route_arguments: tuple[str, ...],
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    _write_direct_exchange_test_tools(bin_dir, log)
    environment = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "EXCHANGE_TEST_LOG": os.fspath(log),
    }

    command_runner.run(
        (
            repo_root / "scripts/registry-pki-direct-exchange",
            "--env",
            "dev",
            "--env-file",
            "/private/dev.ansible.env",
            "--inventory",
            "/private/hosts.yml",
            "--limit",
            "registry-one.test",
            route,
            *route_arguments,
        ),
        environment=environment,
    ).assert_success()

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert "|registry-pki-exchange-access-claim|" in lines[0]
    assert "|registry-pki-exchange-access|" in lines[1]
    assert lines[2] == "|".join(
        ("platform-pki", "direct-exchange", route, *route_arguments)
    )
    assert "|registry-pki-exchange-access-revoke|" in lines[3]
    assert all("|EXTRA_ARGS=" in line for line in (lines[0], lines[1], lines[3]))
    tokens = {
        field
        for line in (lines[0], lines[1], lines[3])
        for field in line.split("|")
        if field.startswith("OPERATION_TOKEN=")
    }
    assert len(tokens) == 1
    token = next(iter(tokens)).removeprefix("OPERATION_TOKEN=")
    assert len(token) == 64
    assert set(token) <= set("0123456789abcdef")


def test_direct_exchange_wrapper_revokes_on_failure_and_rejects_other_routes(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    _write_direct_exchange_test_tools(bin_dir, log)
    environment = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "EXCHANGE_TEST_LOG": os.fspath(log),
        "EXCHANGE_TEST_PLATFORM_STATUS": "17",
    }
    common = (
        repo_root / "scripts/registry-pki-direct-exchange",
        "--env",
        "dev",
        "--env-file",
        "/private/dev.ansible.env",
        "--inventory",
        "/private/hosts.yml",
        "--limit",
        "registry-one.test",
    )

    failed = command_runner.run(
        (*common, "request-pull", "/endpoint.json", REQUEST_ID, "/request"),
        environment=environment,
    )
    assert failed.returncode == 17
    lines = log.read_text(encoding="utf-8").splitlines()
    assert "|registry-pki-exchange-access-revoke|" in lines[-1]

    log.write_text("", encoding="utf-8")
    rejected = command_runner.run(
        (*common, "cleanup-outcome", REQUEST_ID),
        environment=environment,
    ).assert_failure()
    assert rejected.returncode == 2
    assert log.read_text(encoding="utf-8") == ""

    source = (repo_root / "scripts/registry-pki-direct-exchange").read_text(
        encoding="utf-8"
    )
    for signal_name in ("HUP", "INT", "TERM"):
        assert f"trap 'exit " in source
        assert signal_name in source
    assert 'platform-pki direct-exchange "$route" "${route_arguments[@]}"' in source
    assert "make_access registry-pki-exchange-access-revoke\ncommand" not in source


def _direct_exchange_test_command(repo_root: Path) -> tuple[str | Path, ...]:
    return (
        repo_root / "scripts/registry-pki-direct-exchange",
        "--env",
        "dev",
        "--env-file",
        "/private/dev.ansible.env",
        "--inventory",
        "/private/hosts.yml",
        "--limit",
        "registry-one.test",
        "request-pull",
        "/endpoint.json",
        REQUEST_ID,
        "/request",
    )


def test_overlapping_lease_rejection_cleanup_does_not_mutate_owner(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    _write_direct_exchange_test_tools(bin_dir, log)
    lease = tmp_path / "target.lease"
    lease.mkdir()
    lease_token = Path(f"{lease}.token")
    lease_token.write_text(f"{'f' * 64}\n", encoding="utf-8")
    result = command_runner.run(
        _direct_exchange_test_command(repo_root),
        environment={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "EXCHANGE_TEST_LOG": os.fspath(log),
            "EXCHANGE_TEST_LEASE_DIR": os.fspath(lease),
        },
    )
    assert result.returncode == 31
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert "|registry-pki-exchange-access-claim|" in lines[0]
    assert "|registry-pki-exchange-access-revoke|" in lines[1]
    assert not any(line.startswith("platform-pki|") for line in lines)
    assert lease.is_dir()
    assert lease_token.read_text(encoding="utf-8") == f"{'f' * 64}\n"


@pytest.mark.parametrize(
    ("signal_name", "expected_status"),
    (("HUP", 129), ("INT", 130), ("TERM", 143)),
)
def test_direct_exchange_wrapper_cleans_claim_completed_before_signal_delivery(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
    signal_name: str,
    expected_status: int,
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    lease = tmp_path / "target.lease"
    _write_direct_exchange_test_tools(bin_dir, log)
    result = command_runner.run(
        _direct_exchange_test_command(repo_root),
        environment={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "EXCHANGE_TEST_LOG": os.fspath(log),
            "EXCHANGE_TEST_LEASE_DIR": os.fspath(lease),
            "EXCHANGE_TEST_SIGNAL_DURING_CLAIM": signal_name,
            "EXCHANGE_TEST_REVOKE_STATUS": "33",
        },
    )
    assert result.returncode == expected_status
    assert "final access revocation failed with status 33" in result.stderr
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert "|registry-pki-exchange-access-claim|" in lines[0]
    assert "|registry-pki-exchange-access-revoke|" in lines[1]
    assert not lease.exists()
    assert not Path(f"{lease}.token").exists()
    assert not any(line.startswith("platform-pki|") for line in lines)


def test_partial_enable_failure_attempts_owned_cleanup(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    _write_direct_exchange_test_tools(bin_dir, log)
    result = command_runner.run(
        _direct_exchange_test_command(repo_root),
        environment={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "EXCHANGE_TEST_LOG": os.fspath(log),
            "EXCHANGE_TEST_ENABLE_STATUS": "32",
        },
    )
    assert result.returncode == 32
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert "|registry-pki-exchange-access-claim|" in lines[0]
    assert "|registry-pki-exchange-access|" in lines[1]
    assert "|registry-pki-exchange-access-revoke|" in lines[2]
    assert not any(line.startswith("platform-pki|") for line in lines)


def test_successful_transfer_returns_final_revoke_failure(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    _write_direct_exchange_test_tools(bin_dir, log)
    result = command_runner.run(
        _direct_exchange_test_command(repo_root),
        environment={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "EXCHANGE_TEST_LOG": os.fspath(log),
            "EXCHANGE_TEST_REVOKE_STATUS": "33",
        },
    )
    assert result.returncode == 33
    assert "final access revocation failed with status 33" in result.stderr
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert lines[2].startswith("platform-pki|direct-exchange|request-pull|")
    assert "|registry-pki-exchange-access-revoke|" in lines[3]


@pytest.mark.parametrize(
    ("signal_name", "expected_status"),
    (("HUP", 129), ("INT", 130), ("TERM", 143)),
)
def test_direct_exchange_wrapper_revokes_on_handled_signals(
    repo_root: Path,
    command_runner: CommandRunner,
    tmp_path: Path,
    signal_name: str,
    expected_status: int,
) -> None:
    bin_dir = tmp_path / "bin"
    log = tmp_path / "exchange.log"
    _write_direct_exchange_test_tools(bin_dir, log)
    result = command_runner.run(
        (
            repo_root / "scripts/registry-pki-direct-exchange",
            "--env",
            "dev",
            "--env-file",
            "/private/dev.ansible.env",
            "--inventory",
            "/private/hosts.yml",
            "--limit",
            "registry-one.test",
            "request-pull",
            "/endpoint.json",
            REQUEST_ID,
            "/request",
        ),
        environment={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "EXCHANGE_TEST_LOG": os.fspath(log),
            "EXCHANGE_TEST_SIGNAL_PARENT": signal_name,
        },
    )
    assert result.returncode == expected_status
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert "|registry-pki-exchange-access-revoke|" in lines[-1]


def test_absent_role_is_idempotent_when_managed_marker_is_absent(
    repo_root: Path,
) -> None:
    absent = yaml.safe_load(
        (
            repo_root
            / "roles/pki_host_local_exchange_access/tasks/absent.yml"
        ).read_text(encoding="utf-8")
    )
    mutating_actions = {
        "ansible.builtin.file",
        "ansible.builtin.group",
        "ansible.builtin.user",
    }

    for task in absent:
        actions = mutating_actions.intersection(task)
        if actions:
            assert "marker.stat.exists" in str(task.get("when", ""))
        for child in task.get("block", []):
            if mutating_actions.intersection(child):
                assert "marker.stat.exists" in str(task.get("when", ""))


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
