from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


def load_plugin(
    repo_root: Path,
    name: str = "platform_pki_transport_client",
) -> ModuleType:
    path = repo_root / f"plugins/action/{name}.py"
    spec = importlib.util.spec_from_loader(
        f"{name}_test",
        SourceFileLoader(f"{name}_test", str(path)),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakePinned:
    def __init__(
        self,
        *,
        data: bytes = b"transport-client",
        fail_recheck: int | None = None,
    ) -> None:
        self.path = ""
        self.data = data
        self.fail_recheck = fail_recheck
        self.rechecks = 0
        self.closed = False

    def recheck(self) -> None:
        self.rechecks += 1
        if self.rechecks == self.fail_recheck:
            raise RuntimeError("source changed")

    def close(self) -> None:
        self.closed = True


def make_action(
    plugin: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    pinned: FakePinned,
    *,
    transfer_error: Exception | None = None,
    module_result: dict[str, Any] | None = None,
    cleanup_error: Exception | None = None,
    task_args: dict[str, str] | None = None,
) -> tuple[Any, list[tuple[str, Any]]]:
    events: list[tuple[str, Any]] = []
    monkeypatch.setattr(plugin.ActionBase, "run", lambda *args, **kwargs: {})
    monkeypatch.setattr(plugin, "pin_source", lambda source, digest: pinned)
    action = object.__new__(plugin.ActionModule)
    action._task = SimpleNamespace(
        args=task_args
        or {
            "source": "/outside-git/platform-pki",
            "sha256": "0" * 64,
            "dest": "/usr/local/libexec/platform-pki",
        },
        check_mode=False,
    )
    action._connection = SimpleNamespace(
        _shell=SimpleNamespace(
            join_path=lambda root, name: f"{root}/{name}"
        )
    )
    action._make_tmp_path = lambda: "/remote/tmp"

    def transfer(path: str, data: bytes) -> None:
        events.append(("transfer", (path, data)))
        if transfer_error is not None:
            raise transfer_error

    def execute_module(**kwargs: Any) -> dict[str, Any]:
        events.append(("module", kwargs))
        return {"changed": True} if module_result is None else module_result

    def remove(path: str) -> None:
        events.append(("cleanup", path))
        if cleanup_error is not None:
            raise cleanup_error

    action._transfer_data = transfer
    action._execute_module = execute_module
    action._remove_tmp_path = remove
    return action, events


def test_action_transfers_pinned_bytes_and_propagates_change(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root)
    pinned = FakePinned()
    action, events = make_action(plugin, monkeypatch, pinned)

    result = action.run(task_vars={"inventory_hostname": "target"})

    assert result == {"changed": True, "status": "installed"}
    assert pinned.rechecks == 3
    assert pinned.closed
    assert events[0] == (
        "transfer",
        ("/remote/tmp/.platform-pki", b"transport-client"),
    )
    module = events[1][1]
    assert module["module_name"] == "ansible.legacy.copy"
    assert module["module_args"] == {
        "src": "/remote/tmp/.platform-pki",
        "dest": "/usr/local/libexec/platform-pki",
        "remote_src": True,
        "owner": "root",
        "group": "root",
        "mode": "0755",
        "force": True,
        "follow": False,
    }
    assert events[-1] == ("cleanup", "/remote/tmp")


@pytest.mark.parametrize(
    ("case", "pinned", "options", "error"),
    (
        (
            "transfer",
            FakePinned(),
            {"transfer_error": RuntimeError("transfer failed")},
            "transfer failed",
        ),
        (
            "source-recheck",
            FakePinned(fail_recheck=2),
            {},
            "source changed",
        ),
        (
            "cleanup",
            FakePinned(),
            {"cleanup_error": RuntimeError("cleanup failed")},
            "cleanup failed",
        ),
    ),
)
def test_action_closes_pinned_source_on_failure(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    pinned: FakePinned,
    options: dict[str, Any],
    error: str,
) -> None:
    del case
    plugin = load_plugin(repo_root)
    action, events = make_action(plugin, monkeypatch, pinned, **options)

    with pytest.raises(RuntimeError, match=error):
        action.run()

    assert pinned.closed
    assert ("cleanup", "/remote/tmp") in events


def test_action_returns_module_failure_and_closes_pinned_source(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root)
    pinned = FakePinned()
    failure = {"failed": True, "msg": "copy failed"}
    action, events = make_action(
        plugin, monkeypatch, pinned, module_result=failure
    )

    assert action.run() == failure
    assert pinned.rechecks == 3
    assert pinned.closed
    assert events[-1] == ("cleanup", "/remote/tmp")


def test_action_rejects_unexpected_arguments_before_pinning(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root)
    pinned = FakePinned()
    action, _ = make_action(plugin, monkeypatch, pinned)
    action._task.args["mode"] = "0777"

    with pytest.raises(plugin.AnsibleActionFail, match="accepts only"):
        action.run()

    assert pinned.rechecks == 0
    assert not pinned.closed


def test_reviewed_ca_action_installs_pinned_bytes_with_selected_mode(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root, "platform_pki_reviewed_ca")
    pinned = FakePinned(data=b"reviewed CA bytes\n")
    action, events = make_action(
        plugin,
        monkeypatch,
        pinned,
        task_args={
            "source": "/outside-git/reviewed-ca.crt",
            "sha256": "0" * 64,
            "dest": "/etc/platform-config/reviewed-ca.crt",
            "mode": "0644",
        },
    )

    assert action.run() == {"changed": True, "status": "installed"}
    assert pinned.rechecks == 3
    assert pinned.closed
    assert events[0] == (
        "transfer",
        ("/remote/tmp/.reviewed-ca", b"reviewed CA bytes\n"),
    )
    assert events[1][1]["module_args"] == {
        "src": "/remote/tmp/.reviewed-ca",
        "dest": "/etc/platform-config/reviewed-ca.crt",
        "remote_src": True,
        "owner": "root",
        "group": "root",
        "mode": "0644",
        "force": True,
        "follow": False,
    }
    assert events[-1] == ("cleanup", "/remote/tmp")


@pytest.mark.parametrize(
    ("destination_stat", "changed", "status"),
    (
        ({"exists": False}, True, "would-install"),
        (
            {
                "exists": True,
                "isreg": True,
                "islnk": False,
                "uid": 0,
                "gid": 0,
                "nlink": 1,
                "mode": "0644",
                "checksum": "0" * 64,
            },
            False,
            "current",
        ),
    ),
)
def test_reviewed_ca_action_validates_destination_in_check_mode(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination_stat: dict[str, Any],
    changed: bool,
    status: str,
) -> None:
    plugin = load_plugin(repo_root, "platform_pki_reviewed_ca")
    pinned = FakePinned(data=b"reviewed CA bytes\n")
    action, events = make_action(
        plugin,
        monkeypatch,
        pinned,
        module_result={"changed": False, "stat": destination_stat},
        task_args={
            "source": "/outside-git/reviewed-ca.crt",
            "sha256": "0" * 64,
            "dest": "/etc/platform-config/reviewed-ca.crt",
            "mode": "0644",
        },
    )
    action._task.check_mode = True

    assert action.run() == {"changed": changed, "status": status}
    assert pinned.rechecks == 2
    assert pinned.closed
    assert events == [
        (
            "module",
            {
                "module_name": "ansible.legacy.stat",
                "module_args": {
                    "path": "/etc/platform-config/reviewed-ca.crt",
                    "follow": False,
                    "get_checksum": True,
                    "checksum_algorithm": "sha256",
                    "get_attributes": False,
                    "get_mime": False,
                },
                "task_vars": {},
            },
        )
    ]


def test_reviewed_ca_action_returns_module_failure_and_cleans_up(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root, "platform_pki_reviewed_ca")
    pinned = FakePinned(data=b"reviewed CA bytes\n")
    failure = {"failed": True, "msg": "copy failed"}
    action, events = make_action(
        plugin,
        monkeypatch,
        pinned,
        module_result=failure,
        task_args={
            "source": "/outside-git/reviewed-ca.crt",
            "sha256": "0" * 64,
            "dest": "/etc/platform-config/reviewed-ca.crt",
            "mode": "0600",
        },
    )

    assert action.run() == failure
    assert pinned.rechecks == 3
    assert pinned.closed
    assert events[-1] == ("cleanup", "/remote/tmp")


def test_reviewed_ca_action_cleans_up_after_source_recheck_failure(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root, "platform_pki_reviewed_ca")
    pinned = FakePinned(data=b"reviewed CA bytes\n", fail_recheck=2)
    action, events = make_action(
        plugin,
        monkeypatch,
        pinned,
        task_args={
            "source": "/outside-git/reviewed-ca.crt",
            "sha256": "0" * 64,
            "dest": "/etc/platform-config/reviewed-ca.crt",
            "mode": "0644",
        },
    )

    with pytest.raises(RuntimeError, match="source changed"):
        action.run()

    assert pinned.closed
    assert events[-1] == ("cleanup", "/remote/tmp")


@pytest.mark.parametrize("mode", ("", "644", "0666", "0755"))
def test_reviewed_ca_action_rejects_unsafe_mode_before_pinning(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    plugin = load_plugin(repo_root, "platform_pki_reviewed_ca")
    pinned = FakePinned(data=b"reviewed CA bytes\n")
    action, _ = make_action(
        plugin,
        monkeypatch,
        pinned,
        task_args={
            "source": "/outside-git/reviewed-ca.crt",
            "sha256": "0" * 64,
            "dest": "/etc/platform-config/reviewed-ca.crt",
            "mode": mode,
        },
    )

    with pytest.raises(plugin.AnsibleActionFail, match="mode must be 0600 or 0644"):
        action.run()

    assert pinned.rechecks == 0
    assert not pinned.closed


def test_trust_ingress_cleanup_failure_closes_all_pinned_sources(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = load_plugin(repo_root, "platform_pki_trust_ingress")
    monkeypatch.setattr(plugin.ActionBase, "run", lambda *args, **kwargs: {})
    pinned = {name: FakePinned() for name in plugin.TRUST_NAMES}
    for name, source in pinned.items():
        source.path = f"/outside-git/{name}"
    monkeypatch.setattr(
        plugin,
        "pin_source",
        lambda path, digest: pinned[Path(path).name],
    )
    action = object.__new__(plugin.ActionModule)
    action._task = SimpleNamespace(
        args={
            "sources": {
                name: f"/outside-git/{name}" for name in plugin.TRUST_NAMES
            },
            "sha256": {name: "0" * 64 for name in plugin.TRUST_NAMES},
            "ingress_root": "/var/lib/platform-pki/trust-ingress",
        },
        check_mode=False,
    )
    action._connection = SimpleNamespace(
        _shell=SimpleNamespace(
            join_path=lambda root, name: f"{root}/{name}"
        )
    )
    action._make_tmp_path = lambda: "/remote/tmp"
    action._transfer_data = lambda path, data: None
    action._execute_module = lambda **kwargs: {"changed": False}
    action._remove_tmp_path = lambda path: (_ for _ in ()).throw(
        RuntimeError("cleanup failed")
    )

    with pytest.raises(RuntimeError, match="cleanup failed"):
        action.run()

    assert all(source.closed for source in pinned.values())
