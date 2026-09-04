from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import CommandRunner


COUNTERS = ("ok", "changed", "failures", "unreachable", "skipped", "rescued", "ignored")


def _summary_root(isolated_test_dir: Path) -> tuple[Path, Path]:
    root = isolated_test_dir / "summary"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root, root / "events.jsonl"


def _launcher_summary_output(isolated_test_dir: Path) -> Path:
    root = isolated_test_dir / "launcher-summary"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    output = root / "summary.txt"
    output.touch(mode=0o600)
    output.chmod(0o600)
    return output


def _initialize(
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
    operation: str,
) -> Path:
    _, events = _summary_root(isolated_test_dir)
    command_runner.run(
        [
            repo_root / "scripts/platform-config-operation-summary",
            "initialize",
            "--operation",
            operation,
            "--output",
            events,
        ]
    ).assert_success()
    assert events.stat().st_mode & 0o777 == 0o600
    return events


def _append(events: Path, *records: dict[str, object]) -> None:
    with events.open("a", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")


def _phase(phase: str, status: int = 0) -> tuple[dict[str, object], dict[str, object]]:
    return (
        {"schema": 1, "kind": "phase", "phase": phase, "state": "started"},
        {
            "schema": 1,
            "kind": "phase",
            "phase": phase,
            "state": "completed",
            "status": status,
        },
    )


def _recap(
    phase: str,
    host: str,
    *,
    changed: int = 0,
    failures: int = 0,
    unreachable: int = 0,
    rescued: int = 0,
) -> dict[str, object]:
    values = {counter: 0 for counter in COUNTERS}
    values.update(
        changed=changed,
        failures=failures,
        unreachable=unreachable,
        rescued=rescued,
    )
    return {
        "schema": 1,
        "kind": "recap",
        "phase": phase,
        "host": host,
        "counters": values,
    }


def _render(
    repo_root: Path,
    command_runner: CommandRunner,
    events: Path,
    status: int,
):
    return command_runner.run(
        [
            repo_root / "scripts/platform-config-operation-summary",
            "render",
            "--input",
            events,
            "--status",
            str(status),
        ]
    )


def test_summary_renders_unchanged_changed_and_rescued_success(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "rke2-converge-plan"
    )
    _append(
        events,
        {"schema": 1, "kind": "host", "host": "server-a", "role": "server"},
        {"schema": 1, "kind": "host", "host": "agent-b", "role": "agent"},
    )
    phases = (
        "inventory",
        "connectivity",
        "core-health",
        "convergence-preflight",
        "rke2-plan",
        "kube-vip-plan",
    )
    for phase in phases:
        _append(events, *_phase(phase))
        if phase == "inventory":
            continue
        _append(events, _recap(phase, "server-a", changed=1 if phase == "rke2-plan" else 0))
        if phase != "kube-vip-plan":
            _append(events, _recap(phase, "agent-b", rescued=1 if phase == "core-health" else 0))
    _append(
        events,
        {
            "schema": 1,
            "kind": "task",
            "phase": "rke2-plan",
            "host": "server-a",
            "outcome": "changed",
            "task": "Write RKE2 configuration",
        },
        {
            "schema": 1,
            "kind": "task",
            "phase": "rke2-plan",
            "host": "agent-b",
            "outcome": "changed",
            "task": "Write RKE2 configuration",
        },
    )

    result = _render(repo_root, command_runner, events, 0).assert_success()

    assert result.stdout.splitlines()[0] == "=== PLATFORM CONFIG OPERATION SUMMARY ==="
    assert result.stdout.splitlines()[-1] == "=== END PLATFORM CONFIG OPERATION SUMMARY ==="
    assert "Overall: PASS" in result.stdout
    assert "agent-b" in result.stdout
    assert "server-a" in result.stdout
    assert "kube-vip-plan" in result.stdout
    assert "N/A" in result.stdout
    assert "Write RKE2 configuration: agent-b, server-a" in result.stdout
    assert "Observed failed tasks:\n  none" in result.stdout


@pytest.mark.parametrize(
    ("changed_phase", "changed_host"),
    [
        (None, None),
        ("rke2-post-check", "server-a"),
        ("rke2-post-check", "agent-b"),
        ("kube-vip-post-check", "server-a"),
    ],
)
def test_summary_requires_post_checks_to_predict_no_changes(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    changed_phase: str | None,
    changed_host: str | None,
) -> None:
    events = _initialize(repo_root, command_runner, isolated_test_dir, "rke2-deploy")
    _append(
        events,
        {"schema": 1, "kind": "host", "host": "server-a", "role": "server"},
        {"schema": 1, "kind": "host", "host": "agent-b", "role": "agent"},
    )
    phases = (
        "core-health",
        "convergence-preflight",
        "rke2-apply",
        "kube-vip-apply",
        "rke2-smoke",
        "kube-vip-smoke",
        "rke2-post-check",
        "kube-vip-post-check",
    )
    for phase in phases:
        _append(events, *_phase(phase))
        server_changed = phase == "rke2-apply" or (
            phase == changed_phase and changed_host == "server-a"
        )
        _append(events, _recap(phase, "server-a", changed=int(server_changed)))
        if not phase.startswith("kube-vip-"):
            agent_changed = phase == "rke2-apply" or (
                phase == changed_phase and changed_host == "agent-b"
            )
            _append(
                events,
                _recap(phase, "agent-b", changed=int(agent_changed)),
            )

    result = _render(repo_root, command_runner, events, 0)
    if changed_phase is None:
        result.assert_success()
        assert "Overall: PASS" in result.stdout
    else:
        result.assert_failure()
        assert result.returncode == 2
        assert "Overall: FAIL" in result.stdout
        assert changed_host is not None
        role = "server" if changed_host == "server-a" else "agent"
        assert any(
            line.split()[:4] == [changed_host, role, changed_phase, "FAIL"]
            for line in result.stdout.splitlines()
        )

    assert any(
        line.split()[:4] == ["server-a", "server", "rke2-apply", "PASS"]
        and line.split()[4] == "1"
        for line in result.stdout.splitlines()
    )
    assert any(
        line.split()[:4] == ["agent-b", "agent", "kube-vip-post-check", "N/A"]
        for line in result.stdout.splitlines()
    )


def test_summary_renders_failed_unreachable_and_partial_hosts(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "rke2-bootstrap-plan"
    )
    for host, role in (
        ("server-a", "server"),
        ("agent-b", "agent"),
        ("server-c", "server"),
    ):
        _append(events, {"schema": 1, "kind": "host", "host": host, "role": role})
    _append(events, *_phase("inventory"), *_phase("connectivity", 1))
    _append(
        events,
        _recap("connectivity", "server-a", failures=1),
        _recap("connectivity", "agent-b", unreachable=1),
        {
            "schema": 1,
            "kind": "task",
            "phase": "connectivity",
            "host": "server-a",
            "outcome": "failed",
            "task": "Fixed failed task",
        },
        {
            "schema": 1,
            "kind": "task",
            "phase": "connectivity",
            "host": "agent-b",
            "outcome": "unreachable",
            "task": "ansible.builtin.ping",
        },
    )

    result = _render(repo_root, command_runner, events, 1).assert_success()

    assert "Overall: FAIL" in result.stdout
    assert all(host in result.stdout for host in ("server-a", "agent-b", "server-c"))
    assert "bootstrap-preflight" in result.stdout
    assert "Fixed failed task: server-a" in result.stdout
    assert "ansible.builtin.ping: agent-b" in result.stdout


def test_summary_renders_empty_pre_inventory_failure(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(repo_root, command_runner, isolated_test_dir, "openbao-status")

    result = _render(repo_root, command_runner, events, 2).assert_success()

    assert "Overall: FAIL" in result.stdout
    assert "Selected VMs: none established" in result.stdout
    assert "openbao-a" not in result.stdout


def test_summary_initializes_only_selected_inventory_hosts(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "rke2-converge-plan"
    )
    inventory = events.parent / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "rke2_cluster": {"hosts": ["server-a", "agent-b", "unknown-c"]},
                "rke2_servers": {"hosts": ["server-a"]},
                "rke2_agents": {"hosts": ["agent-b"]},
                "bastion": {"hosts": ["bastion-secret"]},
                "_meta": {"hostvars": {"server-a": {"token": "inventory-secret"}}},
            }
        ),
        encoding="utf-8",
    )
    inventory.chmod(0o600)

    command_runner.run(
        [
            repo_root / "scripts/platform-config-operation-summary",
            "hosts",
            "--operation",
            "rke2-converge-plan",
            "--inventory",
            inventory,
            "--output",
            events,
        ]
    ).assert_success()
    output = events.read_text(encoding="utf-8")

    assert '"host":"server-a","role":"server"' in output
    assert '"host":"agent-b","role":"agent"' in output
    assert '"host":"unknown-c","role":"N/A"' in output
    assert "bastion-secret" not in output
    assert "inventory-secret" not in output


def test_openbao_summary_requires_exact_three_host_evidence(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "openbao-restart-plan"
    )
    for host in ("openbao-a", "openbao-b"):
        _append(events, {"schema": 1, "kind": "host", "host": host, "role": "openbao"})
    for phase in (
        "inventory",
        "connectivity",
        "openbao-status",
        "openbao-restart-check",
    ):
        _append(events, *_phase(phase))
        if phase != "inventory":
            for host in ("openbao-a", "openbao-b"):
                _append(events, _recap(phase, host))

    result = _render(repo_root, command_runner, events, 0).assert_failure()

    assert result.returncode == 2
    assert "Overall: FAIL" in result.stdout


def test_summary_marks_missing_applicable_openbao_phase_failed(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "openbao-converge-plan"
    )
    for host in ("openbao-a", "openbao-b", "openbao-c"):
        _append(events, {"schema": 1, "kind": "host", "host": host, "role": "openbao"})
    for phase in ("inventory", "connectivity", "openbao-status"):
        _append(events, *_phase(phase))
        if phase != "inventory":
            for host in ("openbao-a", "openbao-b", "openbao-c"):
                _append(events, _recap(phase, host))

    result = _render(repo_root, command_runner, events, 0).assert_failure()

    assert result.returncode == 2
    missing_phase_rows = [
        line.split()[:4]
        for line in result.stdout.splitlines()
        if "openbao-converge-check" in line
    ]
    assert missing_phase_rows == [
        [host, "openbao", "openbao-converge-check", "FAIL"]
        for host in ("openbao-a", "openbao-b", "openbao-c")
    ]


@pytest.mark.parametrize(
    "invalid_record",
    [
        {
            "schema": 1,
            "kind": "task",
            "phase": "connectivity",
            "host": "server-a",
            "outcome": "failed",
            "task": "terminal-secret\nsecond-line",
        },
        {
            "schema": 1,
            "kind": "recap",
            "phase": "connectivity",
            "host": "server-a",
            "counters": {
                "ok": 0,
                "changed": -1,
                "failures": 0,
                "unreachable": 0,
                "skipped": 0,
                "rescued": 0,
                "ignored": 0,
            },
        },
        {
            "schema": 1,
            "kind": "task",
            "phase": "connectivity",
            "host": "server-a",
            "outcome": "failed",
            "task": "terminal\u009bcontrol",
        },
        {
            "schema": 1,
            "kind": "task",
            "phase": "connectivity",
            "host": "server-a",
            "outcome": "failed",
            "task": "terminal\u202espoof",
        },
    ],
)
def test_summary_rejects_malformed_records_without_disclosure(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    invalid_record: dict[str, object],
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "rke2-bootstrap-plan"
    )
    _append(
        events,
        {"schema": 1, "kind": "host", "host": "server-a", "role": "server"},
        invalid_record,
    )

    result = _render(repo_root, command_runner, events, 0).assert_failure()

    assert result.stderr.strip() == "platform-config-operation-summary: invalid summary input"
    assert "terminal-secret" not in result.stdout + result.stderr


def test_summary_marks_zero_recap_failed_when_phase_command_failed(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(repo_root, command_runner, isolated_test_dir, "openbao-status")
    _append(
        events,
        {"schema": 1, "kind": "host", "host": "openbao-a", "role": "openbao"},
        *_phase("inventory"),
        *_phase("connectivity", 7),
        _recap("connectivity", "openbao-a"),
    )

    result = _render(repo_root, command_runner, events, 7).assert_success()

    assert "Overall: FAIL" in result.stdout
    assert any(
        line.split()[2:4] == ["connectivity", "FAIL"]
        for line in result.stdout.splitlines()
        if line.startswith("openbao-a")
    )


def test_summary_fails_closed_for_unresolved_rke2_role(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(
        repo_root, command_runner, isolated_test_dir, "rke2-bootstrap-plan"
    )
    _append(events, {"schema": 1, "kind": "host", "host": "node-a", "role": "N/A"})
    for phase in (
        "inventory",
        "connectivity",
        "bootstrap-preflight",
        "rke2-plan",
    ):
        _append(events, *_phase(phase))
        if phase != "inventory":
            _append(events, _recap(phase, "node-a"))

    result = _render(repo_root, command_runner, events, 0).assert_failure()

    assert result.returncode == 2
    assert "node-a" in result.stdout
    assert any(
        line.split()[:2] == ["node-a", "N/A"]
        for line in result.stdout.splitlines()
    )
    assert "Overall: FAIL" in result.stdout


def test_callback_records_only_allowlisted_fields(
    repo_root: Path,
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, events = _summary_root(isolated_test_dir)
    events.touch(mode=0o600)
    events.chmod(0o600)
    callback_path = (
        repo_root / "plugins/callback/platform_config_operation_summary.py"
    )
    spec = importlib.util.spec_from_file_location("operation_summary_callback", callback_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    callback = module.CallbackModule()
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_SUMMARY_PATH", str(events))
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_PHASE", "rke2-plan")
    host = SimpleNamespace(get_name=lambda: "server-a")
    task = SimpleNamespace(get_name=lambda: "Write RKE2 configuration")
    changed = SimpleNamespace(
        _host=host,
        _task=task,
        _result={"changed": True, "msg": "result-secret", "diff": "diff-secret"},
    )
    failed = SimpleNamespace(
        _host=host,
        _task=SimpleNamespace(get_name=lambda: "Fixed failed task"),
        _result={"changed": False, "exception": "exception-secret"},
    )
    unreachable = SimpleNamespace(
        _host=host,
        _task=SimpleNamespace(get_name=lambda: "ansible.builtin.ping"),
        _result={"msg": "transport-secret"},
    )

    callback.v2_runner_on_ok(changed)
    callback.v2_runner_on_failed(failed, ignore_errors=True)
    callback.v2_runner_on_failed(failed)
    callback.v2_runner_on_unreachable(unreachable)
    callback.v2_playbook_on_stats(
        SimpleNamespace(
            processed={"server-a": object()},
            summarize=lambda _host: {
                "ok": 3,
                "changed": 1,
                "failures": 1,
                "unreachable": 0,
                "skipped": 2,
                "rescued": 0,
                "ignored": 0,
            },
        )
    )
    records = [json.loads(line) for line in events.read_text().splitlines()]

    assert [record["kind"] for record in records] == ["task", "task", "task", "recap"]
    assert set(records[0]) == {"schema", "kind", "phase", "host", "outcome", "task"}
    assert set(records[-1]) == {"schema", "kind", "phase", "host", "counters"}
    assert not any(
        secret in events.read_text()
        for secret in ("result-secret", "diff-secret", "exception-secret", "transport-secret")
    )


def test_callback_records_error_after_task_write_failure(
    repo_root: Path,
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, events = _summary_root(isolated_test_dir)
    events.touch(mode=0o600)
    events.chmod(0o600)
    callback_path = (
        repo_root / "plugins/callback/platform_config_operation_summary.py"
    )
    spec = importlib.util.spec_from_file_location("failing_operation_callback", callback_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    append_record = module._append_record
    calls = 0

    def fail_first_write(path: Path, record: dict[str, object]) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError
        append_record(path, record)

    monkeypatch.setattr(module, "_append_record", fail_first_write)
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_SUMMARY_PATH", str(events))
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_PHASE", "connectivity")
    callback = module.CallbackModule()
    callback.v2_runner_on_ok(
        SimpleNamespace(
            _host=SimpleNamespace(get_name=lambda: "server-a"),
            _task=SimpleNamespace(get_name=lambda: "Changed task"),
            _result={"changed": True},
        )
    )
    callback.v2_playbook_on_stats(
        SimpleNamespace(
            processed={"server-a": object()},
            summarize=lambda _host: {counter: 0 for counter in COUNTERS},
        )
    )

    records = [json.loads(line) for line in events.read_text().splitlines()]
    assert records == [{"schema": 1, "kind": "error", "phase": "connectivity"}]


def test_callback_rejects_ip_inventory_hostname(
    repo_root: Path,
    isolated_test_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, events = _summary_root(isolated_test_dir)
    events.touch(mode=0o600)
    events.chmod(0o600)
    callback_path = (
        repo_root / "plugins/callback/platform_config_operation_summary.py"
    )
    spec = importlib.util.spec_from_file_location("safe_operation_callback", callback_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_SUMMARY_PATH", str(events))
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_PHASE", "connectivity")
    callback = module.CallbackModule()

    callback.v2_runner_on_failed(
        SimpleNamespace(
            _host=SimpleNamespace(get_name=lambda: "192.0.2.10"),
            _task=SimpleNamespace(get_name=lambda: "Fixed failed task"),
            _result={},
        )
    )

    assert "192.0.2.10" not in events.read_text()
    assert [json.loads(line) for line in events.read_text().splitlines()] == [
        {"schema": 1, "kind": "error", "phase": "connectivity"}
    ]


def test_callback_loads_for_ansible_ad_hoc_commands(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    events = _initialize(repo_root, command_runner, isolated_test_dir, "openbao-status")

    command_runner.run(
        [
            "ansible",
            "-i",
            "callback-test,",
            "all",
            "-c",
            "local",
            "-m",
            "ansible.builtin.ping",
        ],
        environment={
            "ANSIBLE_CALLBACK_PLUGINS": str(repo_root / "plugins/callback"),
            "ANSIBLE_CALLBACKS_ENABLED": "platform_config_operation_summary",
            "ANSIBLE_LOAD_CALLBACK_PLUGINS": "1",
            "PLATFORM_CONFIG_OPERATION_SUMMARY_PATH": str(events),
            "PLATFORM_CONFIG_OPERATION_PHASE": "connectivity",
        },
    ).assert_success()
    records = [json.loads(line) for line in events.read_text().splitlines()]
    recaps = [record for record in records if record["kind"] == "recap"]

    assert len(recaps) == 1
    assert recaps[0]["phase"] == "connectivity"
    assert recaps[0]["host"] == "callback-test"
    assert set(recaps[0]["counters"]) == set(COUNTERS)


def test_launcher_prints_empty_failure_summary_and_cleans_up(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    result = command_runner.run(
        [repo_root / "scripts/platform-config-operation", "openbao-status"]
    ).assert_failure()

    assert "Overall: FAIL" in result.stdout
    assert "Selected VMs: none established" in result.stdout
    assert not list((isolated_test_dir / "tmp").glob("platform-config-operation.*"))


def test_launcher_hands_failed_operation_summary_to_wrapper(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    output = _launcher_summary_output(isolated_test_dir)

    result = command_runner.run(
        [repo_root / "scripts/platform-config-operation", "openbao-status"],
        environment={"PLATFORM_CONFIG_OPERATION_SUMMARY_OUTPUT": str(output)},
    ).assert_failure()

    summary = output.read_text(encoding="utf-8")
    assert result.stdout == ""
    assert summary.count("=== PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    assert summary.count("=== END PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    assert "Overall: FAIL" in summary
    assert "Selected VMs: none established" in summary


@pytest.mark.parametrize(
    "unsafe_kind",
    ["empty", "relative", "missing", "symlink", "parent-symlink", "public-parent"],
)
def test_launcher_rejects_unsafe_summary_output_without_disclosure(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    unsafe_kind: str,
) -> None:
    private = isolated_test_dir / "private-output"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    target = private / "unsafe-summary-secret.txt"
    target.write_text("unchanged", encoding="utf-8")
    target.chmod(0o600)

    if unsafe_kind == "empty":
        output = ""
    elif unsafe_kind == "relative":
        output = "unsafe-summary-secret.txt"
    elif unsafe_kind == "missing":
        output = str(private / "missing-unsafe-summary-secret.txt")
    elif unsafe_kind == "symlink":
        link = private / "symlink-unsafe-summary-secret.txt"
        link.symlink_to(target)
        output = str(link)
    elif unsafe_kind == "parent-symlink":
        parent_link = isolated_test_dir / "linked-private-output"
        parent_link.symlink_to(private, target_is_directory=True)
        output = str(parent_link / target.name)
    else:
        public = isolated_test_dir / "public-output"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        public_target = public / "unsafe-summary-secret.txt"
        public_target.touch(mode=0o600)
        output = str(public_target)

    result = command_runner.run(
        [repo_root / "scripts/platform-config-operation", "openbao-status"],
        environment={"PLATFORM_CONFIG_OPERATION_SUMMARY_OUTPUT": output},
    ).assert_failure()

    assert result.returncode == 2
    assert result.stdout == ""
    assert "PLATFORM CONFIG OPERATION SUMMARY" not in result.stderr
    assert "unsafe-summary-secret" not in result.stdout + result.stderr
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_launcher_rejects_public_controller_vars(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    inventory = isolated_test_dir / "hosts.yml"
    controller_vars = isolated_test_dir / "controller-vars.yml"
    inventory.write_text("all: {}\n", encoding="utf-8")
    controller_vars.write_text("---\n{}\n", encoding="utf-8")
    controller_vars.chmod(0o644)

    result = command_runner.run(
        [
            repo_root / "scripts/platform-config-operation",
            "openbao-status",
            "--inventory",
            inventory,
            "--controller-vars",
            controller_vars,
        ]
    ).assert_failure()

    lines = result.stdout.splitlines()
    assert "controller-vars must not be group- or world-readable" in result.stderr
    assert lines.count("=== PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    assert lines.count("=== END PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    assert "Overall: FAIL" in result.stdout


def test_launcher_fails_closed_once_when_callback_evidence_is_missing(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    inventory = isolated_test_dir / "hosts.yml"
    controller_vars = isolated_test_dir / "controller-vars.yml"
    fake_bin = isolated_test_dir / "bin"
    inventory.write_text("all: {}\n", encoding="utf-8")
    controller_vars.write_text("---\n{}\n", encoding="utf-8")
    controller_vars.chmod(0o600)
    fake_bin.mkdir()
    inventory_script = """#!/usr/bin/env python3
import json

print(json.dumps({"openbao": {"hosts": ["openbao-a"]}}))
"""
    (fake_bin / "ansible-inventory").write_text(inventory_script, encoding="utf-8")
    (fake_bin / "ansible-inventory").chmod(0o755)
    for name in ("ansible", "ansible-playbook"):
        (fake_bin / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (fake_bin / name).chmod(0o755)

    result = command_runner.run(
        [
            repo_root / "scripts/platform-config-operation",
            "openbao-status",
            "--inventory",
            inventory,
            "--controller-vars",
            controller_vars,
        ],
        environment={"PATH": f"{fake_bin}:{os.environ['PATH']}"},
    ).assert_failure()

    lines = result.stdout.splitlines()
    assert result.returncode == 2
    assert lines.count("=== PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    assert lines.count("=== END PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    assert "Overall: FAIL" in result.stdout
    assert not list((isolated_test_dir / "tmp").glob("platform-config-operation.*"))
