"""Offline failover dispatch and reporting; no service or network qualification."""

from __future__ import annotations

import importlib.util
import json
import os
import pty
import select
import shutil
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from test_operation_summary import _append, _initialize, _phase, _recap, _render
from test_rke2_operations import _write_executable


HOSTS = ("openbao-a", "openbao-b", "openbao-c")
ROUTES = {
    "openbao-haproxy-failover-plan": "plan",
    "openbao-haproxy-failover": "test",
    "openbao-haproxy-failover-recover": "recover",
}
PLAYBOOK = "playbooks/maintenance/openbao-haproxy-failover.yml"
REPORT_TASK = "Publish sanitized failover phase results on every selected host"


def _values(mode="test", **overrides):
    return {
        "failover_test_result": "passed" if mode == "test" else "not_run",
        "recovery_result": "passed" if mode == "test" else "not_required",
        "final_smoke_result": "not_run" if mode == "plan" else "passed",
        "failover_elapsed_seconds": 1.25 if mode == "test" else None,
        "transaction_elapsed_seconds": 12 if mode == "test" else None,
        **overrides,
    }


def _records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def launcher(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir / "paths with 'quotes' \" $HOME;$(false) [*]\\"
    root.mkdir(mode=0o700)
    inventory = root / "hosts.yml"
    inventory.write_text(yaml.safe_dump({"all": {"children": {
        "openbao": {"hosts": {host: {"ansible_connection": "local"} for host in HOSTS}},
        "unrelated": {"hosts": {"outside": {}}},
    }}}))
    controller = root / "controller vars.json"
    controller.write_text(json.dumps({
        "openbao_failover_mode": "bogus-controller-mode",
        "openbao_failover_plan_path": "/bogus/controller-plan.json",
    }))
    controller.chmod(0o600)
    binary = isolated_test_dir / "bin"
    binary.mkdir()
    log = isolated_test_dir / "calls.jsonl"
    script = r'''#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import select
import signal
import sys
from types import SimpleNamespace

name = pathlib.Path(sys.argv[0]).name
phase = os.environ['PLATFORM_CONFIG_OPERATION_PHASE']
with open(os.environ['FAILOVER_CALL_LOG'], 'a') as stream:
    stream.write(json.dumps(dict(argv=[name, *sys.argv[1:]], phase=phase, tty=os.isatty(0))) + '\n')
fault = os.environ.get('FAILOVER_FAULT', '')
hosts = ['openbao-a', 'openbao-b', 'openbao-c']
if fault == 'two-hosts':
    hosts.pop()
if name == 'ansible-inventory':
    if os.environ.get('FAILOVER_REAL_PLAYBOOK'):
        executable = os.environ['FAILOVER_REAL_INVENTORY']
        os.execv(executable, [executable, *sys.argv[1:]])
    print(json.dumps({'openbao': {'hosts': hosts}, 'unrelated': {'hosts': ['outside']}}))
    raise SystemExit(7 if fault == 'inventory-exit' else 0)
assert name == 'ansible-playbook'
if fault == 'interrupt':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    os.kill(os.getppid(), int(os.environ['FAILOVER_SIGNAL']))
    signal.pause()
if os.environ.get('FAILOVER_READ_STDIN') == '1':
    assert os.isatty(0)
    print('FAILOVER_STDIN_READY', flush=True)
    assert select.select([sys.stdin], [], [], 5)[0]
    assert sys.stdin.readline() == 'synthetic approval\n'
if os.environ.get('FAILOVER_REAL_PLAYBOOK'):
    args = sys.argv[1:]
    assert args[2] == os.environ['FAILOVER_SOURCE_PLAYBOOK']
    args[2] = os.environ['FAILOVER_REAL_PLAYBOOK']
    os.execv(os.environ['FAILOVER_REAL_ANSIBLE'], [os.environ['FAILOVER_REAL_ANSIBLE'], *args])
spec = importlib.util.spec_from_file_location('callback', os.environ['FAILOVER_CALLBACK'])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
callback = module.CallbackModule()
values = json.loads(os.environ['FAILOVER_VALUES'])
for host in hosts:
    if fault == 'missing-report' and host == hosts[-1]:
        continue
    callback.v2_runner_on_ok(SimpleNamespace(
        _host=SimpleNamespace(get_name=lambda: host),
        _task=SimpleNamespace(get_name=lambda: os.environ['FAILOVER_REPORT_TASK'], action='ansible.builtin.debug'),
        _result={'changed': False, 'msg': values, 'exception': 'private-exception-sentinel'},
    ))
counts = dict.fromkeys(('ok', 'changed', 'failures', 'unreachable', 'skipped', 'rescued', 'ignored'), 0)
counts['ok'] = 1
if fault in counts:
    counts[fault] = 1
callback.v2_playbook_on_stats(SimpleNamespace(
    processed=dict.fromkeys(hosts[:-1] if fault == 'missing-recap' else hosts),
    summarize=lambda _: counts,
))
raise SystemExit(7 if fault == 'phase-exit' else 0)
'''
    for name in ("ansible-inventory", "ansible-playbook", "ansible"):
        _write_executable(binary / name, script)
    return SimpleNamespace(
        script=repo_root / "scripts/platform-config-operation",
        inventory=inventory, controller=controller, plan=root / "failover plan.json", log=log,
        environment={
            **command_runner.environment,
            "PATH": f"{binary}:{command_runner.environment['PATH']}",
            "FAILOVER_CALL_LOG": str(log),
            "FAILOVER_CALLBACK": str(repo_root / "plugins/callback/platform_config_operation_summary.py"),
            "FAILOVER_REPORT_TASK": REPORT_TASK,
            "FAILOVER_VALUES": json.dumps(_values()),
            "CI": "true",
        },
    )


def _argv(launcher, operation):
    args = [str(launcher.script), operation, "--inventory", str(launcher.inventory),
            "--controller-vars", str(launcher.controller)]
    if ROUTES[operation] != "recover":
        args += ["--plan", str(launcher.plan)]
    if ROUTES[operation] == "test":
        launcher.plan.write_text("{}\n")
        launcher.plan.chmod(0o600)
    return args


def _assert_dispatch(repo_root, launcher, operation, *, tty=False):
    mode = ROUTES[operation]
    extra = ["--extra-vars", f"@{launcher.controller}"]
    expected = [
        ["ansible-inventory", "-i", str(launcher.inventory), "--list", *extra],
        ["ansible-playbook", "-i", str(launcher.inventory), str(repo_root / PLAYBOOK),
         "--limit", "openbao", *extra, "--extra-vars", json.dumps({
             "openbao_failover_mode": mode,
             "openbao_failover_plan_path": "" if mode == "recover" else str(launcher.plan),
         })],
    ]
    assert _records(launcher.log) == [
        {"argv": argv, "phase": phase, "tty": tty}
        for argv, phase in zip(expected, ("inventory", f"failover-{mode}"))
    ]


@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("ci", ["false", "true"])
def test_fixed_dispatch_and_complete_callback_summary(repo_root, launcher, command_runner, operation, ci):
    mode = ROUTES[operation]
    result = command_runner.run(_argv(launcher, operation), environment={
        **launcher.environment, "CI": ci, "FAILOVER_VALUES": json.dumps(_values(mode)),
    })
    if mode != "plan" and ci == "false":
        assert result.returncode == 2, result.diagnostics()
        assert "requires an interactive terminal" in result.stderr
        assert not launcher.log.exists()
        return
    result.assert_success()
    _assert_dispatch(repo_root, launcher, operation)
    assert "Overall: PASS" in result.stdout
    assert ("Execution context: GitLab Runner" in result.stdout) == (ci == "true")
    rows = [line.split() for line in result.stdout.splitlines() if line.startswith(HOSTS)]
    assert rows == [[host, "openbao", phase, "PASS", "0", "0", "0", "PASS"]
                    for host in HOSTS for phase in ("inventory", f"failover-{mode}")]
    assert "outside" not in result.stdout
    assert "private-exception-sentinel" not in result.stdout + result.stderr
    assert not list(Path(launcher.environment["TMPDIR"]).glob("platform-config-operation.*"))


@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("extra", [
    ["--node", "openbao-a"], ["--limit", "openbao"], ["--check"], ["--diff"],
    ["--extra-vars", "openbao_failover_mode=recover"], ["--tags", "stop"],
    ["--playbook", "other.yml"], ["--retry"], ["other.yml"],
])
def test_rejects_selectors_and_passthrough_before_ansible(launcher, command_runner, operation, extra):
    result = command_runner.run([*_argv(launcher, operation), *extra], environment=launcher.environment)
    assert result.returncode == 2, result.diagnostics()
    assert not launcher.log.exists()


@pytest.mark.parametrize("operation", list(ROUTES)[:2])
@pytest.mark.parametrize("case", ["omitted", "missing-value", "empty", "duplicate", "relative"])
def test_plan_argument_required_before_ansible(launcher, command_runner, operation, case):
    args = _argv(launcher, operation)
    if case == "omitted":
        args = args[:-2]
    elif case == "missing-value":
        args.pop()
    elif case == "duplicate":
        args += args[-2:]
    else:
        args[-1] = "" if case == "empty" else "relative.json"
    result = command_runner.run(args, environment=launcher.environment)
    assert result.returncode == 2, result.diagnostics()
    assert not launcher.log.exists()


def test_recovery_forbids_plan_before_ansible(launcher, command_runner):
    result = command_runner.run([
        *_argv(launcher, "openbao-haproxy-failover-recover"), "--plan", str(launcher.plan),
    ], environment=launcher.environment)
    assert result.returncode == 2, result.diagnostics()
    assert "--plan is forbidden" in result.stderr
    assert not launcher.log.exists()


@pytest.mark.serial
@pytest.mark.parametrize("operation", list(ROUTES)[1:])
def test_operator_tty_reaches_playbook_stdin(repo_root, launcher, operation):
    master, slave = pty.openpty()
    process = None
    try:
        process = subprocess.Popen(
            _argv(launcher, operation), cwd=repo_root,
            env={**launcher.environment, "CI": "false", "FAILOVER_READ_STDIN": "1",
                 "FAILOVER_VALUES": json.dumps(_values(ROUTES[operation]))},
            stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        os.close(slave)
        slave = -1
        assert process.stdout is not None
        assert select.select([process.stdout], [], [], 10)[0], "no stdin request"
        assert process.stdout.readline() == "FAILOVER_STDIN_READY\n"
        os.write(master, b"synthetic approval\n")
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr
        assert "Overall: PASS" in stdout
        _assert_dispatch(repo_root, launcher, operation, tty=True)
    finally:
        os.close(master)
        if slave != -1:
            os.close(slave)
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2)


@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("fault", ["inventory-exit", "phase-exit", "missing-recap", "missing-report", "two-hosts", "failures", "unreachable"])
def test_failure_never_redispatches_or_automatically_recovers(repo_root, launcher, command_runner, operation, fault):
    result = command_runner.run(_argv(launcher, operation), environment={
        **launcher.environment, "FAILOVER_FAULT": fault,
        "FAILOVER_VALUES": json.dumps(_values(ROUTES[operation])),
    })
    assert result.returncode == (7 if fault.endswith("exit") else 2), result.diagnostics()
    assert "Overall: FAIL" in result.stdout
    assert result.stdout.count("=== PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    if fault == "inventory-exit":
        assert len(_records(launcher.log)) == 1
    else:
        _assert_dispatch(repo_root, launcher, operation)
    assert not list(Path(launcher.environment["TMPDIR"]).glob("platform-config-operation.*"))


@pytest.mark.serial
@pytest.mark.parametrize("operation", ROUTES)
@pytest.mark.parametrize("signum,status", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_cancellation_preserves_status_without_retry(repo_root, launcher, command_runner, operation, signum, status):
    result = command_runner.run(_argv(launcher, operation), environment={
        **launcher.environment, "FAILOVER_FAULT": "interrupt", "FAILOVER_SIGNAL": str(signum),
    }, timeout=10)
    assert result.returncode == status, result.diagnostics()
    assert "Overall: FAIL" in result.stdout
    assert result.stdout.count("=== PLATFORM CONFIG OPERATION SUMMARY ===") == 1
    _assert_dispatch(repo_root, launcher, operation)
    assert not list(Path(launcher.environment["TMPDIR"]).glob("platform-config-operation.*"))


def _summary(repo_root, isolated_test_dir, command_runner, operation, values, *, omit=None):
    events = _initialize(repo_root, command_runner, isolated_test_dir, operation)
    phase = f"failover-{ROUTES[operation]}"
    assert _records(events)[0]["phases"] == ["inventory", phase]
    for host in HOSTS:
        _append(events, {"schema": 1, "kind": "host", "host": host, "role": "openbao"})
    _append(events, *_phase("inventory"), *_phase(phase))
    for host in HOSTS:
        _append(events, _recap(phase, host))
        if host != omit:
            _append(events, {"schema": 1, "kind": "failover", "phase": phase, "host": host, **values})
    return events


@pytest.mark.parametrize("mode,overrides,passed", [
    ("plan", {}, True),
    ("test", {}, True),
    ("test", {"failover_test_result": "failed"}, False),
    ("test", {"recovery_result": "failed"}, False),
    ("test", {"final_smoke_result": "failed"}, False),
    ("test", {"failover_test_result": "not_run"}, False),
    ("test", {"recovery_result": "not_required"}, False),
    ("test", {"final_smoke_result": "not_run"}, False),
    ("recover", {}, True),  # No retained record: not_run / not_required / passed.
    ("recover", {"failover_test_result": "failed", "recovery_result": "passed"}, True),
    ("recover", {"recovery_result": "failed"}, False),
    ("recover", {"final_smoke_result": "failed"}, False),
    ("plan", {"failover_test_result": "passed"}, False),
    ("plan", {"final_smoke_result": "passed"}, False),
])
def test_summary_keeps_proof_restoration_and_smoke_independent(
    repo_root, isolated_test_dir, command_runner, mode, overrides, passed,
):
    operation = next(route for route, value in ROUTES.items() if value == mode)
    values = _values(mode, **overrides)
    events = _summary(repo_root, isolated_test_dir, command_runner, operation, values)
    result = _render(repo_root, command_runner, events, 0)
    assert result.returncode == (0 if passed else 2), result.diagnostics()
    assert f"Overall: {'PASS' if passed else 'FAIL'}" in result.stdout
    for key, value in values.items():
        expected = (f"{key}: {'not measured' if value is None else value}"
                    if key.endswith("seconds") else f"{key}={value}")
        assert result.stdout.count(expected) == 3


@pytest.mark.parametrize("defect", ["missing", "duplicate", "foreign-host", "wrong-phase", "callback-error", "changed-plan"])
def test_summary_rejects_incomplete_or_unbound_reports(repo_root, isolated_test_dir, command_runner, defect):
    operation = "openbao-haproxy-failover-plan" if defect == "changed-plan" else "openbao-haproxy-failover"
    values = _values(ROUTES[operation])
    events = _summary(repo_root, isolated_test_dir, command_runner, operation, values, omit=HOSTS[-1])
    record = {"schema": 1, "kind": "failover", "phase": f"failover-{ROUTES[operation]}", "host": HOSTS[-1], **values}
    if defect == "duplicate":
        record["host"] = HOSTS[0]
    elif defect == "foreign-host":
        record["host"] = "outside"
    elif defect == "wrong-phase":
        record["phase"] = "inventory"
    elif defect == "callback-error":
        record = {"schema": 1, "kind": "error", "phase": "failover-test"}
    if defect != "missing":
        _append(events, record)
    if defect == "changed-plan":
        records = _records(events)
        next(item for item in records if item["kind"] == "recap")["counters"]["changed"] = 1
        events.write_text("".join(json.dumps(item) + "\n" for item in records))
    result = _render(repo_root, command_runner, events, 0)
    assert result.returncode == 2, result.diagnostics()
    assert "Overall: PASS" not in result.stdout
    if defect == "missing":
        assert "openbao-c: failover_test_result=unknown, recovery_result=unknown, final_smoke_result=unknown" in result.stdout


@pytest.fixture
def callback(repo_root, isolated_test_dir, monkeypatch):
    path = repo_root / "plugins/callback/platform_config_operation_summary.py"
    spec = importlib.util.spec_from_file_location("failover_summary_callback", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    events = isolated_test_dir / "callback.jsonl"
    events.touch(mode=0o600)
    events.chmod(0o600)
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_SUMMARY_PATH", str(events))
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_PHASE", "failover-test")
    return module.CallbackModule(), events


def _result(values, *, name=REPORT_TASK, action="ansible.builtin.debug"):
    return SimpleNamespace(
        _host=SimpleNamespace(get_name=lambda: HOSTS[0]),
        _task=SimpleNamespace(get_name=lambda: name, action=action),
        _result={"changed": False, "msg": values, "diff": "private-diff-sentinel"},
    )


BAD_VALUES = [
    pytest.param("unexpected", "private-value-sentinel", id="unexpected-key"),
    pytest.param("failover_test_result", "private-value-sentinel", id="unexpected-result"),
    pytest.param("recovery_result", "not_run", id="wrong-result-domain"),
    pytest.param("final_smoke_result", True, id="boolean-result"),
    pytest.param("failover_test_result", ["private-value-sentinel"], id="list-result"),
    pytest.param("recovery_result", {"private-value-sentinel": True}, id="mapping-result"),
    *[pytest.param(key, value, id=f"{key}-{label}")
      for key in ("failover_elapsed_seconds", "transaction_elapsed_seconds")
      for label, value in (("nan", float("nan")), ("inf", float("inf")),
                           ("negative-inf", -float("inf")), ("bool", True),
                           ("negative", -1), ("over-limit", 86401), ("string", "private-value-sentinel"))],
]


@pytest.mark.parametrize("key,value", BAD_VALUES)
def test_callback_rejects_invalid_report_without_payload_disclosure(callback, key, value):
    plugin, events = callback
    plugin.v2_runner_on_ok(_result(_values(**{key: value})))
    assert _records(events) == [{"schema": 1, "kind": "error", "phase": "failover-test"}]
    assert "private-value-sentinel" not in events.read_text()


@pytest.mark.parametrize("key,value", BAD_VALUES)
def test_summary_rejects_invalid_report_without_payload_or_traceback(repo_root, isolated_test_dir, command_runner, key, value):
    events = _summary(repo_root, isolated_test_dir, command_runner, "openbao-haproxy-failover", _values(**{key: value}))
    result = _render(repo_root, command_runner, events, 0)
    assert result.returncode == 2, result.diagnostics()
    assert result.stderr.strip() == "platform-config-operation-summary: invalid summary input"
    assert result.stdout == ""
    assert "private-value-sentinel" not in result.stdout + result.stderr


@pytest.mark.parametrize("phase", ["failover-plan", "failover-test", "failover-recover"])
@pytest.mark.parametrize("elapsed", [None, 0, 1.25, 86400])
def test_callback_accepts_only_allowlisted_result_fields(callback, monkeypatch, phase, elapsed):
    plugin, events = callback
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_PHASE", phase)
    values = _values(failover_elapsed_seconds=elapsed, transaction_elapsed_seconds=elapsed)
    plugin.v2_runner_on_ok(_result(values))
    assert _records(events) == [{"schema": 1, "kind": "failover", "phase": phase, "host": HOSTS[0], **values}]
    assert "private-diff-sentinel" not in events.read_text()


@pytest.mark.parametrize("phase,name", [
    ("inventory", REPORT_TASK), ("edge-plan", REPORT_TASK), ("failover-test-extra", REPORT_TASK),
    ("failover-test", REPORT_TASK + " extra"), ("failover-test", "role : " + REPORT_TASK),
    ("failover-test", "Publish sanitized reviewed failover identity"),
])
def test_callback_ignores_other_tasks_and_phases(callback, monkeypatch, phase, name):
    plugin, events = callback
    monkeypatch.setenv("PLATFORM_CONFIG_OPERATION_PHASE", phase)
    plugin.v2_runner_on_ok(_result(_values(), name=name))
    assert events.read_text() == ""


def test_callback_does_not_consume_non_debug_task_with_same_name(callback):
    plugin, events = callback
    plugin.v2_runner_on_ok(_result(_values(), action="ansible.builtin.command"))
    assert events.read_text() == ""


@pytest.mark.parametrize("operation,failed_proof", [
    ("openbao-haproxy-failover-plan", False),
    ("openbao-haproxy-failover", False),
    ("openbao-haproxy-failover", True),
    ("openbao-haproxy-failover-recover", False),
])
def test_launcher_real_ansible_reporting_tasks_callback_and_summary(
    repo_root, isolated_test_dir, launcher, command_runner, operation, failed_proof,
):
    # Execute the real reporting play, including its final all-host assertions.
    # Only earlier service/approval work is replaced by synthetic host facts.
    plays = yaml.safe_load((repo_root / PLAYBOOK).read_text())
    report = plays[-1]
    assert report["tasks"][0]["name"] == REPORT_TASK
    assert "ansible.builtin.debug" in report["tasks"][0]
    assert "run_once" not in report["tasks"][0]
    # Ansible expands environment variables in inventory/@file names itself.
    # Keep the hostile plan path (a JSON value), but use literal input filenames.
    for attribute in ("inventory", "controller"):
        original = getattr(launcher, attribute)
        literal = isolated_test_dir / original.name
        literal.write_bytes(original.read_bytes())
        literal.chmod(0o600)
        setattr(launcher, attribute, literal)
    values = _values(ROUTES[operation])
    if failed_proof:
        values["failover_test_result"] = "failed"
    facts = {
        "openbao_failover_test_result": values["failover_test_result"],
        "openbao_failover_recovery_result": values["recovery_result"],
        "openbao_failover_smoke_ok": True,
        "openbao_failover_finish_ok": True,
        "openbao_failover_elapsed_seconds": values["failover_elapsed_seconds"],
        "openbao_failover_transaction_elapsed_seconds": values["transaction_elapsed_seconds"],
    }
    report["pre_tasks"] = [{
        "name": "Seed synthetic completed transaction facts on every host",
        "ansible.builtin.set_fact": facts,
    }]
    report["tasks"].insert(0, {
        "name": "Verify exact launcher mode and JSON plan path reached Ansible",
        "ansible.builtin.assert": {"that": [
            "openbao_failover_mode == fixture_expected_mode",
            "openbao_failover_plan_path == fixture_expected_path",
            "ansible_play_hosts_all | sort == groups['openbao'] | sort",
        ]},
    })
    report["vars"] = {
        "fixture_expected_mode": ROUTES[operation],
        "fixture_expected_path": "" if ROUTES[operation] == "recover" else str(launcher.plan),
    }
    fixture = isolated_test_dir / "report.yml"
    fixture.write_text(yaml.safe_dump([report], sort_keys=False))
    real_ansible = shutil.which("ansible-playbook", path=command_runner.environment["PATH"])
    real_inventory = shutil.which("ansible-inventory", path=command_runner.environment["PATH"])
    assert real_ansible is not None and real_inventory is not None
    result = command_runner.run(_argv(launcher, operation), environment={
        **launcher.environment,
        "FAILOVER_REAL_PLAYBOOK": str(fixture),
        "FAILOVER_SOURCE_PLAYBOOK": str(repo_root / PLAYBOOK),
        "FAILOVER_REAL_ANSIBLE": real_ansible,
        "FAILOVER_REAL_INVENTORY": real_inventory,
    }, timeout=30)
    assert result.returncode == (2 if failed_proof else 0), result.diagnostics()
    if failed_proof:
        assert "Failover proof or verified recovery failed; retained records require the fixed recovery route." in result.stdout
        assert "Error while evaluating conditional" not in result.stdout
    _assert_dispatch(repo_root, launcher, operation)
    summary = result.stdout.split("=== PLATFORM CONFIG OPERATION SUMMARY ===", 1)[1]
    assert f"Overall: {'FAIL' if failed_proof else 'PASS'}" in summary
    assert "unknown" not in summary.replace("missing observations remain unknown", "")
    for host in HOSTS:
        assert f"{host}: failover_test_result={values['failover_test_result']}, recovery_result={values['recovery_result']}, final_smoke_result={values['final_smoke_result']}" in summary
    assert "outside" not in summary
