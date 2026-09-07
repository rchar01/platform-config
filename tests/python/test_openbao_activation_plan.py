"""Bounded offline plan contracts, real Git identities, and real Ansible actions.

Only disposable repositories are committed. The integration fixture has three
local aliases and no production roles, service operations, or private inputs.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import tempfile
import termios
import time
from pathlib import Path

import pytest
import yaml


HOSTS = ["fixture-bao-1", "fixture-bao-2", "fixture-bao-3"]
NOW = 1_800_000_000
CONTEXT = {
    "config_sha": "a" * 40, "private_sha": "b" * 40,
    "inventory": "hosts.yml", "environment": "fixture", "lane": "operator",
    "project": "", "pipeline": "", "image": "", "plan_job": "",
}
EVIDENCE = {host: {"host": host, "state": "staged"} for host in HOSTS}


@pytest.fixture(scope="module")
def plans(repo_root):
    # Do not occupy the fallback module name used by standalone Ansible actions.
    spec = importlib.util.spec_from_file_location(
        "_openbao_activation_plan_contract_tests",
        repo_root / "plugins/module_utils/platform_openbao_activation_plan.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def plan(plans):
    return plans.prepare(
        "haproxy", "interactive", "", HOSTS.copy(), copy.deepcopy(CONTEXT),
        copy.deepcopy(EVIDENCE), now=NOW,
    )


@pytest.fixture
def plan_directory(command_runner):
    # The test profile's usual pytest scratch is inside /workspace/.ansible.
    # Operator plans must instead live outside *every* Git checkout.
    with tempfile.TemporaryDirectory(prefix="openbao-plan-test-", dir="/tmp") as directory:
        path = Path(directory)
        result = command_runner.run(
            ["git", "-C", path, "rev-parse", "--git-dir"],
            environment={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
            timeout=10,
        ).assert_failure()
        assert "not a git repository" in result.stderr, result.diagnostics()
        yield path


def test_plan_canonical_digest_and_exact_ttl(plans, plan):
    assert plans.TTL == 1800
    assert plan["expires"] == NOW + 1800
    assert re.fullmatch(r"[0-9a-f]{32}", plan["plan_id"])
    payload = {key: value for key, value in plan.items() if key != "digest"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert plan["digest"] == hashlib.sha256(encoded).hexdigest()
    assert plans.digest(dict(reversed(list(plan.items())))) == plan["digest"]
    assert plans.canonical({"ready": True}) != plans.canonical({"ready": 1})


@pytest.mark.parametrize("now,valid", [
    (NOW - 1, False), (NOW, True), (NOW + 1799, True), (NOW + 1800, False),
])
def test_plan_time_boundaries(plans, plan, now, valid):
    if valid:
        assert plans.validate(plan, "haproxy", HOSTS, CONTEXT, EVIDENCE, now=now) is plan
    else:
        with pytest.raises(plans.PlanError, match="expired, future-dated"):
            plans.validate(plan, "haproxy", HOSTS, CONTEXT, EVIDENCE, now=now)


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("schema", 1.0), ("schema", "1"), ("schema", 2),
    ("created", True), ("created", float(NOW)), ("created", str(NOW)),
    ("expires", False), ("expires", float(NOW + 1800)),
    ("expires", NOW + 1799), ("expires", NOW + 1801),
    ("plan_id", "A" * 32), ("plan_id", "a" * 31), ("plan_id", None),
    ("operation", "keepalived"), ("operation", "unknown"),
])
def test_plan_rejects_resigned_invalid_schema(plans, plan, field, value):
    plan[field] = value
    plan["digest"] = plans.digest(plan)
    with pytest.raises(plans.PlanError):
        plans.validate(plan, "haproxy", HOSTS, CONTEXT, EVIDENCE, now=NOW)


@pytest.mark.parametrize("shape", ["list", "null", "missing", "extra"])
def test_plan_requires_exact_top_level_keys(plans, plan, shape):
    if shape == "list":
        plan = list(plan)
    elif shape == "null":
        plan = None
    elif shape == "missing":
        del plan["evidence"]
    else:
        plan["extra"] = True
    with pytest.raises(plans.PlanError, match="schema"):
        plans.validate(plan, "haproxy", HOSTS, CONTEXT, EVIDENCE, now=NOW)


@pytest.mark.parametrize("field,value", [
    ("digest", "0" * 64), ("digest", True),
    ("hosts", [*HOSTS[:2], "wrong-host"]), ("hosts", list(reversed(HOSTS))),
    ("evidence", {"ready": True}), ("context", {**CONTEXT, "lane": "gitlab"}),
])
def test_plan_rejects_tampering(plans, plan, field, value):
    plan[field] = value
    if field != "digest":
        # Reach the binding checks, rather than failing only the digest check.
        plan["digest"] = plans.digest(plan)
    with pytest.raises(plans.PlanError, match="digest, source, lane, hosts, or live evidence"):
        plans.validate(plan, "haproxy", HOSTS, CONTEXT, EVIDENCE, now=NOW)


@pytest.mark.parametrize("field,value", [
    ("config_sha", "c" * 40), ("private_sha", "d" * 40),
    ("inventory", "other/hosts.yml"), ("environment", "other"),
    ("lane", "gitlab"), ("project", "42"), ("pipeline", "43"),
    ("image", "registry.invalid/tool@sha256:" + "e" * 64),
    ("plan_job", "fixture-haproxy-plan"),
])
def test_plan_rejects_current_context_drift(plans, plan, field, value):
    with pytest.raises(plans.PlanError, match="source, lane"):
        plans.validate(plan, "haproxy", HOSTS, {**CONTEXT, field: value}, EVIDENCE, now=NOW)


@pytest.mark.parametrize("original,current", [(True, 1), (False, 0), (1, 1.0)])
def test_plan_evidence_comparison_preserves_json_types(plans, plan, original, current):
    plan["evidence"] = {"ready": original}
    plan["digest"] = plans.digest(plan)
    with pytest.raises(plans.PlanError, match="live evidence"):
        plans.validate(plan, "haproxy", HOSTS, CONTEXT, {"ready": current}, now=NOW)


@pytest.mark.parametrize("hosts", [[], HOSTS[:2], HOSTS + ["fourth"], [HOSTS[0]] * 3,
                                        list(reversed(HOSTS)), tuple(HOSTS)])
def test_prepare_requires_exact_sorted_three_hosts(plans, hosts):
    with pytest.raises(plans.PlanError, match="exactly three sorted hosts"):
        plans.prepare("haproxy", "interactive", "", hosts, CONTEXT, EVIDENCE, now=NOW)


@pytest.mark.parametrize("operation,mode,path,evidence", [
    ("unknown", "interactive", "", EVIDENCE),
    ("haproxy", "unknown", "", EVIDENCE),
    ("haproxy", "plan", "", EVIDENCE),
    ("haproxy", "ci", "", EVIDENCE),
    ("haproxy", "interactive", "", {}),
    ("haproxy", "interactive", "", []),
])
def test_prepare_rejects_missing_or_unsupported_inputs(plans, operation, mode, path, evidence):
    with pytest.raises(plans.PlanError):
        plans.prepare(operation, mode, path, HOSTS, CONTEXT, evidence, now=NOW)


def test_plan_private_exclusive_publication_and_saved_roundtrip(plans, plan_directory):
    path = plan_directory / "plan.json"
    generated = plans.prepare("haproxy", "plan", str(path), HOSTS, CONTEXT, EVIDENCE, now=NOW)
    assert path.stat().st_mode & 0o777 == 0o600
    assert plans.read_plan(str(path)) == generated
    assert plans.prepare("haproxy", "interactive", str(path), HOSTS, CONTEXT, EVIDENCE,
                         now=NOW + 1) == generated
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        plans.write_plan(str(path), generated)
    assert path.read_bytes() == before


@pytest.mark.parametrize("payload", [
    b'{"schema":1,"schema":1}', b'{"evidence":{"ready":true,"ready":false}}',
    b'{"evidence":[{"host":"one","host":"two"}]}',
])
def test_read_rejects_duplicate_json_at_every_depth(plans, tmp_path, payload):
    path = tmp_path / "plan.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    with pytest.raises(plans.PlanError, match="duplicate JSON keys"):
        plans.read_plan(str(path))


@pytest.mark.parametrize("mode", [0o400, 0o640, 0o644, 0o660, 0o700])
def test_read_requires_exact_private_permissions(plans, plan, plan_directory, mode):
    path = plan_directory / "plan.json"
    plans.write_plan(str(path), plan)
    path.chmod(mode)
    with pytest.raises(plans.PlanError, match="owner-private regular file"):
        plans.read_plan(str(path))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo", "oversized"])
def test_read_rejects_unsafe_files_without_blocking(plans, plan, plan_directory, kind):
    path = plan_directory / "plan.json"
    if kind in {"symlink", "hardlink"}:
        target = plan_directory / "target.json"
        plans.write_plan(str(target), plan)
        if kind == "symlink":
            path.symlink_to(target)
        else:
            os.link(target, path)
    elif kind == "directory":
        path.mkdir(mode=0o600)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(b" " * (plans.MAX_BYTES + 1))
        path.chmod(0o600)
    with pytest.raises((plans.PlanError, OSError)):
        plans.read_plan(str(path))


def test_read_rejects_wrong_owner(plans, plan, plan_directory, monkeypatch):
    path = plan_directory / "plan.json"
    plans.write_plan(str(path), plan)
    uid = os.geteuid()
    monkeypatch.setattr(plans.os, "geteuid", lambda: uid + 1)
    with pytest.raises(plans.PlanError, match="owner-private"):
        plans.read_plan(str(path))


@pytest.mark.parametrize("kind", ["relative", "symlink-parent", "public-parent", "oversized"])
def test_write_rejects_unsafe_destinations_before_publication(plans, plan_directory, plan, kind):
    path = plan_directory / "plan.json"
    if kind == "relative":
        path = Path("plan.json")
    elif kind == "symlink-parent":
        (plan_directory / "link").symlink_to(plan_directory, target_is_directory=True)
        path = plan_directory / "link/plan.json"
    elif kind == "public-parent":
        plan_directory.chmod(0o755)
    else:
        plan["evidence"] = {"large": "x" * plans.MAX_BYTES}
    with pytest.raises(plans.PlanError):
        plans.write_plan(str(path), plan)
    assert not (plan_directory / "plan.json").exists()


@pytest.fixture
def checkouts(repo_root, isolated_test_dir, command_runner, plan_directory):
    root = isolated_test_dir
    config = root / "checkout"
    inventory = root / "inventory"
    artifacts = plan_directory
    shutil.copytree(repo_root / "tests/fixtures/openbao-activation-plan", config)
    for relative in ("plugins/action/openbao_activation_plan.py",
                     "plugins/module_utils/platform_openbao_activation_plan.py"):
        target = config / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo_root / relative, target)
    (config / "ansible.cfg").write_text(
        "[defaults]\naction_plugins = plugins/action\nroles_path = roles\n"
        "retry_files_enabled = False\nstdout_callback = default\n"
        "[inventory]\nenable_plugins = yaml\n",
    )
    inventory.mkdir()
    (inventory / "hosts.yml").write_text(yaml.safe_dump({"all": {
        "vars": {"ansible_connection": "local", "ansible_python_interpreter": "{{ ansible_playbook_python }}"},
        "children": {"openbao": {"hosts": {host: {} for host in reversed(HOSTS)}}},
    }}))
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "ANSIBLE_CONFIG": str(config / "ansible.cfg"), "ANSIBLE_NOCOLOR": "1",
    }

    def git(directory, *args):
        return command_runner.run(
            ["git", "-c", "user.name=Activation Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
            cwd=directory, environment=environment, timeout=10,
        ).assert_success().stdout.strip()

    for directory in (config, inventory):
        git(directory, "init", "--template=", "--object-format=sha1", "--initial-branch=main")
        git(directory, "add", ".")
        git(directory, "commit", "-m", "Synthetic activation fixture")
        assert git(directory, "status", "--porcelain") == ""
    return {
        "config": config, "inventory": inventory / "hosts.yml", "artifacts": artifacts,
        "environment": environment, "git": git,
        "config_sha": git(config, "rev-parse", "HEAD"),
        "private_sha": git(inventory, "rev-parse", "HEAD"),
    }


@pytest.mark.parametrize("location", ["config", "inventory", "unrelated", "ignored", "git-metadata"])
def test_operator_plan_output_rejects_every_git_repository(plans, plan, checkouts, location):
    if location == "inventory":
        parent = checkouts["inventory"].parent
    elif location == "unrelated":
        parent = checkouts["artifacts"] / "unrelated"
        parent.mkdir(mode=0o700)
        checkouts["git"](parent, "init", "--template=", "--initial-branch=main")
    elif location == "git-metadata":
        parent = checkouts["config"] / ".git"
    else:
        parent = checkouts["config"]
        if location == "ignored":
            (parent / ".git/info").mkdir(exist_ok=True)
            (parent / ".git/info/exclude").write_text("private-plans/\n")
    parent = parent / "private-plans"
    parent.mkdir(mode=0o700)
    path = parent / "plan.json"
    with pytest.raises(plans.PlanError, match="(?i)git"):
        plans.write_plan(str(path), plan)
    assert not path.exists()


def _ci(checkouts, operation="haproxy", mode="plan"):
    return {
        "CI": "true", "CI_PIPELINE_SOURCE": "web", "CI_COMMIT_REF_PROTECTED": "true",
        "CI_DEFAULT_BRANCH": "main", "CI_COMMIT_BRANCH": "main",
        "CI_COMMIT_SHA": checkouts["private_sha"], "CI_PROJECT_ID": "41", "CI_PIPELINE_ID": "42",
        "CI_JOB_IMAGE": "registry.example.invalid/tool@sha256:" + "c" * 64,
        "CI_JOB_NAME": f"fixture-{operation}-{'plan' if mode == 'plan' else 'activate'}",
        "CI_JOB_MANUAL": "true",
    }


def test_source_identity_uses_real_clean_commits_and_ignores_git_env(plans, checkouts, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/nonexistent/fixture-git-dir")
    monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent/fixture-worktree")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.worktree")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/nonexistent/fixture-worktree")
    assert plans.source_identity(checkouts["config"] / "ansible.cfg") == (checkouts["config_sha"], "ansible.cfg")
    assert plans.source_identity(checkouts["inventory"]) == (checkouts["private_sha"], "hosts.yml")


@pytest.mark.parametrize("kind", ["modified", "staged", "untracked", "untracked-source", "symlink", "symlink-parent", "not-git"])
def test_source_identity_rejects_noncanonical_or_dirty_sources(plans, checkouts, kind):
    config = checkouts["config"]
    path = config / "ansible.cfg"
    if kind in {"modified", "staged"}:
        path.write_text(path.read_text() + "\n# changed\n")
        if kind == "staged":
            checkouts["git"](config, "add", "ansible.cfg")
    elif kind in {"untracked", "untracked-source"}:
        other = config / "untracked.yml"
        other.write_text("---\n")
        if kind == "untracked-source":
            path = other
    elif kind == "symlink":
        path = checkouts["artifacts"] / "source"
        path.symlink_to(config / "ansible.cfg")
    elif kind == "symlink-parent":
        link = checkouts["artifacts"] / "checkout"
        link.symlink_to(config, target_is_directory=True)
        path = link / "ansible.cfg"
    else:
        path = checkouts["artifacts"] / "source"
        path.write_text("not a git checkout\n")
    with pytest.raises(plans.PlanError):
        plans.source_identity(path)


@pytest.mark.parametrize("operation", ["haproxy", "keepalived"])
def test_context_matches_protected_plan_and_manual_apply(plans, checkouts, operation):
    args = (checkouts["config"] / "ansible.cfg", checkouts["inventory"], "fixture", operation)
    planned = plans.context(*args, "plan", env=_ci(checkouts, operation))
    applied = plans.context(*args, "ci", env=_ci(checkouts, operation, "ci"))
    assert planned == applied
    assert planned == {
        **CONTEXT, "config_sha": checkouts["config_sha"], "private_sha": checkouts["private_sha"],
        "lane": "gitlab", "project": "41", "pipeline": "42",
        "image": _ci(checkouts)["CI_JOB_IMAGE"], "plan_job": f"fixture-{operation}-plan",
    }
    assert plans.context(*args, "interactive", env={})["lane"] == "operator"


@pytest.mark.parametrize("key,value", [
    ("CI", "false"), ("CI_PIPELINE_SOURCE", "push"), ("CI_PIPELINE_SOURCE", "schedule"),
    ("CI_COMMIT_REF_PROTECTED", "false"), ("CI_DEFAULT_BRANCH", ""),
    ("CI_COMMIT_BRANCH", "feature"), ("CI_COMMIT_SHA", "d" * 40),
    ("CI_PROJECT_ID", "0"), ("CI_PROJECT_ID", "01"), ("CI_PIPELINE_ID", "-1"),
    ("CI_JOB_NAME", "fixture-keepalived-activate"), ("CI_JOB_NAME", "fixture-haproxy-plan"),
    ("CI_JOB_NAME", "-haproxy-activate"), ("CI_JOB_NAME", "bad name-haproxy-activate"),
    ("CI_JOB_IMAGE", "registry.example.invalid/tool:latest"),
    ("CI_JOB_IMAGE", "tool@sha256:" + "C" * 64),
    ("CI_JOB_IMAGE", "tool@sha256:" + "c" * 63), ("CI_JOB_MANUAL", "false"),
    ("CI_JOB_MANUAL", ""),
])
def test_context_rejects_invalid_ci_claims_with_real_sources(plans, checkouts, key, value):
    env = {**_ci(checkouts, mode="ci"), key: value}
    with pytest.raises(plans.PlanError):
        plans.context(checkouts["config"] / "ansible.cfg", checkouts["inventory"],
                      "fixture", "haproxy", "ci", env=env)


@pytest.mark.parametrize("mode,env", [("ci", {}), ("interactive", {"CI": "true"})])
def test_context_rejects_cross_lane_invocations(plans, checkouts, mode, env):
    with pytest.raises(plans.PlanError):
        plans.context(checkouts["config"] / "ansible.cfg", checkouts["inventory"],
                      "fixture", "haproxy", mode, env=env)


@pytest.mark.parametrize("environment", ["", "../dev", "dev prod", "a" * 65, True])
def test_context_requires_safe_explicit_environment(plans, checkouts, environment):
    with pytest.raises(plans.PlanError, match="environment"):
        plans.context(checkouts["config"] / "ansible.cfg", checkouts["inventory"],
                      environment, "haproxy", "plan", env={})


def _argv(checkouts, mode, operation="haproxy", **variables):
    values = {
        "fixture_mode": mode, "fixture_operation": operation,
        "fixture_plan_path": str(checkouts["artifacts"] / "plan.json"),
        "fixture_result_path": str(checkouts["artifacts"] / f"{mode}-result.json"),
        **variables,
    }
    return [
        "ansible-playbook", "-i", str(checkouts["inventory"]),
        str(checkouts["config"] / "playbook.yml"), "--limit", "openbao",
        "-e", json.dumps(values),
    ]


@pytest.mark.parametrize("operation", ["haproxy", "keepalived"])
def test_action_plugin_real_ci_prepare_saved_apply_and_verify(plans, checkouts, command_runner, operation):
    for mode in ("plan", "ci"):
        command_runner.run(
            _argv(checkouts, mode, operation), cwd=checkouts["config"],
            environment={**checkouts["environment"], **_ci(checkouts, operation, mode)}, timeout=25,
        ).assert_success()
    saved = plans.read_plan(str(checkouts["artifacts"] / "plan.json"))
    applied = json.loads((checkouts["artifacts"] / "ci-result.json").read_text())
    assert applied["plan"] == saved
    assert saved["context"]["config_sha"] == checkouts["config_sha"]
    assert saved["context"]["private_sha"] == checkouts["private_sha"]
    assert saved["context"]["lane"] == "gitlab"
    assert saved["evidence"] == EVIDENCE
    assert saved["hosts"] == HOSTS
    assert applied["approval"] == f"activate-openbao-{operation}|{','.join(HOSTS)}|{saved['digest']}"
    for directory in (checkouts["config"], checkouts["inventory"].parent):
        assert checkouts["git"](directory, "status", "--porcelain") == ""


@pytest.mark.parametrize("drift", ["pipeline", "job", "image", "lane", "source", "evidence", "verify-evidence"])
def test_action_plugin_rejects_saved_plan_drift(checkouts, command_runner, drift):
    env = {**checkouts["environment"], **_ci(checkouts)}
    command_runner.run(_argv(checkouts, "plan"), cwd=checkouts["config"],
                       environment=env, timeout=25).assert_success()
    before = (checkouts["artifacts"] / "plan.json").read_bytes()
    env = {**checkouts["environment"], **_ci(checkouts, mode="ci")}
    variables = {}
    mode = "ci"
    if drift == "pipeline":
        env["CI_PIPELINE_ID"] = "43"
    elif drift == "job":
        env["CI_JOB_NAME"] = "other-haproxy-activate"
    elif drift == "image":
        env["CI_JOB_IMAGE"] = "registry.example.invalid/tool@sha256:" + "d" * 64
    elif drift == "lane":
        env = checkouts["environment"]
        mode = "interactive"
    elif drift == "source":
        config = checkouts["config"]
        (config / "revision.txt").write_text("new committed configuration\n")
        checkouts["git"](config, "add", "revision.txt")
        checkouts["git"](config, "commit", "-m", "Change synthetic configuration")
    elif drift == "evidence":
        variables["fixture_state"] = "active"
    else:
        variables["fixture_drift"] = True
    result = command_runner.run(_argv(checkouts, mode, **variables), cwd=checkouts["config"],
                                environment=env, timeout=25).assert_failure()
    assert "live evidence changed; create a new plan" in result.stdout, result.diagnostics()
    if drift == "verify-evidence":
        assert "Verify again immediately before" in result.stdout
    assert not (checkouts["artifacts"] / f"{mode}-result.json").exists()
    assert (checkouts["artifacts"] / "plan.json").read_bytes() == before


@pytest.mark.serial
@pytest.mark.parametrize("approve", [True, False])
def test_action_plugin_interactive_approval_roundtrip(plans, checkouts, command_runner, approve):
    command_runner.run(_argv(checkouts, "plan"), cwd=checkouts["config"],
                       environment=checkouts["environment"], timeout=25).assert_success()
    saved = plans.read_plan(str(checkouts["artifacts"] / "plan.json"))
    expected = f"activate-openbao-haproxy|{','.join(HOSTS)}|{saved['digest']}"
    master, slave = pty.openpty()

    def terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        _argv(checkouts, "interactive"), cwd=checkouts["config"],
        env={**command_runner.environment, **checkouts["environment"]},
        stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal,
    )
    os.close(slave)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if not sent and f"Type exactly {expected}" in output.decode(errors="replace"):
                    # pause installs terminal input handling just after printing.
                    time.sleep(0.2)
                    os.write(master, ((expected if approve else expected + "-wrong") + "\r").encode())
                    sent = True
            elif process.poll() is not None:
                break
        process.wait(timeout=2)
    finally:
        os.close(master)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
    rendered = output.decode(errors="replace")
    assert sent, rendered
    result_path = checkouts["artifacts"] / "interactive-result.json"
    if approve:
        assert process.returncode == 0, rendered
        result = json.loads(result_path.read_text())
        assert result["plan"] == saved
        assert result["approval"] == expected
        assert result["plan"]["context"]["lane"] == "operator"
    else:
        assert process.returncode != 0, rendered
        assert "Fixture exact approval did not match" in rendered
        assert not result_path.exists()
