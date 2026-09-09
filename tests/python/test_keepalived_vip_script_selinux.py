from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml


ROLE = "roles/keepalived_vip"
GUARD = "script_selinux_guard.yml"
DEPENDENCIES = ("bash", "systemctl", "ip", "ss", "awk")


def test_script_uses_policy_specific_default_location(repo_root):
    defaults = yaml.safe_load((repo_root / ROLE / "defaults/main.yml").read_text())
    assert defaults["keepalived_vip_script_dir"] == "/usr/libexec/keepalived"
    assert defaults["keepalived_vip_script_path"] == "{{ keepalived_vip_script_dir }}/keepalived-check-service"


def test_script_policy_guard_precedes_uid_only_readiness(repo_root):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks/activation_preflight_checks.yml").read_text())
    guards = [i for i, task in enumerate(tasks) if task.get("ansible.builtin.include_tasks") == GUARD]
    assert len(guards) == 1, "Keepalived preflight needs a read-only script SELinux guard"
    readiness = next(i for i, task in enumerate(tasks)
                     if task.get("ansible.builtin.command", {}).get("argv", [None])[0] == "runuser")
    assert guards[0] < readiness
    observation = tasks[-1]["ansible.builtin.set_fact"]["keepalived_vip_activation_observation"]
    assert observation["script_selinux"] == "{{ keepalived_vip_script_selinux_probe.stdout | from_json }}"


def test_staging_defaults_only_script_and_directory_contexts(repo_root):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks/main.yml").read_text())[1]["block"]
    labeled = []
    for task in tasks:
        for module in ("ansible.builtin.file", "ansible.builtin.template"):
            args = task.get(module, {})
            if any(key.startswith("se") for key in args):
                assert {key: args[key] for key in ("seuser", "serole", "setype", "selevel")} == {
                    key: "_default" for key in ("seuser", "serole", "setype", "selevel")
                }
                assert not args.get("recurse", False)
                labeled.append((module, args.get("path", args.get("dest"))))
    assert labeled == [
        ("ansible.builtin.file", "{{ keepalived_vip_script_dir }}"),
        ("ansible.builtin.template", "{{ keepalived_vip_script_path }}"),
    ]


@pytest.fixture
def native_probe(repo_root, tmp_path, monkeypatch, capsys):
    """Execute the production Python with read-only API-shaped policy doubles."""
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / GUARD).read_text())
    probe = tasks[0]
    assert probe["changed_when"] is False and probe["check_mode"] is False
    argv = probe["ansible.builtin.command"]["argv"]
    assert argv[:2] == ["{{ ansible_facts.python.executable }}", "-c"]
    assert argv[3:] == ["{{ keepalived_vip_binary_path }}", "{{ keepalived_vip_script_path }}"]
    state = {"case": "ready", "mode": "Enforcing", "range": "s0:c1.c4"}
    events = []
    paths = {}
    for name in DEPENDENCIES:
        target = tmp_path / (name + "-resolved")
        target.write_text("synthetic executable\n")
        link = tmp_path / name
        link.symlink_to(target)
        paths[name] = str(link)
    script = str(tmp_path / "custom-script-dir/keepalived-check-service")

    def context(kind, role="object_r"):
        return f"system_u:{role}:{kind}:{state['range']}"

    def getenforce(args, *, text):
        assert args == ["getenforce"] and text is True
        events.append(("getenforce",))
        if state["case"] == "getenforce-error":
            raise subprocess.CalledProcessError(1, args)
        return state["mode"] + "\n"

    def getpidcon(pid):
        assert pid == 1
        events.append(("getpidcon", pid))
        return (-1 if state["case"] == "pid-error" else 0), (
            None if state["case"] == "pid-none" else context("init_t", "system_r")
        )

    def getfilecon(path):
        events.append(("getfilecon", path))
        types = {"/usr/sbin/keepalived": "keepalived_exec_t", script: "keepalived_unconfined_script_exec_t",
                 os.path.dirname(script): "keepalived_unconfined_script_exec_t"}
        types.update({os.path.realpath(paths[name]): name + "_exec_t" for name in DEPENDENCIES})
        label = context(types[path])
        if path == script and state["case"] == "wrong-script-label":
            label = context("usr_t")
        if state["case"] == "context-error":
            return -1, label
        if state["case"] == "context-none":
            return 0, None
        # getfilecon returns a positive length, not just zero on success.
        return len(label), label

    def compute_create(source, executable, cls):
        assert cls == 19
        events.append(("create", source, executable))
        if source == context("keepalived_unconfined_script_t", "system_r"):
            assert executable in [context(name + "_exec_t") for name in DEPENDENCIES]
            return 0, context("keepalived_t", "system_r") if state["case"] == "dependency-transition" else source
        daemon = source == context("init_t", "system_r")
        assert source == context("init_t" if daemon else "keepalived_t", "system_r")
        assert executable == context("keepalived_exec_t" if daemon else "keepalived_unconfined_script_exec_t")
        kind = "daemon" if daemon else "script"
        label = context("keepalived_t" if daemon else "keepalived_unconfined_script_t", "system_r")
        if state["case"] == kind + "-wrong":
            label = source
        return (-1 if state["case"] == kind + "-error" else 0), (
            None if state["case"] == kind + "-none" else label
        )

    def security_class(name):
        return 0 if state["case"] == "class-" + name else {"process": 19, "file": 31}[name]

    def permission(cls, name):
        bits = {19: {"transition": 512}, 31: {"execute": 128, "entrypoint": 1024, "execute_no_trans": 32}}
        return 0 if state["case"] == "permission-missing" else bits[cls][name]

    def compute_av(source, target, cls, mask, decision):
        src_type, target_type = source.split(":")[2], target.split(":")[2]
        allowed_calls = {
            ("init_t", "keepalived_exec_t"): (31, 128),
            ("init_t", "keepalived_t"): (19, 512),
            ("keepalived_t", "keepalived_exec_t"): (31, 1024),
            ("keepalived_t", "keepalived_unconfined_script_exec_t"): (31, 128),
            ("keepalived_t", "keepalived_unconfined_script_t"): (19, 512),
            ("keepalived_unconfined_script_t", "keepalived_unconfined_script_exec_t"): (31, 1024),
            **{("keepalived_unconfined_script_t", name + "_exec_t"): (31, 160) for name in DEPENDENCIES},
        }
        expected_class, allowed = allowed_calls[src_type, target_type]
        assert cls == expected_class and mask > 0 and mask & allowed == mask
        events.append(("av", source, target, cls, mask))
        decision.allowed = allowed | 2
        denials = {
            "deny-daemon-execute": ("init_t", "keepalived_exec_t", 128),
            "deny-daemon-transition": ("init_t", "keepalived_t", 512),
            "deny-daemon-entrypoint": ("keepalived_t", "keepalived_exec_t", 1024),
            "deny-script-execute": ("keepalived_t", "keepalived_unconfined_script_exec_t", 128),
            "deny-script-transition": ("keepalived_t", "keepalived_unconfined_script_t", 512),
            "deny-script-entrypoint": ("keepalived_unconfined_script_t", "keepalived_unconfined_script_exec_t", 1024),
            "deny-execute_no_trans": ("keepalived_unconfined_script_t", "systemctl_exec_t", 32),
            **{"deny-" + name: ("keepalived_unconfined_script_t", name + "_exec_t", 128) for name in DEPENDENCIES},
        }
        denied_source, denied_target, denied_bit = denials.get(state["case"], (None, None, 0))
        if (src_type, target_type) == (denied_source, denied_target):
            decision.allowed &= ~denied_bit
        return -1 if state["case"] == "av-error" else None if state["case"] == "av-none" else 0

    def which(name, *, path):
        assert path == "/usr/sbin:/usr/bin" and name in DEPENDENCIES
        events.append(("which", name, path))
        return None if state["case"] == "missing-" + name else paths[name]

    binding = SimpleNamespace(
        getpidcon=getpidcon, getfilecon=getfilecon, security_compute_create=compute_create,
        string_to_security_class=security_class, string_to_av_perm=permission,
        av_decision=lambda: SimpleNamespace(allowed=0), security_compute_av=compute_av,
    )
    monkeypatch.setitem(sys.modules, "selinux", binding)
    monkeypatch.setattr(subprocess, "check_output", getenforce)
    monkeypatch.setattr(shutil, "which", which)
    monkeypatch.setattr(sys, "argv", ["probe", "/usr/sbin/keepalived", script])

    def run(case="ready", mode="Enforcing", level="s0:c1.c4"):
        state.update(case=case, mode=mode, range=level)
        events.clear()
        capsys.readouterr()
        if case == "missing-bindings":
            monkeypatch.setitem(sys.modules, "selinux", None)
        exec(compile(argv[2], GUARD, "exec"), {})
        return json.loads(capsys.readouterr().out)

    return run, events, paths, script


@pytest.mark.parametrize("mode", ["Enforcing", "Permissive"])
def test_native_probe_binds_full_contexts_and_canonical_dependencies(native_probe, mode):
    run, events, paths, script = native_probe
    observation = run(mode=mode)
    assert observation == {
        "mode": mode,
        "source_context": "system_u:system_r:init_t:s0:c1.c4",
        "executable_context": "system_u:object_r:keepalived_exec_t:s0:c1.c4",
        "prospective_daemon_domain": "system_u:system_r:keepalived_t:s0:c1.c4",
        "script_context": "system_u:object_r:keepalived_unconfined_script_exec_t:s0:c1.c4",
        "script_directory_context": "system_u:object_r:keepalived_unconfined_script_exec_t:s0:c1.c4",
        "prospective_script_domain": "system_u:system_r:keepalived_unconfined_script_t:s0:c1.c4",
        "dependencies": {name: {"path": os.path.realpath(paths[name]),
                                "context": f"system_u:object_r:{name}_exec_t:s0:c1.c4"}
                         for name in DEPENDENCIES},
    }
    assert len([event for event in events if event[0] == "create"]) == 7
    assert [event[-2:] for event in events if event[0] == "av"] == (
        [(31, 128), (19, 512), (31, 1024)] * 2 + [(31, 160)] * 5
    )
    assert ("getfilecon", script) in events  # Custom paths remain label-validated.
    drifted = run(mode=mode, level="s0:c2.c5")
    assert drifted != observation
    assert drifted["script_context"].endswith(":s0:c2.c5")
    assert run(mode="Disabled") == {"mode": "Disabled"}
    assert events == [("getenforce",)]


@pytest.mark.parametrize("case,mode", [
    (case, mode) for mode in ("Enforcing", "Permissive")
    for case in ("wrong-script-label", "daemon-wrong", "script-wrong", *["deny-" + name for name in DEPENDENCIES])
] + [(case, "Enforcing") for case in (
    "pid-error", "pid-none", "context-error", "context-none", "daemon-error", "daemon-none",
    "script-error", "script-none", "class-process", "class-file", "permission-missing",
    "av-error", "av-none", "getenforce-error", "missing-bindings", *["missing-" + name for name in DEPENDENCIES],
)] + [("ready", "Unknown"), ("ready", "")])
def test_native_probe_fails_closed(native_probe, capsys, case, mode):
    run, _, _, _ = native_probe
    with pytest.raises((SystemExit, subprocess.CalledProcessError, ModuleNotFoundError)):
        run(case, mode)
    assert not capsys.readouterr().out


@pytest.mark.parametrize("case,mode", [
    ("deny-daemon-execute", "Enforcing"),
    ("deny-script-execute", "Permissive"),
    ("deny-daemon-transition", "Enforcing"),
    ("deny-script-transition", "Permissive"),
    ("deny-daemon-entrypoint", "Enforcing"),
    ("deny-script-entrypoint", "Permissive"),
    ("deny-execute_no_trans", "Enforcing"),
    ("deny-execute_no_trans", "Permissive"),
    ("dependency-transition", "Enforcing"),
])
def test_native_probe_rejects_missing_execution_authorization(native_probe, capsys, case, mode):
    run, _, _, _ = native_probe
    with pytest.raises(SystemExit):
        run(case, mode)
    assert not capsys.readouterr().out


def test_disabled_mode_needs_no_bindings(native_probe):
    run, events, _, _ = native_probe
    assert run("missing-bindings", "Disabled") == {"mode": "Disabled"}
    assert events == [("getenforce",)]


@pytest.mark.parametrize("probe", [
    {}, {"rc": -1}, {"rc": 0, "skipped": True}, {"rc": 0, "unreachable": True}, {"rc": 0, "failed": True},
])
def test_guard_rejects_incomplete_observation(repo_root, tmp_path, command_runner, probe):
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / GUARD).read_text())
    play = {
        "hosts": "localhost", "gather_facts": False,
        "vars": {"keepalived_vip_script_selinux_probe": {"stdout": '{"mode": "Disabled"}'} | probe},
        "tasks": [tasks[-1], {"ansible.builtin.fail": {"msg": "UNEXPECTED READINESS CONTINUATION"}}],
    }
    playbook = tmp_path / "guard.yml"
    playbook.write_text(yaml.safe_dump([play]))
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", "-c", "local", playbook]).assert_failure()
    assert "Require a complete reachable Keepalived script SELinux policy observation" in result.stdout
    assert "UNEXPECTED READINESS CONTINUATION" not in result.stdout
