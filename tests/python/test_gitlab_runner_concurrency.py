from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook


@pytest.mark.parametrize("value", [1, 3, 0, -1, True, "3"])
def test_concurrency_input_validation(value, repo_root, command_runner):
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/gitlab-runner/render.yml",
        extra_vars=({"gitlab_runner_concurrent": value},),
    )
    if type(value) is int and value > 0:
        result.assert_success()
    else:
        assert_failed_with(result, "documented types and required values")


CONFIG = b'''# synthetic registration; preserve every byte except the root integer
concurrent = 1  # manager capacity
check_interval = 0
unknown = { literal = "keep", values = [1, 2] }
note = """opaque text
concurrent = 77
"""
[[runners]]
  name = "example-runner"
  url = "https://gitlab.example.invalid"
  token = "fixture-auth-do-not-return"
  executor = "shell"
  concurrent = 8
  request_concurrency = 1
  [runners.unknown]
    concurrent = 9
'''


@pytest.fixture
def module_target(repo_root, tmp_path, namespace_root_runner):
    config = tmp_path / "config.toml"
    config.write_bytes(CONFIG)
    config.chmod(0o600)
    os.utime(config, ns=(1_000_000_000, 1_000_000_000))

    def invoke(value=3, check=False, driver=None):
        arguments = tmp_path / "arguments.json"
        arguments.write_text(json.dumps({"ANSIBLE_MODULE_ARGS": {
            "path": str(config), "concurrent": value, "_ansible_check_mode": check,
        }}))
        result = namespace_root_runner.run([
            sys.executable,
            driver or repo_root / "roles/gitlab_runner/library/gitlab_runner_concurrency.py",
            arguments,
        ])
        assert "fixture-auth" not in result.stdout + result.stderr
        return result, json.loads(result.stdout)

    return config, invoke


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_module_preserves_bytes_check_mode_and_idempotency(module_target, newline):
    config, invoke = module_target
    # Put multiline lookalikes after the first real table: they must never be edited.
    original = CONFIG.replace(b'note = """opaque text\nconcurrent = 77\n"""\n', b"")
    original += b'note = """opaque text\nconcurrent = 77\n"""\n'
    original = original.replace(b"\n", newline)
    config.write_bytes(original)
    before = config.stat()
    result, data = invoke(check=True)
    result.assert_success()
    assert data["changed"] and data["current_concurrent"] == 1
    after = config.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_atime_ns) == (
        before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_atime_ns,
    )
    assert config.read_bytes() == original
    result, data = invoke()
    result.assert_success()
    assert data["changed"]
    assert config.read_bytes() == original.replace(b"concurrent = 1 ", b"concurrent = 3 ", 1)
    after = config.stat()
    assert after.st_mode & 0o7777 == 0o600
    assert after.st_uid == before.st_uid and after.st_gid == before.st_gid
    assert after.st_ino != before.st_ino and after.st_mtime_ns > before.st_mtime_ns
    result, data = invoke()
    result.assert_success()
    assert not data["changed"] and data["current_concurrent"] == 3
    assert config.stat().st_mtime_ns == after.st_mtime_ns
    assert sorted(p.name for p in config.parent.glob(".config.toml.concurrent-*")) == []


@pytest.mark.parametrize("content", [
    b'concurrent = 1\ninvalid = "fixture-auth',
    b'[[runners]]\nconcurrent = 1\n',
    b'concurrent = 1\nconcurrent = 1\n',
    b'"concurrent" = 1\n',
    b'concurrent = +1\n',
    b'concurrent = true\n',
    CONFIG,  # Ambiguous canonical-looking assignment inside a root multiline value.
    b'"concurrent" = 1\nnote = """\nconcurrent = 1\n"""\n',
])
def test_module_rejects_unsupported_or_ambiguous_config(module_target, content):
    config, invoke = module_target
    config.write_bytes(content)
    before = config.stat()
    result, data = invoke()
    result.assert_failure()
    assert data["failed"]
    assert config.read_bytes() == content
    assert config.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize("value", [0, -1, True, "3"])
def test_module_rejects_invalid_input(module_target, value):
    config, invoke = module_target
    before = config.stat()
    result, data = invoke(value)
    result.assert_failure()
    assert data["failed"]
    assert config.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize("unsafe", ["mode", "symlink", "hardlink"])
def test_module_rejects_unsafe_files(module_target, unsafe):
    config, invoke = module_target
    if unsafe == "mode":
        config.chmod(0o644)
    elif unsafe == "hardlink":
        os.link(config, config.with_suffix(".link"))
    else:
        target = config.with_suffix(".target")
        config.rename(target)
        config.symlink_to(target)
    result, data = invoke()
    result.assert_failure()
    assert data["failed"]
    assert config.read_bytes() == CONFIG


def test_module_rejects_multiline_false_match_even_on_noop(module_target):
    config, invoke = module_target
    content = b'"concurrent" = 1\nnote = """\nconcurrent = 1\n"""\n'
    config.write_bytes(content)
    result, data = invoke(value=1)
    result.assert_failure()
    assert data["failed"] and config.read_bytes() == content


def test_module_detects_rotation_before_publication(module_target, repo_root, tmp_path):
    config, invoke = module_target
    content = b'concurrent = 1\ntoken = "fixture-auth-original"\n'
    config.write_bytes(content)
    rotated = config.with_suffix(".rotated")
    replacement = content.replace(b"original", b"rotated")
    rotated.write_bytes(replacement)
    rotated.chmod(0o600)
    driver = tmp_path / "rotate_before_recheck.py"
    driver.write_text(
        "import os, runpy\noriginal_lstat = os.lstat\n"
        "def rotate(path, *args, **kwargs):\n"
        f"    if path == {str(config)!r}:\n"
        f"        os.replace({str(rotated)!r}, path)\n"
        "    return original_lstat(path, *args, **kwargs)\n"
        "os.lstat = rotate\n"
        f"runpy.run_path({str(repo_root / 'roles/gitlab_runner/library/gitlab_runner_concurrency.py')!r}, "
        "run_name='__main__')\n"
    )
    result, data = invoke(driver=driver)
    result.assert_failure()
    assert data["failed"] and config.read_bytes() == replacement
    assert not list(config.parent.glob(".config.toml.concurrent-*"))


@pytest.fixture
def role_target(repo_root, tmp_path, namespace_root_runner):
    role = tmp_path / "gitlab_runner"
    shutil.copytree(repo_root / "roles/gitlab_runner", role)
    events = tmp_path / "events.jsonl"
    # Only systemd and Quadlet rendering are doubles; registration runs a toy
    # Podman command. All config/stat/copy/backup/module operations are real.
    for path in [*role.glob("tasks/*.yml"), *role.glob("handlers/*.yml")]:
        path.write_text(path.read_text().replace(
            "ansible.builtin.systemd_service:", "fixture_service:",
        ).replace("ansible.builtin.service:", "fixture_service:").replace(
            "ansible.builtin.template:", "fixture_template:",
        ))
    actions = role / "action_plugins"
    actions.mkdir()
    action_source = (
        "import json\nfrom pathlib import Path\n"
        "from ansible.plugins.action import ActionBase\n"
        "class ActionModule(ActionBase):\n"
        "    def run(self, tmp=None, task_vars=None):\n"
        f"        with Path({str(events)!r}).open('a') as log:\n"
        "            log.write(json.dumps({'action': self._task.action, 'args': self._task.args}) + '\\n')\n"
        "        return {'changed': False}\n"
    )
    for name in ("fixture_service", "fixture_template"):
        (actions / f"{name}.py").write_text(action_source)
    config_dir = tmp_path / "runner"
    config_dir.mkdir()
    config = config_dir / "config.toml"
    original = CONFIG.replace(b'note = """opaque text\nconcurrent = 77\n"""\n', b"")
    config.write_bytes(original)
    config.chmod(0o600)
    token = tmp_path / "token"
    token.write_text("fixture-auth-registration")
    token.chmod(0o600)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    (binaries / "systemctl").write_text(
        f"#!{sys.executable}\nimport sys\n"
        "assert sys.argv[1] in ['is-enabled', 'is-active']\n"
        "print('enabled' if sys.argv[1] == 'is-enabled' else 'active')\n"
    )
    (binaries / "podman").write_text(
        f"#!{sys.executable}\nimport os, sys\nfrom pathlib import Path\n"
        "assert 'register' in sys.argv\n"
        f"config = Path({str(config)!r})\n"
        "assert not config.exists(), 'must not register over existing token'\n"
        "os.umask(0o077)\n"
        f"config.write_bytes({original!r})\n"
        f"with Path({str(events)!r}).open('a') as log:\n"
        "    log.write('{\"action\": \"register\"}\\n')\n"
    )
    for path in binaries.iterdir():
        path.chmod(0o755)

    # Reuse the public caller's actual deferred cleanup and rescue contract.
    play = yaml.safe_load((repo_root / "playbooks/gitlab-runners.yml").read_text())[0]
    play.update(hosts="localhost", connection="local", gather_facts=False, become=False)
    transaction = play["tasks"][0]
    transaction["block"].pop(0)  # Shared Podman host convergence is outside this fixture.
    transaction["block"].insert(1, {
        "name": "Observe backup before caller cleanup",
        "ansible.builtin.stat": {"path": "{{ gitlab_runner_config_backup.path }}"},
        "register": "fixture_backup",
        "when": "gitlab_runner_config_backup_ready | default(false) | bool",
    })
    transaction["block"].insert(2, {
        "name": "Require deferred root-only backup",
        "ansible.builtin.assert": {"that": [
            "fixture_backup.stat.exists", "fixture_backup.stat.uid == 0",
            "fixture_backup.stat.mode == '0600'",
        ]},
        "when": "gitlab_runner_config_backup_ready | default(false) | bool",
    })
    transaction["block"].insert(3, {
        "name": "Inject later convergence failure",
        "ansible.builtin.fail": {"msg": "synthetic later failure"},
        "when": "fixture_later_failure | default(false)",
    })
    for task in [*play["pre_tasks"], *transaction["block"], *transaction["rescue"]]:
        if "ansible.builtin.include_role" in task:
            task["ansible.builtin.include_role"]["name"] = str(role)
    play["vars"] = {
        "ansible_python_interpreter": sys.executable,
        "gitlab_runner_config_dir": str(config_dir),
        "gitlab_runner_data_dir": str(tmp_path / "data"),
        "gitlab_runner_quadlet_dir": str(tmp_path),
        "gitlab_runner_token_src": str(token),
        "gitlab_runner_gitlab_url": "https://gitlab.example.invalid",
        "gitlab_runner_name": "example-runner",
        "gitlab_runner_concurrent": 3,
    }
    playbook = tmp_path / "play.yml"
    playbook.write_text(yaml.safe_dump([play]))

    def invoke(*, force=False, check=False, later_failure=False):
        if events.exists():
            events.unlink()
        result = namespace_root_runner.run([
            "ansible-playbook", "-i", "localhost,", str(playbook), "--limit", "localhost",
            "-e", json.dumps({"gitlab_runner_force_register": force,
                              "fixture_later_failure": later_failure}),
            *(["--check", "--diff"] if check else []),
        ], environment={"PATH": f"{binaries}:{os.environ['PATH']}"}, timeout=45)
        assert "fixture-auth" not in result.stdout + result.stderr
        observed = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
        return result, observed

    return config, original, invoke


@pytest.mark.parametrize("state", ["existing", "fresh", "forced"])
def test_role_concurrency_registration_and_cleanup(role_target, state):
    config, original, invoke = role_target
    if state == "fresh":
        config.unlink()
    result, events = invoke(force=state == "forced")
    result.assert_success()
    assert config.read_bytes() == original.replace(b"concurrent = 1 ", b"concurrent = 3 ", 1)
    assert sum(event["action"] == "register" for event in events) == (state != "existing")
    stops = [event for event in events if event.get("args", {}).get("state") == "stopped"]
    assert bool(stops) == (state == "forced")
    assert not any(event.get("args", {}).get("state") == "restarted" for event in events)
    assert not list(config.parent.glob(".config.toml.ansible-*"))
    if state == "existing":
        result, events = invoke()
        result.assert_success()
        assert "changed=0" in result.stdout
        assert not any(event["action"] == "register" for event in events)


@pytest.mark.parametrize("state", ["existing", "fresh", "forced"])
def test_role_concurrency_check_mode(role_target, state):
    config, original, invoke = role_target
    if state == "fresh":
        config.unlink()
    before = config.stat() if config.exists() else None
    result, events = invoke(force=state == "forced", check=True)
    result.assert_success()
    assert not any(event["action"] == "register" for event in events)
    assert not list(config.parent.glob(".config.toml.ansible-*"))
    if before:
        assert config.read_bytes() == original
        assert config.stat().st_mtime_ns == before.st_mtime_ns
    else:
        assert not config.exists()
    match = re.search(
        r"TASK \[[^\n]*Reconcile GitLab Runner manager concurrency\][^\n]*\n([^\n]+)",
        result.stdout,
    )
    assert match, result.diagnostics()
    reconcile = match.group(1)
    assert ("changed: [localhost]" if state == "existing" else "skipping: [localhost]") in reconcile


@pytest.mark.parametrize("force", [False, True])
def test_role_later_failure_restores_original_token_and_config(role_target, force):
    config, original, invoke = role_target
    result, events = invoke(force=force, later_failure=True)
    assert_failed_with(result, "synthetic later failure")
    assert "All assertions passed" in result.stdout
    assert config.read_bytes() == original
    assert not list(config.parent.glob(".config.toml.ansible-*"))


def test_role_existing_executor_drift_still_blocks_changes(role_target):
    config, original, invoke = role_target
    drifted = original.replace(b'executor = "shell"', b'executor = "docker"')
    config.write_bytes(drifted)
    result, events = invoke()
    assert_failed_with(result, "one declared")
    assert config.read_bytes() == drifted
    assert not events and not list(config.parent.glob(".config.toml.ansible-*"))
