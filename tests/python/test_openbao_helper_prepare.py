from __future__ import annotations

import shutil

import pytest
import yaml


@pytest.fixture
def helper_prepare(repo_root, isolated_test_dir, namespace_root_runner):
    root = isolated_test_dir
    role = root / "roles/pki_host_local_certificate"
    shutil.copytree(repo_root / "roles/pki_host_local_certificate", role)
    target = root / "target"
    (target / "usr/local").mkdir(parents=True)
    for name in ("lifecycle_helper_prepare.yml", "lifecycle_helper_install.yml", "lifecycle_helper.yml"):
        path = role / "tasks" / name
        tasks = yaml.safe_load(path.read_text())
        for task in tasks:
            for module, field in (("ansible.builtin.stat", "path"), ("ansible.builtin.file", "path"), ("ansible.builtin.copy", "dest")):
                if module in task and task.get("delegate_to") != "localhost":
                    task[module][field] = "{{ fixture_target }}" + task[module][field]
        path.write_text(yaml.safe_dump(tasks, sort_keys=False))
    play = root / "helper.yml"

    def run(check=False, entry="lifecycle_helper_prepare.yml"):
        play.write_text(yaml.safe_dump([{
            "hosts": "localhost", "gather_facts": False, "connection": "local",
            "vars": {"fixture_target": str(target)},
            "tasks": [{"ansible.builtin.include_role": {"name": str(role), "tasks_from": entry}}],
        }]))
        return namespace_root_runner.run(["ansible-playbook", "-i", "localhost,", play,
                                          *(["--check", "--diff"] if check else [])], timeout=45)
    return run, target, repo_root / "roles/pki_host_local_certificate/files/platform-pki-host-local-lifecycle"


def test_fresh_check_apply_and_real_replay(helper_prepare):
    run, target, source = helper_prepare
    helper = target / "usr/local/libexec/platform-pki-host-local-lifecycle"
    result = run(check=True)
    result.assert_success()
    assert "changed=2" in result.stdout
    assert not helper.parent.exists()
    result = run()
    result.assert_success()
    assert helper.read_bytes() == source.read_bytes()
    assert helper.stat().st_mode & 0o777 == 0o755
    for check in (False, True):
        result = run(check=check)
        result.assert_success()
        assert "changed=0" in result.stdout
    result = run(check=True, entry="lifecycle_helper.yml")
    result.assert_success()


def test_existing_pki_check_contract_still_rejects_absent_helper(helper_prepare):
    run, target, _ = helper_prepare
    result = run(check=True, entry="lifecycle_helper.yml")
    result.assert_failure()
    assert "Read-only lifecycle use requires the exact shipped helper" in result.stdout
    assert not (target / "usr/local/libexec").exists()


@pytest.mark.parametrize("unsafe", ["symlink", "mode", "hardlink", "directory"])
def test_helper_preparation_rejects_unsafe_existing_objects(helper_prepare, unsafe):
    run, target, source = helper_prepare
    directory = target / "usr/local/libexec"
    directory.mkdir()
    helper = directory / "platform-pki-host-local-lifecycle"
    if unsafe == "symlink": helper.symlink_to(source)
    elif unsafe == "directory": helper.mkdir()
    else:
        helper.write_bytes(source.read_bytes())
        helper.chmod(0o777 if unsafe == "mode" else 0o755)
        if unsafe == "hardlink": (directory / "other-link").hardlink_to(helper)
    result = run(check=True)
    result.assert_failure()
    assert "Reject unsafe existing lifecycle helper preparation paths" in result.stdout
