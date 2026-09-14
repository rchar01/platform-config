"""Exercise the real validator and yum_repository tasks in a temporary reposdir."""

from __future__ import annotations

import configparser
import sys

import pytest
import yaml


DEFAULT = object()


def run_repository_tasks(repo_root, isolated_test_dir, command_runner, value=DEFAULT):
    variables = yaml.safe_load((repo_root / "roles/rke2/defaults/main.yml").read_text())
    variables.update({
        "ansible_python_interpreter": sys.executable,
        "rke2_rpm_common_repository_url": "https://rpm.example.test/common",
        "rke2_rpm_version_repository_url": "https://rpm.example.test/version",
        "rke2_rpm_gpg_key_url": "https://rpm.example.test/public.key",
        "rke2_rpm_version": "1.35.5~rke2r2",
    })
    if value is not DEFAULT:
        variables["rke2_rpm_repo_gpgcheck"] = value
    reposdir = isolated_test_dir / "repos"
    reposdir.mkdir(exist_ok=True)
    tasks = [{"ansible.builtin.import_tasks": str(
        repo_root / "roles/rke2/tasks/validate_rpm_sources.yml"
    )}]
    for task in yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text()):
        if "ansible.builtin.yum_repository" in task:
            # Redirect only the filesystem location; execute the real repo settings.
            task["ansible.builtin.yum_repository"]["reposdir"] = str(reposdir)
            tasks.append(task)
    assert len(tasks) == 3
    playbook = isolated_test_dir / "repositories.yml"
    playbook.write_text(yaml.safe_dump([{
        "name": "Verify isolated repository policy",
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "become": False, "vars": variables, "tasks": tasks,
    }]))
    result = command_runner.run([
        "ansible-playbook", "-i", "localhost,", playbook,
    ], timeout=60)
    return result, reposdir / "rancher-rke2.repo"


@pytest.mark.parametrize("value,expected", [(DEFAULT, True), (True, True), (False, False)],
                         ids=["default", "enabled", "disabled"])
def test_metadata_verification_repo_settings(
    repo_root, isolated_test_dir, command_runner, value, expected,
):
    result, path = run_repository_tasks(repo_root, isolated_test_dir, command_runner, value)
    result.assert_success()
    parser = configparser.ConfigParser()
    parser.read(path)
    assert set(parser.sections()) == {"rancher-rke2-common", "rancher-rke2"}
    for name in parser.sections():
        section = parser[name]
        assert section.getboolean("repo_gpgcheck") is expected
        assert section.getboolean("gpgcheck") is True
        assert section.getboolean("enabled") is False
        assert section.getboolean("sslverify", fallback=True) is True
        assert section["baseurl"].startswith("https://rpm.example.test/")
        assert section["gpgkey"] == "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rancher-RKE2"
    second, _ = run_repository_tasks(repo_root, isolated_test_dir, command_runner, value)
    second.assert_success()
    assert "changed=0" in second.stdout


@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}],
                         ids=["string-false", "string-true", "zero", "one", "null", "list", "mapping"])
def test_metadata_verification_invalid_type_prevents_repo_writes(
    repo_root, isolated_test_dir, command_runner, value,
):
    result, path = run_repository_tasks(repo_root, isolated_test_dir, command_runner, value)
    result.assert_failure()
    assert "rke2_rpm_repo_gpgcheck must be a boolean" in result.stdout
    assert not path.exists()
