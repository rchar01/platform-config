from __future__ import annotations

import re
from pathlib import Path

import pytest

from conftest import CommandRunner


SCRIPT = "scripts/gitlab-runner-self-bootstrap-preflight"
DEFAULT_OPTIONS = {
    "--env": "test",
    "--limit": "gitlab-runner-01",
    "--min-controller-free-gib": "1",
    "--min-root-free-gib": "1",
    "--connect-timeout": "10",
    "--connect-retries": "6",
}


def _arguments(**overrides: str) -> list[str]:
    options = DEFAULT_OPTIONS | overrides
    arguments = ["inspect"]
    for name, value in options.items():
        arguments.extend((name, value))
    return arguments


@pytest.fixture(scope="module")
def preflight_source(repo_root: Path) -> str:
    return (repo_root / SCRIPT).read_text(encoding="utf-8")


def test_preflight_is_executable_and_has_valid_bash_syntax(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    script = repo_root / SCRIPT

    assert script.is_file()
    assert script.stat().st_mode & 0o111
    assert script.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")
    command_runner.run(["bash", "-n", script]).assert_success()


def test_preflight_help_is_available_without_an_operation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run([repo_root / SCRIPT, "--help"]).assert_success()

    assert result.stdout == ""
    assert "{inspect|build|connect|all}" in result.stderr
    for option in DEFAULT_OPTIONS:
        assert option in result.stderr
    assert "--allow-dirty" in result.stderr


def test_preflight_requires_an_operation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run([repo_root / SCRIPT]).assert_failure()

    assert result.returncode == 2
    assert result.stderr.startswith("Usage: gitlab-runner-self-bootstrap-preflight")


def test_preflight_rejects_an_unsupported_operation(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    result = command_runner.run([repo_root / SCRIPT, "apply"]).assert_failure()

    assert result.returncode == 2
    assert "unsupported operation: apply" in result.stderr


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        ({"--env": "../test"}, "--env must be a literal environment name"),
        ({"--limit": "gitlab-runner-*"}, "--limit must be one literal inventory hostname"),
        ({"--min-controller-free-gib": "0"}, "--min-controller-free-gib must be a positive integer"),
        ({"--min-root-free-gib": "0"}, "--min-root-free-gib must be a positive integer"),
        ({"--min-controller-free-gib": "1000001"}, "--min-controller-free-gib is unreasonably large"),
        ({"--min-root-free-gib": "1000001"}, "--min-root-free-gib is unreasonably large"),
        ({"--connect-timeout": "0"}, "--connect-timeout must be a positive integer"),
        ({"--connect-timeout": "3601"}, "--connect-timeout must not exceed 3600 seconds"),
        ({"--connect-retries": "0"}, "--connect-retries must be a positive integer"),
        ({"--connect-retries": "101"}, "--connect-retries must not exceed 100"),
    ),
)
def test_preflight_rejects_unsafe_cli_values_before_inspection(
    overrides: dict[str, str],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    result = command_runner.run(
        [repo_root / SCRIPT, *_arguments(**overrides)]
    ).assert_failure()

    assert result.returncode == 2
    assert message in result.stderr
    assert "== Inspect" not in result.stdout


def test_preflight_operations_and_worktree_policy_are_explicit(
    preflight_source: str,
) -> None:
    operation_case = re.search(
        r'case "\$operation" in\s+([^\n)]+)\) ;;', preflight_source
    )

    assert operation_case is not None
    assert operation_case.group(1).split("|") == ["inspect", "build", "connect", "all"]
    assert "inspect_phase\ncase \"$operation\" in" in preflight_source
    for dispatch in (
        "inspect) ;;",
        "build) build_phase ;;",
        "connect) connect_phase ;;",
    ):
        assert dispatch in preflight_source
    assert re.search(r"\n  all\)\s+build_phase\s+connect_phase\s+;;", preflight_source)

    assert "allow_dirty=false" in preflight_source
    assert "--allow-dirty)\n      allow_dirty=true" in preflight_source
    assert 'worktree_status=$(git -C "$path" status --porcelain=v1 --untracked-files=normal' in preflight_source
    assert 'fail "repository.$label.clean" "could not inspect worktree status"' in preflight_source
    assert 'elif [[ -z $worktree_status ]]; then' in preflight_source
    assert "elif [[ $allow_dirty == true ]]; then" in preflight_source
    assert 'fail "repository.$label.clean" "worktree is dirty; review it or use --allow-dirty"' in preflight_source
    assert "check_worktree public \"$repo_root\"" in preflight_source
    assert "check_worktree private \"$private_root\"" in preflight_source


def test_preflight_only_syntax_checks_the_required_playbooks(
    preflight_source: str,
) -> None:
    expected = [
        "bootstrap.yml",
        "base-os.yml",
        "storage-volumes.yml",
        "container-runtime.yml",
        "gitlab-runners.yml",
    ]
    playbook_loop = re.search(r"for playbook in ([^;\n]+); do", preflight_source)
    ansible_playbook_lines = [
        line.strip()
        for line in preflight_source.splitlines()
        if "run_in_environment ansible-playbook" in line
    ]

    assert playbook_loop is not None
    assert playbook_loop.group(1).split() == expected
    assert preflight_source.count("ansible-playbook") == 1
    assert len(ansible_playbook_lines) == 1
    syntax_command = ansible_playbook_lines[0]
    assert '"/workspace/playbooks/$playbook"' in syntax_command
    assert "--syntax-check" in syntax_command
    assert '--limit "$limit"' in syntax_command
    assert "--check" not in syntax_command.split()
    assert "--diff" not in syntax_command.split()


def test_preflight_rejects_unsafe_host_keys_and_requires_a_literal_limit(
    preflight_source: str,
) -> None:
    for variable in (
        "ansible_ssh_args",
        "ansible_ssh_common_args",
        "ansible_ssh_extra_args",
    ):
        assert variable in preflight_source
    assert "no|false|off|0|accept-new" in preflight_source
    assert "/dev/null|none" in preflight_source
    assert 'item.get("name") == "HOST_KEY_CHECKING"' in preflight_source
    assert 'matches[0].get("value") is True' in preflight_source
    assert 'if strict not in {"yes", "true", "ask"}:' in preflight_source
    assert 'normalized_value != "/tmp/platform-home/.ssh/known_hosts"' in preflight_source
    assert 'value != "/tmp/platform-home/.ssh/known_hosts"' in preflight_source

    assert '[[ $limit =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]' in preflight_source
    assert "if target not in hostvars:" in preflight_source
    assert 'ansible -i "$container_inventory" all --list-hosts --limit "$limit"' in preflight_source
    assert '${#listed_hosts[@]} -eq 1 && ${listed_hosts[0]} == "$limit"' in preflight_source
    assert preflight_source.count('--limit "$3"') == 3


def test_preflight_canonicalizes_secret_paths_before_use(
    preflight_source: str,
) -> None:
    secret_root = "/tmp/platform-home/.config/platform-infrastructure"

    assert preflight_source.count(f"root=$(realpath -e {secret_root})") == 2
    assert preflight_source.count('resolved=$(realpath -e "$path")') == 2
    assert preflight_source.count('case "$resolved" in "$root"/*) ;; *) exit 1 ;; esac') == 2
    assert preflight_source.count('test -f "$resolved" && test ! -L "$path"') == 2


def test_preflight_disk_signature_probes_are_privileged_and_read_only(
    preflight_source: str,
) -> None:
    wipefs = 'sudo wipefs --no-act --noheadings --output TYPE,UUID,LABEL "$device"'
    blkid = 'sudo blkid "$device"'

    assert preflight_source.count(wipefs) == 1
    assert preflight_source.count(blkid) == 1
    assert preflight_source.index(wipefs) < preflight_source.index(blkid)
    assert "wipefs --all" not in preflight_source
    assert "wipefs -a" not in preflight_source
    assert "blkid_status == 2" in preflight_source


def test_preflight_storage_checks_fail_closed(preflight_source: str) -> None:
    assert "type(capacity) is not int" in preflight_source
    assert "type(size) is not int" in preflight_source
    assert "type(required_free) is not int" in preflight_source
    assert "type(partition) is not int" in preflight_source
    assert 'pv_parent_real == "$device_real"' in preflight_source
    assert 'pv_partition == "$partition"' in preflight_source
    assert '[[ ! -e $mountpoint && ! -L $mountpoint ]]' in preflight_source
    assert '[[ -L $mountpoint || ! -d $mountpoint ]]' in preflight_source
    assert "size_bytes == rounded_bytes" in preflight_source
    assert "vg_missing_bytes[$vg]" in preflight_source


def test_preflight_make_targets_forward_the_development_image(repo_root: Path) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")

    for operation in ("inspect", "build", "connect", "all"):
        target = f"runner-self-bootstrap-{operation}:"
        assert target in makefile
    assert makefile.count('PLATFORM_CONFIG_DEV_IMAGE="$(DEV_IMAGE)" ./scripts/gitlab-runner-self-bootstrap-preflight') == 4
