from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


def _load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _task(tasks: list[dict], name: str) -> dict:
    return next(task for task in tasks if task["name"] == name)


def test_reuse_validation_requires_explicit_noninitialization(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    playbook = repo_root / "tests/fixtures/ha-handoff/validate-storage-layout.yml"
    run_playbook(
        command_runner,
        playbook,
        extra_vars=({"test_reuse_existing_vg": True},),
    ).assert_success()

    result = run_playbook(
        command_runner,
        playbook,
        extra_vars=(
            {"test_initialize": True, "test_reuse_existing_vg": True},
        ),
    )
    assert_failed_with(result, "reuse_existing_vg: true requires explicit initialize: false")

    missing = run_playbook(
        command_runner,
        repo_root
        / "tests/fixtures/ha-handoff/validate-storage-reuse-missing-initialize.yml",
    )
    assert_failed_with(
        missing, "reuse_existing_vg: true requires explicit initialize: false"
    )


def test_reuse_accepts_reviewed_one_pv_and_charges_only_missing_lvs(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
    ).assert_success()


def test_reuse_assertions_run_in_check_mode(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    command_runner.run(
        [
            "ansible-playbook",
            repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
            "--check",
        ]
    ).assert_success()


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("wrong_vg", "does not match its reviewed"),
        ("extra_pv", "does not match its reviewed"),
        ("wrong_size", "unexpected identity or size"),
        ("wrong_filesystem", "unexpected filesystem"),
        ("blank_filesystem", "no filesystem or an unexpected filesystem"),
        ("wrong_mountpoint", "mounted outside its declared mountpoint"),
        ("insufficient", "lacks free VG space"),
    ],
)
def test_reuse_rejects_unsafe_live_state_before_mutation(
    scenario: str,
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
        extra_vars=({"test_storage_reuse_scenario": scenario},),
    )
    assert_failed_with(result, message)


def test_reuse_preflight_precedes_mutation_and_is_read_only(repo_root: Path) -> None:
    role = repo_root / "roles/storage_volume/tasks"
    main_tasks = _load_yaml(role / "main.yml")
    preflight_tasks = _load_yaml(role / "reuse_existing_vg.yml")
    verifier_tasks = _load_yaml(role / "verify_reused_layout.yml")
    names = [task["name"] for task in main_tasks]

    assert names.index("Verify reused storage volume groups before mutation") < names.index(
        "Manage storage volumes"
    )
    assert all(
        set(task) <= {
            "name",
            "ansible.builtin.assert",
            "ansible.builtin.command",
            "ansible.builtin.include_tasks",
            "ansible.builtin.set_fact",
            "ansible.builtin.stat",
            "changed_when",
            "check_mode",
            "failed_when",
            "loop",
            "loop_control",
            "register",
            "vars",
            "when",
        }
        for task in preflight_tasks + verifier_tasks
    )
    commands = [
        task["ansible.builtin.command"]["argv"][0]
        for task in preflight_tasks
        if "ansible.builtin.command" in task
    ]
    assert set(commands) == {
        "blkid",
        "findmnt",
        "lsblk",
        "lvs",
        "pvs",
        "realpath",
        "vgs",
    }
    for task in preflight_tasks:
        if "ansible.builtin.command" in task:
            assert task["check_mode"] is False
            assert task["changed_when"] is False


def test_reuse_mode_guards_all_disk_and_vg_mutators(repo_root: Path) -> None:
    tasks = _load_yaml(repo_root / "roles/storage_volume/tasks/volume.yml")
    partition = _task(tasks, "Create LVM partition for storage volume")
    volume_group = _task(tasks, "Create storage volume group")
    check_mode_state = _task(tasks, "Track storage volume check-mode initialization state")

    assert "not storage_volume_reuse_existing_vg" in partition["when"]
    assert "not storage_volume_reuse_existing_vg" in volume_group["when"]
    assert volume_group["community.general.lvg"]["remove_extra_pvs"] is False
    assert "ansible_check_mode" in check_mode_state["ansible.builtin.set_fact"][
        "storage_volume_skip_lvm_tasks"
    ]
    assert "storage_volume_reuse_existing_vg" in check_mode_state[
        "ansible.builtin.set_fact"
    ]["storage_volume_skip_lvm_tasks"]
    assert "storage_volume_lv_preexisting" in check_mode_state[
        "ansible.builtin.set_fact"
    ]["storage_volume_skip_lvm_tasks"]

    task_text = (repo_root / "roles/storage_volume/tasks/volume.yml").read_text(
        encoding="utf-8"
    )
    assert "pvcreate" not in task_text
    assert "vgcreate" not in task_text
    assert "vgextend" not in task_text
    assert "vgreduce" not in task_text
