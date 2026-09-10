from __future__ import annotations

import json
import os
from pathlib import Path
import sys

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


def test_growth_validation_is_explicit_and_xfs_only(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    playbook = repo_root / "tests/fixtures/ha-handoff/validate-storage-growth.yml"
    run_playbook(command_runner, playbook).assert_success()

    for extra_vars in (
        {"test_reuse_existing_vg": False},
        {"test_grow_from_size_gib": 8},
        {"test_grow_from_size_gib": 9},
        {"test_fstype": "ext4"},
        {"test_mount_state": "present"},
        {
            "storage_volumes": [
                {
                    "name": "test_primary",
                    "layout": "test_data",
                    "lv_name": "primary",
                    "grow_from_size_gib": 6,
                    "size_gib": 8,
                    "lv_size": "9g",
                    "mountpoint": "/srv/test/primary",
                }
            ]
        },
    ):
        result = run_playbook(command_runner, playbook, extra_vars=(extra_vars,))
        assert_failed_with(result, "grow_from_size_gib requires an existing-VG layout")


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
    "scenario",
    ["valid", "growth_transitional", "growth_converged"],
)
def test_reuse_accepts_reviewed_growth_states(
    scenario: str, repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
        extra_vars=(
            {"test_storage_growth": True, "test_storage_reuse_scenario": scenario},
        ),
    ).assert_success()


def test_reuse_growth_assertions_run_in_check_mode(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    command_runner.run(
        [
            "ansible-playbook",
            repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
            "--check",
            "--extra-vars",
            "test_storage_growth=true",
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


@pytest.mark.parametrize(
    ("scenario", "message"),
    [
        ("wrong_size", "unexpected identity or size"),
        ("growth_missing", "is missing or has an unexpected identity or size"),
        ("growth_wrong_geometry", "does not match the reviewed source or target size"),
        ("insufficient", "lacks free VG space"),
    ],
)
def test_reuse_rejects_unsafe_growth_before_mutation(
    scenario: str,
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
        extra_vars=(
            {"test_storage_growth": True, "test_storage_reuse_scenario": scenario},
        ),
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
            "environment",
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
        "xfs_growfs",
    }
    for task in preflight_tasks:
        if "ansible.builtin.command" in task:
            assert task["check_mode"] is False
            assert task["changed_when"] is False


def test_mountpoint_guard_precedes_mutation_and_mount(repo_root: Path) -> None:
    role = repo_root / "roles/storage_volume/tasks"
    volume_tasks = _load_yaml(role / "volume.yml")
    guard_tasks = _load_yaml(role / "verify_mountpoint.yml")
    names = [task["name"] for task in volume_tasks]

    assert names.index("Verify storage volume mountpoint before mutation") < names.index(
        "Create LVM partition for storage volume"
    )
    assert names.index("Ensure storage volume mountpoint exists") < names.index(
        "Recheck storage volume mountpoint before mounting"
    )
    assert names.index("Recheck storage volume mountpoint before mounting") < names.index(
        "Mount storage volume by UUID"
    )

    commands = [
        task["ansible.builtin.command"]["argv"][0]
        for task in guard_tasks
        if "ansible.builtin.command" in task
    ]
    assert commands == ["findmnt", "lsblk", "find"]
    for task in guard_tasks:
        if "ansible.builtin.command" in task:
            assert task["changed_when"] is False
            assert task["check_mode"] is False

    source = (role / "verify_mountpoint.yml").read_text(encoding="utf-8")
    assert "TARGET,SOURCE,FSTYPE,FSROOT,MAJ:MIN" in source
    assert "storage_volume_mountpoint_records[0]['maj:min']" in source
    assert "storage_volume_mountpoint_lv_identity.stdout" in source
    assert "not empty; refusing to hide its contents" in source
    for unsafe in ("ansible.builtin.copy", "ansible.posix.synchronize", "rsync", "rm -", "mv "):
        assert unsafe not in source


def test_mountpoint_guard_accepts_safe_paths_and_rejects_unsafe_paths(
    repo_root: Path, command_runner: CommandRunner
) -> None:
    run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/verify-storage-mountpoint.yml",
    ).assert_success()


def test_preinstalled_storage_packages_skip_package_manager(repo_root: Path) -> None:
    tasks = _load_yaml(repo_root / "roles/storage_volume/tasks/main.yml")
    package_facts = _task(tasks, "Collect installed storage volume packages")
    install = _task(tasks, "Install missing storage volume packages")

    assert package_facts["ansible.builtin.package_facts"] == {"manager": "auto"}
    assert install["ansible.builtin.package"] == {
        "name": "{{ storage_volume_packages }}",
        "state": "present",
    }
    assert (
        "storage_volume_packages | difference(ansible_facts.packages) | length > 0"
        in install["when"]
    )


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


def test_growth_runs_after_mount_and_verifies_target_state(repo_root: Path) -> None:
    tasks = _load_yaml(repo_root / "roles/storage_volume/tasks/volume.yml")
    names = [task["name"] for task in tasks]
    logical_volume = _task(tasks, "Create storage logical volume")
    grow = _task(tasks, "Grow existing XFS storage volume")
    verify = _task(tasks, "Verify grown storage logical volume and XFS geometry")

    assert logical_volume["community.general.lvol"]["shrink"] is False
    assert names.index("Mount storage volume by UUID") < names.index(
        "Grow existing XFS storage volume"
    )
    assert names.index("Grow existing XFS storage volume") < names.index(
        "Verify grown storage logical volume and XFS geometry"
    )
    assert grow["ansible.builtin.command"]["argv"] == [
        "xfs_growfs",
        "-d",
        "{{ storage_volume_mountpoint }}",
    ]
    assert "storage_volume_growth_xfs_pending | bool" in grow["when"]
    assert "not ansible_check_mode" in grow["when"]
    assert "storage_volume_growth_enabled | bool" in verify["when"]
    assert "not ansible_check_mode" in verify["when"]


def test_growth_geometry_probes_use_read_only_mounted_xfs(repo_root: Path) -> None:
    role = repo_root / "roles/storage_volume/tasks"
    for filename, name, mountpoint in (
        (
            "reuse_existing_vg.yml",
            "Inspect requested existing XFS growth geometry",
            "{{ storage_volume_reuse_requested_volume.mountpoint }}",
        ),
        (
            "volume.yml",
            "Inspect grown XFS storage geometry",
            "{{ storage_volume_mountpoint }}",
        ),
    ):
        probe = _task(_load_yaml(role / filename), name)
        assert probe["ansible.builtin.command"]["argv"] == [
            "xfs_growfs", "-n", mountpoint,
        ]
        assert probe["environment"]["LC_ALL"] == "C"
        assert probe["changed_when"] is False
        assert probe["check_mode"] is False


def _growth_post_vars(repo_root: Path) -> dict:
    variables = _load_yaml(
        repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml"
    )[0]["vars"]
    variables.update(
        test_storage_growth=True,
        test_storage_reuse_scenario="growth_converged",
        storage_volume_growth_enabled=True,
        storage_volume_vg_name="test_data",
        storage_volume_lv_name="primary",
        storage_volume_lv_device="/dev/test_data/primary",
        storage_volume_mountpoint="/srv/test/primary",
        storage_volume_matching_layout={"name": "test_data"},
        storage_volume_reuse_layout_state={
            "test_data": {
                "growth_target_bytes": {"primary": 8589934592},
                "vg_extent_bytes": 4194304,
            },
        },
        storage_volume_growth_lv_report={
            "stdout": json.dumps({"report": [{"lv": [{
                "vg_name": "test_data", "lv_name": "primary", "lv_size": "8589934592",
            }]}]}),
        },
        storage_volume_growth_xfs_report={
            "stdout": "{{ test_storage_xfs_geometry | default(storage_volume_reuse_test_geometry) }}",
        },
    )
    return variables


@pytest.mark.parametrize(
    ("geometry", "accepted"),
    [
        pytest.param("data = bsize=4096 blocks=2097152, imaxpct=25\n", True, id="exact-target"),
        # Preserve the existing strict one-extent tolerance, including its open lower bound.
        pytest.param("data = bsize=4096 blocks=2096129, imaxpct=25\n", True, id="inside-extent"),
        pytest.param("data = bsize=4096 blocks=2096128, imaxpct=25\n", False, id="one-extent-short"),
        pytest.param("data = bsize=4096 blocks=2097153, imaxpct=25\n", False, id="one-block-oversized"),
        pytest.param("data = bsize=4096 blocks=1572864, imaxpct=25\n", False, id="source-only"),
        pytest.param("data = bsize=4096 blocks=2097152, imaxpct=25\n" * 2, False, id="duplicate-data"),
        pytest.param("data = bsize=oops blocks=2097152, imaxpct=25\n", False, id="malformed"),
        pytest.param("data = bsize=4096 blocks=2097152oops, imaxpct=25\n", False, id="malformed-blocks"),
        pytest.param("data = bsize=4096 blocks=2097152\n", False, id="missing-comma"),
        pytest.param("log =internal log bsize=4096 blocks=2097152, version=2\n", False, id="missing-data"),
        pytest.param("meta-data = bsize=4096 blocks=2097152, imaxpct=25\n", False, id="metadata-only"),
        pytest.param("data = bsize=0 blocks=2097152, imaxpct=25\n", False, id="zero-bsize"),
        pytest.param("data = bsize=4096 blocks=0, imaxpct=25\n", False, id="zero-blocks"),
        pytest.param("blocksize = 4096\ndblocks = 2097152\n", False, id="old-raw-format"),
    ],
)
def test_growth_geometry_contract_preflight_and_postassert(
    geometry: str,
    accepted: bool,
    repo_root: Path,
    tmp_path: Path,
    command_runner: CommandRunner,
) -> None:
    # Execute the production assertion, rather than reimplementing its Jinja parser.
    postassert = _task(
        _load_yaml(repo_root / "roles/storage_volume/tasks/volume.yml"),
        "Verify grown storage logical volume and XFS geometry",
    )
    playbook = tmp_path / "postassert.yml"
    playbook.write_text(yaml.safe_dump([{
        "name": "Exercise production growth postassert",
        "hosts": "localhost",
        "gather_facts": False,
        "vars": _growth_post_vars(repo_root),
        "tasks": [postassert],
    }]), encoding="utf-8")
    result = run_playbook(
        command_runner, playbook, extra_vars=({"test_storage_xfs_geometry": geometry},),
    )
    if accepted:
        result.assert_success()
    else:
        assert_failed_with(result, "reviewed target size after growth")

    # Source geometry is valid preflight for an already extended LV, but not post-grow.
    preflight_accepted = accepted or "blocks=1572864," in geometry
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/ha-handoff/verify-storage-reuse.yml",
        extra_vars=({
            "test_storage_growth": True,
            "test_storage_reuse_scenario": (
                "growth_transitional" if "blocks=1572864," in geometry else "growth_converged"
            ),
            "test_storage_xfs_geometry": geometry,
        },),
    )
    if preflight_accepted:
        result.assert_success()
    else:
        assert_failed_with(result, "does not match the reviewed source or target size")


def test_growth_probes_accept_live_target_without_reading_stale_raw_geometry(
    repo_root: Path, tmp_path: Path, command_runner: CommandRunner,
) -> None:
    # Synthetic divergent observations; this does not reproduce a target timing race.
    # Use the real command module and untouched selected production tasks, with only
    # the external binaries replaced. No filesystem, LV, or mount is created.
    trace = tmp_path / "probe-trace.jsonl"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    variables = _growth_post_vars(repo_root)
    live_geometry = variables["storage_volume_reuse_test_geometry"].replace(
        "{{ storage_volume_reuse_test_blocks }}", "2097152",
    )
    script = f"""#!{sys.executable}
import json
import os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
with open({str(trace)!r}, 'a') as stream:
    stream.write(json.dumps([name, sys.argv[1:], os.environ.get('LC_ALL')]) + '\\n')
if name == 'xfs_db':
    print('blocksize = 4096\\ndblocks = 1572864')
elif name == 'xfs_growfs':
    assert sys.argv[1:] == ['-n', '/srv/test/primary'], sys.argv
    assert os.environ.get('LC_ALL') == 'C'
    print({live_geometry!r})
else:
    raise AssertionError(name)
"""
    for name in ("xfs_db", "xfs_growfs"):
        binary = fake_bin / name
        binary.write_text(script, encoding="utf-8")
        binary.chmod(0o755)
    role = repo_root / "roles/storage_volume/tasks"
    volume_tasks = _load_yaml(role / "volume.yml")
    tasks = [
        _task(_load_yaml(role / "reuse_existing_vg.yml"), "Inspect requested existing XFS growth geometry"),
        _task(volume_tasks, "Inspect grown XFS storage geometry"),
        _task(volume_tasks, "Verify grown storage logical volume and XFS geometry"),
        {
            "name": "Verify read-only probe results",
            "ansible.builtin.assert": {"that": [
                "not storage_volume_reuse_filesystem_sizes.changed",
                "not storage_volume_growth_xfs_report.changed",
                "storage_volume_reuse_filesystem_sizes.results | length == 1",
                "storage_volume_reuse_filesystem_sizes.results[0].stdout == storage_volume_growth_xfs_report.stdout",
            ]},
        },
    ]
    playbook = tmp_path / "live-probes.yml"
    playbook.write_text(yaml.safe_dump([{
        "name": "Exercise production mounted geometry probes and postassert",
        "hosts": "localhost",
        "gather_facts": False,
        "vars": variables,
        "tasks": tasks,
    }]), encoding="utf-8")
    result = run_playbook(
        command_runner, playbook,
        environment={"PATH": f"{fake_bin}{os.pathsep}{command_runner.environment['PATH']}"},
    )
    result.assert_success()
    assert [json.loads(line) for line in trace.read_text().splitlines()] == [
        ["xfs_growfs", ["-n", "/srv/test/primary"], "C"],
        ["xfs_growfs", ["-n", "/srv/test/primary"], "C"],
    ]


def test_mounted_volume_restores_only_mount_root_selinux_type(
    repo_root: Path,
) -> None:
    tasks = _load_yaml(repo_root / "roles/storage_volume/tasks/volume.yml")
    ownership = _task(tasks, "Ensure mounted storage volume ownership")

    assert ownership["ansible.builtin.file"]["setype"] == "_default"
    assert "recurse" not in ownership["ansible.builtin.file"]
