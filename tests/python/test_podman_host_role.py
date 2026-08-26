from __future__ import annotations

from pathlib import Path

import yaml


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_podman_host_requires_exact_nevra_and_versionlock(repo_root: Path) -> None:
    defaults = load_yaml(repo_root / "roles/podman_host/defaults/main.yml")
    tasks = load_yaml(repo_root / "roles/podman_host/tasks/main.yml")
    by_name = {task["name"]: task for task in tasks}

    assert defaults["podman_host_package_nevra"] == ""
    assert defaults["podman_host_versionlock_package"] == (
        "python3-dnf-plugin-versionlock"
    )
    assert defaults["podman_host_versionlock_path"] == (
        "/etc/dnf/plugins/versionlock.list"
    )
    assert defaults["podman_host_storage_contract_enabled"] is False
    assert defaults["podman_host_storage_mountpoint"] == "/var/lib/containers"
    assert defaults["podman_host_graphroot"] == "/var/lib/containers/storage"
    validation = by_name["Require exact Podman package and versionlock inputs"]
    assert "^podman-" in validation["ansible.builtin.assert"]["that"][1]
    install = by_name["Install exact Podman package"]["ansible.builtin.dnf"]
    assert install == {
        "name": "{{ podman_host_package_nevra }}",
        "state": "present",
        "allow_downgrade": True,
    }


def test_podman_host_verifies_identity_before_socket(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/podman_host/tasks/main.yml")
    names = [task["name"] for task in tasks]
    by_name = {task["name"]: task for task in tasks}

    assert names.index("Require exact installed Podman package identity") < names.index(
        "Manage Podman socket"
    )
    assert names.index("Require one exact effective Podman versionlock") < names.index(
        "Manage Podman socket"
    )
    assert names.index("Validate dedicated Podman storage") < names.index(
        "Manage Podman socket"
    )
    assert names.index("Manage Podman socket") < names.index(
        "Verify enabled Podman API socket"
    )
    query = by_name["Query installed Podman package identity"]
    assert query["ansible.builtin.command"]["argv"] == [
        "rpm",
        "-q",
        "--qf",
        "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
        "{{ podman_host_package_name }}",
    ]
    lock_assertions = by_name[
        "Require one exact effective Podman versionlock"
    ]["ansible.builtin.assert"]["that"]
    assert "| list | length == 1" in lock_assertions[0]
    assert lock_assertions[1] == (
        "podman_host_package_nevra in podman_host_versionlock_list.stdout_lines"
    )


def test_podman_host_preserves_unrelated_versionlocks(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/podman_host/tasks/main.yml")
    by_name = {task["name"]: task for task in tasks}
    build = by_name["Build the exact Podman versionlock list"]
    converge = by_name["Converge the exact Podman versionlock atomically"]

    expression = build["ansible.builtin.set_fact"][
        "podman_host_versionlock_content"
    ]
    assert "reject('match', '^[ \\t]*!?podman(?:-|$)')" in expression
    assert "+ [podman_host_package_nevra]" in expression
    assert converge["ansible.builtin.copy"]["dest"] == (
        "{{ podman_host_versionlock_path }}"
    )
    assert converge["ansible.builtin.copy"]["mode"] == "0644"


def test_podman_host_rejects_unsafe_versionlock_paths(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/podman_host/tasks/main.yml")
    by_name = {task["name"]: task for task in tasks}
    readiness = by_name["Track Podman versionlock list readiness"]
    existing_requirement = by_name[
        "Reject an unsafe existing Podman versionlock path"
    ]
    requirement = by_name["Require a safe Podman versionlock list"]

    expression = readiness["ansible.builtin.set_fact"][
        "podman_host_versionlock_list_ready"
    ]
    assert "stat.exists" in expression
    assert "stat.isreg" in expression
    assert "not podman_host_versionlock_stat.stat.islnk" in expression
    existing_safety = existing_requirement["ansible.builtin.assert"]["that"][0]
    assert "not podman_host_versionlock_stat.stat.exists" in existing_safety
    assert "podman_host_versionlock_stat.stat.isreg" in existing_safety
    assert "not podman_host_versionlock_stat.stat.islnk" in existing_safety
    safety = requirement["ansible.builtin.assert"]["that"][0]
    assert "ansible_check_mode" in safety
    assert "not podman_host_versionlock_stat.stat.exists" in safety
    assert "podman_host_versionlock_list_ready | bool" in safety
    assert requirement["when"] == "podman_host_versionlock_ready | bool"


def test_podman_host_storage_contract_is_fail_closed(repo_root: Path) -> None:
    main = load_yaml(repo_root / "roles/podman_host/tasks/main.yml")
    tasks = load_yaml(repo_root / "roles/podman_host/tasks/storage.yml")
    validation = {
        task["name"]: task for task in main
    }["Validate Podman storage contract inputs"]["ansible.builtin.assert"]["that"]
    assert "'//' not in podman_host_storage_mountpoint" in validation
    assert "'/./' not in podman_host_storage_mountpoint" in validation
    assert "not podman_host_graphroot.endswith('/..')" in validation
    by_name = {task["name"]: task for task in tasks}

    mount = by_name["Require dedicated Podman XFS mount"]["ansible.builtin.assert"]
    assert any("fstype == 'xfs'" in item for item in mount["that"])
    assert any("'noexec' not in" in item for item in mount["that"])
    geometry = by_name["Require Podman XFS directory entry support"]
    assert "ftype=1" in geometry["ansible.builtin.assert"]["that"][0]
    effective = by_name["Require effective rootful Podman storage contract"]
    effective_checks = effective["ansible.builtin.assert"]["that"]
    assert any("graphRoot == podman_host_graphroot" in item for item in effective_checks)
    assert any("graphDriverName == 'overlay'" in item for item in effective_checks)
    assert any("Backing Filesystem" in item for item in effective_checks)
