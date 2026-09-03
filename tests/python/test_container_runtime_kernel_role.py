from __future__ import annotations

from pathlib import Path

import yaml


UNIT_PATH = "/etc/systemd/system/platform-container-runtime-overlayfs-exception.service"
UNIT_CONTENT = """[Unit]
Description=Platform container runtime OverlayFS policy exception
Documentation=man:modprobe(8)
DefaultDependencies=no
Conflicts=shutdown.target
Before=sysinit.target shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/modprobe --ignore-install overlay
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
"""


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_public_default_and_podman_dependency(repo_root: Path) -> None:
    defaults = load_yaml(
        repo_root / "roles/container_runtime_kernel/defaults/main.yml"
    )
    metadata = load_yaml(repo_root / "roles/podman_host/meta/main.yml")

    assert defaults == {
        "container_runtime_kernel_packages": ["kmod"],
        "container_runtime_overlayfs_policy_exception_enabled": True,
    }
    assert metadata == {
        "dependencies": [
            {"role": "podman_registry_remaps"},
            {"role": "rocky_repository_policy"},
            {"role": "container_runtime_kernel"},
        ]
    }


def test_kernel_packages_are_installed_before_module_probes(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/container_runtime_kernel/tasks/main.yml")
    task_names = [task["name"] for task in tasks]
    package_task = tasks[0]

    assert package_task["name"] == "Install container runtime kernel packages"
    assert package_task["ansible.builtin.package"] == {
        "name": "{{ container_runtime_kernel_packages }}",
        "state": "present",
    }
    assert task_names.index("Install container runtime kernel packages") < task_names.index(
        "Inspect OverlayFS module availability"
    )


def test_fresh_check_mode_defers_unavailable_kernel_commands(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/container_runtime_kernel/tasks/main.yml")
    task_by_name = {task["name"]: task for task in tasks}

    command_check = task_by_name["Inspect container runtime kernel commands"]
    command_requirement = task_by_name[
        "Require container runtime kernel commands after package convergence"
    ]
    modinfo_probe = task_by_name["Probe modinfo command"]
    modprobe_probe = task_by_name["Probe modprobe command"]
    overlay_requirement = task_by_name[
        "Require OverlayFS support from the running kernel"
    ]

    assert command_check["loop"] == ["/usr/sbin/modinfo", "/usr/sbin/modprobe"]
    assert command_check["ansible.builtin.stat"]["follow"] is True
    assert modinfo_probe["ansible.builtin.command"]["argv"] == [
        "/usr/sbin/modinfo",
        "--version",
    ]
    assert modinfo_probe["failed_when"] is False
    assert modprobe_probe["ansible.builtin.command"]["argv"] == [
        "/usr/sbin/modprobe",
        "--version",
    ]
    assert modprobe_probe["failed_when"] is False
    assert command_requirement["when"] == "not ansible_check_mode"
    assert command_requirement["ansible.builtin.assert"]["that"] == [
        "container_runtime_kernel_command_stats.results[0].stat.isreg | default(false)",
        "container_runtime_kernel_command_stats.results[0].stat.executable | default(false)",
        "container_runtime_kernel_command_stats.results[1].stat.isreg | default(false)",
        "container_runtime_kernel_command_stats.results[1].stat.executable | default(false)",
        "container_runtime_kernel_modinfo_version.rc | default(1) == 0",
        "container_runtime_kernel_modprobe_version.rc | default(1) == 0",
    ]
    assert overlay_requirement["when"] == [
        "not ansible_check_mode or container_runtime_kernel_command_stats.results[0].stat.exists or (container_runtime_kernel_overlayfs_module.stat.isdir | default(false))"
    ]


def test_enabled_unit_is_narrow_and_auditable(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/container_runtime_kernel/tasks/enabled.yml")
    unit_task = tasks[0]["ansible.builtin.copy"]

    assert unit_task["dest"] == UNIT_PATH
    assert unit_task["owner"] == "root"
    assert unit_task["group"] == "root"
    assert unit_task["mode"] == "0644"
    assert unit_task["content"] == UNIT_CONTENT

    task_names = [task["name"] for task in tasks]
    service_task = tasks[task_names.index("Enable and start the OverlayFS policy exception")]
    assert service_task["when"] == "not ansible_check_mode"
    assert "Inspect OverlayFS exception enabled state in check mode" in task_names
    assert "Inspect OverlayFS exception active state in check mode" in task_names


def test_role_does_not_manage_modprobe_policy_or_unload_overlay(repo_root: Path) -> None:
    role_root = repo_root / "roles/container_runtime_kernel"
    role_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(role_root.rglob("*.yml"))
    )
    disabled_tasks = load_yaml(role_root / "tasks/disabled.yml")
    task_names = [task["name"] for task in disabled_tasks]

    assert "/etc/modprobe.d" not in role_text
    assert "modprobe -r" not in role_text
    assert "rmmod" not in role_text
    assert task_names.index("Load OverlayFS through normal module policy") < task_names.index(
        "Stop and disable the managed OverlayFS exception"
    )


def test_disabled_check_mode_predicts_unit_removal_without_reloading_systemd(
    repo_root: Path,
) -> None:
    role_root = repo_root / "roles/container_runtime_kernel"
    tasks = load_yaml(role_root / "tasks/disabled.yml")
    handlers = load_yaml(role_root / "handlers/main.yml")
    remove_task = next(
        task
        for task in tasks
        if task["name"] == "Remove the managed OverlayFS exception unit"
    )

    assert remove_task["when"] == (
        "container_runtime_kernel_overlayfs_unit.stat.exists | default(false)"
    )
    assert handlers[0]["when"] == "not ansible_check_mode"


def test_disabled_fresh_check_mode_defers_absent_modprobe(repo_root: Path) -> None:
    tasks = load_yaml(repo_root / "roles/container_runtime_kernel/tasks/disabled.yml")
    task_by_name = {task["name"]: task for task in tasks}
    command_present = (
        "container_runtime_kernel_command_stats.results[1].stat.exists"
    )

    assert task_by_name["Inspect normal modprobe policy"]["when"] == command_present
    assert task_by_name["Reject normal policy that restricts OverlayFS"]["when"] == [
        command_present
    ]


def test_rke2_integrates_after_kernel_transition_and_avoids_duplicate_overlay(
    repo_root: Path,
) -> None:
    tasks = load_yaml(repo_root / "roles/rke2/tasks/main.yml")
    task_names = [task["name"] for task in tasks]
    integration_index = task_names.index("Prepare the RKE2 container runtime kernel")
    persistence_index = task_names.index("Persist RKE2 kernel modules")
    module_load_index = task_names.index("Load RKE2 kernel modules")
    integration = tasks[integration_index]
    persistence = tasks[persistence_index]["ansible.builtin.copy"]["content"]
    module_load = tasks[module_load_index]

    assert integration_index > task_names.index("Verify RKE2 kernel modules are available")
    assert integration_index < persistence_index
    assert persistence_index < module_load_index
    assert integration["ansible.builtin.include_role"] == {
        "name": "container_runtime_kernel"
    }
    assert "rke2_direct_kernel_modules" in persistence
    assert module_load["ansible.builtin.command"]["argv"] == [
        "/usr/sbin/modprobe",
        "{{ item }}",
    ]
    assert module_load["changed_when"] is False
    assert module_load["loop"] == "{{ rke2_direct_kernel_modules }}"
    assert module_load["when"] == "not ansible_check_mode"


def test_bastion_uses_shared_podman_foundation(repo_root: Path) -> None:
    playbook = load_yaml(repo_root / "playbooks/k8s-bastion-access.yml")
    defaults = load_yaml(repo_root / "roles/k8s_bastion_access/defaults/main.yml")

    assert playbook[0]["roles"] == [
        "bastion_host",
        "podman_host",
        "k8s_bastion_access",
    ]
    assert "podman" not in defaults["k8s_bastion_os_packages"]


def test_bastion_podman_maintenance_playbook_is_focused(repo_root: Path) -> None:
    playbook = load_yaml(repo_root / "playbooks/k8s-bastion-podman.yml")

    assert len(playbook) == 1
    assert set(playbook[0]) == {"name", "hosts", "become", "pre_tasks", "roles"}
    assert playbook[0]["hosts"] == "k8s_bastion"
    assert playbook[0]["become"] is True
    assert playbook[0]["pre_tasks"] == [
        {
            "name": "Require one explicitly limited bastion",
            "ansible.builtin.assert": {
                "that": [
                    "ansible_limit | default('') == inventory_hostname",
                    "ansible_play_hosts_all | length == 1",
                ],
                "fail_msg": (
                    "Set LIMIT to one exact k8s_bastion inventory hostname before "
                    "converging Podman."
                ),
            },
        }
    ]
    assert playbook[0]["roles"] == ["podman_host"]
