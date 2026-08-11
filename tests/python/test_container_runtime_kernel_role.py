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

    assert defaults == {"container_runtime_overlayfs_policy_exception_enabled": True}
    assert metadata == {"dependencies": [{"role": "container_runtime_kernel"}]}


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


def test_rke2_integrates_after_kernel_transition_and_avoids_duplicate_overlay(
    repo_root: Path,
) -> None:
    tasks = load_yaml(repo_root / "roles/rke2/tasks/main.yml")
    task_names = [task["name"] for task in tasks]
    integration_index = task_names.index("Prepare the RKE2 container runtime kernel")
    persistence_index = task_names.index("Persist RKE2 kernel modules")
    integration = tasks[integration_index]
    persistence = tasks[persistence_index]["ansible.builtin.copy"]["content"]

    assert integration_index > task_names.index("Verify RKE2 kernel modules are available")
    assert integration_index < persistence_index
    assert integration["ansible.builtin.include_role"] == {
        "name": "container_runtime_kernel"
    }
    assert "rke2_direct_kernel_modules" in persistence


def test_bastion_uses_shared_podman_foundation(repo_root: Path) -> None:
    playbook = load_yaml(repo_root / "playbooks/k8s-bastion-access.yml")
    defaults = load_yaml(repo_root / "roles/k8s_bastion_access/defaults/main.yml")

    assert playbook[0]["roles"] == [
        "bastion_host",
        "podman_host",
        "k8s_bastion_access",
    ]
    assert "podman" not in defaults["k8s_bastion_os_packages"]
