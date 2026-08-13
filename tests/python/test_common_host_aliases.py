from __future__ import annotations

from pathlib import Path

import yaml


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_common_preserves_aliases_across_cloud_init_rewrites(repo_root: Path) -> None:
    defaults = load_yaml(repo_root / "roles/common/defaults/main.yml")
    tasks = load_yaml(repo_root / "roles/common/tasks/main.yml")
    by_name = {task["name"]: task for task in tasks}

    assert defaults["platform_host_aliases_cloud_init_template"] == (
        "/etc/cloud/templates/hosts.redhat.tmpl"
    )
    directory_requirement = by_name[
        "Require a trusted cloud-init hosts template directory"
    ]
    directory_safety = directory_requirement["ansible.builtin.assert"]["that"]
    assert "platform_host_aliases_cloud_init_template_dir_stat.stat.isdir" in (
        directory_safety
    )
    assert (
        "not platform_host_aliases_cloud_init_template_dir_stat.stat.islnk"
        in directory_safety
    )
    assert "is not search('[2367]')" in directory_safety[-1]
    requirement = by_name["Require a safe cloud-init hosts template"]
    safety = requirement["ansible.builtin.assert"]["that"]
    assert "platform_host_aliases_cloud_init_template_stat.stat.isreg" in safety
    assert "not platform_host_aliases_cloud_init_template_stat.stat.islnk" in safety

    cloud = by_name["Manage platform host aliases in cloud-init template"]
    live = by_name["Manage platform host aliases"]
    assert cloud["ansible.builtin.blockinfile"]["marker"] == (
        live["ansible.builtin.blockinfile"]["marker"]
    )
    assert cloud["ansible.builtin.blockinfile"]["block"] == (
        live["ansible.builtin.blockinfile"]["block"]
    )
    assert "if platform_host_aliases | length > 0 else 'absent'" in (
        cloud["ansible.builtin.blockinfile"]["state"]
    )
