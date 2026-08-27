from __future__ import annotations

from pathlib import Path

import yaml


def test_ssh_dropin_directory_preserves_rocky_package_mode(repo_root: Path) -> None:
    tasks = yaml.safe_load(
        (repo_root / "roles/ssh/tasks/main.yml").read_text(encoding="utf-8")
    )
    by_name = {task["name"]: task for task in tasks}

    directory = by_name["Ensure SSH configuration drop-in directory exists"][
        "ansible.builtin.file"
    ]
    assert directory == {
        "path": "/etc/ssh/sshd_config.d",
        "state": "directory",
        "owner": "root",
        "group": "root",
        "mode": "0700",
    }
