from __future__ import annotations

from pathlib import Path

import yaml


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text())


def task_named(tasks: list[dict], name: str) -> dict:
    return next(task for task in tasks if task.get("name") == name)


def test_registry_playbook_installs_ca_trust_on_hosts_and_clients(
    repo_root: Path,
) -> None:
    plays = load_yaml(repo_root / "playbooks/registry.yml")

    assert plays[0]["roles"][-1] == "registry_ca_trust"
    assert plays[1]["roles"][-1] == "registry_ca_trust"


def test_registry_ca_trust_pins_source_and_refreshes_on_change(
    repo_root: Path,
) -> None:
    tasks = load_yaml(repo_root / "roles/registry_ca_trust/tasks/main.yml")
    install = task_named(tasks, "Install reviewed registry CA trust anchor")
    refresh = task_named(tasks, "Refresh system CA trust")

    assert install["platform_pki_reviewed_ca"] == {
        "source": "{{ registry_ca_trust_source }}",
        "sha256": "{{ registry_ca_trust_sha256 }}",
        "dest": "{{ registry_ca_trust_target }}",
        "mode": "0644",
    }
    assert refresh["ansible.builtin.command"]["argv"] == [
        "update-ca-trust",
        "extract",
    ]
    assert refresh["changed_when"] == "registry_ca_trust_install is changed"
    assert "registry_ca_trust_install is changed" not in refresh["when"]
    assert "registry_ca_trust_source | length > 0" in refresh["when"]
    assert "not ansible_check_mode" in refresh["when"]
