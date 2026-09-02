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
    defaults = load_yaml(repo_root / "roles/registry_ca_trust/defaults/main.yml")
    tasks = load_yaml(repo_root / "roles/registry_ca_trust/tasks/main.yml")
    install = task_named(tasks, "Install reviewed registry CA trust anchor")
    pending = task_named(tasks, "Check for a pending registry CA trust refresh")
    record = task_named(tasks, "Record a pending registry CA trust refresh")
    required = task_named(tasks, "Determine whether registry CA trust requires refresh")
    refresh = task_named(tasks, "Refresh system CA trust")
    clear = task_named(tasks, "Clear the pending registry CA trust refresh")

    assert defaults["registry_ca_trust_source"] == ""
    assert defaults["registry_ca_trust_sha256"] == ""
    assert defaults["registry_ca_trust_defer_marker_clear"] is False
    assert install["platform_pki_reviewed_ca"] == {
        "source": "{{ registry_ca_trust_source }}",
        "sha256": "{{ registry_ca_trust_sha256 }}",
        "dest": "{{ registry_ca_trust_target }}",
        "mode": "0644",
    }
    marker = "{{ registry_ca_trust_refresh_marker }}"
    assert pending["ansible.builtin.stat"]["path"] == marker
    assert record["ansible.builtin.file"]["path"] == marker
    assert record["changed_when"] is False
    assert tasks.index(record) < tasks.index(install)
    expression = required["ansible.builtin.set_fact"][
        "registry_ca_trust_refresh_required"
    ]
    assert "registry_ca_trust_install is changed" in expression
    assert "registry_ca_trust_refresh_pending.stat.exists" in expression
    assert refresh["ansible.builtin.command"]["argv"] == [
        "update-ca-trust",
        "extract",
    ]
    assert refresh["changed_when"] is True
    assert "registry_ca_trust_source | length > 0" in refresh["when"]
    assert "registry_ca_trust_refresh_required | bool" in refresh["when"]
    assert "not ansible_check_mode" in refresh["when"]
    assert clear["ansible.builtin.file"] == {"path": marker, "state": "absent"}
    assert clear["changed_when"] is False
    assert "not registry_ca_trust_defer_marker_clear | bool" in clear["when"]
    assert "registry_ca_trust_refresh_required | bool" not in clear["when"]
    assert tasks.index(record) < tasks.index(refresh) < tasks.index(clear)


def test_registry_ca_trust_defaults_to_preinstalled_trust_noop(
    repo_root: Path,
) -> None:
    defaults = load_yaml(repo_root / "roles/registry_ca_trust/defaults/main.yml")
    tasks = load_yaml(repo_root / "roles/registry_ca_trust/tasks/main.yml")

    assert defaults["registry_ca_trust_source"] == ""
    assert defaults["registry_ca_trust_sha256"] == ""
    for task in tasks:
        if task["name"] == "Validate registry CA trust inputs":
            continue
        conditions = task["when"]
        if isinstance(conditions, str):
            conditions = [conditions]
        assert "registry_ca_trust_source | length > 0" in conditions
