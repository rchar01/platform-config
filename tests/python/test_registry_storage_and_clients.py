from __future__ import annotations

import yaml
import pytest


@pytest.mark.parametrize("case", ["registry", "default", "unknown", "multiple", "rke2", "missing-rocky", "missing-container"])
def test_registry_mounted_verification_fixed_scope(repo_root, isolated_test_dir, command_runner, case):
    root = isolated_test_dir
    mount = root / "mount"
    mount.mkdir()
    groups = {group: {"hosts": {"registry-a": {}}}
              for group in ("registry", "rocky", "container_hosts", "storage_volume_hosts")}
    if case == "multiple":
        groups["registry"]["hosts"]["registry-b"] = {}
    elif case == "rke2":
        groups["rke2_cluster"] = {"hosts": {"registry-a": {}}}
    elif case == "missing-rocky":
        del groups["rocky"]
    elif case == "missing-container":
        del groups["container_hosts"]
    inventory = root / "hosts.yml"
    inventory.write_text(yaml.safe_dump({"all": {
        "vars": {"ansible_connection": "local", "ansible_become": False,
                 "storage_volumes": [{"vg_name": "absent", "lv_name": "absent", "mountpoint": str(mount)}]},
        "children": groups,
    }}))
    argv = ["ansible-playbook", "-i", inventory,
            repo_root / "playbooks/maintenance/storage-volumes-verify.yml", "--limit", "registry-a"]
    if case != "default":
        argv += ["--extra-vars", f"storage_verify_scope={'unknown' if case == 'unknown' else 'registry'}"]
    result = command_runner.run(argv)
    result.assert_failure()
    if case == "registry":
        # The accepted registry scope reaches the real read-only mount probe.
        assert "must be actively mounted after apply" in result.stdout, result.diagnostics()
    else:
        assert "TASK [Read storage defaults" not in result.stdout, result.diagnostics()
    assert "changed=0" in result.stdout
    assert list(mount.iterdir()) == []


def test_clients_playbook_runs_only_tools_then_trust(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    play = yaml.safe_load((repo_root / "playbooks/registry-clients.yml").read_text())
    play[0]["gather_facts"] = False
    roles = root / "roles"
    for name, before, after in (("registry_client_tools", "", "tools"), ("registry_ca_trust", "tools", "trust")):
        tasks = roles / name / "tasks"
        tasks.mkdir(parents=True)
        (tasks / "main.yml").write_text(yaml.safe_dump([
            {"ansible.builtin.assert": {"that": [f"observed | default('') == '{before}'",
                                                 "inventory_hostname in ['client-a', 'client-b']"]}},
            {"ansible.builtin.set_fact": {"observed": after}},
        ]))
    play[0]["post_tasks"] = [{"ansible.builtin.assert": {"that": "observed == 'trust'"}}]
    path = root / "clients.yml"
    path.write_text(yaml.safe_dump(play))
    inventory = root / "hosts.yml"
    inventory.write_text(yaml.safe_dump({"all": {
        "vars": {"ansible_connection": "local", "ansible_become": False},
        "children": {"registry": {"hosts": {"registry-a": {}}},
                     "registry_clients": {"hosts": {"client-a": {}, "client-b": {}}}},
    }}))
    result = command_runner.run(["ansible-playbook", "-i", inventory, path],
                                environment={"ANSIBLE_ROLES_PATH": str(roles)})
    result.assert_success()
    assert "registry-a" not in result.stdout
    assert "client-a" in result.stdout and "client-b" in result.stdout
