"""Exercise public staging's cross-play default scope without target I/O."""

import shutil

import pytest
import yaml


@pytest.mark.parametrize(
    ("declaration", "isolate_keepalived", "failure"),
    [
        pytest.param(
            {"firewalld_service_enabled": False, "firewalld_service_state": "stopped"},
            False,
            None,
            id="explicit-stopped",
        ),
        pytest.param({}, False, "OpenBao HAProxy requires explicit boolean", id="missing"),
        pytest.param(
            {"firewalld_enabled": False},
            False,
            "OpenBao HAProxy requires explicit boolean",
            id="legacy-only",
        ),
        pytest.param(
            {"firewalld_enabled": False},
            True,
            "Keepalived VIP requires strict lifecycle booleans",
            id="keepalived-legacy-only",
        ),
    ],
)
def test_staging_requires_firewall_declaration_before_later_role_defaults(
    repo_root, tmp_path, command_runner, declaration, isolate_keepalived, failure
):
    plays = yaml.safe_load((repo_root / "playbooks/openbao.yml").read_text())
    validation, staging = plays[1:3]
    assert staging["roles"] == [
        "firewalld", "podman_host", "openbao", "openbao_haproxy", "keepalived_vip"
    ]
    tasks = validation["tasks"]
    boundary = next(i for i, task in enumerate(tasks) if "ansible.builtin.stat" in task)
    assert [task["ansible.builtin.include_role"] for task in tasks[:boundary]
            if "ansible.builtin.include_role" in task] == [
        {"name": "openbao", "tasks_from": "validate.yml"},
        {"name": "openbao_haproxy", "tasks_from": "validate.yml"},
        {"name": "keepalived_vip", "tasks_from": "validate.yml"},
    ]
    # Retain the public plays and validation calls, stopping before the first read
    # of target state. Later static roles still load their real defaults.
    validation["tasks"] = tasks[:boundary] + [
        {"name": "Reached safe staging boundary", "ansible.builtin.meta": "end_play"}
    ]
    staging["post_tasks"] = [{"ansible.builtin.meta": "end_play"}]
    for play in plays:
        play["gather_facts"] = False
        play["become"] = False
        play["connection"] = "local"
        assert not play.get("pre_tasks")
        for task in play.get("tasks", []):
            assert set(task) <= {
                "name", "ansible.builtin.assert", "ansible.builtin.include_role",
                "ansible.builtin.meta", "run_once", "when",
            }

    roles = tmp_path / "roles"
    noop = [{"ansible.builtin.debug": {"msg": "Controller-only role double"}}]
    for role in staging["roles"]:
        target = roles / role
        (target / "tasks").mkdir(parents=True)
        (target / "tasks/main.yml").write_text(yaml.safe_dump(noop))
        if role in ("firewalld", "openbao_haproxy", "keepalived_vip"):
            (target / "defaults").mkdir()
            shutil.copyfile(
                repo_root / f"roles/{role}/defaults/main.yml",
                target / "defaults/main.yml",
            )
    (roles / "openbao/tasks/validate.yml").write_text(yaml.safe_dump([
        {"ansible.builtin.assert": {"that": ["firewalld_package is undefined"]}}
    ]))
    haproxy_validation = yaml.safe_load(
        (repo_root / "roles/openbao_haproxy/tasks/validate.yml").read_text()
    )
    lifecycle = [task for task in haproxy_validation if task["name"] ==
                 "Require explicit managed OpenBao HAProxy firewall lifecycle inputs"]
    assert len(lifecycle) == 1
    # Only this case doubles HAProxy's earlier rejection to reach Keepalived's
    # independent gate; neither production firewall-management flag is disabled.
    (roles / "openbao_haproxy/tasks/validate.yml").write_text(
        yaml.safe_dump(noop if isolate_keepalived else lifecycle)
    )
    keepalived_validation = yaml.safe_load(
        (repo_root / "roles/keepalived_vip/tasks/validate.yml").read_text()
    )
    assert keepalived_validation[0]["ansible.builtin.include_tasks"] == "validate_lifecycle.yml"
    (roles / "keepalived_vip/tasks/validate.yml").write_text(
        yaml.safe_dump(keepalived_validation[:1])
    )
    shutil.copyfile(
        repo_root / "roles/keepalived_vip/tasks/validate_lifecycle.yml",
        roles / "keepalived_vip/tasks/validate_lifecycle.yml",
    )
    (roles / "firewalld/tasks/main.yml").write_text(yaml.safe_dump([
        {"name": "Later static firewalld defaults are visible", "ansible.builtin.assert": {
            "that": ["firewalld_package == 'firewalld'"],
        }}
    ]))
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {
        "vars": {
            "ansible_connection": "local",
            "openbao_orchestration_ready": True,
            "openbao_enabled": True,
            "openbao_haproxy_enabled": True,
            "keepalived_vip_enabled": True,
            **declaration,
        },
        "children": {"openbao": {"hosts": {
            f"openbao-test-{number}": {} for number in range(1, 4)
        }}},
    }}))
    playbook = tmp_path / "openbao.yml"
    playbook.write_text(yaml.safe_dump(plays, sort_keys=False))
    result = command_runner.run(
        ["ansible-playbook", "-i", str(inventory), str(playbook)],
        cwd=tmp_path,
        environment={"ANSIBLE_ROLES_PATH": str(roles), "ANSIBLE_NOCOLOR": "1"},
        timeout=15,
    )
    output = result.stdout + result.stderr
    assert validation["name"] in output, result.diagnostics()
    if failure:
        result.assert_failure()
        assert failure in output, result.diagnostics()
        assert "Reached safe staging boundary" not in output, result.diagnostics()
        assert staging["name"] not in output, result.diagnostics()
    else:
        result.assert_success()
        assert lifecycle[0]["name"] in output, result.diagnostics()
        assert "Assert shared Keepalived VIP lifecycle is coherent" in output, result.diagnostics()
        assert "Reached safe staging boundary" in output, result.diagnostics()
        assert "Later static firewalld defaults are visible" in output, result.diagnostics()
