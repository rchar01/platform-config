from __future__ import annotations

import yaml


def test_registry_storage_binding_matrix(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    plays = root / "playbooks"
    plays.mkdir()
    (root / "roles").symlink_to(repo_root / "roles", target_is_directory=True)
    data = "/var/lib/zot/data"
    volume = {"mountpoint": "/var/lib/zot"}
    cases = [
        dict(name="parent", valid=True, volumes=[volume]),
        dict(name="exact", valid=True, volumes=[{"mountpoint": data}]),
        dict(name="inventory-data-override", valid=True, data="/srv/registry/blobs",
             volumes=[{"mountpoint": "/srv/registry"}]),
        dict(name="separate-runtime-volume", valid=True, volumes=[volume, {"mountpoint": "/srv/containers"}]),
        dict(name="explicit-mounted-overrides-default", valid=True, default_state="unmounted",
             volumes=[dict(volume, state="mounted")]),
        dict(name="unrelated", volumes=[{"mountpoint": "/srv/data"}]),
        dict(name="component-prefix-is-not-parent", volumes=[{"mountpoint": "/var/lib/zo"}]),
        dict(name="child-only", volumes=[{"mountpoint": data + "/blobs"}]),
        dict(name="overlapping-parents", volumes=[volume, {"mountpoint": "/var/lib"}]),
        dict(name="overlapping-child", volumes=[volume, {"mountpoint": data + "/blobs"}]),
        dict(name="duplicate", volumes=[volume, volume]),
        dict(name="unmounted-default", default_state="unmounted", volumes=[volume]),
        dict(name="explicit-unmounted", volumes=[dict(volume, state="unmounted")]),
        dict(name="invalid-state-type", volumes=[dict(volume, state=True)]),
        dict(name="no-volumes", volumes=[]),
        dict(name="mapping-is-not-list", volumes=volume),
        dict(name="invalid-volume", volumes=[None]),
        dict(name="missing-mountpoint", volumes=[{}]),
        *[dict(name=f"invalid-mount-{i}", volumes=[{"mountpoint": path}]) for i, path in enumerate(
            ["/", "relative", "/var//lib/zot", "/var/./lib/zot", "/var/lib/../zot", "/var/lib/zot/", "/var/lib/zot\n", 3])],
        *[dict(name=f"invalid-data-{i}", data=path, volumes=[volume]) for i, path in enumerate(
            ["/", "/var/lib/zot/../data", "/var/lib/zot/data/", [data]])],
    ]
    # One Ansible invocation executes the production data-only validator for all
    # cases, including inventory precedence. No filesystem or lifecycle doubles.
    case_tasks = plays / "case.yml"
    case_tasks.write_text(yaml.safe_dump([
        {"ansible.builtin.set_fact": {"binding_accepted": False}},
        {"block": [
            {"ansible.builtin.include_tasks": "../roles/pki_host_local_certificate/tasks/registry_storage.yml"},
            {"ansible.builtin.set_fact": {"binding_accepted": True}},
        ], "rescue": [{"ansible.builtin.debug": {"msg": "Rejected {{ binding_case.name }}"}}]},
        {"ansible.builtin.assert": {"that": ["binding_accepted == binding_case.valid | default(false)"],
                                    "fail_msg": "Unexpected binding decision for {{ binding_case.name }}"}},
    ], sort_keys=False))
    play = plays / "matrix.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "tasks": [{"ansible.builtin.include_tasks": "case.yml", "loop": cases,
                   "loop_control": {"loop_var": "binding_case", "label": "{{ binding_case.name }}"},
                   "vars": {"zot_registry_data_dir": "{{ binding_case.data | default('" + data + "') }}",
                            "storage_volumes": "{{ binding_case.volumes }}",
                            "storage_volume_default_mount_state": "{{ binding_case.default_state | default('mounted') }}"}}],
    }], sort_keys=False))
    result = command_runner.run(["ansible-playbook", "-i", "localhost,", play], timeout=60)
    result.assert_success()
    assert "changed=0" in result.stdout
    assert all(case["name"] in result.stdout for case in cases)
