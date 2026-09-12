from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import socket
from pathlib import Path

import pytest
import yaml


ALIASES = [{"address": "192.0.2.61", "names": ["registry.example.test", "registry-01"]}]
OUTSIDE = b"# untouched\n127.0.0.1 unrelated\n192.0.2.61 registry.example.test # same IP\n"


@pytest.fixture
def guard(repo_root):
    path = repo_root / "roles/common/library/platform_host_aliases_guard.py"
    spec = importlib.util.spec_from_file_location("alias_guard", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_common_alias_extraction_is_byte_identical_and_in_place(repo_root):
    extracted = (repo_root / "roles/common/tasks/host_aliases.yml").read_bytes()
    # SHA-256 of the original main.yml lines 16-94, including their final LF.
    assert hashlib.sha256(extracted.removeprefix(b"---\n")).hexdigest() == (
        "121bc68ce63de6a9a4b06d6aed77bc665f9c7e39ee27561b1b26540d0e8f6a4d"
    )
    tasks = yaml.safe_load((repo_root / "roles/common/tasks/main.yml").read_text())
    assert tasks[1]["name"] == "Ensure common platform directories exist"
    assert tasks[2]["ansible.builtin.import_tasks"] == "host_aliases.yml"
    assert tasks[3]["name"] == "Enable logrotate compression"


@pytest.mark.parametrize("aliases", [
    None, False, {}, [], "192.0.2.1 name", [None],
    [{"address": "192.0.2.1", "names": ["name"], "extra": True}],
    [{"address": "192.0.2.1"}],
    [{"address": 123, "names": ["name"]}],
    [{"address": "192.0.2.999", "names": ["name"]}],
    [{"address": "192.0.2.1/24", "names": ["name"]}],
    [{"address": "fe80::1%eth0", "names": ["name"]}],
    [{"address": "192.0.2.1", "names": "name"}],
    [{"address": "192.0.2.1", "names": []}],
    *[[{"address": "192.0.2.1", "names": [name]}] for name in (
        None, 3, "", "foo bar", "bad\nname", "bad#name", "-name", "name-",
        "name.", "a..b", "under_score", "éxample", "a" * 64, "192.0.2.1",
    )],
    [{"address": "192.0.2.1", "names": ["name", "NAME"]}],
    [{"address": "192.0.2.1", "names": ["name"]}, {"address": "192.0.2.2", "names": ["name"]}],
])
def test_guard_rejects_invalid_declarations(guard, aliases):
    with pytest.raises(ValueError):
        guard.declarations(aliases)


def test_guard_accepts_ipv6_and_multiple_names(guard):
    desired = guard.declarations([{"address": "2001:db8::1", "names": ["Service.example", "svc-01"]}])
    assert set(desired) == {"service.example", "svc-01"}
    assert str(desired["svc-01"]) == "2001:db8::1"


@pytest.mark.parametrize("data", [
    b"# BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\n",
    b"# END ANSIBLE MANAGED PLATFORM HOST ALIASES\n",
    b" # BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\n",
    b"# BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\r\n",
    b"# BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\n" * 2,
    (b"# BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\n"
     b"# END ANSIBLE MANAGED PLATFORM HOST ALIASES\n") * 2,
])
def test_guard_rejects_malformed_markers(guard, data):
    with pytest.raises(ValueError, match="marker"):
        guard.outside_block(data)


def test_guard_preserves_unmanaged_bytes_and_ignores_old_managed_addresses(guard):
    data = OUTSIDE + b"# BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\n192.0.2.99 registry.example.test\n"
    data += b"# END ANSIBLE MANAGED PLATFORM HOST ALIASES\n# suffix\xff\n"
    assert guard.outside_block(data) == OUTSIDE + b"# suffix\xff\n"


@pytest.mark.parametrize("mode,uid,gid,directory", [
    (0o100666, 0, 0, False), (0o100644, 1, 0, False), (0o100644, 0, 1, False),
    (0o120777, 0, 0, False), (0o040755, 0, 0, False), (0o010644, 0, 0, False),
    (0o104644, 0, 0, False), (0o040775, 0, 0, True), (0o120755, 0, 0, True),
])
def test_guard_rejects_unsafe_metadata(guard, mode, uid, gid, directory):
    from types import SimpleNamespace

    with pytest.raises(ValueError, match="root-owned"):
        guard.trusted(SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid), directory)


@pytest.mark.parametrize("observed", [["192.0.2.61"], ["192.0.2.62"], ["192.0.2.61", "192.0.2.62"], []])
def test_resolution_requires_exact_address_for_every_alias(guard, monkeypatch, observed):
    calls = []

    def resolve(name, *args):
        calls.append(name)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in observed]

    monkeypatch.setattr(guard.socket, "getaddrinfo", resolve)
    if observed == ["192.0.2.61"]:
        guard.check_resolution(guard.declarations(ALIASES))
        assert calls == ["registry.example.test", "registry-01"]
    else:
        with pytest.raises(ValueError, match="NSS resolution"):
            guard.check_resolution(guard.declarations(ALIASES))


@pytest.fixture
def sandbox(repo_root, isolated_test_dir, command_runner):
    """Real playbooks/role/modules; relocate only fixed target paths in a role copy."""
    root = isolated_test_dir
    roles = root / "roles"
    common = roles / "common"
    shutil.copytree(repo_root / "roles/common", common)
    tasks = common / "tasks/host_aliases.yml"
    tasks.write_text(tasks.read_text().replace("path: /etc/hosts", 'path: "{{ fixture_etc }}/hosts"'))
    module = common / "library/platform_host_aliases_guard.py"
    module.write_text(module.read_text().replace('ETC = "/etc"', 'ETC = os.environ["ALIAS_TEST_ETC"]')
                      .replace('HOSTS = "/etc/hosts"', 'HOSTS = ETC + "/hosts"'))
    # Exercise common defaults through real import_role; no cloud path override is
    # added to production. The original selector is the sole template input.
    hosts = {}
    for index in range(9):
        name = f"node-{index}"
        etc = root / name
        etc.mkdir(mode=0o755)
        (etc / "hosts").write_bytes(OUTSIDE)
        (etc / "hosts").chmod(0o644)
        hosts[name] = {"ansible_connection": "local", "ansible_become": False,
                       "fixture_etc": str(etc), "platform_host_aliases": ALIASES,
                       "platform_host_aliases_cloud_init_template": ""}
    inv = root / "inventory.yml"

    def run(check=False, verify=False, limit=None, launcher=False):
        inv.write_text(yaml.safe_dump({"all": {"children": {"rke2_cluster": {"children": {
            "rke2_servers": {"hosts": {name: values for name, values in hosts.items() if int(name[-1]) < 3}},
            "rke2_agents": {"hosts": {name: values for name, values in hosts.items() if int(name[-1]) >= 3}},
        }}}}}))
        source = "rke2-host-aliases-verify.yml" if verify else "rke2-host-aliases.yml"
        for filename in ("rke2-host-aliases.yml", "rke2-host-aliases-verify.yml"):
            play = yaml.safe_load((repo_root / "playbooks" / filename).read_text())
            play[0]["environment"] = {"ALIAS_TEST_ETC": "{{ fixture_etc }}"}
            for task in play[0]["pre_tasks"]:
                if "ansible.builtin.import_tasks" in task:
                    task["ansible.builtin.import_tasks"] = str(repo_root / "playbooks" / task["ansible.builtin.import_tasks"])
            (root / filename).write_text(yaml.safe_dump(play, sort_keys=False))
        if launcher:
            variables = root / "vars.json"
            variables.write_text("{}")
            variables.chmod(0o600)
            binary = root / "bin"
            binary.mkdir()
            wrapper = binary / "ansible-playbook"
            real = shutil.which("ansible-playbook")
            assert real
            wrapper.write_text(
                "#!/usr/bin/env python3\nimport os, sys\n"
                f"paths = {{{str(repo_root / 'playbooks/rke2-host-aliases.yml')!r}: {str(root / 'rke2-host-aliases.yml')!r}, "
                f"{str(repo_root / 'playbooks/rke2-host-aliases-verify.yml')!r}: {str(root / 'rke2-host-aliases-verify.yml')!r}}}\n"
                f"os.execv({real!r}, [{real!r}, *[paths.get(arg, arg) for arg in sys.argv[1:]]])\n"
            )
            wrapper.chmod(0o755)
            return command_runner.run([
                repo_root / "scripts/platform-config-operation", "rke2-host-aliases-apply",
                "--inventory", inv, "--controller-vars", variables,
            ], environment={"ANSIBLE_ROLES_PATH": str(roles), "PATH": f"{binary}:{os.environ['PATH']}"}, timeout=120)
        return command_runner.run([
            "ansible-playbook", "-i", inv, root / source,
            *(["--check", "--diff"] if check else []), *(["--limit", limit] if limit else []),
        ], environment={"ANSIBLE_ROLES_PATH": str(roles)}, timeout=120)

    return root, hosts, run


def test_real_nine_node_check_insert_idempotence_and_preservation(sandbox):
    root, hosts, run = sandbox
    before = {name: ((root / name / "hosts").read_bytes(), (root / name / "hosts").stat().st_mtime_ns) for name in hosts}
    planned = run(check=True).assert_success()
    assert planned.stdout.count("changed=1") == 9, planned.diagnostics()
    assert {name: ((root / name / "hosts").read_bytes(), (root / name / "hosts").stat().st_mtime_ns) for name in hosts} == before
    applied = run().assert_success()
    assert applied.stdout.count("changed=1") == 9, applied.diagnostics()
    for name in hosts:
        content = (root / name / "hosts").read_bytes()
        assert content.startswith(OUTSIDE)
        assert b"192.0.2.61 registry.example.test registry-01\n" in content
    again = run().assert_success()
    assert again.stdout.count("changed=0") == 9, again.diagnostics()
    final = run(check=True).assert_success()
    assert final.stdout.count("changed=0") == 9, final.diagnostics()


@pytest.mark.parametrize("fault", ["conflict", "schema", "default", "markers", "symlink", "writable", "missing", "cloud"])
def test_real_last_node_guard_failure_prevents_every_host_write(sandbox, fault):
    root, hosts, run = sandbox
    path = root / "node-8/hosts"
    if fault == "conflict":
        path.write_bytes(OUTSIDE + b"192.0.2.99 REGISTRY-01 # collision\n")
    elif fault == "schema":
        hosts["node-8"]["platform_host_aliases"] = [{"address": "bad", "names": ["registry-01"]}]
    elif fault == "default":
        del hosts["node-8"]["platform_host_aliases"]
    elif fault == "markers":
        path.write_bytes(OUTSIDE + b"# BEGIN ANSIBLE MANAGED PLATFORM HOST ALIASES\n")
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(root / "node-0/hosts")
    elif fault == "writable":
        path.chmod(0o666)
    elif fault == "missing":
        path.unlink()
    else:
        for name, values in hosts.items():
            template = root / name / "template"
            template.write_text("original\n")
            template.chmod(0o666 if name == "node-8" else 0o644)
            values["platform_host_aliases_cloud_init_template"] = str(template)
    before = {file: file.read_bytes() for file in root.glob("node-*/*") if file.is_file()}
    result = run().assert_failure()
    if fault == "default":
        assert "Host aliases must be a nonempty list" in result.stdout  # imported common default
    assert "Manage platform host aliases]" not in result.stdout
    assert {file: file.read_bytes() for file in before} == before
    assert "changed=1" not in result.stdout


def test_real_partial_scope_fails_before_guard_or_writes(sandbox):
    root, _, run = sandbox
    result = run(limit="node-0").assert_failure()
    assert "complete nonempty rke2_cluster" in result.stdout
    assert (root / "node-0/hosts").read_bytes() == OUTSIDE


def test_real_wrong_nss_after_apply_leaves_aliases_and_check_skips_resolution(sandbox):
    root, hosts, run = sandbox
    for values in hosts.values():
        values["platform_host_aliases"] = [{"address": "192.0.2.61", "names": ["localhost"]}]
    run().assert_success()
    run(check=True).assert_success()
    skipped = run(check=True, verify=True).assert_success()
    assert skipped.stdout.count("skipped=1") == 9
    result = run(verify=True).assert_failure()
    assert "NSS resolution does not match" in result.stdout
    assert "changed=1" not in result.stdout
    assert all(b"192.0.2.61 localhost\n" in (root / name / "hosts").read_bytes() for name in hosts)


def test_real_launcher_callbacks_report_post_apply_resolution_failure(sandbox):
    root, hosts, run = sandbox
    for values in hosts.values():
        values["platform_host_aliases"] = [{"address": "192.0.2.61", "names": ["localhost"]}]
    result = run(launcher=True).assert_failure()
    assert "Overall: FAIL" in result.stdout
    assert "NSS resolution does not match" in result.stdout
    rows = [line.split() for line in result.stdout.splitlines() if line.startswith("node-")]
    for phase in ("host-aliases-check", "host-aliases-apply", "host-aliases-post-check", "host-aliases-verify"):
        selected = [row for row in rows if len(row) == 8 and row[2] == phase]
        assert len(selected) == 9, result.diagnostics()
        assert all(row[3] == ("FAIL" if phase == "host-aliases-verify" else "PASS") for row in selected)
        assert all(row[4] == ("1" if phase in ("host-aliases-check", "host-aliases-apply") else "0") for row in selected)
    assert all(b"192.0.2.61 localhost\n" in (root / name / "hosts").read_bytes() for name in hosts)


def test_real_cloud_template_existing_guard_and_idempotence(sandbox):
    root, hosts, run = sandbox
    for name, values in hosts.items():
        template = root / name / "hosts.redhat.tmpl"
        template.write_bytes(b"# cloud-init template\n")
        template.chmod(0o644)
        values["platform_host_aliases_cloud_init_template"] = str(template)
    result = run(check=True).assert_success()
    assert result.stdout.count("changed=2") == 9
    assert all((root / name / "hosts.redhat.tmpl").read_bytes() == b"# cloud-init template\n" for name in hosts)
    run().assert_success()
    assert all((root / name / "hosts.redhat.tmpl").read_bytes().startswith(b"# cloud-init template\n# BEGIN ") for name in hosts)
    assert run().assert_success().stdout.count("changed=0") == 9
