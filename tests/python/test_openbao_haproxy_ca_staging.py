from __future__ import annotations

import os
import sys

import pytest
import yaml

from ansible_test_helpers import assert_failed_with


@pytest.fixture
def staging(repo_root, tmp_path, command_runner):
    role = repo_root / "roles/openbao_haproxy"
    source = tmp_path / "source.crt"
    destination = tmp_path / "haproxy/openbao-ca.crt"
    command_runner.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=offline-ca.example.invalid", "-keyout", str(tmp_path / "key.pem"),
        "-out", str(source),
    ]).assert_success()
    tasks = yaml.safe_load((role / "tasks/main.yml").read_text())[0]["block"]
    names = [
        "Check OpenBao HAProxy source backend CA",
        "Assert OpenBao HAProxy source backend CA exists",
        "Ensure OpenBao HAProxy configuration directory exists",
        "Install a dedicated public backend CA for OpenBao HAProxy",
        "Write validated OpenBao HAProxy configuration",
    ]
    tasks = [task for task in tasks if task["name"] in names]
    assert [task["name"] for task in tasks] == names
    assert tasks[0]["ansible.builtin.stat"]["follow"] is False
    assert tasks[0]["check_mode"] is False
    copy = tasks[3]["ansible.builtin.copy"]
    assert copy["src"] == "{{ openbao_haproxy_backend_ca_src }}"
    assert copy["dest"] == "{{ openbao_haproxy_backend_ca_path }}"
    assert copy["remote_src"] is True and copy["mode"] == "0644"
    assert copy["validate"] == "/usr/bin/openssl x509 -in %s -noout"
    assert tasks[3]["when"] == [
        "openbao_haproxy_backend_ca_stat.stat.exists",
        "not ansible_check_mode or openbao_haproxy_config_directory_result is not changed",
    ]
    for task, module in zip(tasks[2:], ("file", "copy", "template")):
        args = task[f"ansible.builtin.{module}"]
        assert args["owner"] == args["group"] == "root"
        if module != "template":
            assert all(args[key] == "_default" for key in ("seuser", "serole", "setype", "selevel"))
        # Only fixture ownership changes; the real built-in modules still run.
        args.update(owner=str(os.geteuid()), group=str(os.getegid()))
    tasks[4]["ansible.builtin.template"]["src"] = str(role / "templates/haproxy.cfg.j2")
    variables = yaml.safe_load((role / "defaults/main.yml").read_text()) | {
        "ansible_python_interpreter": sys.executable,
        "openbao_haproxy_backend_ca_src": str(source),
        "openbao_haproxy_backend_ca_path": str(destination),
        "openbao_haproxy_config_path": str(destination.parent / "haproxy.cfg"),
        "openbao_haproxy_binary_ready": False,
        "openbao_haproxy_backend_health_host": "bao.example.invalid",
        "openbao_cluster_members": [
            {"name": "bao-1", "address": "192.0.2.1", "dns": "bao-1.example.invalid"},
        ],
    }

    def run(*, check=False, **overrides):
        play = [{
            "hosts": "localhost", "gather_facts": False, "vars": variables | overrides,
            "tasks": tasks,
            "handlers": [{"name": "Reload OpenBao HAProxy", "ansible.builtin.debug": {"msg": "offline only"}}],
        }]
        path = tmp_path / "staging.yml"
        path.write_text(yaml.safe_dump(play), encoding="utf-8")
        return command_runner.run([
            "ansible-playbook", "-i", "localhost,", "-c", "local", str(path),
            *(["--check"] if check else []),
        ], timeout=15)

    return source, destination, run


def test_ca_copy_bytes_permissions_and_idempotence(staging):
    source, destination, run = staging
    run().assert_success()
    assert source != destination and destination.read_bytes() == source.read_bytes()
    assert not destination.is_symlink()
    for path, mode in ((destination, 0o644), (destination.parent, 0o755)):
        metadata = path.stat()
        assert metadata.st_mode & 0o7777 == mode
        assert (metadata.st_uid, metadata.st_gid) == (os.geteuid(), os.getegid())
    config = destination.with_name("haproxy.cfg").read_text()
    assert f"ca-file {destination} " in config and f"ca-file {source} " not in config
    before = destination.stat().st_mtime_ns
    result = run().assert_success()
    assert "changed=0" in result.stdout
    assert destination.stat().st_mtime_ns == before


def test_invalid_certificate_preserves_cached_ca(staging):
    source, destination, run = staging
    run().assert_success()
    before = destination.read_bytes(), destination.with_name("haproxy.cfg").read_bytes()
    source.write_text("not a certificate\n", encoding="utf-8")
    assert_failed_with(run(), "failed to validate")
    assert (destination.read_bytes(), destination.with_name("haproxy.cfg").read_bytes()) == before


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_nonregular_source_rejected_before_target_changes(staging, kind):
    source, destination, run = staging
    certificate = source.with_name("public.crt")
    source.rename(certificate)
    if kind == "symlink":
        source.symlink_to(certificate)
    else:
        source.mkdir()
    assert_failed_with(run(), "requires the installed backend CA")
    assert not destination.parent.exists()


@pytest.mark.parametrize("source_state", [
    "present", "present-directory", "present-ready-directory", "planned", "missing", "unchanged",
])
def test_first_deploy_check_mode_never_writes_target(staging, source_state):
    source, destination, run = staging
    present = source_state.startswith("present")
    directory_exists = source_state in {"present-directory", "present-ready-directory"}
    directory_mode = 0o755 if source_state == "present-ready-directory" else 0o700
    if directory_exists:
        destination.parent.mkdir(mode=directory_mode)
    overrides = {"openbao_haproxy_binary_ready": present}
    if not present:
        source.unlink()
    if source_state in {"planned", "unchanged"}:
        overrides["openbao_tls_ca_result"] = {"changed": source_state == "planned"}
    result = run(check=True, **overrides)
    assert destination.parent.exists() == directory_exists
    assert not destination.exists() and not destination.with_name("haproxy.cfg").exists()
    if directory_exists:
        assert destination.parent.stat().st_mode & 0o7777 == directory_mode
    assert source.exists() == present
    if present or source_state == "planned":
        result.assert_success()
        assert "changed=0" not in result.stdout
        assert "Write validated OpenBao HAProxy configuration" in result.stdout
    else:
        assert_failed_with(result, "requires the installed backend CA")
