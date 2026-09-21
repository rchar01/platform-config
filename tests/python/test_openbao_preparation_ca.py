from __future__ import annotations

import hashlib

import pytest
import yaml


@pytest.mark.parametrize("pinned", [False, True])
def test_shipped_ca_install_and_readiness(repo_root, isolated_test_dir, namespace_root_runner, pinned):
    root = isolated_test_dir
    source, destination = root / "validation-ca.pem", root / "installed-ca.crt"
    source.write_text("reviewed public test CA\n")
    source.chmod(0o600)
    # Execute the actual changed installation/readiness tasks. Other OpenBao
    # service convergence is deliberately outside this controller-source proof.
    tasks = yaml.safe_load((repo_root / "roles/openbao/tasks/main.yml").read_text())[0]["block"]
    names = {"Install OpenBao CA certificate", "Install digest-bound OpenBao public validation CA",
             "Record OpenBao CA staging readiness"}
    selected = [task for task in tasks if task.get("name") in names]
    assert len(selected) == 3
    variables = {"openbao_tls_ca_src": str(source), "openbao_tls_ca_path": str(destination)}
    if pinned:
        variables["openbao_tls_ca_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    play = root / "ca.yml"
    play.write_text(yaml.safe_dump([{
        "name": "Exercise shipped OpenBao CA installation",
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": variables,
        "tasks": selected + [{"ansible.builtin.assert": {"that": [
            "openbao_tls_ca_result is succeeded", "openbao_tls_ca_result.changed == expected_changed",
        ]}}],
        "handlers": [{"name": "Restart OpenBao HA service", "ansible.builtin.assert": {"that": "true"}}],
    }]))

    def run(check, changed):
        return namespace_root_runner.run([
            "ansible-playbook", "-i", "localhost,", play,
            "--extra-vars", '{"expected_changed":' + str(changed).lower() + '}',
            *(["--check"] if check else []),
        ], timeout=30)

    run(True, True).assert_success()
    assert not destination.exists()
    run(False, True).assert_success()
    assert destination.read_bytes() == source.read_bytes()
    run(True, False).assert_success()
    if pinned:
        before = destination.read_bytes()
        source.write_text("unreviewed replacement\n")
        result = run(False, True)
        result.assert_failure()
        assert "digest mismatch" in result.stdout
        assert destination.read_bytes() == before
