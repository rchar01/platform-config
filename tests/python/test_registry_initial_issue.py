from __future__ import annotations

import runpy

import pytest
import yaml

from test_pki_host_local_request_helper import request_scenario  # noqa: F401


@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize("check", [False, True])
def test_issue_rejects_active_before_pending_publication(request_scenario, pending, check):
    scenario = request_scenario
    if pending:
        scenario.run().assert_success()
    else:
        scenario.state.mkdir(mode=0o700)
        (scenario.state / "lock").touch(mode=0o600)
    helper = runpy.run_path(str(scenario.helper))
    values = dict.fromkeys(helper["ACTIVE_FIELDS"], "1" * 64)
    values.update(schema="2", kind="host-local-active", service="registry-test",
                  target="test-target", request_id="1" * 32)
    active = scenario.state / "active"
    active.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    active.chmod(0o600)
    before = {str(path): path.read_bytes() for path in scenario.work.rglob("*") if path.is_file()}
    result = scenario.run(check=check)
    result.assert_failure()
    assert "issue requires no active predecessor" in result.stderr
    assert {str(path): path.read_bytes() for path in scenario.work.rglob("*") if path.is_file()} == before
    assert scenario.pending.exists() == pending


def test_filesystem_request_read_only_ancestor_probe(repo_root, isolated_test_dir, command_runner):
    tasks = yaml.safe_load((repo_root / "roles/pki_host_local_certificate/tasks/filesystem_preflight.yml").read_text())
    path = isolated_test_dir / "ancestors.yml"
    path.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"pki_host_local_certificate_filesystem_exchange_root": "/var/lib/registry-exchange"},
        "tasks": [tasks[0], {"ansible.builtin.assert": {"that": [
            "pki_host_local_certificate_filesystem_ancestor_stats.results | map(attribute='item') | list == ['/', '/var', '/var/lib']",
        ]}}],
    }]))
    command_runner.run(["ansible-playbook", "-i", "localhost,", path]).assert_success()
