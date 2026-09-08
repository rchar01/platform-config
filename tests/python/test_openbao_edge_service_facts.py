from __future__ import annotations

import copy
import json
import re

import pytest
import yaml


TASK_NAMES = {
    "haproxy": "Require actual inactive OpenBao edge services",
    "keepalived": "Require actual active HAProxy and inactive Keepalived",
}


def _cases(phase):
    baseline: dict[str, dict[str, object]] = {
        "keepalived.service": {"state": "stopped", "status": "disabled"},
        "haproxy.service": {
            "state": "stopped" if phase == "haproxy" else "running",
            "status": "disabled" if phase == "haproxy" else "enabled",
        },
        "firewalld.service": {"state": "running", "status": "enabled"},
    }
    cases = []

    def add(name, services, expected, variables=None, diagnostic=()):
        cases.append({
            "id": name, "services": services, "expected": expected,
            "variables": variables or {}, "diagnostic": list(diagnostic),
        })

    inactive_services = ["keepalived.service"]
    if phase == "haproxy":
        inactive_services.append("haproxy.service")
    for service in inactive_services:
        for state in ("stopped", "inactive"):
            services = copy.deepcopy(baseline)
            services[service]["state"] = state
            add(f"{service}-{state}-disabled", services, True)
        for status in ("enabled", "unknown", True, False, None, "weird"):
            services = copy.deepcopy(baseline)
            services[service] = {"state": "inactive", "status": status}
            add(f"{service}-inactive-status={status!r}", services, False)
        services = copy.deepcopy(baseline)
        services[service] = {"state": "inactive"}
        add(f"{service}-inactive-missing-status", services, False)

    # Change one field at a time so another closed gate cannot hide a regression.
    for service in ("keepalived.service", "haproxy.service"):
        active = phase == "keepalived" and service == "haproxy.service"
        invalid_states = ["failed", "unknown", True, False, None, "", "weird"]
        invalid_states += ["stopped", "inactive"] if active else ["running"]
        invalid_statuses = ["disabled" if active else "enabled", "unknown",
                            True, False, None, "", "weird"]
        for field, values in (("state", invalid_states), ("status", invalid_statuses)):
            for value in values:
                services = copy.deepcopy(baseline)
                services[service][field] = value
                add(f"{service}-{field}={value!r}", services, False)
            services = copy.deepcopy(baseline)
            del services[service][field]
            add(f"{service}-missing-{field}", services, False)
        services = copy.deepcopy(baseline)
        del services[service]
        add(f"missing-{service}", services, False)

    for state in ("stopped", "inactive"):
        services = copy.deepcopy(baseline)
        for service in inactive_services:
            services[service]["state"] = state
        services["firewalld.service"]["state"] = "inactive"
        add(f"{state}-edges-inactive-managed-firewall", services, phase == "keepalived")
        add(f"{state}-edges-inactive-unmanaged-firewall", services, True,
            {"openbao_haproxy_firewalld_manage": False})
    for state in ("failed", "unknown", True, False, None):
        services = copy.deepcopy(baseline)
        services["firewalld.service"]["state"] = state
        add(f"managed-firewall-state={state!r}", services, phase == "keepalived")
    for missing in ("service", "state"):
        services = copy.deepcopy(baseline)
        if missing == "service":
            del services["firewalld.service"]
        else:
            del services["firewalld.service"]["state"]
        add(f"managed-firewall-missing-{missing}", services, phase == "keepalived")

    services = copy.deepcopy(baseline)
    services["firewalld.service"]["status"] = "disabled"
    add("running-firewall-status-is-not-an-enable-gate", services, True)

    services = copy.deepcopy(baseline)
    services["keepalived.service"] = {"state": "failed", "status": "unknown"}
    services["haproxy.service"] = {"state": "running", "status": "enabled"}
    services["firewalld.service"]["state"] = "inactive"
    diagnostic = ["keepalived", "haproxy", "failed", "unknown", "running", "enabled"]
    if phase == "haproxy":
        diagnostic += ["firewalld", "inactive"]
    add("observed-service-diagnostics", services, False, diagnostic=diagnostic)

    services = copy.deepcopy(baseline)
    services["haproxy.service"] = {"state": "unknown", "status": "masked"}
    services["firewalld.service"]["state"] = "failed"
    diagnostic = ["keepalived", "stopped", "disabled", "haproxy", "unknown", "masked"]
    if phase == "haproxy":
        diagnostic += ["firewalld", "failed"]
    add("observed-haproxy-and-firewall-diagnostics", services, False, diagnostic=diagnostic)

    services = copy.deepcopy(baseline)
    for service in inactive_services:
        services[service]["state"] = "inactive"
    services["custom-keepalived.service"] = services.pop("keepalived.service")
    services["custom-haproxy.service"] = services.pop("haproxy.service")
    add("configured-service-names-inactive", services, True, {
        "keepalived_vip_service_name": "custom-keepalived.service",
        "openbao_haproxy_service_name": "custom-haproxy.service",
    })
    return cases


@pytest.mark.parametrize("phase", TASK_NAMES)
def test_production_edge_service_fact_assertions(
    phase, repo_root, isolated_test_dir, command_runner,
):
    source = repo_root / f"playbooks/maintenance/tasks/openbao-{phase}-preflight.yml"
    tasks = yaml.safe_load(source.read_text())
    matches = [task for task in tasks if task.get("name") == TASK_NAMES[phase]]
    assert len(matches) == 1
    task = matches[0]
    assert "ansible.builtin.assert" in task
    # Preserve the entire production task; only register its result for inspection.
    assert "register" not in task
    task = {**task, "register": "edge_result"}
    cases = _cases(phase)
    case_file = isolated_test_dir / "case.yml"
    case_file.write_text(yaml.safe_dump([
        {
            "block": [task],
            "rescue": [{"ansible.builtin.assert": {"that": [
                "edge_result is failed", "not edge_result.changed",
            ]}}],
        },
        {"ansible.builtin.set_fact": {
            "edge_results": "{{ edge_results + [{'id': edge_case.id, 'result': edge_result}] }}",
        }},
    ]), encoding="utf-8")
    playbook = isolated_test_dir / "services.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"edge_cases": cases, "edge_results": []},
        "tasks": [
            {
                "ansible.builtin.include_tasks": str(case_file),
                "loop": "{{ edge_cases }}",
                "loop_control": {"loop_var": "edge_case", "label": "{{ edge_case.id }}"},
                "vars": {
                    "ansible_facts": {"services": "{{ edge_case.services }}"},
                    "openbao_haproxy_firewalld_manage": (
                        "{{ edge_case.variables.openbao_haproxy_firewalld_manage | default(true) }}"
                    ),
                    "keepalived_vip_service_name": (
                        "{{ edge_case.variables.keepalived_vip_service_name | default('keepalived.service') }}"
                    ),
                    "openbao_haproxy_service_name": (
                        "{{ edge_case.variables.openbao_haproxy_service_name | default('haproxy.service') }}"
                    ),
                },
            },
            {"ansible.builtin.debug": {"msg": {"edge_results": "{{ edge_results }}"}}},
        ],
    }]), encoding="utf-8")
    run = command_runner.run(
        ["ansible-playbook", "-i", "localhost,", str(playbook)],
        environment={
            "ANSIBLE_STDOUT_CALLBACK": "default",
            "ANSIBLE_CALLBACK_RESULT_FORMAT": "json",
            "ANSIBLE_FORCE_COLOR": "0",
        },
        timeout=30,
    )
    run.assert_success()
    assert re.search(r"localhost\s+:.*\bchanged=0\b", run.stdout), run.diagnostics()
    summaries = []
    for match in re.finditer(r"^ok: \[localhost\] => ", run.stdout, re.MULTILINE):
        payload, _ = json.JSONDecoder().raw_decode(run.stdout[match.end():])
        message = payload.get("msg")
        if isinstance(message, dict) and "edge_results" in message:
            summaries.append(message["edge_results"])
    assert len(summaries) == 1, run.diagnostics()
    results = summaries[0]
    assert [entry["id"] for entry in results] == [case["id"] for case in cases]
    failures = []
    for case, entry in zip(cases, results, strict=True):
        observed = entry["result"]
        assert observed["changed"] is False, entry
        assert not observed.get("skipped", False), entry
        passed = not observed.get("failed", False)
        if passed != case["expected"]:
            failures.append(
                f"{case['id']}: expected {'pass' if case['expected'] else 'failure'}, "
                f"observed {'pass' if passed else 'failure'}: {observed.get('msg')}"
            )
        message = observed.get("msg", "").lower()
        missing = [value for value in case["diagnostic"] if value not in message]
        if missing:
            failures.append(f"{case['id']}: diagnostic missing {missing}: {message}")
    assert not failures, "\n".join(failures)
