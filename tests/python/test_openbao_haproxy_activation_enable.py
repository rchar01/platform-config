from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from test_openbao_haproxy_firewall_guard import ROLE, RULES, stage_firewall_target
from test_openbao_haproxy_activation_preflight import activation_fixture
from test_openbao_haproxy_ca_guard import stage_ca_target


@pytest.fixture
def activation_target(repo_root, tmp_path, command_runner):
    role = tmp_path / ROLE
    shutil.copytree(repo_root / ROLE, role)
    variables = stage_firewall_target(role, tmp_path, command_runner)
    variables.update(stage_ca_target(role, tmp_path, command_runner, mock_policy=True))
    plays = yaml.safe_load((repo_root / "playbooks/maintenance/openbao-haproxy-activate.yml").read_text())
    block = next(task["block"] for task in plays[2]["tasks"] if "block" in task)
    include = next(task for task in block if task.get("ansible.builtin.include_role", {}).get("name") ==
                   "openbao_haproxy")
    route = include["ansible.builtin.include_role"]
    route["name"] = str(role)
    # Preserve the actual entry point, including main.yml on the unfixed caller.
    entry = role / "tasks" / route.get("tasks_from", "main.yml")
    entry.write_text(entry.read_text().replace(
        "ansible.builtin.systemd_service:", "fixture_systemd_service:",
    ), encoding="utf-8")
    collections = tmp_path / "empty-collections"
    collections.mkdir()
    command_runner.environment.update({
        "ANSIBLE_COLLECTIONS_PATH": str(collections),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False",
    })
    variables.update({
        "openbao_haproxy_enabled": True,
        "openbao_haproxy_selinux_manage": False,
        "openbao_haproxy_selinux_observation": {"managed": True, "mode": "stale"},
        "openbao_haproxy_activation_observation": {
            "selinux": {"managed": False},
            "ca": {"source_checksum": "b" * 64, "ca_checksum": "b" * 64,
                   "config_checksum": "a" * 64, "selinux": {"managed": False}},
        },
        "openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"],
        "openbao_haproxy_backend_health_host": "bao.example.invalid",
        "openbao_cluster_members": [
            {"name": f"bao-{i}", "address": f"192.0.2.{i}", "dns": f"bao-{i}.example.invalid"}
            for i in range(1, 4)
        ],
        "ansible_python_interpreter": sys.executable,
        "ansible_facts": {"python": {"executable": sys.executable}},
    })
    return {"hosts": "localhost", "gather_facts": False, "vars": variables, "tasks": [include]}


def run_activation(play, tmp_path, command_runner):
    path = tmp_path / "activate.yml"
    path.write_text(yaml.safe_dump([play]), encoding="utf-8")
    result = command_runner.run([
        "ansible-playbook", "-i", "localhost,", "-c", "local", str(path),
    ])
    log = Path(play["vars"]["fixture_log"])
    events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return result, events


def test_activation_role_loads_without_collections(activation_target, tmp_path, command_runner):
    result, events = run_activation(activation_target, tmp_path, command_runner)
    # This must be red for missing seport before the caller selects activation_enable.yml.
    result.assert_success()
    services = [event for event in events if event["kind"] == "systemd_service"]
    assert len(services) == 1
    assert services[0]["args"] == {"name": "haproxy.service", "enabled": True, "state": "started"}
    assert events[-1] == services[0]
    assert events[-2]["args"]["argv"] == ["firewall-offline-cmd", f"--query-rich-rule={RULES[-1]}"]
    assert not any(event["kind"] in {"copy", "firewalld"} for event in events)


def test_activation_missing_firewall_rule_blocks_service(activation_target, tmp_path, command_runner):
    activation_target["vars"]["fixture_missing_permanent"] = RULES[-1]
    result, events = run_activation(activation_target, tmp_path, command_runner)
    result.assert_failure()
    assert any(event["args"].get("argv") == [
        "firewall-offline-cmd", f"--query-rich-rule={RULES[-1]}",
    ] for event in events), result.diagnostics()
    assert not any(event["kind"] == "systemd_service" for event in events)


@pytest.mark.parametrize("change", ["trust", "configuration"])
def test_activation_ca_drift_blocks_service(change, activation_target, tmp_path, command_runner):
    checksums = activation_target["vars"]["fixture_ca_checksums"]
    if change == "trust":
        checksums["source"] = checksums["ca"] = "c" * 64
    else:
        checksums["config"] = "c" * 64
    result, events = run_activation(activation_target, tmp_path, command_runner)
    result.assert_failure()
    assert "CA or access changed after approved preflight" in result.stdout
    assert events == [], "CA evidence drift must block firewall I/O and service startup"


@pytest.mark.parametrize("owned", [True, False, "true"])
def test_activation_requires_explicit_role_ownership(owned, repo_root, tmp_path, command_runner):
    preflight = yaml.safe_load((repo_root / "playbooks/maintenance/tasks/openbao-haproxy-preflight.yml").read_text())
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"children": {"openbao": {"hosts": {
        f"bao-{i}": {"ansible_connection": "local"} for i in range(1, 4)
    }}}}}), encoding="utf-8")
    playbook = tmp_path / "ownership.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "openbao", "gather_facts": False,
        "vars": {"openbao_activation_mode": "plan", "openbao_haproxy_enabled": owned},
        "tasks": [preflight[0]],
    }]), encoding="utf-8")
    result = command_runner.run(["ansible-playbook", "-i", str(inventory), str(playbook), "--limit", "openbao"])
    if owned is True:
        result.assert_success()
    else:
        result.assert_failure()
        assert "enabled HAProxy ownership" in result.stdout


def stage_selinux_target(tmp_path, case):
    mode = {"permissive": "Permissive", "disabled": "Disabled", "invalid-mode": "Unknown"}.get(
        case, "Enforcing",
    )
    records = {(8200, 8200, "tcp"): ("http_port_t", "s0"),
               (8404, 8404, "tcp"): ("http_port_t", "s0:c0.c3")}
    if case == "mls-drift":
        records[(8404, 8404, "tcp")] = ("http_port_t", "s0")
    for port, name in ((8200, "client"), (8404, "stats")):
        if case == f"missing-{name}":
            del records[(port, port, "tcp")]
        elif case == f"wrong-{name}":
            records[(port, port, "tcp")] = ("unreserved_port_t", "s0")
        elif case == f"range-{name}":
            del records[(port, port, "tcp")]
            records[(port - 1, port + 1, "tcp")] = ("http_port_t", "s0")
    records = list(records.items())
    if case == "duplicate-client":
        records += [((8200, 8200, "tcp"), ("trivnet1_port_t", "s0")),
                    ((1024, 65535, "tcp"), ("unreserved_port_t", "s0"))]
        assert dict(records)[(8200, 8200, "tcp")][0] == "trivnet1_port_t"
    log = tmp_path / "selinux-events"
    getenforce = tmp_path / "getenforce"
    getenforce.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:] == [], sys.argv\n"
        f"with Path({str(log)!r}).open('a') as log:\n"
        "    log.write('getenforce\\n')\n"
        f"print(os.environ.get('SELINUX_TEST_MODE', {mode!r}))\n"
        f"sys.exit({1 if case == 'command-fail' else 0})\n",
        encoding="utf-8",
    )
    getenforce.chmod(0o755)
    # A read-only binding double: any attempt to add/modify/delete fails.
    (tmp_path / "seobject.py").write_text(
        "from pathlib import Path\n"
        f"log = Path({str(log)!r})\n"
        "with log.open('a') as stream:\n"
        "    stream.write('import seobject\\n')\n"
        + ("raise ModuleNotFoundError('fixture missing seobject bindings')\n"
           if case in {"disabled", "missing-bindings"} else "")
        + f"records = {records!r}\n"
        "SH = object()\n"
        "class portRecords:\n"
        "    sh = SH\n"
        "    def get_all(self):\n"
        "        with log.open('a') as stream:\n"
        "            stream.write('get_all\\n')\n"
        "        return dict(records)\n",
        encoding="utf-8",
    )
    (tmp_path / "semanage.py").write_text(
        "from seobject import SH, log, records\n"
        f"case = {case!r}\n"
        "def event(name):\n"
        "    with log.open('a') as stream:\n"
        "        stream.write(name + '\\n')\n"
        "event('import semanage')\n"
        "SEMANAGE_PROTO_TCP = 6\n"
        "def semanage_port_key_create(sh, low, high, protocol):\n"
        "    assert sh is SH\n"
        "    assert low == high and protocol == SEMANAGE_PROTO_TCP\n"
        "    event('key_create')\n"
        "    if case == 'key-none':\n"
        "        return 1, None\n"
        "    return (-1 if case == 'key-fail' else 0 if case == 'zero-success' else 1), (low, high, 'tcp')\n"
        "def semanage_port_query(sh, key):\n"
        "    assert sh is SH\n"
        "    event('query')\n"
        "    if case == 'query-none':\n"
        "        return 1, None\n"
        "    for record in records:\n"
        "        if record[0] == key:\n"
        "            return (-1 if case == 'query-fail' else 0 if case == 'zero-success' else 1), record\n"
        "    return -1, None\n"
        "def semanage_port_get_con(record):\n"
        "    return record[1]\n"
        "def semanage_context_get_type(context):\n"
        "    return context[0]\n"
        "def semanage_context_get_mls(context):\n"
        "    return context[1]\n"
        "def semanage_port_free(record):\n"
        "    assert record is not None\n"
        "    event('port_free')\n"
        "def semanage_port_key_free(key):\n"
        "    assert key is not None\n"
        "    event('key_free')\n",
        encoding="utf-8",
    )
    return mode, log


@pytest.mark.parametrize("case", [
    "enforcing", "permissive", "disabled", "missing-client", "missing-stats",
    "wrong-client", "wrong-stats", "range-client", "range-stats",
    "command-fail", "missing-bindings", "invalid-mode", "duplicate-client",
    "zero-success", "key-fail", "key-none", "query-fail", "query-none",
])
def test_selinux_guard_native_probe(case, repo_root, tmp_path, command_runner):
    guard = yaml.safe_load((repo_root / ROLE / "tasks/selinux_guard.yml").read_text())
    tasks = [child for task in guard for child in task.get("block", [task])]
    command = next(task for task in tasks if "ansible.builtin.command" in task)
    code = command["ansible.builtin.command"]["argv"][2]
    compile(code, "selinux_guard.yml", "exec")
    mode, log = stage_selinux_target(tmp_path, case)
    result = command_runner.run([
        sys.executable, "-c", code, "http_port_t", "8200", "8404",
    ], environment={"PATH": f"{tmp_path}:{command_runner.environment['PATH']}",
                    "PYTHONPATH": str(tmp_path)})
    if case in {"enforcing", "permissive", "disabled", "duplicate-client", "zero-success"}:
        result.assert_success()
        assert json.loads(result.stdout) == {
            "managed": True, "mode": mode,
            "ports": {} if case == "disabled" else {
                "8200": ["http_port_t", "s0"], "8404": ["http_port_t", "s0:c0.c3"],
            },
        }
    else:
        result.assert_failure()
        assert not result.stdout.strip()
    expected = ["getenforce"]
    if case not in {"disabled", "command-fail", "invalid-mode"}:
        expected.append("import seobject")
        if case != "missing-bindings":
            expected.append("import semanage")
            for name in ("client", "stats"):
                expected.append("key_create")
                if case == "key-none":
                    break
                if case == "key-fail":
                    expected.append("key_free")
                    break
                expected.append("query")
                missing = case in {f"missing-{name}", f"range-{name}", "query-none"}
                if not missing:
                    expected.append("port_free")
                expected.append("key_free")
                if missing or case in {f"wrong-{name}", "query-fail"}:
                    break
    assert log.read_text().splitlines() == expected


@pytest.mark.parametrize("case", ["enforcing", "wrong-stats", "mode-drift", "mls-drift"])
def test_selinux_guard_at_service_boundary(case, activation_target, tmp_path, command_runner):
    _, log = stage_selinux_target(tmp_path, "disabled" if case == "mode-drift" else case)
    activation_target["vars"]["openbao_haproxy_selinux_manage"] = True
    activation_target["vars"]["openbao_haproxy_activation_observation"]["selinux"] = {
        "managed": True, "mode": "Enforcing", "ports": {
            "8200": ["http_port_t", "s0"], "8404": ["http_port_t", "s0:c0.c3"],
        },
    }
    activation_target["environment"] = {
        "PATH": f"{tmp_path}:{command_runner.environment['PATH']}", "PYTHONPATH": str(tmp_path),
    }
    if case == "enforcing":
        activation_target["tasks"] += [
            {"ansible.builtin.assert": {"that": [
                "openbao_haproxy_selinux_observation == "
                "{'managed': true, 'mode': 'Enforcing', 'ports': "
                "{'8200': ['http_port_t', 's0'], '8404': ['http_port_t', 's0:c0.c3']}}",
            ]}},
            {"ansible.builtin.set_fact": {"openbao_haproxy_selinux_manage": False}},
            {"ansible.builtin.include_role": {
                "name": str(tmp_path / ROLE), "tasks_from": "selinux_guard.yml",
            }},
            {"ansible.builtin.assert": {"that":
                "openbao_haproxy_selinux_observation == {'managed': false}"}},
        ]
    result, events = run_activation(activation_target, tmp_path, command_runner)
    assert log.exists(), result.diagnostics()
    assert log.read_text().splitlines() == (
        ["getenforce"] if case == "mode-drift" else
        ["getenforce", "import seobject", "import semanage"] +
        ["key_create", "query", "port_free", "key_free"] * 2
    )
    if case == "enforcing":
        result.assert_success()
        assert events[-1]["kind"] == "systemd_service"
        assert events[-1]["args"] == {"name": "haproxy.service", "enabled": True, "state": "started"}
    else:
        result.assert_failure()
        assert events == [], "SELinux rejection must precede firewall I/O and service management"


def test_activation_guard_and_evidence_contract(repo_root):
    tasks_dir = repo_root / ROLE / "tasks"
    enable = yaml.safe_load((tasks_dir / "activation_enable.yml").read_text())
    assert len(enable) == 6
    assert enable[0]["ansible.builtin.include_tasks"] == "ca_guard.yml"
    assert enable[1]["ansible.builtin.assert"]["that"] == [
        "openbao_haproxy_ca_observation == openbao_haproxy_activation_observation.ca",
    ]
    assert enable[2]["ansible.builtin.include_tasks"] == "selinux_guard.yml"
    assert enable[3]["ansible.builtin.assert"]["that"] == [
        "openbao_haproxy_selinux_observation == openbao_haproxy_activation_observation.selinux",
    ]
    assert enable[4]["ansible.builtin.include_tasks"] == "firewall_guard.yml"
    assert enable[5]["ansible.builtin.systemd_service"] == {
        "name": "haproxy.service", "enabled": True, "state": "started",
    }
    guard = yaml.safe_load((tasks_dir / "selinux_guard.yml").read_text())
    assert guard[0]["ansible.builtin.set_fact"]["openbao_haproxy_selinux_observation"] == {"managed": False}
    block = next(task for task in guard if "block" in task)
    assert block["when"] == "openbao_haproxy_selinux_manage | bool"
    command = next(task for task in block["block"] if "ansible.builtin.command" in task)
    argv = command["ansible.builtin.command"]["argv"]
    assert argv[:2] == ["{{ ansible_facts.python.executable }}", "-c"]
    assert argv[3:] == ["{{ openbao_haproxy_selinux_port_type }}",
                        "{{ openbao_haproxy_client_port | string }}",
                        "{{ openbao_haproxy_stats_port | string }}"]
    assert command["changed_when"] is False
    assert command["check_mode"] is False
    assert "delegate_to" not in command
    assertions = " ".join(
        expression for task in block["block"]
        for expression in task.get("ansible.builtin.assert", {}).get("that", [])
    )
    result = command["register"]
    assert f"{result} is not unreachable" in assertions
    assert f"{result} is not skipped" in assertions
    assert f"{result}.rc" in assertions and "== 0" in assertions
    observation = block["block"][-1]["ansible.builtin.set_fact"]["openbao_haproxy_selinux_observation"]
    assert f"{result}.stdout" in observation and "from_json" in observation
    preflight = yaml.safe_load((tasks_dir / "activation_preflight.yml").read_text())
    guard_index = next(i for i, task in enumerate(preflight)
                       if task.get("ansible.builtin.include_tasks") == "selinux_guard.yml")
    evidence_index = next(i for i, task in enumerate(preflight)
                          if "openbao_haproxy_activation_observation" in task.get("ansible.builtin.set_fact", {}))
    assert guard_index < evidence_index
    evidence = preflight[evidence_index]["ansible.builtin.set_fact"]["openbao_haproxy_activation_observation"]
    assert evidence["selinux"] == "{{ openbao_haproxy_selinux_observation }}"


def test_activation_observation_binds_selinux_mode(activation_fixture, tmp_path, command_runner):
    play, role = activation_fixture
    stage_selinux_target(tmp_path, "enforcing")
    play["vars"]["openbao_haproxy_selinux_manage"] = True
    play["environment"].update({
        "PATH": f"{tmp_path}:{command_runner.environment['PATH']}",
        "SELINUX_TEST_MODE": "{{ fixture_selinux_mode | default('Enforcing') }}",
    })
    include = {"ansible.builtin.include_role": {"name": str(role), "tasks_from": "activation_preflight.yml"}}
    play["tasks"] = [include, {"ansible.builtin.set_fact": {
        "first_observation": "{{ openbao_haproxy_activation_observation }}",
        "fixture_selinux_mode": "Permissive",
    }}, include, {"ansible.builtin.assert": {"that": [
        "first_observation != openbao_haproxy_activation_observation",
        "first_observation.selinux.mode == 'Enforcing'",
        "openbao_haproxy_activation_observation.selinux.mode == 'Permissive'",
        "first_observation.firewalld == openbao_haproxy_activation_observation.firewalld",
        "first_observation.config_checksum == openbao_haproxy_activation_observation.config_checksum",
    ]}}]
    result, _ = run_activation(play, tmp_path, command_runner)
    result.assert_success()
    assert "changed=0" in result.stdout
