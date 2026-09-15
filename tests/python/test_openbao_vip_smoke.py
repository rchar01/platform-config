from __future__ import annotations

import json
import shutil

import pytest
import yaml

import test_openbao_keepalived_activation as activation_tests
from test_openbao_keepalived_activation import activation  # noqa: F401
from ansible_test_helpers import assert_failed_with, run_playbook


FIXTURE = "tests/fixtures/openbao-vip-smoke"
PLAYBOOK = "playbooks/openbao-vip-smoke.yml"
HOSTS = ["bao-1", "bao-2", "bao-3"]


def _copy_tasks(repo_root, root):
    destination = root / "playbooks/tasks"
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("openbao-smoke.yml", "openbao-vip-status.yml", "openbao-vip-sample.yml"):
        source = (repo_root / "playbooks/tasks" / name).read_text()
        source = source.replace("ansible.builtin.command:", "ansible.legacy.command:")
        source = source.replace("ansible.builtin.pause:", "ansible.legacy.vip_pause:")
        (destination / name).write_text(source)
    plugins = root / "action_plugins"
    plugins.mkdir(exist_ok=True)
    for name in ("command", "vip_pause"):
        shutil.copyfile(repo_root / FIXTURE / "action.py", plugins / f"{name}.py")


@pytest.fixture
def vip_smoke(repo_root, isolated_test_dir, test_environment):
    root = isolated_test_dir
    fixture = repo_root / FIXTURE
    _copy_tasks(repo_root, root)
    roles = root / "roles"
    shutil.copytree(fixture / "roles", roles)
    shutil.copyfile(
        repo_root / "roles/keepalived_vip/tasks/validate_lifecycle.yml",
        roles / "keepalived_vip/tasks/validate_lifecycle.yml",
    )
    for name in ("openbao-vip-smoke.yml", "openbao-smoke.yml"):
        source = (repo_root / "playbooks" / name).read_text()
        source = source.replace("ansible.builtin.command:", "ansible.legacy.command:")
        # Facts are supplied by the active_preflight role double, never gathered.
        source = source.replace("gather_facts: true", "gather_facts: false")
        (root / "playbooks" / name).write_text(source)
    inventory = root / "inventory.yml"
    shutil.copyfile(fixture / "inventory.yml", inventory)
    (root / "ca.crt").write_text("offline CA sentinel, not a real certificate\n")
    environment = dict(test_environment, ANSIBLE_FORCE_COLOR="0",
                       ANSIBLE_ROLES_PATH=str(roles),
                       ANSIBLE_ACTION_PLUGINS=str(root / "action_plugins"))
    return root, root / PLAYBOOK, inventory, environment


def _run(command_runner, vip_smoke, variables=None, limit="openbao"):
    root, playbook, inventory, environment = vip_smoke
    return run_playbook(
        command_runner, playbook, inventory=inventory, limit=limit,
        environment=environment, extra_vars=({
            "openbao_test_root": str(root), "openbao_tls_ca_src": str(root / "ca.crt"),
            **(variables or {}),
        },),
    )


def _events(root):
    return [json.loads(line) for path in sorted(root.glob("vip-*.jsonl"))
            for line in path.read_text().splitlines()]


def _host_vars(vip_smoke, host, variables):
    inventory = vip_smoke[2]
    data = yaml.safe_load(inventory.read_text())
    data["all"]["children"]["openbao"]["hosts"][host] = variables
    inventory.write_text(yaml.safe_dump(data))


def test_vip_smoke_runs_imported_smoke_and_three_fresh_strict_samples(vip_smoke, command_runner):
    result = _run(command_runner, vip_smoke).assert_success()
    assert "Supply offline direct-node and Raft status" in result.stdout
    events = _events(vip_smoke[0])
    haproxy = [e for e in events if "--output" in e["args"].get("argv", [])]
    assert [e["args"]["argv"][e["args"]["argv"].index("--resolve") + 1]
            for e in haproxy] == [f"bao.example.invalid:8200:192.0.2.{n}" for n in (11, 12, 13)]
    for host in HOSTS:
        local = [e for e in events if e["host"] == host]
        addresses = [e for e in local if e["args"].get("argv", [None])[0] == "ip"]
        assert [e["sample"] for e in addresses] == [1, 2, 3]
        for sample in (1, 2, 3):
            services = [e["args"]["argv"] for e in local if e["sample"] == sample
                        and e["args"].get("argv", [None])[0] == "systemctl"]
            assert services == [["systemctl", state, "keepalived.service"]
                                for state in ("is-active", "is-enabled")]
        queries = [e for e in local if e["args"].get("argv", [None])[0] == "curl"
                   and "--output" not in e["args"]["argv"]]
        assert len(queries) == 2
        prefix = ["curl", "--disable", "--silent", "--show-error", "--noproxy", "*",
                  "--connect-timeout", "7", "--max-time", "7", "--cacert", str(vip_smoke[0] / "ca.crt")]
        for event, resolve in zip(queries, (["--resolve", "bao.example.invalid:8200:192.0.2.200"], [])):
            assert event["args"]["argv"] == prefix + resolve + [
                "--write-out", r"\n%{http_code} %{remote_ip}",
                "https://bao.example.invalid:8200/v1/sys/health",
            ]
            assert event["delegate"] == "localhost"
            assert event["become"] is False
            assert event["check_mode"] is False
        dns = [e for e in local if e["args"].get("argv", [None])[0] == "getent"]
        assert len(dns) == 1
        assert dns[0]["args"]["argv"] == ["getent", "ahostsv4", "bao.example.invalid"]
        assert dns[0]["delegate"] == "localhost"
        assert dns[0]["become"] is False
    pauses = [e for e in events if e["action"] == "vip_pause"]
    assert {e["sample"] for e in pauses} == {2, 3}
    assert all(int(e["args"]["seconds"]) >= 2 for e in pauses)


@pytest.mark.parametrize("limit", [None, "bao-1", "openbao,other"])
def test_vip_smoke_requires_exact_full_cluster(vip_smoke, command_runner, limit):
    assert_failed_with(_run(command_runner, vip_smoke, limit=limit), "explicit limit selecting exactly")
    assert not _events(vip_smoke[0])


@pytest.mark.parametrize("host", ["bao-1", "bao-3"])
@pytest.mark.parametrize("variables", [
    {"keepalived_vip_enabled": False, "keepalived_vip_service_enabled": False,
     "keepalived_vip_service_state": "stopped"},
    {"keepalived_vip_service_enabled": False, "keepalived_vip_service_state": "stopped"},
    {"keepalived_vip_service_enabled": "true"},
    {"keepalived_vip_service_state": "restarted"},
])
def test_vip_smoke_requires_active_desired_lifecycle_everywhere(vip_smoke, command_runner, host, variables):
    _host_vars(vip_smoke, host, variables)
    result = _run(command_runner, vip_smoke)
    result.assert_failure()
    assert "VIP smoke requires active desired" in result.stdout or "strict lifecycle booleans" in result.stdout
    assert not any(e["args"].get("argv", [None])[0] == "ip" for e in _events(vip_smoke[0]))


@pytest.mark.parametrize("variables", [
    {"openbao_service_vip": "192.0.2.201", "keepalived_vip_instances": [{"vip": "192.0.2.201/24", "interface": "eth0"}]},
    {"keepalived_vip_instances": [{"vip": "192.0.2.201/24", "interface": "eth0"}]},
    {"openbao_service_dns": "different.example.invalid"},
    {"openbao_client_port": 8201},
    {"keepalived_vip_cluster_members": [{"name": "bao-1"}, {"name": "bao-2"}]},
])
def test_vip_smoke_requires_same_topology_on_nonfirst_host(vip_smoke, command_runner, variables):
    _host_vars(vip_smoke, "bao-3", variables)
    assert_failed_with(_run(command_runner, vip_smoke), "same single VIP and client endpoint")


@pytest.mark.parametrize("fault,message", [
    ("is-active", "verified active/enabled Keepalived"),
    ("is-enabled", "verified active/enabled Keepalived"),
    ("service-error", "offline systemctl error"),
    ("service-unreachable", "offline service unreachable"),
    ("address-unreachable", "offline address unreachable"),
    ("address-malformed", "from_json"),
    ("zero", "exactly one owner"),
    ("duplicate", "exactly one owner"),
    ("duplicate-interface", "exactly one owner"),
    ("wrong-interface", "exactly one owner"),
    ("near-match", "exactly one owner"),
    ("owner-changing", "ownership changed during repeated qualification"),
])
def test_vip_smoke_rejects_bad_actual_state(vip_smoke, command_runner, fault, message):
    assert_failed_with(_run(command_runner, vip_smoke, {"vip_test_fault": fault}), message)
    assert not any(e["args"].get("argv", [None])[0] == "getent" for e in _events(vip_smoke[0]))


@pytest.mark.parametrize("path", ["forced", "dns"])
@pytest.mark.parametrize("variables", [
    {"vip_test_http": "307"}, {"vip_test_http": "503"},
    {"vip_test_body": {"initialized": False}},
    {"vip_test_body": {"sealed": True}},
    {"vip_test_body": {"standby": True}},
    {"vip_test_body": {"initialized": 1}},
    {"vip_test_body": {"sealed": 0}},
    {"vip_test_body": {"standby": 0}},
    {"vip_test_body": {"cluster_id": "other-cluster"}},
    {"vip_test_remote_ip": "192.0.2.11"},
])
def test_vip_smoke_checks_http_body_identity_and_actual_remote_address(vip_smoke, command_runner, path, variables):
    assert_failed_with(_run(command_runner, vip_smoke, {"vip_test_path": path, **variables}),
                       "VIP health must be active, unsealed, strict-TLS verified")


@pytest.mark.parametrize("fault,message", [
    ("curl-error", "offline TLS certificate error"),
    ("body-malformed", "from_json"),
    ("dns-error", "offline DNS error"),
    ("haproxy-error", "failed smoke status"),
])
def test_vip_smoke_rejects_probe_errors(vip_smoke, command_runner, fault, message):
    assert_failed_with(_run(command_runner, vip_smoke, {"vip_test_fault": fault}), message)


@pytest.mark.parametrize("addresses", [[], ["192.0.2.11"], ["192.0.2.200", "192.0.2.11"]])
def test_vip_smoke_rejects_wrong_or_ambiguous_dns(vip_smoke, command_runner, addresses):
    assert_failed_with(_run(command_runner, vip_smoke, {"vip_test_dns": addresses}),
                       "DNS must resolve to the configured VIP")


def test_vip_smoke_preserves_direct_cluster_identity_gate(vip_smoke, command_runner):
    assert_failed_with(_run(command_runner, vip_smoke, {"vip_test_direct_cluster": "other-cluster"}),
                       "runtime cluster identity does not match active markers")
    assert not any(e["args"].get("argv", [None])[0] == "ip" for e in _events(vip_smoke[0]))


@pytest.mark.parametrize("fault,message", [
    ("", "Record fully qualified OpenBao VIP activation"),
    ("zero", "exactly one owner"),
    ("owner-changing", "ownership changed during repeated qualification"),
    ("address-unreachable", "Unknown host address state"),
    ("service-unreachable", "verified active/enabled Keepalived"),
    ("curl-error", "offline TLS certificate error"),
])
def test_activation_uses_real_vip_helper_and_rolls_back_failures(repo_root, activation, fault, message):
    root = activation[0]
    _copy_tasks(repo_root, root)
    fixture_vars = yaml.safe_load((repo_root / FIXTURE / "inventory.yml").read_text())["all"]["vars"]
    variables = {key: fixture_vars[key] for key in (
        "keepalived_vip_instances", "keepalived_vip_cluster_members", "keepalived_vip_advert_interval",
    )}
    variables.update(openbao_tls_ca_src=str(root / "ca.crt"), vip_test_fault=fault)
    code, output = activation_tests._run(repo_root, activation, variables)
    assert "Observe actual Keepalived active and boot-enabled state" in output
    assert message in output
    events = activation_tests._events(root)
    assert len([e for e in events if e["phase"] == "start"]) == 3
    rollbacks = sorted(e["host"] for e in events if e["phase"] == "rollback")
    if fault:
        assert code != 0, output
        assert "Unverified rollback hosts: none" in output
        assert rollbacks == HOSTS
    else:
        assert code == 0, output
        assert not rollbacks


def _read_only_contract(repo_root):
    """Traverse real imports and role entry points, including implicit dependencies."""
    visited = set()
    allowed = {"assert", "set_fact", "debug", "stat", "slurp", "service_facts",
               "command", "uri", "wait_for", "pause", "include_tasks", "import_tasks",
               "include_role", "import_role"}
    keywords = {"name", "when", "vars", "register", "changed_when", "failed_when",
                "check_mode", "become", "delegate_to", "run_once", "loop", "loop_control",
                "tags", "no_log", "until", "retries", "delay", "ignore_errors",
                "ignore_unreachable", "environment", "block", "rescue", "always"}

    def visit_role(spec):
        role = repo_root / "roles" / spec["name"]
        meta = role / "meta/main.yml"
        if meta.exists():
            # include_role executes dependencies even with tasks_from=validate.
            assert not yaml.safe_load(meta.read_text()).get("dependencies", []), meta
        taskfile = spec.get("tasks_from", "main.yml")
        assert "{{" not in taskfile
        visit_file(role / "tasks" / taskfile)

    def visit_tasks(tasks, parent):
        for task in tasks:
            for key in ("block", "rescue", "always"):
                visit_tasks(task.get(key, []), parent)
            actions = set(task) - keywords
            if "block" not in task:
                assert len(actions) == 1, (parent, task)
            for action in actions:
                assert action.startswith("ansible.builtin."), (parent, action)
                module = action.rsplit(".", 1)[-1]
                assert module in allowed, (parent, action)
                args = task[action]
                if module in {"include_tasks", "import_tasks"}:
                    target = args if isinstance(args, str) else args["file"]
                    assert "{{" not in target
                    visit_file(parent / target)
                elif module in {"include_role", "import_role"}:
                    visit_role(args)
                elif module == "command":
                    assert task.get("changed_when") is False, (parent, task)
                    assert isinstance(args, dict) and "argv" in args, (parent, task)
                elif module == "uri":
                    assert args.get("method", "GET") == "GET", (parent, task)
                    assert "dest" not in args, (parent, task)

    def visit_file(path):
        path = path.resolve()
        if path in visited:
            return
        visited.add(path)
        visit_tasks(yaml.safe_load(path.read_text()), path.parent)

    def visit_playbook(path):
        for play in yaml.safe_load(path.read_text()):
            if "ansible.builtin.import_playbook" in play:
                visit_playbook(path.parent / play["ansible.builtin.import_playbook"])
                continue
            for role in play.get("roles", []):
                visit_role({"name": role} if isinstance(role, str) else role)
            for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                visit_tasks(play.get(key, []), path.parent)

    visit_playbook(repo_root / PLAYBOOK)
    return visited


def test_vip_smoke_read_only_traversal_and_import_contract(repo_root):
    plays = yaml.safe_load((repo_root / PLAYBOOK).read_text())
    assert plays[0]["ansible.builtin.import_playbook"] == "openbao-smoke.yml"
    visited = _read_only_contract(repo_root)
    for path in ("playbooks/tasks/openbao-vip-status.yml", "playbooks/tasks/openbao-vip-sample.yml",
                 "roles/keepalived_vip/tasks/validate.yml", "roles/keepalived_vip/tasks/validate_lifecycle.yml",
                 "roles/openbao/tasks/active_preflight.yml", "roles/openbao_status/tasks/main.yml"):
        assert (repo_root / path).resolve() in visited


@pytest.mark.parametrize("mutation", ["module", "nested", "dependency"])
def test_read_only_contract_detects_mutation(repo_root, isolated_test_dir, mutation):
    root = isolated_test_dir
    (root / "playbooks").mkdir()
    role = root / "roles/keepalived_vip"
    (role / "tasks").mkdir(parents=True)
    (role / "meta").mkdir()
    (role / "meta/main.yml").write_text(yaml.safe_dump({
        "dependencies": ["mutating_dependency"] if mutation == "dependency" else [],
    }))
    task = {"ansible.builtin.systemd_service": {"name": "keepalived", "state": "started"}}
    if mutation == "dependency":
        task = {"ansible.builtin.assert": {"that": True}}
    if mutation == "nested":
        task = {"block": [{"ansible.builtin.assert": {"that": True}}], "always": [task]}
    (role / "tasks/validate.yml").write_text(yaml.safe_dump([task]))
    (root / PLAYBOOK).write_text(yaml.safe_dump([{"hosts": "openbao", "tasks": [{
        "ansible.builtin.include_role": {"name": "keepalived_vip", "tasks_from": "validate.yml"},
    }]}]))
    with pytest.raises(AssertionError):
        _read_only_contract(root)
