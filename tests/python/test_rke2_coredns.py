"""Real Ansible CoreDNS validation/convergence with isolated paths and kubectl I/O."""

from __future__ import annotations

import json
import os
import shutil
import sys

import pytest
import yaml


RECORDS = [{"address": "192.0.2.20", "names": ["registry.example.test", "git.example.test"]}]
TYPE_FAILURE = "Validate the CoreDNS records input type"
RECORD_FAILURE = "Validate CoreDNS static record structure and canonical IPv4 addresses"
NAME_FAILURE = "Validate CoreDNS names and reserved namespaces"
PEER_FAILURE = "Require identical CoreDNS inventory on every cluster member"
DUPLICATE_FAILURE = "Reject duplicate CoreDNS addresses and duplicate or conflicting names"
BASELINE = """.:53 {
errors
health {
lameduck 10s
}
ready
HOSTS
kubernetes cluster.local in-addr.arpa ip6.arpa {
pods insecure
fallthrough in-addr.arpa ip6.arpa
ttl 30
}
prometheus 0.0.0.0:9153
forward . /etc/resolv.conf
cache 30
loop
reload
loadbalance
}
"""


@pytest.fixture
def validate_cases(repo_root, isolated_test_dir, command_runner):
    """Keep hostvars real and independent while sharing one Ansible process."""
    def run(cases):
        inventory = {"all": {"children": {}}}
        plays = []
        # A valid control makes an unrelated, unconditional failure visible.
        for index, (records, peer, expected_failure) in enumerate([(RECORDS, {}, None), *cases]):
            server, agent = f"server{index}", f"agent{index}"
            cluster, servers, agents = f"cluster{index}", f"servers{index}", f"agents{index}"
            inventory["all"]["children"][cluster] = {
                "vars": {
                    "ansible_connection": "local", "rke2_version": "v1.35.5+rke2r2",
                    "rke2_coredns_static_hosts": records,
                    "rke2_cluster_group": cluster, "rke2_server_group": servers,
                    "rke2_agent_group": agents,
                },
                "children": {servers: {"hosts": {server: {}}}, agents: {"hosts": {agent: peer}}},
            }
            plays.append({
                "name": f"Validate case {index}: {records!r}, peer={peer!r}",
                "hosts": server, "gather_facts": False,
                "vars": {"expected_failure": expected_failure},
                "tasks": [
                    {"ansible.builtin.set_fact": {"accepted": False}},
                    {"block": [
                        {"ansible.builtin.import_tasks": str(repo_root / "roles/rke2/tasks/coredns_validate.yml")},
                        {"ansible.builtin.set_fact": {"accepted": True}},
                    ], "rescue": [{"ansible.builtin.assert": {"that": [
                         "ansible_failed_task.action == 'ansible.builtin.assert'",
                         "ansible_failed_task.name == expected_failure",
                    ]}}]},
                    {"ansible.builtin.assert": {"that": [f"accepted == {expected_failure is None}"]}},
                ],
            })
        inventory_path = isolated_test_dir / "inventory.yml"
        inventory_path.write_text(yaml.safe_dump(inventory))
        playbook = isolated_test_dir / "validate.yml"
        playbook.write_text(yaml.safe_dump(plays))
        result = command_runner.run([
            "ansible-playbook", "-i", inventory_path, playbook, "--check",
        ], timeout=85).assert_success()
        assert "changed=0" in result.stdout
        return result
    return run


@pytest.fixture
def scenario(repo_root, isolated_test_dir, command_runner):
    root = isolated_test_dir
    role = root / "roles/rke2"
    role.mkdir(parents=True)
    for directory in ("defaults", "templates", "meta"):
        shutil.copytree(repo_root / "roles/rke2" / directory, role / directory)
    (role / "tasks").mkdir()
    target = root / "target"
    target.mkdir()
    # Fixed path relocation only; no public path/ownership bypass is added.
    for path in (repo_root / "roles/rke2/tasks").glob("coredns*.yml"):
        text = path.read_text().replace("/var", str(target / "var"))
        text = text.replace("item.stat.uid == 0", f"item.stat.uid == {os.getuid()}")
        text = text.replace("owner: root", f"owner: '{os.getuid()}'")
        text = text.replace("group: root", f"group: '{os.getgid()}'")
        text = text.replace("retries: 60", "retries: 1").replace("delay: 5", "delay: 0")
        text = text.replace("--timeout=300s", "--timeout=0s")
        (role / "tasks" / path.name).write_text(text)
    inspection = role / "tasks/coredns_inspect.yml"
    tasks = yaml.safe_load(inspection.read_text())
    target_expr = "{{ hostvars[rke2_coredns_source_host].test_target_root | default(" + json.dumps(str(target)) + ") }}"
    tasks[0]["loop"] = [path.replace(str(target), target_expr) for path in tasks[0]["loop"]]
    for task in tasks:
        if "ansible.builtin.slurp" in task:
            task["ansible.builtin.slurp"]["src"] = task["ansible.builtin.slurp"]["src"].replace(str(target), target_expr)
    inspection.write_text(yaml.safe_dump(tasks))
    (role / "tasks/main.yml").write_text(yaml.safe_dump([
        {"ansible.builtin.import_tasks": "coredns_preflight.yml"},
        {"ansible.builtin.include_tasks": "coredns.yml",
         "when": "inventory_hostname == rke2_bootstrap_host"},
        {"name": "Simulate a failed base node", "ansible.builtin.assert": {
            "that": ["not (test_fail_base | default(false))"],
        }},
        {"name": "Record simulated base node completion", "ansible.builtin.copy": {
            "content": "base complete\n", "dest": str(root / "base-{{ inventory_hostname }}"), "mode": "0600",
        }},
    ]))
    for dependency in ("rocky_repository_policy", "registry_ca_trust", "firewalld"):
        tasks_dir = root / "roles" / dependency / "tasks"
        tasks_dir.mkdir(parents=True)
        (tasks_dir / "main.yml").write_text(yaml.safe_dump([{
            "name": f"Detect {dependency} mutation",
            "ansible.builtin.copy": {
                "content": "dependency executed\n", "dest": str(root / dependency), "mode": "0600",
            },
        }]))
    callbacks = root / "callbacks"
    callbacks.mkdir()
    (callbacks / "coredns_actions.py").write_text(f"""from ansible.plugins.callback import CallbackBase
class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'coredns_actions'
    CALLBACK_NEEDS_ENABLED = True
    def v2_playbook_on_task_start(self, task, is_conditional):
        with open({str(root / 'actions')!r}, 'a') as stream:
            stream.write(task.action + '\\n')
""")
    manifest = target / "var/lib/rancher/rke2/server/manifests/rke2-coredns-config.yaml"
    kubeconfig = target / "kubeconfig"
    state = root / "state.json"
    calls = root / "kubectl-calls"
    kubectl = root / "kubectl"
    kubectl.write_text(f"""#!{sys.executable}
import json, pathlib, sys, yaml
state = json.loads(pathlib.Path({str(state)!r}).read_text())
args = sys.argv[1:]
with open({str(calls)!r}, 'a') as stream:
    stream.write(' '.join(args) + '\\n')
if 'helmchartconfig/rke2-coredns' in args:
    if '--ignore-not-found' not in args:
        document = yaml.safe_load(pathlib.Path({str(manifest)!r}).read_text())
        if state.get('stale_hcc'):
            document['spec']['valuesContent'] = 'servers: []'
        print(json.dumps(document))
    elif state.get('hcc'):
        print(json.dumps(state['hcc']))
    sys.exit(state.get('hcc_rc', 0))
if 'rollout' in args:
    if state.get('require_all_nodes'):
        assert all((pathlib.Path({str(root)!r}) / ('base-' + host)).exists()
                   for host in state['require_all_nodes']), 'rollout before base nodes completed'
    sys.exit(state.get('rollout_rc', 0))
manifest = yaml.safe_load(pathlib.Path({str(manifest)!r}).read_text())
values = yaml.safe_load(manifest['spec']['valuesContent'])
annotation = values['podAnnotations']
if 'configmap/rke2-coredns-rke2-coredns' in args:
    if state.get('stale_cm'):
        annotation = {{'platform-config/coredns-spec': 'stale'}}
    print(json.dumps({{'metadata': {{'annotations': annotation}},
                      'data': {{'Corefile': state['corefile']}}}}))
    sys.exit(state.get('cm_rc', 0))
if 'deployment/rke2-coredns-rke2-coredns' in args:
    if state.get('stale_deployment'):
        annotation = {{'platform-config/coredns-spec': 'stale'}}
    print(json.dumps({{'spec': {{'template': {{'metadata': {{'annotations': annotation}}}}}}}}))
    sys.exit(state.get('deployment_rc', 0))
sys.exit(99)
""")
    kubectl.chmod(0o755)

    def run(records=RECORDS, *, check=False, fresh=False, peer=None, state_overrides=None,
            extra=None, host="server", validate_only=False, smoke=False, stage_only=False,
            fixed=False, second_server=None, preflight_only=False, render_only=False, gate_only=False):
        variables = {
            "ansible_connection": "local", "ansible_python_interpreter": sys.executable,
            "rke2_version": "v1.35.5+rke2r2", "rke2_coredns_static_hosts": records,
            "rke2_server_manifest_dir": str(manifest.parent),
            "rke2_extra_config": {"data-dir": str(target / "var/lib/rancher/rke2")},
            "rke2_kubectl": str(kubectl), "rke2_kubeconfig": str(kubeconfig),
        }
        variables.update(extra or {})
        if render_only:
            assert state_overrides is not None
            variables["test_expected_corefile"] = state_overrides["corefile"]
        inventory = root / "inventory.yml"
        inventory.write_text(yaml.safe_dump({"all": {"vars": variables, "children": {
            "rke2_cluster": {"children": {
                "rke2_servers": {"hosts": {"server": {}, **({"server2": second_server} if second_server is not None else {})}},
                "rke2_agents": {"hosts": {"agent": peer or {}}},
            }},
        }}}))
        playbook = root / "playbooks/play.yml"
        playbook.parent.mkdir(exist_ok=True)
        plays = [{
            "hosts": host, "gather_facts": False, "become": False,
            "tasks": ([{"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_preflight.yml"}] if preflight_only else
                      [{"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_smoke.yml"}] if smoke else
                      [{"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_validate.yml"}] if validate_only else
                      [{"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns.yml"}] if stage_only or gate_only else
                      [{"ansible.builtin.include_role": {
                          "name": "rke2", "tasks_from": "main.yml",
                      }}]),
        }]
        if render_only or gate_only:
            plays[0]["tasks"] = [
                {"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_validate.yml"},
                {"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_render.yml"},
                # Materialize the real template for byte comparison only. The
                # lifecycle test separately exercises guarded publication.
                {"ansible.builtin.copy": {
                    "content": "{{ rke2_coredns_manifest }}", "dest": str(manifest), "mode": "0644",
                }},
            ]
            if render_only:
                plays[0]["tasks"].insert(2, {"ansible.builtin.assert": {"that": [
                    "rke2_coredns_expected_corefile.split() == test_expected_corefile.split()",
                ]}})
        if gate_only:
            plays[0]["tasks"].append({"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_verify.yml"})
        if not (smoke or validate_only or stage_only or preflight_only or render_only or gate_only) and host == "server":
            plays.append({"hosts": host, "gather_facts": False, "become": False, "tasks": [
                {"ansible.builtin.import_tasks": "../roles/rke2/tasks/coredns_smoke.yml"},
            ]})
        if fixed:
            plays = yaml.safe_load((repo_root / "playbooks/rke2.yml").read_text())
            for play in plays:
                play.update({"become": False, "gather_facts": False})
        playbook.write_text(yaml.safe_dump(plays))
        if not fresh and not validate_only:
            manifest.parent.mkdir(parents=True, exist_ok=True)
            kubeconfig.touch()
        hosts = "\n".join(
            f"{r['address']} {' '.join(sorted(r['names']))}" for r in records
        ) if isinstance(records, list) and all(isinstance(r, dict) and isinstance(r.get('names'), list)
                                             and all(isinstance(n, str) for n in r['names'])
                                             for r in records) else ""
        corefile = BASELINE.replace("HOSTS", f"hosts /dev/null {{\n{hosts}\nfallthrough\n}}" if hosts else "")
        state.write_text(json.dumps({"corefile": corefile, **(state_overrides or {})}))
        if calls.exists():
            calls.unlink()
        (root / "actions").write_text("")
        return command_runner.run([
            "ansible-playbook", "-i", inventory, playbook, *(["--check", "--diff"] if check else []),
        ], cwd=root, environment={
            "ANSIBLE_ROLES_PATH": str(root / "roles"),
            "ANSIBLE_CALLBACK_PLUGINS": str(callbacks), "ANSIBLE_CALLBACKS_ENABLED": "coredns_actions",
        }, timeout=85)

    return run, manifest, calls, target


def test_apply_idempotence_record_removal_and_empty_reset(scenario):
    run, manifest, calls, _ = scenario
    # Exercise real guarded publication; rollout and whole-playbook ordering
    # have dedicated tests rather than being repeated on every file transition.
    result = run(stage_only=True).assert_success()
    assert manifest.exists(), result.stdout
    document = yaml.safe_load(manifest.read_text())
    values = yaml.safe_load(document["spec"]["valuesContent"])
    plugins = values["servers"][0]["plugins"]
    assert [p["name"] for p in plugins] == [
        "errors", "health", "ready", "hosts", "kubernetes", "prometheus", "forward", "cache", "loop", "reload", "loadbalance",
    ]
    assert plugins[3]["parameters"] == "/dev/null"
    assert plugins[4]["parameters"] == "in-addr.arpa ip6.arpa"
    assert values["servers"][0]["zones"] == [{"zone": ".", "use_tcp": True}]
    old_hash = values["podAnnotations"]
    assert "changed=0" in run(stage_only=True).assert_success().stdout
    assert "changed=0" in run(check=True, stage_only=True).assert_success().stdout
    assert "rollout" not in calls.read_text()
    run([{"address": "192.0.2.20", "names": ["git.example.test"]}], stage_only=True).assert_success()
    assert "registry.example.test" not in manifest.read_text()
    run([], stage_only=True).assert_success()
    values = yaml.safe_load(yaml.safe_load(manifest.read_text())["spec"]["valuesContent"])
    assert "hosts" not in [p["name"] for p in values["servers"][0]["plugins"]]
    assert values["podAnnotations"] != old_hash
    assert "changed=0" in run([], stage_only=True).assert_success().stdout


def test_invalid_structure(validate_cases):
    cases = [(value, {}, TYPE_FAILURE) for value in [None, {}, "bad", False, 1]]
    cases += [(value, {}, RECORD_FAILURE) for value in [
        ["bad"], [{"address": "192.0.2.1", "names": "a.example"}],
        [{"address": "192.0.2.1", "names": []}],
        [{"address": "192.0.2.1", "names": ["a.example"], "extra": True}],
    ]]
    cases += [
        ([{"address": "192.0.2.1", "names": [None]}], {}, NAME_FAILURE),
        ([{"address": "192.0.2.1", "names": [["a.example"]]}], {}, NAME_FAILURE),
    ]
    validate_cases(cases)


def test_custom_domain_excluded_and_rendered_once(scenario):
    run, manifest, _, target = scenario
    extra = {"rke2_extra_config": {
        "data-dir": str(target / "var/lib/rancher/rke2"), "cluster-domain": "cluster.example",
    }}
    run([{"address": "192.0.2.1", "names": ["api.svc.cluster.example"]}],
        extra=extra, validate_only=True).assert_failure()
    corefile = BASELINE.replace("HOSTS", "hosts /dev/null {\n192.0.2.20 git.example.test registry.example.test\nfallthrough\n}")
    run(extra=extra, render_only=True,
        state_overrides={"corefile": corefile.replace("cluster.local", "cluster.example")}).assert_success()
    values = yaml.safe_load(yaml.safe_load(manifest.read_text())["spec"]["valuesContent"])
    kubernetes = next(p for p in values["servers"][0]["plugins"] if p["name"] == "kubernetes")
    assert kubernetes["parameters"] == "in-addr.arpa ip6.arpa"


def test_reordering_does_not_change_manifest(scenario):
    run, manifest, _, _ = scenario
    records = [{"address": "192.0.2.30", "names": ["z.example.test", "a.example.test"]}] + RECORDS
    # Compare the real render with independently supplied sorted records.
    hosts = "hosts /dev/null {\n192.0.2.20 git.example.test registry.example.test\n192.0.2.30 a.example.test z.example.test\nfallthrough\n}"
    state = {"corefile": BASELINE.replace("HOSTS", hosts)}
    run(records, state_overrides=state, render_only=True).assert_success()
    before = manifest.read_bytes()
    reordered = [{"address": r["address"], "names": list(reversed(r["names"]))} for r in reversed(records)]
    assert "changed=0" in run(reordered, state_overrides=state, render_only=True).assert_success().stdout
    assert manifest.read_bytes() == before


def test_owned_live_hcc_without_source_can_reset_to_empty(scenario):
    run, manifest, _, _ = scenario
    run([], stage_only=True, state_overrides={"hcc": {"metadata": {"labels": {
        "app.kubernetes.io/managed-by": "platform-config",
    }}}}).assert_success()
    assert manifest.exists()
    assert "name: hosts" not in manifest.read_text()


def test_invalid_address(validate_cases):
    validate_cases([([{"address": address, "names": ["a.example"]}], {}, RECORD_FAILURE)
                    for address in ["192.00.2.1", "256.0.0.1", "::1", "192.0.2.1\n", 123]])


def test_invalid_name(validate_cases):
    names = [
        "localhost", "a.localhost", "a.localdomain", "kubernetes.default.svc.cluster.local",
        "cluster.local", "a.in-addr.arpa", "a.ip6.arpa", "A.example", "a.example.",
        "a.example\n}", "a example", "*.example", "a_foo.example", "a" * 64 + ".example", "192.0.2.1",
    ]
    validate_cases([([{"address": "192.0.2.1", "names": [name]}], {}, NAME_FAILURE) for name in names])


def test_duplicates_and_conflicts(validate_cases):
    records = [
        RECORDS + RECORDS,
        RECORDS + [{"address": "192.0.2.21", "names": ["git.example.test"]}],
        [{"address": "192.0.2.20", "names": ["git.example.test", "git.example.test"]}],
    ]
    validate_cases([(value, {}, DUPLICATE_FAILURE) for value in records])


def test_serial_bootstrap_checks_unselected_inventory_peer(validate_cases):
    peers = [
        {"rke2_coredns_static_hosts": []}, {"rke2_coredns_static_hosts": "invalid"},
        {"rke2_extra_config": {"cluster-domain": "other.test"}},
        {"rke2_version": "v1.36.0+rke2r1"},
        {"rke2_service_enabled": False}, {"rke2_service_state": "stopped"},
        {"rke2_extra_config": {"data-dir": "/other"}},
        {"rke2_extra_config": {"disable": ["rke2-coredns"]}},
        {"rke2_bootstrap_host": "agent"}, {"rke2_node_role": "server"},
        {"rke2_server_manifest_dir": "/alternate/manifests"},
    ]
    validate_cases([(RECORDS, peer,
                     TYPE_FAILURE if peer.get("rke2_coredns_static_hosts") == "invalid" else PEER_FAILURE)
                    for peer in peers])


def test_fresh_check_renders_without_writes_or_api_calls(scenario):
    run, manifest, calls, target = scenario
    result = run(fresh=True, check=True, stage_only=True).assert_success()
    assert "Predict a new CoreDNS manifest" in result.stdout
    assert "registry.example.test" in result.stdout
    assert not manifest.exists()
    assert not (target / "var").exists()
    assert not calls.exists()


def test_empty_default_and_nonbootstrap_do_not_write(scenario):
    run, manifest, calls, _ = scenario
    run([], fresh=True, stage_only=True).assert_success()
    assert not manifest.exists()
    run(host="agent", fresh=True, stage_only=True).assert_success()
    assert not manifest.exists()
    assert not calls.exists()


def test_foreign_live_hcc_rejected_when_configured(scenario):
    run, manifest, calls, _ = scenario
    run(preflight_only=True, state_overrides={"hcc": {"metadata": {"labels": {}}}}).assert_failure()
    assert not manifest.exists()
    assert "rollout" not in calls.read_text()


@pytest.mark.parametrize("smoke", [False, True])
def test_empty_foreign_source_and_hcc_do_not_impose_managed_contract(scenario, smoke):
    run, manifest, calls, _ = scenario
    manifest.parent.mkdir(parents=True)
    manifest.write_text("foreign: customization\n")
    before = manifest.stat().st_mtime_ns
    extra = {"rke2_version": "future", "rke2_extra_config": {"cluster-domain": "custom"},
             "rke2_cluster_group": "absent-cluster", "rke2_service_state": "stopped"}
    run([], smoke=smoke, preflight_only=not smoke, extra=extra, peer={"rke2_extra_config": {"cluster-domain": "different"}},
        state_overrides={"hcc": {"metadata": {"labels": {"app.kubernetes.io/managed-by": "other"}}}}).assert_success()
    assert manifest.read_text() == "foreign: customization\n"
    assert manifest.stat().st_mtime_ns == before
    assert "rollout" not in calls.read_text()
    assert "get configmap" not in calls.read_text()


@pytest.mark.parametrize("kind", ["foreign", "symlink", "hardlink", "writable", "parent-link"])
def test_unsafe_or_foreign_source_preserved(scenario, kind):
    run, manifest, calls, target = scenario
    manifest.parent.mkdir(parents=True)
    if kind == "parent-link":
        manifest.parent.rmdir()
        manifest.parent.symlink_to(target, target_is_directory=True)
    elif kind == "symlink":
        manifest.symlink_to(target / "absent")
    else:
        manifest.write_text("foreign: true\n")
        if kind == "hardlink":
            os.link(manifest, target / "linked")
        if kind == "writable":
            manifest.chmod(0o666)
    run(fresh=True, check=True, preflight_only=True).assert_failure()
    assert not calls.exists() or "rollout" not in calls.read_text()
    if kind not in ("symlink", "parent-link"):
        assert manifest.read_text() == "foreign: true\n"


@pytest.mark.parametrize("failure,forbidden", [
    ({"stale_hcc": True}, "get configmap/"),
    ({"cm_rc": 1}, "get deployment/"),
    ({"corefile": "stale"}, "get deployment/"),
    ({"corefile": BASELINE.replace("HOSTS", "hosts /dev/null {\n192.0.2.20 git.example.test registry.example.test\nfallthrough\n}")
      .replace("cache 30\nloop", "cache 30 loop")}, "get deployment/"),
    ({"stale_cm": True}, "get deployment/"),
    ({"stale_deployment": True}, "rollout"),
    ({"deployment_rc": 1}, "rollout"),
    ({"rollout_rc": 1}, None),
])
def test_failed_or_stale_current_generation_blocks_later_gates(scenario, failure, forbidden):
    run, manifest, calls, _ = scenario
    run(state_overrides=failure, gate_only=True).assert_failure()
    assert manifest.exists()  # A failed qualification is not rollback.
    if forbidden:
        assert forbidden not in calls.read_text()


def test_role_orders_validation_and_dns_gate(repo_root):
    tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    names = [task["name"] for task in tasks]
    assert tasks[0]["ansible.builtin.import_tasks"] == "coredns_preflight.yml"
    assert names.index("Wait for the local RKE2 server API after convergence") < names.index(
        "Converge bundled CoreDNS on the bootstrap server"
    ) < names.index("Wait for the converged RKE2 node to become Ready")


def test_smoke_reuses_live_gates_without_manifest_writes(scenario):
    run, manifest, calls, _ = scenario
    run(stage_only=True).assert_success()
    before = manifest.stat().st_mtime_ns
    for dependency in ("rocky_repository_policy", "registry_ca_trust"):
        assert not (manifest.parents[7] / dependency).exists()
    owned = {"hcc": {"metadata": {"labels": {"app.kubernetes.io/managed-by": "platform-config"}}}}
    run(smoke=True, state_overrides=owned).assert_success()
    assert "rollout status" in calls.read_text()
    assert manifest.stat().st_mtime_ns == before
    root = manifest.parents[7]
    assert not (root / "rocky_repository_policy").exists()
    assert not (root / "registry_ca_trust").exists()
    assert set((root / "actions").read_text().splitlines()) <= {
        "ansible.builtin.set_fact", "ansible.builtin.stat", "ansible.builtin.slurp",
        "ansible.builtin.command", "ansible.builtin.assert", "ansible.builtin.include_tasks",
    }
    run(smoke=True, state_overrides={**owned, "stale_deployment": True}).assert_failure()
    assert "rollout status" not in calls.read_text()
    run(smoke=True, check=True, state_overrides=owned).assert_success()
    assert "get configmap/" not in calls.read_text()
    assert manifest.stat().st_mtime_ns == before


def test_bootstrap_stages_without_waiting_for_full_dns_replicas(scenario):
    run, manifest, calls, _ = scenario
    run(stage_only=True, state_overrides={"rollout_rc": 1, "stale_cm": True}).assert_success()
    assert manifest.exists()
    assert "rollout" not in calls.read_text()
    assert "get configmap" not in calls.read_text()


@pytest.mark.parametrize("owned,records", [(False, RECORDS), (True, RECORDS), (True, [])])
def test_nonbootstrap_competing_source_rejected_before_any_base_role(scenario, owned, records):
    run, manifest, calls, target = scenario
    root = target.parent
    other = root / "other-target"
    competing = other / "var/lib/rancher/rke2/server/manifests/rke2-coredns-config.yaml"
    competing.parent.mkdir(parents=True)
    document = {"apiVersion": "helm.cattle.io/v1", "kind": "HelmChartConfig", "metadata": {
        "name": "rke2-coredns", "namespace": "kube-system", "labels": {
            "app.kubernetes.io/managed-by": "platform-config" if owned else "someone-else",
        },
    }, "spec": {"valuesContent": "servers: []"}}
    # JSON is valid YAML too; ownership is semantic rather than indentation-based.
    competing.write_text(json.dumps(document))
    before = competing.read_bytes()
    result = run(records, fixed=True, second_server={"test_target_root": str(other)})
    result.assert_failure()
    assert "no competing source" in result.stdout, result.stdout
    assert not manifest.exists()
    assert competing.read_bytes() == before
    for dependency in ("firewalld", "rocky_repository_policy", "registry_ca_trust"):
        assert not (root / dependency).exists()
    assert "ansible.builtin.copy" not in (root / "actions").read_text()
    assert "rollout" not in calls.read_text()


@pytest.mark.parametrize("failure", ["foreign-hcc", "unsafe-source", "invalid-inventory"])
def test_fixed_preflight_failure_precedes_firewall_and_meta_dependencies(scenario, failure):
    run, manifest, _, target = scenario
    kwargs = {}
    if failure == "foreign-hcc":
        kwargs["state_overrides"] = {"hcc": {"metadata": {"labels": {}}}}
    elif failure == "unsafe-source":
        manifest.parent.mkdir(parents=True)
        manifest.symlink_to(target / "absent")
    else:
        kwargs["peer"] = {"rke2_coredns_static_hosts": []}
    run(fixed=True, **kwargs).assert_failure()
    for dependency in ("firewalld", "rocky_repository_policy", "registry_ca_trust"):
        assert not (target.parent / dependency).exists()
    assert "ansible.builtin.copy" not in (target.parent / "actions").read_text()


def test_real_fixed_playbook_completes_all_base_nodes_before_dns_gate(scenario):
    run, manifest, calls, target = scenario
    other = target.parent / "other-target"
    other.mkdir()
    result = run(fixed=True, second_server={"test_target_root": str(other)},
                 state_overrides={"require_all_nodes": ["server", "server2", "agent"]}).assert_success()
    assert manifest.exists()
    assert "rollout status" in calls.read_text()
    assert result.stdout.index("Configure RKE2 agent nodes") < result.stdout.index(
        "Verify CoreDNS after complete RKE2 base convergence"
    )


def test_fresh_preflight_is_readonly_and_preserves_inventory_values(scenario):
    run, manifest, calls, target = scenario
    run(preflight_only=True, fresh=True, check=True).assert_success()
    assert not manifest.exists()
    assert not (target / "var").exists()
    assert not calls.exists()
    for dependency in ("firewalld", "rocky_repository_policy", "registry_ca_trust"):
        assert not (target.parent / dependency).exists()


def test_failed_base_agent_prevents_final_coredns_verification(scenario):
    run, manifest, calls, _ = scenario
    run(fixed=True, peer={"test_fail_base": True}).assert_failure()
    assert manifest.exists()
    assert "get configmap/" not in calls.read_text()
    assert "rollout" not in calls.read_text()


def test_owned_empty_still_requires_supported_inventory(scenario):
    run, manifest, _, _ = scenario
    run(stage_only=True).assert_success()
    before = manifest.read_bytes()
    run([], preflight_only=True, extra={"rke2_version": "future"}).assert_failure()
    assert manifest.read_bytes() == before


def test_smoke_playbook_imports_tasks_without_loading_role_defaults_or_dependencies(repo_root):
    smoke = yaml.safe_load((repo_root / "playbooks/rke2-smoke.yml").read_text())[1]
    task = smoke["tasks"][0]
    assert task["ansible.builtin.include_tasks"] == "../roles/rke2/tasks/coredns_smoke.yml"
    fixed = yaml.safe_load((repo_root / "playbooks/rke2.yml").read_text())
    assert fixed[0]["tasks"][0]["ansible.builtin.include_tasks"].endswith("coredns_preflight.yml")
    assert fixed[-1]["tasks"][0]["ansible.builtin.include_tasks"].endswith("coredns_smoke.yml")
    assert [p["hosts"] for p in fixed[1:-1]] == ["rke2_servers", "rke2_agents"]
    assert "roles" not in fixed[0] and "roles" not in fixed[-1]
    for path in (repo_root / "roles/rke2/tasks").glob("coredns*.yml"):
        text = path.read_text()
        assert "include_role" not in text and "import_role" not in text
        assert "include_vars" not in text and "vars_files" not in text


@pytest.mark.parametrize("check", [False, True])
def test_unmanaged_empty_unavailable_api_is_readonly_noop(scenario, check):
    run, manifest, calls, target = scenario
    # A kubeconfig can remain while the service is stopped. Even an incomplete
    # response claiming ownership cannot establish it when kubectl failed.
    result = run([], preflight_only=True, check=check, extra={"rke2_service_state": "stopped"},
                 state_overrides={"hcc_rc": 1, "hcc": {"metadata": {"labels": {
                     "app.kubernetes.io/managed-by": "platform-config",
                 }}}})
    result.assert_success()
    assert "changed=0" in result.stdout
    assert not manifest.exists()
    assert "rollout" not in calls.read_text()
    assert "ansible.builtin.copy" not in (target.parent / "actions").read_text()


@pytest.mark.parametrize("owned_source", [False, True])
def test_managed_unavailable_api_still_fails_before_publication(scenario, owned_source):
    run, manifest, calls, _ = scenario
    if owned_source:
        run(stage_only=True).assert_success()
    before = manifest.read_bytes() if manifest.exists() else None
    result = run([] if owned_source else RECORDS, preflight_only=True,
                 state_overrides={"hcc_rc": 1})
    result.assert_failure()
    assert "Cannot inspect CoreDNS API ownership" in result.stdout
    assert (manifest.read_bytes() if manifest.exists() else None) == before
    assert "rollout" not in calls.read_text()


@pytest.mark.parametrize("caller", ["server", "agent"])
def test_delegated_coredns_transport_uses_each_targets_ci_identity(scenario, caller):
    run, manifest, _, target = scenario
    run(stage_only=True).assert_success()
    root = target.parent
    capture = root / "ssh-argv.jsonl"
    fake_ssh = root / "offline-ssh"
    fake_ssh.write_text(f"""#!{sys.executable}
import json, pathlib, subprocess, sys
args = sys.argv[1:]
assert any(host in args for host in ('server', 'server2', 'agent')), args
with pathlib.Path({str(capture)!r}).open('a') as stream:
    stream.write(json.dumps(args) + '\\n')
# Run only the Ansible-generated remote shell locally in the disposable test
# container. Native SSH builds its real transport argv; no socket/key is opened.
sys.exit(subprocess.call(args[-1], shell=True))
""")
    fake_ssh.chmod(0o755)
    other = root / "other-target"
    other.mkdir()
    keys = {host: f"/synthetic/{host}.key" for host in ("server", "server2", "agent")}
    result = run(smoke=True, host=caller, second_server={"test_target_root": str(other)}, extra={
        "ansible_connection": "ssh", "ansible_ssh_executable": str(fake_ssh),
        "ansible_ssh_pipelining": True,
        "platform_ci_ssh_private_key_files": keys,
        "ansible_ssh_private_key_file": "{{ platform_ci_ssh_private_key_files[inventory_hostname] }}",
    })
    result.assert_success()
    transports = [json.loads(line) for line in capture.read_text().splitlines()]
    assert {host for args in transports for host in keys if host in args} == {"server", "server2"}
    for args in transports:
        host = next(host for host in keys if host in args)
        identity = next(arg for arg in args if arg.startswith("IdentityFile="))
        assert identity == f'IdentityFile="{keys[host]}"', (host, identity, args)
    # Real module execution reaches source slurp and all four kubectl gates.
    actions = (root / "actions").read_text().splitlines()
    assert "ansible.builtin.stat" in actions and "ansible.builtin.slurp" in actions
    assert "ansible.builtin.command" in actions
    assert manifest.exists()
