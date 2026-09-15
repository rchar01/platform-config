"""Standalone smoke regression, using real Ansible and template-derived API fixtures.

Only local scratch files are used. The kube-vip URI is an assert sentinel: these
tests do not qualify API networking, TLS, Helm downloads, or a live cluster.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest
import yaml

from conftest import CommandRunner


ROLES = ("rke2_kube_vip", "rke2_gitlab_runner")
RUNNER_OPTIONAL = ("chart_version", "manager_image", "helper_image", "default_job_image")
TIMINGS = ("vip_leaseduration", "vip_renewdeadline", "vip_retryperiod")
SERVERS = ("server-1", "server-2", "server-3")


def _read_play(repo_root: Path, role: str) -> dict:
    return yaml.safe_load(
        (repo_root / "playbooks" / f"{role.replace('_', '-')}-smoke.yml").read_text()
    )[0]


# The stub derives desired resources from the *role template*, never from smoke
# predicates. Unknown commands fail closed; every invocation is audited.
KUBECTL = r'''
import json
import os
from pathlib import Path
import sys
import yaml

args = sys.argv[1:]
with open(os.environ["FIXTURE_CALLS"], "a") as stream:
    stream.write(json.dumps([os.environ["FIXTURE_HOST"], args]) + "\n")
assert args[:2] == ["--kubeconfig", os.environ["FIXTURE_KUBECONFIG"]], args
args = args[2:]
namespace = None
if args[:1] == ["-n"]:
    namespace, args = args[1], args[2:]
manifest = yaml.safe_load(Path(os.environ["FIXTURE_MANIFEST"]).read_text())
values = yaml.safe_load(manifest["spec"]["valuesContent"])
runner = manifest["spec"]["chart"] == "gitlab-runner"
release = "rke2-gitlab-runner" if runner else "kube-vip"
if args == ["rollout", "status", ("deployment/" if runner else "daemonset/") + release,
            "--timeout=1s"]:
    assert namespace == ("gitlab-runner" if runner else "kube-system")
    print("successfully rolled out")
    sys.exit(0)
assert args[0] == "get", args
kind = args[1]
if kind == "helmchart":
    assert args == ["get", kind, release, "-o=json"] and namespace == "kube-system"
    result = manifest
elif not runner:
    assert kind == "daemonset" and args[2] == release and namespace == "kube-system"
    if args[3] == '-o=jsonpath={.status.desiredNumberScheduled}{" "}{.status.numberReady}':
        print("3 3")
        sys.exit(0)
    assert args[3:] == ["-o=json"]
    result = {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": release},
              "spec": {"template": {"spec": {"containers": [{"name": release,
                  "image": "ghcr.io/kube-vip/kube-vip:" + values["image"]["tag"],
                  "env": [{"name": k, "value": str(v)} for k, v in values["env"].items()]}]}}},
              "status": {"desiredNumberScheduled": 3, "numberReady": 3}}
else:
    assert namespace == (None if kind == "namespace" else "gitlab-runner")
    if args == ["get", "deployment", release, "-o=name"]:
        print("deployment.apps/" + release)
        sys.exit(0)
    if kind == "pods":
        assert args == ["get", "pods", "-l", "app=" + release, "-o=json"]
        result = {"apiVersion": "v1", "kind": "PodList", "items": [
            {"metadata": {"name": release + "-fixture"}, "spec": {"nodeName": "worker-node"},
             "status": {"phase": "Running"}}]}
    else:
        assert args[3:] == ["-o=json"], args
        name = args[2]
        assert name in (release, release + "-job", release + "-token", release + "-ca", "gitlab-runner")
        result = {"apiVersion": "v1", "metadata": {"name": name}}
        if kind == "namespace":
            result["metadata"]["labels"] = {"pod-security.kubernetes.io/enforce": "baseline"}
        elif kind == "deployment":
            result["spec"] = {"template": {"spec": {
                "serviceAccountName": values["serviceAccount"]["name"],
                "affinity": values["affinity"],
                "containers": [{"name": release, "image": "/".join([
                    values["image"]["registry"], values["image"]["image"]]) + ":" + values["image"]["tag"],
                    "securityContext": values["securityContext"]}],
                "volumes": [
                    {"name": "projected-secrets", "projected": {"sources": [
                        {"secret": {"name": values["runners"]["secret"]}}]}},
                    {"name": "custom-certs", "secret": {"secretName": values["certsSecretName"]}}]}}}
        elif kind == "role":
            result["rules"] = values["rbac"]["rules"]
        elif kind == "rolebinding":
            result.update(roleRef={"kind": "Role", "name": release},
                          subjects=[{"kind": "ServiceAccount", "name": release}])
        elif kind == "serviceaccount":
            result["automountServiceAccountToken"] = (
                values["extraObjects"][0]["automountServiceAccountToken"]
                if name.endswith("-job") else values["automountServiceAccountToken"])
        elif kind == "configmap":
            result["data"] = {"config.template.toml": values["runners"]["config"]}
        elif kind == "secret":
            result["data"] = ({"runner-registration-token": "", "runner-token": "Zml4dHVyZQ=="}
                if name.endswith("-token") else {"gitlab.example.test.crt": "Zml4dHVyZQ=="})
        else:
            raise AssertionError(args)
print(json.dumps(result))
'''


CALLBACK = '''
import json
import os
from ansible.plugins.callback import CallbackBase

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "smoke_audit"
    CALLBACK_NEEDS_ENABLED = True

    def record(self, result, status):
        with open(os.environ["FIXTURE_EVENTS"], "a") as stream:
            stream.write(json.dumps({"host": result._host.name,
                "task": result._task.get_name(), "action": result._task.action,
                "status": status, "changed": result._result.get("changed", False)}) + "\\n")

    def v2_runner_on_ok(self, result):
        self.record(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.record(result, "failed")

    def v2_runner_on_skipped(self, result):
        self.record(result, "skipped")
'''


def _assert_task(name: str, expressions: list[str]) -> dict:
    return {"name": name, "ansible.builtin.assert": {"that": expressions}}


def _rejection(task: dict, name: str, evidence: str) -> dict:
    """Rescue only the production failure, not our unexpected-success sentinel."""
    task = deepcopy(task)
    task["name"] = name
    return {
        "name": f"Expect rejection: {name}",
        "block": [task, _assert_task("Unexpected acceptance", ["false"])],
        "rescue": [_assert_task(f"Prove rejection: {name}", [
            f"ansible_failed_task.name == {json.dumps(name)}", evidence,
        ])],
    }


def _exercise(repo_root, isolated_test_dir, command_runner, role, overrides, negative=False):
    root = isolated_test_dir
    play = deepcopy(_read_play(repo_root, role))
    original_tasks = deepcopy(play["tasks"])
    assert not any(key in play for key in ("roles", "pre_tasks", "post_tasks", "vars_files"))
    allowed = {"ansible.builtin.command", "ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.uri"}
    for task in original_tasks:
        assert {key for key in task if key.startswith("ansible.")} <= allowed
        assert any(key in task for key in allowed)
        if "ansible.builtin.command" in task:
            assert task["changed_when"] is False

    defaults = yaml.safe_load((repo_root / f"roles/{role}/defaults/main.yml").read_text())
    roles_dir = root / "roles"
    for current in ROLES:
        directory = roles_dir / current
        directory.mkdir(parents=True)
        (directory / "defaults").symlink_to(repo_root / f"roles/{current}/defaults", target_is_directory=True)
        (directory / "tasks").mkdir()
        (directory / "tasks/main.yml").write_text(yaml.safe_dump([
            _assert_task("ROLE CONVERGENCE IS FORBIDDEN", ["false"])]))
    (root / "playbooks").mkdir()
    callbacks = root / "callbacks"
    callbacks.mkdir()
    (callbacks / "smoke_audit.py").write_text(CALLBACK)
    stub = root / "kubectl"
    stub.write_text(f"#!{sys.executable}\n" + KUBECTL)
    stub.chmod(0o700)
    manifest = root / "manifest.yml"
    calls, events = root / "calls.jsonl", root / "events.jsonl"
    kubeconfig = str(root / "unused-kubeconfig")  # Deliberately never created/read.
    vip = role == "rke2_kube_vip"
    supplied = {
        "rke2_kube_vip_enabled": True,
        "rke2_kube_vip_api_vip": "192.0.2.72",
        "rke2_kube_vip_interface": "fixture0",
        "rke2_kube_vip_chart_repo": "https://charts.example.test/repository/kube-vip/",
        "rke2_gitlab_runner_enabled": True,
        "rke2_gitlab_runner_gitlab_url": "https://gitlab.example.test",
        "rke2_gitlab_runner_name": "fixture-runner",
        "rke2_gitlab_runner_chart_repo": "https://charts.example.test/repository/gitlab/",
    }
    if overrides:
        if vip:
            supplied[f"{role}_env"] = defaults[f"{role}_env"] | dict(zip(TIMINGS, ("24", "16", "4")))
            supplied[f"{role}_image_tag"] = "v1.2.1@sha256:" + "a" * 64
        else:
            supplied.update({f"{role}_{key}": defaults[f"{role}_{key}"].split("@sha256:")[0] + "@sha256:" + digit * 64
                             for key, digit in zip(RUNNER_OPTIONAL[1:], "abc")})
            supplied[f"{role}_chart_version"] = defaults[f"{role}_chart_version"]
    inventory = root / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {
        "vars": supplied | {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
        "children": {"rke2_servers": {"hosts": {host: {} for host in SERVERS}},
                     "rke2_agents": {"hosts": {"worker-1": {"rke2_node_name": "worker-node"}}}},
    }}, sort_keys=False))

    render_vars = defaults | supplied
    if not vip:
        render_vars.update({
            f"{role}_namespace": "gitlab-runner", f"{role}_release_name": "rke2-gitlab-runner",
            f"{role}_token_secret_name": "rke2-gitlab-runner-token",
            f"{role}_ca_secret_name": "rke2-gitlab-runner-ca",
            f"{role}_job_service_account": "rke2-gitlab-runner-job",
            f"{role}_manager_image_tag": render_vars[f"{role}_manager_image"].split(":", 1)[1],
        })
    template = repo_root / f"roles/{role}/templates/{'kube-vip' if vip else 'gitlab-runner'}-helmchart.yaml.j2"
    render = {"name": "Render independent role fixture", "hosts": "localhost", "connection": "local",
              "gather_facts": False, "vars": render_vars, "tasks": [{
                  "ansible.builtin.copy": {"dest": str(manifest), "mode": "0600",
                      "content": "{{ lookup('ansible.builtin.template', " + json.dumps(str(template)) + ") }}"}}]}
    play["become"] = False
    play["vars"][f"{role}_smoke_kubectl"] = str(stub)
    play["vars"][f"{role}_smoke_kubeconfig"] = kubeconfig
    play["environment"] = {"FIXTURE_CALLS": str(calls), "FIXTURE_MANIFEST": str(manifest),
                           "FIXTURE_HOST": "{{ inventory_hostname }}", "FIXTURE_KUBECONFIG": kubeconfig}
    for task in play["tasks"]:
        if "retries" in task:
            # Ansible skips evaluation of `until` entirely when retries is zero.
            task.update(retries=1, delay=0)
        if "ansible.builtin.command" in task:
            argv = task["ansible.builtin.command"]["argv"]
            task["ansible.builtin.command"]["argv"] = ["--timeout=1s" if arg == "--timeout=300s" else arg for arg in argv]
        if "ansible.builtin.uri" in task:
            del task["ansible.builtin.uri"]
            task["ansible.builtin.assert"] = {"that": [f"{role}_smoke_is_bootstrap | bool"],
                                               "success_msg": "FIXTURE_API_REACHED"}

    # Public defaults must not leak into inventory or clobber supplied values.
    expressions = [f"{key} is {'defined' if key in supplied else 'undefined'}" for key in defaults]
    expressions += [f"{key} == {json.dumps(value)}" for key, value in supplied.items()
                    if isinstance(value, str)]
    expressions += [f"{role}_smoke_defaults.{role}_{'image_tag' if vip else 'chart_version'} == "
                    + json.dumps(defaults[f"{role}_{'image_tag' if vip else 'chart_version'}"])]
    namespace_check = _assert_task("Defaults stay namespaced and inventory stays authoritative", expressions)
    # Place this after the real tasks so RED reproduces the original bug first.
    play["tasks"].append(namespace_check)

    if negative:
        guard = {"when": [f"{role}_smoke_is_bootstrap | bool"]}
        if vip:
            wait = next(task for task in play["tasks"] if task["name"] == "Wait for kube-vip DaemonSet configuration")
            assertion = next(task for task in play["tasks"] if task["name"] == "Assert kube-vip image and leader-election policy")
            play["tasks"].append({"name": "Retain known-good observation for independent assertion checks",
                                  "ansible.builtin.set_fact": {
                                      "fixture_daemonset_config": "{{ rke2_kube_vip_smoke_daemonset_config }}"},
                                  **guard})
            variants = [(key, {f"{role}_env": defaults[f"{role}_env"] | {key: "999"}}) for key in TIMINGS]
            variants += [("image", {f"{role}_image_tag": "v0.0.0"}),
                         ("partial", {f"{role}_env": {TIMINGS[0]: "15"}})]
            for label, variables in variants:
                for phase, task in (("until", wait), ("assert", assertion)):
                    candidate = deepcopy(task)
                    candidate.setdefault("vars", {}).update(variables)
                    if phase == "assert":
                        play["tasks"].append({"name": "Restore independent known-good observation",
                                              "ansible.builtin.set_fact": {
                                                  "rke2_kube_vip_smoke_daemonset_config": "{{ fixture_daemonset_config }}"},
                                              **guard})
                    evidence = ("'vip_renewdeadline' in (ansible_failed_result | to_json)" if label == "partial"
                                else "ansible_failed_result.attempts == 1" if phase == "until"
                                else f"'{label}' in ansible_failed_result.assertion")
                    play["tasks"].append(_rejection(candidate, f"Reject {label} {phase}", evidence) | guard)
        else:
            assertion = next(task for task in play["tasks"] if task["name"] == "Assert RKE2 GitLab Runner security contract")
            for key in RUNNER_OPTIONAL:
                candidate = deepcopy(assertion)
                candidate["vars"][f"{role}_{key}"] = "deliberately-wrong-fixture-value"
                # no_log is retained; rescue inspects only the failed expression.
                play["tasks"].append(_rejection(candidate, f"Reject {key}",
                    f"'{role}_{key}' in ansible_failed_result.assertion") | guard)

    path = root / "playbooks/smoke.yml"
    path.write_text(yaml.safe_dump([render, play], sort_keys=False))
    result = command_runner.run(["ansible-playbook", "-i", inventory, path], environment={
        "ANSIBLE_ROLES_PATH": str(roles_dir), "ANSIBLE_CALLBACK_PLUGINS": str(callbacks),
        "ANSIBLE_CALLBACKS_ENABLED": "smoke_audit", "FIXTURE_EVENTS": str(events),
    }, timeout=70).assert_success()
    audit = [json.loads(line) for line in events.read_text().splitlines()]
    commands = [json.loads(line) for line in calls.read_text().splitlines()]
    assert {host for host, _ in commands} == {SERVERS[0]}
    assert not Path(kubeconfig).exists()
    for task in original_tasks:
        observed = [event for event in audit if event["task"] == task["name"]]
        assert {event["host"] for event in observed} == set(SERVERS), (task["name"], observed)
        assert all(not event["changed"] for event in observed)
        assert next(event for event in observed if event["host"] == SERVERS[0])["status"] == "ok", result.diagnostics()
        if task["name"] != "Assert RKE2 GitLab Runner smoke topology":
            assert all(event["status"] == "skipped" for event in observed if event["host"] != SERVERS[0])
    assert all(event["action"] in allowed | {"ansible.builtin.copy"} for event in audit)
    # Full positive paths issue exactly the expected read-only queries; additional
    # negative kube-vip waits retry once, never a rollout/write. Undefined partial
    # input fails on the first evaluation rather than retrying.
    kinds = Counter(args[args.index("get") + 1] if "get" in args else "rollout" for _, args in commands)
    assert kinds == (Counter(helmchart=1, daemonset=3 + (9 if negative else 0), rollout=1) if vip else
                     Counter(helmchart=1, deployment=2, rollout=1, namespace=1, role=1,
                             rolebinding=1, serviceaccount=2, configmap=1, secret=2, pods=1))
    if negative:
        failures = [event for event in audit if event["status"] == "failed"]
        assert len(failures) == (10 if vip else 4)
        assert all(event["task"].startswith("Reject ") for event in failures)
    else:
        assert all(event["status"] != "failed" for event in audit)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("overrides", [False, True], ids=["omitted-defaults", "private-overrides"])
def test_standalone_smoke_full_play(repo_root, isolated_test_dir, command_runner: CommandRunner, role, overrides):
    _exercise(repo_root, isolated_test_dir, command_runner, role, overrides)


@pytest.mark.parametrize("role", ROLES)
def test_standalone_smoke_rejects_drift(repo_root, isolated_test_dir, command_runner: CommandRunner, role):
    _exercise(repo_root, isolated_test_dir, command_runner, role, False, negative=True)
