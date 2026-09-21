"""Client Ansible contracts; helper crypto and privilege boundaries live elsewhere.

The response harness substitutes only trust/helper installation. The entry point,
validator, filesystem include, commands, conditionals and result guards are real.
Scripted helper processes check argv and record calls; they do not implement PKI.
"""

from __future__ import annotations

import copy
import itertools
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from ansible_test_helpers import run_playbook
from conftest import CommandRunner
# Import the existing fixture chain to exercise the real schema-4 facade output.
from test_pki_host_local_gitlab import GitLabCase, assert_bounded, client_case, gitlab_case


ROLE = "pki_host_local_certificate"
PREFIX = "pki_host_local_certificate_"
REQUEST_ID = "a" * 32
STATES = ("request-pending", "response-partial", "response-ready", "staged-pending", "staged")
FIRST_GUARD = "Validate issue-only client inputs before target mutation"
PATH_GUARD = "Validate fixed client lifecycle paths"
TRANSPORT_GUARD = "Validate selected client transport inputs"
TRUST_GUARD = "Validate host-local certificate trust bootstrap contract"
DESTINATION_GUARD = "Reject client helper and transport paths that alias protected state"


def load(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def write_yaml(path: Path, value: Any) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False))


def named(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(task for task in tasks if task.get("name") == name)


def client_vars(repo_root: Path, root: Path, transport: str = "filesystem") -> dict[str, Any]:
    variables = load(repo_root / "roles" / ROLE / "defaults/main.yml")
    values: dict[str, Any] = dict(
        service="telemetry-client", target="localhost", requester_principal="localhost",
        response_principal="response.test", operation="issue",
        profile="client-p384-sha384-v1", service_adapter="client-stage-v1",
        transport=transport, current_cert_sha256="none", inventory_sha256="b" * 64,
        subject_cn="telemetry-01", subject_ou="metrics", subject_o="Example", subject_c="US",
        validity_days=397, minimum_remaining_lifetime_seconds=2592000,
        state_root=str(root / "state"), pending_root=str(root / "pending"),
        versions_root=str(root / "versions"), filesystem_exchange_root=str(root / "exchange"),
        filesystem_owner_uid=1000, trust_id="reviewed-v3",
        gitlab_spool_root=str(root / "spool"),
        gitlab_config_path=str(root / "gitlab.json"),
        gitlab_project_record_source=str(root / "project"),
        gitlab_ca_source=str(root / "ca.crt"),
        platform_pki_source=str(root / "platform-pki"), platform_pki_sha256="c" * 64,
    )
    trust_names = ("approvers.allowed_signers", "policy", "requesters.allowed_signers", "responses.allowed_signers")
    values["trust_paths"] = {
        name: f"{values['state_root']}/trust/reviewed-v3/{name}" for name in trust_names
    }
    values["trust_sources"] = {name: str(root / "reviewed" / name) for name in trust_names}
    values["trust_sha256"] = dict.fromkeys(trust_names, "d" * 64)
    variables.update({PREFIX + key: value for key, value in values.items()})
    return variables


def play(variables: dict[str, Any], tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return dict(name=name, hosts="localhost", connection="local", gather_facts=False,
                vars=variables, tasks=tasks)


def rejected(tasks: list[dict[str, Any]], failure_task: str) -> dict[str, Any]:
    # The deliberate failure cannot satisfy rescue: the exact production assert
    # must reject, rather than an undefined variable or later helper invocation.
    return {
        "block": tasks + [{"name": "Unexpected acceptance", "ansible.builtin.fail": {"msg": "accepted"}}],
        "rescue": [{"ansible.builtin.assert": {"that": [
            "ansible_failed_task.action == 'ansible.builtin.assert'",
            "ansible_failed_task.name == " + json.dumps(failure_task),
            "ansible_failed_result.assertion is defined or "
            "(ansible_failed_result.results | default([]) | selectattr('assertion', 'defined') | list | length > 0)",
        ]}}],
    }


def task_chain(directory: Path, entry: str) -> list[dict[str, Any]]:
    """Walk every include and nested branch; reject opaque/dynamic task routes."""
    result: list[dict[str, Any]] = []

    def walk(tasks: list[dict[str, Any]], ancestors: tuple[str, ...]) -> None:
        for task in tasks:
            result.append(task)
            for action in ("ansible.builtin.import_tasks", "ansible.builtin.include_tasks"):
                if action in task:
                    child = task[action]
                    assert isinstance(child, str) and "{{" not in child
                    assert child not in ancestors
                    walk(load(directory / child), (*ancestors, child))
            for branch in ("block", "rescue", "always"):
                walk(task.get(branch, []), ancestors)

    walk(load(directory / entry), (entry,))
    return result


@pytest.mark.parametrize("entry", ["client_request_publish.yml", "client_response_stage.yml"])
def test_client_task_chains_validate_first_and_never_activate(repo_root: Path, entry: str) -> None:
    directory = repo_root / "roles" / ROLE / "tasks"
    tasks = load(directory / entry)
    assert tasks[0]["ansible.builtin.import_tasks"] == "validate_client_stage.yml"
    if entry == "client_request_publish.yml":
        assert [task["ansible.builtin.import_tasks"] for task in tasks] == [
            "validate_client_stage.yml", "request_exchange.yml",
        ]
    else:
        assert [task["ansible.builtin.import_tasks"] for task in tasks
                if "ansible.builtin.import_tasks" in task] == [
            "validate_client_stage.yml", "trust.yml", "gitlab_setup.yml", "filesystem_response.yml",
        ]
    validator = task_chain(directory, "validate_client_stage.yml")
    assert all(set(task) <= {"name", "ansible.builtin.assert", "ansible.builtin.import_tasks",
                             "vars", "loop", "loop_control"} for task in validator)
    chain = task_chain(directory, entry)
    source = yaml.safe_dump(chain)
    for forbidden in ("systemd", "ansible.builtin.service", "ansible.builtin.shell",
                      "ansible.builtin.include_role", "ansible.builtin.import_role",
                      "ansible.builtin.fetch", "ansible.builtin.slurp", "target-activate",
                      "target-recover", "response_activate.yml", "response_preflight.yml",
                      "systemctl", "state: link"):
        assert forbidden not in source
    for task in chain:
        for action in ("ansible.builtin.file", "ansible.builtin.copy", "ansible.builtin.template"):
            if action in task:
                destination = task[action].get("dest", task[action].get("path", ""))
                assert "current" not in destination
                assert "tls.key" not in yaml.safe_dump(task[action])
    commands = [yaml.safe_dump(task["ansible.builtin.command"]) for task in chain
                if "ansible.builtin.command" in task]
    if entry == "client_response_stage.yml":
        assert sum("target-stage-status" in command for command in commands) == 2
        assert any("response-download" in command for command in commands)
        assert any("target-response-import" in command for command in commands)
        assert any("target-response-install" in command for command in commands)


def test_client_validator_rejects_early_input_matrix(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
) -> None:
    validator = {"ansible.builtin.import_tasks": str(
        repo_root / "roles" / ROLE / "tasks/validate_client_stage.yml"
    )}
    cases: list[tuple[str, str, dict[str, Any], str]] = []
    for field, values in {
        "operation": ["renew", ""], "profile": ["server-p384-sha384-v1"],
        "service_adapter": ["zot-v1", "openbao-pristine-v1"],
        "service": ["", "bad/service"], "target": ["other.test"],
        "requester_principal": ["other.test"], "transport": ["direct"],
        "subject_cn": ["", "bad name", "a" * 65], "subject_ou": [""],
        "subject_o": [""], "subject_c": ["us", "USA"],
        "common_name": ["server.test"], "dns_sans": [["server.test"], "[]"],
        "ip_sans": [["192.0.2.1"], "[]"], "current_cert_sha256": ["a" * 64],
        "current_cert_path": ["/old/tls.crt"], "inventory_sha256": ["", "A" * 64],
        "request_namespace": ["platform-pki-csr-request-v1"],
        "validity_days": [0, 365001, "397", True, 1.5],
        "minimum_remaining_lifetime_seconds": [0, "1", True],
        "request_ttl_seconds": [0, 604801, "3600", True],
    }.items():
        for value in values:
            cases.append((f"{field}={value!r}", "filesystem", {field: value}, FIRST_GUARD))
    for transport in ("filesystem", "gitlab"):
        roots = ["state_root", "pending_root", "versions_root",
                 "filesystem_exchange_root" if transport == "filesystem" else "gitlab_spool_root"]
        for left, right in itertools.combinations(roots, 2):
            for suffix in ("", "/nested"):
                cases.append((f"{transport}:{left}/{right}{suffix}", transport,
                              {left: "/overlap", right: "/overlap" + suffix}, FIRST_GUARD))
        for path in ("relative", "/unsafe/../path", "/unsafe/./path", "/trailing/", "/newline\n"):
            cases.append((f"{transport}:path={path!r}", transport, {roots[-1]: path}, PATH_GUARD))
    for field, values in {
        "filesystem_owner_uid": [None, 0, -1, "1000", True],
        "gitlab_timeout": [0, 121, "30", True],
        "gitlab_processing_attempts": [0, 21, "5", True],
        "gitlab_processing_interval": [-1, 61, "2", True],
        "platform_pki_sha256": ["", "A" * 64],
    }.items():
        transport = "filesystem" if field.startswith("filesystem") else "gitlab"
        cases.extend((f"{field}={value!r}", transport, {field: value}, TRANSPORT_GUARD)
                     for value in values)
    cases.append(("missing reviewed trust", "filesystem", {"trust_sources": {}}, TRUST_GUARD))
    plays = []
    for transport in ("filesystem", "gitlab"):
        variables = client_vars(repo_root, isolated_test_dir, transport)
        plays.append(play(variables, [validator], f"Accept reviewed {transport} client"))
    for label, transport, changes, guard in cases:
        variables = client_vars(repo_root, isolated_test_dir, transport)
        variables.update({PREFIX + key: value for key, value in changes.items()})
        plays.append(play(variables, [rejected([validator], guard)], label))
    path = isolated_test_dir / "validator.yml"
    write_yaml(path, plays)
    result = run_playbook(command_runner, path, timeout=120).assert_success()
    assert "changed=0" in result.stdout
    for name in ("state", "pending", "versions", "exchange", "spool"):
        assert not (isolated_test_dir / name).exists()


def stage_status(variables: dict[str, Any], status: str) -> dict[str, Any]:
    result = dict(
        kind="platform-config-target-local-certificate-stage-status", schema="2",
        service=variables[PREFIX + "service"], target="localhost", request_id=REQUEST_ID,
        status=status, required_action={
            "request-pending": "await-response", "response-partial": "await-response",
            "response-ready": "install-response", "staged-pending": "install-response", "staged": "none",
        }[status],
    )
    if status in ("response-ready", "staged-pending", "staged"):
        result.update(artifact_sha256="1" * 64, certificate_sha256="2" * 64, certificate_spki_sha256="3" * 64)
    if status in ("staged-pending", "staged"):
        result["version_path"] = variables[PREFIX + "versions_root"] + "/" + REQUEST_ID
    return result


def gitlab_download_status(status: str) -> dict[str, Any]:
    # Response identity is authenticated by the mandatory final stage-status,
    # not exposed by the GitLab facade's bounded public download result.
    return {
        "schema": 2,
        "kind": "platform-config-target-local-gitlab-status",
        "command": "response-download",
        "status": status,
    }


SPY = '''import json
import pathlib
import sys

root = pathlib.Path(__file__).parent
queue = json.loads((root / "queue.json").read_text())
log = root / "calls.jsonl"
calls = log.read_text().splitlines() if log.exists() else []
argv = sys.argv[1:]
with log.open("a") as stream:
    stream.write(json.dumps(argv) + "\\n")
expected = queue[len(calls)]
if argv != expected["argv"]:
    sys.exit("unexpected helper argv: " + repr(argv))
print(json.dumps(expected["output"]))
'''


@pytest.fixture
def response_role(repo_root: Path, isolated_test_dir: Path) -> Path:
    directory = isolated_test_dir / "roles" / ROLE
    shutil.copytree(repo_root / "roles" / ROLE / "tasks", directory / "tasks")
    # Installation/crypto have their own tests. No response task or transport
    # include is rewritten, so skip conditions and registered results stay real.
    for entry in ("trust.yml", "gitlab_setup.yml"):
        write_yaml(directory / "tasks" / entry, [{
            "name": "Fixture reviewed helpers already installed",
            "ansible.builtin.debug": {"msg": "installation boundary"},
        }])
    return directory


def prepare_response_case(
    repo_root: Path, root: Path, transport: str, initial: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    root.mkdir()
    variables = client_vars(repo_root, root, transport)
    for helper in ("lifecycle", "gitlab"):
        spy = root / f"{helper}-helper"
        spy.write_text(f"#!{sys.executable}\n" + SPY)
        spy.chmod(0o755)
        variables[PREFIX + f"{helper}_helper_path"] = str(spy)
    common = ["--state-root", str(root / "state"), "--pending-root", str(root / "pending"),
              "--versions-root", str(root / "versions"), "--service", "telemetry-client",
              "--target", "localhost", "--service-adapter", "client-stage-v1"]
    candidate = ["--trust-id", "reviewed-v3", "--subject-cn", "telemetry-01",
                 "--subject-ou", "metrics", "--subject-o", "Example", "--subject-c", "US",
                 "--validity-days", "397", "--minimum-remaining-lifetime-seconds", "2592000"]
    final = stage_status(variables, "staged")
    status_argv = ["target-stage-status", *common, *candidate]
    queue = [dict(argv=status_argv, output=stage_status(variables, initial))]
    if initial != "staged":
        if transport == "gitlab":
            queue.append(dict(argv=["response-download", "--config", str(root / "gitlab.json")],
                              output=gitlab_download_status(
                                  "existing" if initial == "staged-pending" else "installed")))
        else:
            queue.append(dict(argv=["target-response-prepare", *common, "--trust-id", "reviewed-v3"],
                              output=dict(status="existing", request_id=REQUEST_ID, ingress_device=1,
                                          ingress_inode=2, ingress_dir=str(root / "versions" / (".ingress-" + REQUEST_ID)))))
            if initial in ("request-pending", "response-partial"):
                queue.append(dict(argv=["target-response-import", *common, "--trust-id", "reviewed-v3",
                                        "--exchange-root", str(root / "exchange"), "--input-owner-uid", "1000"],
                                  output=dict(status="imported", request_id=REQUEST_ID)))
            installed = {key: value for key, value in final.items()
                         if key in {"status", "request_id", "version_path", "artifact_sha256",
                                    "certificate_sha256", "certificate_spki_sha256"}}
            queue.append(dict(argv=["target-response-install", *common, *candidate], output=installed))
    queue.append(dict(argv=status_argv, output=final))
    return variables, queue


def test_response_routes_initial_partial_complete_ingress_and_replay(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner, response_role: Path,
) -> None:
    plays = []
    queues = []
    for transport, state in itertools.product(("filesystem", "gitlab"), STATES):
        root = isolated_test_dir / f"{transport}-{state}"
        variables, queue = prepare_response_case(repo_root, root, transport, state)
        (root / "queue.json").write_text(json.dumps(queue))
        queues.append((root, queue))
        plays.append(play(variables, [{"ansible.builtin.import_tasks": str(response_role / "tasks/client_response_stage.yml")}],
                          f"{transport}: {state}"))
    path = isolated_test_dir / "responses.yml"
    write_yaml(path, plays)
    result = run_playbook(command_runner, path, timeout=120).assert_success()
    assert "Report client staging without claiming activation" in result.stdout
    for root, queue in queues:
        calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
        assert calls == [item["argv"] for item in queue]
        assert not (root / "versions/current").exists()


def test_response_rejects_transport_evidence_before_final_status(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner, response_role: Path,
) -> None:
    cases = [
        ("gitlab", "response-download", "status", "staged", "Validate the client GitLab staging result"),
        # Even a well-formed extra request_id violates the four-key facade contract.
        ("gitlab", "response-download", "request_id", "b" * 32, "Validate the client GitLab staging result"),
        ("filesystem", "target-response-prepare", "request_id", "b" * 32, "Validate filesystem response ingress preparation"),
        ("filesystem", "target-response-import", "request_id", "b" * 32, "Validate filesystem response import result"),
        ("filesystem", "target-response-install", "status", "installed", "Validate filesystem response installation result"),
    ]
    plays = []
    queues = []
    for index, (transport, command, field, value, guard) in enumerate(cases):
        root = isolated_test_dir / f"bad-{index}"
        variables, queue = prepare_response_case(repo_root, root, transport, "request-pending")
        stop = next(i for i, item in enumerate(queue) if item["argv"][0] == command)
        queue[stop]["output"][field] = value
        queue = queue[:stop + 1]
        (root / "queue.json").write_text(json.dumps(queue))
        queues.append((root, queue))
        plays.append(play(variables, [rejected([
            {"ansible.builtin.import_tasks": str(response_role / "tasks/client_response_stage.yml")},
        ], guard)], f"Reject {command} {field}"))
    path = isolated_test_dir / "bad-responses.yml"
    write_yaml(path, plays)
    run_playbook(command_runner, path).assert_success()
    for root, queue in queues:
        assert [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()] == [
            item["argv"] for item in queue
        ]


def test_stage_status_guards_require_exact_final_identity_and_metadata(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
) -> None:
    tasks = load(repo_root / "roles" / ROLE / "tasks/client_response_stage.yml")
    initial_guard = named(tasks, "Require actionable client staging state")
    final_guard = named(tasks, "Require complete client staging evidence")
    assert named(tasks, "Report client staging without claiming activation")["ansible.builtin.debug"] == {
        "msg": "{{ pki_host_local_certificate_client_final_status.stdout | from_json }}",
    }
    variables = client_vars(repo_root, isolated_test_dir)
    initial = stage_status(variables, "request-pending")
    final = stage_status(variables, "staged")
    plays = []
    for guard, baseline, result_name in (
        (initial_guard, initial, "actionable_status_result"),
        (final_guard, final, "client_final_status"),
    ):
        mutations = [("kind", "platform-config-target-local-certificate-status"), ("schema", 2),
                     ("service", "other-client"), ("target", "other.test"), ("request_id", "bad"),
                     ("status", "complete")]
        if guard is final_guard:
            mutations += [("request_id", "b" * 32), ("required_action", "activate-response"),
                          ("version_path", str(isolated_test_dir / "versions/current")), ("extra", "field")]
            mutations += [(key, "A" * 64) for key in
                          ("artifact_sha256", "certificate_sha256", "certificate_spki_sha256")]
            mutations += [("status", state) for state in STATES if state != "staged"]
            mutations += [("missing", key) for key in final]
        else:
            mutations += [("status", "none"), ("status", "activating")]
        for field, value in [(None, None), *mutations, ("stderr", "helper warning")]:
            inputs = copy.deepcopy(variables)
            inputs[PREFIX + "actionable_status_result"] = dict(stdout=json.dumps(initial), stderr="")
            inputs[PREFIX + "client_final_status"] = dict(stdout=json.dumps(final), stderr="")
            status = dict(baseline)
            if field == "missing":
                status.pop(value)
            elif field not in (None, "stderr"):
                status[field] = value
                if guard is final_guard and field == "request_id":
                    # Keep the version path consistent with the wrong ID so a
                    # path mismatch cannot mask a missing request-ID binding.
                    status["version_path"] = variables[PREFIX + "versions_root"] + "/" + value
            inputs[PREFIX + result_name] = dict(stdout=json.dumps(status), stderr=value if field == "stderr" else "")
            checked = [guard] if field is None else [rejected([guard], guard["name"])]
            plays.append(play(inputs, checked, f"{guard['name']}: {field}"))
    path = isolated_test_dir / "status-guards.yml"
    write_yaml(path, plays)
    run_playbook(command_runner, path).assert_success()


def test_real_schema_four_facade_download_result_passes_ansible_guard(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    client_case: GitLabCase,
) -> None:
    assert client_case.config["schema"] == 4
    published = client_case.run("request-publish")
    assert published.returncode == 0, published.stderr
    tasks = load(repo_root / "roles" / ROLE / "tasks/client_response_stage.yml")
    guard = named(tasks, "Validate the client GitLab staging result")
    plays = []
    for status in ("installed", "existing"):
        result = client_case.run("response-download")
        assert_bounded(result, "response-download", status)
        assert json.loads(result.stdout) == gitlab_download_status(status)
        variables = {PREFIX + "client_download": dict(stdout=result.stdout, stderr=result.stderr)}
        plays.append(play(variables, [guard], f"Validate actual facade {status} JSON"))
    path = isolated_test_dir / "facade-output.yml"
    write_yaml(path, plays)
    run_playbook(command_runner, path).assert_success()


def test_response_routes_reject_final_request_identity_mismatch(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner, response_role: Path,
) -> None:
    plays = []
    queues = []
    for transport in ("filesystem", "gitlab"):
        root = isolated_test_dir / f"wrong-final-{transport}"
        variables, queue = prepare_response_case(repo_root, root, transport, "request-pending")
        queue[-1]["output"]["request_id"] = "b" * 32
        queue[-1]["output"]["version_path"] = str(root / "versions" / ("b" * 32))
        (root / "queue.json").write_text(json.dumps(queue))
        queues.append((root, queue))
        rejection = rejected([
            {"ansible.builtin.import_tasks": str(response_role / "tasks/client_response_stage.yml")},
        ], "Require complete client staging evidence")
        rejection["rescue"][0]["ansible.builtin.assert"]["that"].append(
            "ansible_failed_result.assertion == " + json.dumps(
                "pki_host_local_certificate_client_status.request_id "
                "== (pki_host_local_certificate_actionable_status_result.stdout | from_json).request_id"
            )
        )
        plays.append(play(variables, [rejection], f"Bind final {transport} request ID"))
    path = isolated_test_dir / "wrong-final-identity.yml"
    write_yaml(path, plays)
    run_playbook(command_runner, path).assert_success()
    for root, queue in queues:
        assert [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()] == [
            item["argv"] for item in queue
        ]


def test_client_validator_rejects_destination_collisions_before_mutation(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
) -> None:
    validator = {"ansible.builtin.import_tasks": str(
        repo_root / "roles" / ROLE / "tasks/validate_client_stage.yml"
    )}
    plays = []
    for transport in ("filesystem", "gitlab"):
        baseline = client_vars(repo_root, isolated_test_dir, transport)
        collisions = [
            ("request_helper_path", baseline[PREFIX + "request_signing_key_path"]),
            ("lifecycle_helper_path", baseline[PREFIX + "request_helper_path"]),
            ("trust_helper_path", baseline[PREFIX + "request_helper_path"]),
            ("request_helper_path", baseline[PREFIX + "trust_paths"]["policy"]),
        ]
        for root_name in ("state_root", "pending_root", "versions_root"):
            root = Path(baseline[PREFIX + root_name])
            for destination in (root, root / "helper", root.parent):
                collisions.append(("request_helper_path", str(destination)))
        if transport == "gitlab":
            collisions += [
                ("gitlab_helper_path", baseline[PREFIX + "lifecycle_helper_path"]),
                ("gitlab_config_path", baseline[PREFIX + "gitlab_token_path"]),
                ("gitlab_project_record_path", baseline[PREFIX + "gitlab_ca_path"]),
                ("platform_pki_path", baseline[PREFIX + "request_helper_path"]),
                ("gitlab_config_path", baseline[PREFIX + "state_root"] + "/config.json"),
            ]
        for field, destination in collisions:
            variables = dict(baseline)
            variables[PREFIX + field] = destination
            plays.append(play(variables, [rejected([validator], DESTINATION_GUARD)],
                              f"Reject {transport} {field} collision: {destination}"))
    path = isolated_test_dir / "destination-collisions.yml"
    write_yaml(path, plays)
    result = run_playbook(command_runner, path).assert_success()
    assert "changed=0" in result.stdout
    for name in ("state", "pending", "versions", "exchange", "spool"):
        assert not (isolated_test_dir / name).exists()


def test_client_gitlab_config_is_local_schema_four_with_typed_identity(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
) -> None:
    tasks = load(repo_root / "roles" / ROLE / "tasks/gitlab_setup.yml")
    server = named(tasks, "Install target-local GitLab facade configuration")
    client = named(tasks, "Install target-local GitLab client-stage facade configuration")
    assert server["when"] == "pki_host_local_certificate_service_adapter != 'client-stage-v1'"
    assert client["when"] == "pki_host_local_certificate_service_adapter == 'client-stage-v1'"
    assert client["ansible.builtin.copy"]["mode"] == "0600"
    assert client["ansible.builtin.copy"]["owner"] == "root"
    assert client["ansible.builtin.copy"]["group"] == "root"
    # Exercise both production selectors and actual copy rendering in an
    # unprivileged temporary directory; ownership itself is checked above.
    rendered_tasks = copy.deepcopy([server, client])
    for task in rendered_tasks:
        task["ansible.builtin.copy"].pop("owner")
        task["ansible.builtin.copy"].pop("group")
    variables = client_vars(repo_root, isolated_test_dir, "gitlab")
    path = isolated_test_dir / "render.yml"
    write_yaml(path, [play(variables, rendered_tasks, "Render client config")])
    run_playbook(command_runner, path).assert_success()
    output = isolated_test_dir / "gitlab.json"
    config = json.loads(output.read_text())
    assert output.stat().st_mode & 0o777 == 0o600
    assert config["schema"] == 4
    assert config["kind"] == "platform-config-target-local-gitlab"
    assert config["profile"] == "client-p384-sha384-v1"
    assert config["service_adapter"] == "client-stage-v1"
    assert config["operation"] == "issue"
    assert config["current_cert_sha256"] == config["current_cert_path"] == "none"
    assert config["common_name"] == ""
    assert config["dns_sans"] == config["ip_sans"] == []
    for key in ("subject_cn", "subject_ou", "subject_o", "subject_c", "service", "target"):
        assert config[key] == variables[PREFIX + key]
    for key, value in dict(validity_days=397, request_ttl_seconds=3600,
                           minimum_remaining_lifetime_seconds=2592000, timeout=30,
                           processing_attempts=5, processing_interval=2).items():
        assert type(config[key]) is int
        assert config[key] == value
    assert config["token_file"] == variables[PREFIX + "gitlab_token_path"]
    assert not {"service_unit", "service_config", "node_dns", "node_address", "endpoint",
                "rollback_seconds", "writer", "token"}.intersection(config)


def test_client_validator_rejects_non_string_subject_before_installation(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
) -> None:
    # The GitLab facade requires a string subject. Regex tests must not silently
    # coerce an inventory integer and defer rejection until after installation.
    variables = client_vars(repo_root, isolated_test_dir, "gitlab")
    variables[PREFIX + "subject_cn"] = 17
    validator = {"ansible.builtin.import_tasks": str(
        repo_root / "roles" / ROLE / "tasks/validate_client_stage.yml"
    )}
    path = isolated_test_dir / "subject-type.yml"
    write_yaml(path, [play(variables, [rejected([validator], FIRST_GUARD)], "Reject integer client CN")])
    run_playbook(command_runner, path).assert_success()
