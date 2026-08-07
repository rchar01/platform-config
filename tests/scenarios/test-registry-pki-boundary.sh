#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ROLE_DIR="${ROOT_DIR}/roles/pki_host_local_certificate"
DEFAULTS="${ROLE_DIR}/defaults/main.yml"
TASKS="${ROLE_DIR}/tasks/main.yml"
REQUEST_PLAYBOOK="${ROOT_DIR}/playbooks/registry-pki-request.yml"
ACTIVATE_PLAYBOOK="${ROOT_DIR}/playbooks/registry-pki-activate.yml"
TRUST_PLAYBOOK="${ROOT_DIR}/playbooks/registry-pki-trust.yml"
SITE_PLAYBOOK="${ROOT_DIR}/playbooks/site.yml"
INTEGRATION_PLAYBOOK="${ROOT_DIR}/tests/fixtures/registry-pki-boundary/integration.yml"
ACTION_PLUGIN="${ROOT_DIR}/plugins/action/platform_pki_trust_ingress.py"

python3 - "$DEFAULTS" "$TASKS" "$REQUEST_PLAYBOOK" "$ACTIVATE_PLAYBOOK" "$TRUST_PLAYBOOK" "$SITE_PLAYBOOK" "$ACTION_PLUGIN" <<'PY'
import pathlib
import re
import sys

import yaml

defaults_path, tasks_path, request_path, activate_path, trust_path, site_path, action_plugin_path = map(pathlib.Path, sys.argv[1:])
role_dir = defaults_path.parent.parent
trust_helper_path = role_dir / "files" / "platform-pki-host-local-trust"

with defaults_path.open(encoding="utf-8") as stream:
    defaults = yaml.safe_load(stream)
with tasks_path.open(encoding="utf-8") as stream:
    tasks = yaml.safe_load(stream)
with (role_dir / "tasks" / "validate.yml").open(encoding="utf-8") as stream:
    validation_tasks = yaml.safe_load(stream)

if defaults["pki_host_local_certificate_profile"] != "server-p384-sha384-v1":
    raise SystemExit("host-local profile is not frozen")
if defaults["pki_host_local_certificate_request_namespace"] != "platform-pki-csr-request-v1":
    raise SystemExit("request signature namespace is not frozen")
if defaults["pki_host_local_certificate_deployment_namespace"] != "platform-pki-csr-deployment-v1":
    raise SystemExit("deployment signature namespace is not frozen")

common = next(task for task in validation_tasks if task.get("name") == "Validate host-local certificate common contract")
common_assertions = common["ansible.builtin.assert"]["that"]
required = {
    "pki_host_local_certificate_target == inventory_hostname",
    "pki_host_local_certificate_requester_principal == pki_host_local_certificate_target",
    "pki_host_local_certificate_profile == 'server-p384-sha384-v1'",
    "pki_host_local_certificate_deployment_signing_key_path == '/etc/ssh/ssh_host_ed25519_key'",
}
missing = required.difference(common_assertions)
if missing:
    raise SystemExit(f"host-local common contract assertions missing: {sorted(missing)}")

if len(tasks) != 1 or set(tasks[0]) != {"name", "ansible.builtin.fail"}:
    raise SystemExit("implicit host-local role execution is not one unconditional failure")

site = site_path.read_text(encoding="utf-8")
for name in (request_path.name, activate_path.name, trust_path.name):
    if name in site:
        raise SystemExit(f"normal site convergence imports operator-only playbook {name}")

allowed_actions = {
    "ansible.builtin.assert",
    "ansible.builtin.command",
    "ansible.builtin.copy",
    "ansible.builtin.fail",
    "ansible.builtin.file",
    "ansible.builtin.import_tasks",
    "ansible.builtin.stat",
    "platform_pki_trust_ingress",
}
task_metadata = {
    "name", "vars", "loop", "loop_control", "when", "become",
    "delegate_to", "register", "changed_when", "check_mode",
}
metadata_by_action = {
    "ansible.builtin.assert": {"name", "vars", "loop", "loop_control", "when"},
    "ansible.builtin.command": {"name", "register", "changed_when", "check_mode", "when"},
    "ansible.builtin.copy": {"name", "loop", "loop_control", "when"},
    "ansible.builtin.fail": {"name"},
    "ansible.builtin.file": {"name", "loop", "loop_control", "when"},
    "ansible.builtin.import_tasks": {"name", "when"},
    "ansible.builtin.stat": {
        "name", "loop", "loop_control", "become", "delegate_to", "register",
    },
    "platform_pki_trust_ingress": {"name", "when"},
}

def reject_controller_templating(value, source):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_controller_templating(key, source)
            reject_controller_templating(child, source)
    elif isinstance(value, list):
        for child in value:
            reject_controller_templating(child, source)
    elif isinstance(value, str) and re.search(r"\b(?:lookup|query|q)\b", value):
        raise SystemExit(f"controller-side lookup or query is forbidden in {source}")

def validate_task(task, source):
    if not isinstance(task, dict):
        raise SystemExit(f"non-mapping task in {source}")
    if "action" in task or "local_action" in task:
        raise SystemExit(f"dynamic action syntax is forbidden in {source}")
    reject_controller_templating(task, source)
    nested = any(section in task for section in ("block", "rescue", "always"))
    for section in ("block", "rescue", "always"):
        for child in task.get(section, []):
            validate_task(child, source)
    actions = set(task).difference(task_metadata).difference({"block", "rescue", "always"})
    if nested and not actions:
        return
    if len(actions) != 1 or not actions.issubset(allowed_actions):
        raise SystemExit(f"host-local boundary contains a non-allowlisted action in {source}: {sorted(actions)}")
    action = next(iter(actions))
    metadata = set(task).difference(actions)
    if not metadata.issubset(metadata_by_action[action]):
        raise SystemExit(f"host-local boundary contains fail-neutralizing or unexpected metadata in {source}")
    if "when" in task:
        allowed_conditions = {
            ("ansible.builtin.assert", "Require installed helper for non-mutating request preflight"): "ansible_check_mode",
            ("ansible.builtin.assert", "Require installed trust helper for non-mutating bootstrap preflight"): "ansible_check_mode",
            ("ansible.builtin.copy", "Install host-local certificate request helper"): "not ansible_check_mode",
            ("ansible.builtin.copy", "Install host-local certificate trust helper"): "not ansible_check_mode",
            ("ansible.builtin.file", "Create absent host-local certificate helper directory"): "not pki_host_local_certificate_helper_directory.stat.exists",
            ("ansible.builtin.file", "Create absent host-local certificate trust helper directory"): "not ansible_check_mode and not pki_host_local_certificate_trust_helper_directory.stat.exists",
            ("ansible.builtin.command", "Prepare protected target trust ingress"): "not ansible_check_mode and not pki_host_local_certificate_target_trust.stat.exists",
            ("platform_pki_trust_ingress", "Transfer pinned reviewed public trust into protected target ingress"): "not ansible_check_mode and not pki_host_local_certificate_target_trust.stat.exists",
        }
        if task["when"] != allowed_conditions.get((action, task.get("name"))):
            raise SystemExit(f"host-local boundary contains an unexpected conditional in {source}")
    if "ansible.builtin.import_tasks" in actions and task["ansible.builtin.import_tasks"] not in {
        "validate.yml", "validate_trust.yml", "request_apply.yml",
    }:
        raise SystemExit(f"host-local boundary imports an unexpected task file in {source}")
    if action == "ansible.builtin.command" and set(task[action]) != {"argv"}:
        raise SystemExit(f"host-local boundary command must use argv only in {source}")
    if action == "ansible.builtin.command":
        fixed_commands = {
            "Create or validate the target-local certificate request",
            "Prepare protected target trust ingress",
            "Install or validate complete host-local certificate trust tree",
        }
        if task.get("name") not in fixed_commands:
            raise SystemExit(f"host-local boundary contains an unexpected command dispatch in {source}")
    if action == "ansible.builtin.copy":
        fixed_copies = {
            "Install host-local certificate request helper",
            "Install host-local certificate trust helper",
        }
        if task.get("name") not in fixed_copies:
            raise SystemExit(f"host-local boundary contains an unexpected copy transfer in {source}")
        copy_source = str(task[action].get("src", ""))
        if "tls.key" in copy_source or "request_signing_key" in copy_source:
            raise SystemExit(f"host-local boundary copies private key material in {source}")
    if action == "platform_pki_trust_ingress":
        if task.get("name") != "Transfer pinned reviewed public trust into protected target ingress":
            raise SystemExit(f"host-local boundary contains an unexpected trust ingress dispatch in {source}")
        if set(task[action]) != {"sources", "sha256", "ingress_root"}:
            raise SystemExit(f"trust ingress action has unexpected options in {source}")
    if action == "ansible.builtin.file" and task.get("name") not in {
        "Create absent host-local certificate helper directory",
        "Create absent host-local certificate trust helper directory",
    }:
        raise SystemExit(f"host-local boundary contains an unexpected file mutation in {source}")

executable_files = []
for directory in (role_dir / "tasks", role_dir / "handlers"):
    if directory.is_dir():
        executable_files += sorted(directory.rglob("*.yml"))
        executable_files += sorted(directory.rglob("*.yaml"))
for executable in executable_files:
    with executable.open(encoding="utf-8") as stream:
        for task in yaml.safe_load(stream):
            validate_task(task, executable)

meta_files = []
if (role_dir / "meta").is_dir():
    meta_files += sorted((role_dir / "meta").rglob("*.yml"))
    meta_files += sorted((role_dir / "meta").rglob("*.yaml"))
for meta_path in meta_files:
    with meta_path.open(encoding="utf-8") as stream:
        metadata = yaml.safe_load(stream) or {}
    if metadata.get("dependencies"):
        raise SystemExit(f"host-local role dependencies are forbidden: {meta_path}")

def validate_operator_playbook(plays, expected_tasks_from, source):
    reject_controller_templating(plays, source)
    if not isinstance(plays, list) or len(plays) != 1:
        raise SystemExit(f"{source} must contain exactly one play")
    play = plays[0]
    required_play_keys = {"name", "hosts", "become", "gather_facts", "tasks"}
    if set(play) != required_play_keys:
        raise SystemExit(f"{source} contains imports, roles, handlers, or another executable section")
    if play.get("hosts") != "registry" or play.get("become") is not True or play.get("gather_facts") is not False:
        raise SystemExit(f"{source} is not constrained to the registry boundary")
    play_tasks = play.get("tasks", [])
    if len(play_tasks) != 1:
        raise SystemExit(f"{source} must contain exactly one structural role dispatch")
    task = play_tasks[0]
    if set(task) != {"name", "ansible.builtin.include_role"}:
        raise SystemExit(f"{source} contains an unexpected playbook action")
    if task["ansible.builtin.include_role"] != {
        "name": "pki_host_local_certificate",
        "tasks_from": expected_tasks_from,
    }:
        raise SystemExit(f"{source} does not structurally pin {expected_tasks_from}")

for playbook_path, tasks_from in (
    (request_path, "request"),
    (activate_path, "activate"),
    (trust_path, "trust"),
):
    with playbook_path.open(encoding="utf-8") as stream:
        validate_operator_playbook(yaml.safe_load(stream), tasks_from, playbook_path)

bad_examples = [
    {"name": "short action", "copy": {"src": "tls.key"}},
    {"name": "collection action", "community.crypto.openssl_privatekey": {}},
    {"name": "dynamic action", "action": "copy src=tls.key dest=/tmp/key"},
    {"name": "nested action", "block": [{"ansible.builtin.copy": {"src": "tls.key"}}]},
    {"name": "concealed private transfer", "ansible.builtin.copy": {"content": "private", "dest": "/tmp/tls.key"}},
    {"name": "foreign argv command", "ansible.builtin.command": {"argv": ["/bin/true"]}},
    {"name": "foreign custom action", "unsafe_local_action": {}},
    {"name": "misnamed trust ingress", "platform_pki_trust_ingress": {"sources": {}, "sha256": {}, "ingress_root": "/tmp"}},
    {"name": "foreign import", "ansible.builtin.import_tasks": "mutate.yml"},
    {"name": "controller lookup", "ansible.builtin.assert": {"that": ["lookup('pipe', 'id')"]}},
    {"name": "parenthesized controller lookup", "ansible.builtin.assert": {"that": ["(lookup)('pipe', 'id')"]}},
    {"name": "parenthesized controller query", "ansible.builtin.assert": {"that": ["(query)('pipe', 'id')"]}},
    {"name": "parenthesized controller q", "ansible.builtin.assert": {"that": ["(q)('pipe', 'id')"]}},
    {"name": "ignored failure", "ansible.builtin.fail": {"msg": "stop"}, "ignore_errors": True},
    {"name": "skipped assertion", "ansible.builtin.assert": {"that": [True]}, "when": False},
]
for bad in bad_examples:
    try:
        validate_task(bad, "scanner self-test")
    except SystemExit:
        continue
    raise SystemExit(f"module allowlist scanner accepted unsafe fixture: {bad['name']}")

bad_playbooks = [
    [{"import_playbook": "mutate.yml"}],
    [{"hosts": "registry", "gather_facts": False, "roles": ["mutating_role"]}],
    [
        {"hosts": "registry", "gather_facts": False, "tasks": []},
        {"hosts": "registry", "gather_facts": False, "roles": ["mutating_role"]},
    ],
    [
        {
            "name": "{{ lookup('pipe', 'id') }}",
            "hosts": "registry",
            "become": True,
            "gather_facts": False,
            "tasks": [
                {
                    "name": "request",
                    "ansible.builtin.include_role": {
                        "name": "pki_host_local_certificate",
                        "tasks_from": "request",
                    },
                }
            ],
        }
    ],
    [
        {
            "name": "request",
            "hosts": "registry",
            "become": True,
            "gather_facts": False,
            "tasks": [
                {
                    "name": "{{ query('pipe', 'id') }}",
                    "ansible.builtin.include_role": {
                        "name": "pki_host_local_certificate",
                        "tasks_from": "request",
                    },
                }
            ],
        }
    ],
]
for bad in bad_playbooks:
    try:
        validate_operator_playbook(bad, "request", "playbook scanner self-test")
    except SystemExit:
        continue
    raise SystemExit("operator playbook scanner accepted an unsafe fixture")

if not trust_helper_path.is_file() or not trust_helper_path.stat().st_mode & 0o111:
    raise SystemExit("dedicated target trust helper is missing or not executable")
if not action_plugin_path.is_file():
    raise SystemExit("pinned controller trust ingress action plugin is missing")
trust_tasks = (role_dir / "tasks" / "trust.yml").read_text(encoding="utf-8")
request_tasks = (role_dir / "tasks" / "request.yml").read_text(encoding="utf-8")
request_apply_tasks = (role_dir / "tasks" / "request_apply.yml").read_text(encoding="utf-8")
if "platform-pki-host-local-trust" not in trust_tasks:
    raise SystemExit("trust action does not structurally dispatch the dedicated helper")
if "platform_pki_trust_ingress" not in trust_tasks:
    raise SystemExit("trust action does not structurally dispatch the pinned ingress action")
action_plugin = action_plugin_path.read_text(encoding="utf-8")
for required_fragment in ("O_NOFOLLOW", "source.recheck()", "self._transfer_data", "REPOSITORY_ROOT"):
    if required_fragment not in action_plugin:
        raise SystemExit(f"pinned ingress action is missing required boundary logic: {required_fragment}")
if "trust_sources" in request_tasks or "trust_sources" in request_apply_tasks:
    raise SystemExit("request action attempts to source or install controller trust")
for forbidden in ("tls.key", "request_signing_key", "private_key"):
    if forbidden in trust_tasks:
        raise SystemExit(f"trust action references forbidden private-key material: {forbidden}")
PY

ansible-playbook --check -i localhost, "$INTEGRATION_PLAYBOOK"

printf '%s\n' 'Registry host-local PKI boundary checks passed.'
