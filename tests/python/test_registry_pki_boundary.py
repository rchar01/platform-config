from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import CommandRunner


ALLOWED_ACTIONS = {
    "ansible.builtin.assert",
    "ansible.builtin.command",
    "ansible.builtin.copy",
    "ansible.builtin.fail",
    "ansible.builtin.file",
    "ansible.builtin.import_tasks",
    "ansible.builtin.stat",
    "platform_pki_trust_ingress",
}
TASK_METADATA = {
    "name",
    "vars",
    "loop",
    "loop_control",
    "when",
    "become",
    "delegate_to",
    "register",
    "changed_when",
    "check_mode",
}
METADATA_BY_ACTION = {
    "ansible.builtin.assert": {"name", "vars", "loop", "loop_control", "when"},
    "ansible.builtin.command": {
        "name",
        "register",
        "changed_when",
        "check_mode",
        "when",
    },
    "ansible.builtin.copy": {"name", "loop", "loop_control", "when"},
    "ansible.builtin.fail": {"name"},
    "ansible.builtin.file": {"name", "loop", "loop_control", "when"},
    "ansible.builtin.import_tasks": {"name", "when"},
    "ansible.builtin.stat": {
        "name",
        "loop",
        "loop_control",
        "become",
        "delegate_to",
        "register",
    },
    "platform_pki_trust_ingress": {"name", "when"},
}
ALLOWED_CONDITIONS = {
    (
        "ansible.builtin.assert",
        "Require installed helper for non-mutating request preflight",
    ): "ansible_check_mode",
    (
        "ansible.builtin.assert",
        "Require installed trust helper for non-mutating bootstrap preflight",
    ): "ansible_check_mode",
    (
        "ansible.builtin.copy",
        "Install host-local certificate request helper",
    ): "not ansible_check_mode",
    (
        "ansible.builtin.copy",
        "Install host-local certificate trust helper",
    ): "not ansible_check_mode",
    (
        "ansible.builtin.file",
        "Create absent host-local certificate helper directory",
    ): "not pki_host_local_certificate_helper_directory.stat.exists",
    (
        "ansible.builtin.file",
        "Create absent host-local certificate trust helper directory",
    ): (
        "not ansible_check_mode and not "
        "pki_host_local_certificate_trust_helper_directory.stat.exists"
    ),
    (
        "ansible.builtin.command",
        "Prepare protected target trust ingress",
    ): (
        "not ansible_check_mode and not "
        "pki_host_local_certificate_target_trust.stat.exists"
    ),
    (
        "platform_pki_trust_ingress",
        "Transfer pinned reviewed public trust into protected target ingress",
    ): (
        "not ansible_check_mode and not "
        "pki_host_local_certificate_target_trust.stat.exists"
    ),
}
EXPECTED_COPIES = {
    "Install host-local certificate request helper": {
        "src": "platform-pki-host-local-request",
        "dest": "{{ pki_host_local_certificate_request_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
    "Install host-local certificate trust helper": {
        "src": "platform-pki-host-local-trust",
        "dest": "{{ pki_host_local_certificate_trust_helper_path }}",
        "owner": "root",
        "group": "root",
        "mode": "0755",
    },
}


class BoundaryViolation(AssertionError):
    pass


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _reject_controller_templating(value: Any, source: str | Path) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_controller_templating(key, source)
            _reject_controller_templating(child, source)
    elif isinstance(value, list):
        for child in value:
            _reject_controller_templating(child, source)
    elif isinstance(value, str) and re.search(r"\b(?:lookup|query|q)\b", value):
        raise BoundaryViolation(
            f"controller-side lookup or query is forbidden in {source}"
        )


def _validate_task(task: Any, source: str | Path) -> None:
    if not isinstance(task, dict):
        raise BoundaryViolation(f"non-mapping task in {source}")
    if "action" in task or "local_action" in task:
        raise BoundaryViolation(f"dynamic action syntax is forbidden in {source}")
    _reject_controller_templating(task, source)

    nested = any(section in task for section in ("block", "rescue", "always"))
    for section in ("block", "rescue", "always"):
        for child in task.get(section, []):
            _validate_task(child, source)
    actions = (
        set(task).difference(TASK_METADATA).difference({"block", "rescue", "always"})
    )
    if nested and not actions:
        return
    if len(actions) != 1 or not actions.issubset(ALLOWED_ACTIONS):
        raise BoundaryViolation(
            "host-local boundary contains a non-allowlisted action in "
            f"{source}: {sorted(actions)}"
        )
    action = next(iter(actions))
    metadata = set(task).difference(actions)
    if not metadata.issubset(METADATA_BY_ACTION[action]):
        raise BoundaryViolation(
            "host-local boundary contains fail-neutralizing or unexpected metadata "
            f"in {source}"
        )
    task_name = str(task.get("name", ""))
    if "when" in task and task["when"] != ALLOWED_CONDITIONS.get(
        (action, task_name)
    ):
        raise BoundaryViolation(
            f"host-local boundary contains an unexpected conditional in {source}"
        )
    if action == "ansible.builtin.import_tasks" and task[action] not in {
        "validate.yml",
        "validate_trust.yml",
        "request_apply.yml",
    }:
        raise BoundaryViolation(
            f"host-local boundary imports an unexpected task file in {source}"
        )
    if action == "ansible.builtin.command" and set(task[action]) != {"argv"}:
        raise BoundaryViolation(
            f"host-local boundary command must use argv only in {source}"
        )
    if action == "ansible.builtin.command" and task.get("name") not in {
        "Create or validate the target-local certificate request",
        "Prepare protected target trust ingress",
        "Install or validate complete host-local certificate trust tree",
    }:
        raise BoundaryViolation(
            f"host-local boundary contains an unexpected command dispatch in {source}"
        )
    if action == "ansible.builtin.copy":
        expected_copy = EXPECTED_COPIES.get(task_name)
        if expected_copy is None:
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected copy transfer in {source}"
            )
        if task[action] != expected_copy:
            raise BoundaryViolation(
                f"host-local boundary contains an unpinned copy transfer in {source}"
            )
    if action == "platform_pki_trust_ingress":
        if (
            task.get("name")
            != "Transfer pinned reviewed public trust into protected target ingress"
        ):
            raise BoundaryViolation(
                f"host-local boundary contains an unexpected trust ingress dispatch in {source}"
            )
        if set(task[action]) != {"sources", "sha256", "ingress_root"}:
            raise BoundaryViolation(
                f"trust ingress action has unexpected options in {source}"
            )
    if action == "ansible.builtin.file" and task.get("name") not in {
        "Create absent host-local certificate helper directory",
        "Create absent host-local certificate trust helper directory",
    }:
        raise BoundaryViolation(
            f"host-local boundary contains an unexpected file mutation in {source}"
        )


def _validate_operator_playbook(
    plays: Any, expected_tasks_from: str, source: str | Path
) -> None:
    _reject_controller_templating(plays, source)
    if not isinstance(plays, list) or len(plays) != 1:
        raise BoundaryViolation(f"{source} must contain exactly one play")
    play = plays[0]
    required_play_keys = {"name", "hosts", "become", "gather_facts", "tasks"}
    if set(play) != required_play_keys:
        raise BoundaryViolation(
            f"{source} contains imports, roles, handlers, or another executable section"
        )
    if (
        play.get("hosts") != "registry"
        or play.get("become") is not True
        or play.get("gather_facts") is not False
    ):
        raise BoundaryViolation(f"{source} is not constrained to the registry boundary")
    play_tasks = play.get("tasks", [])
    if len(play_tasks) != 1:
        raise BoundaryViolation(
            f"{source} must contain exactly one structural role dispatch"
        )
    task = play_tasks[0]
    if set(task) != {"name", "ansible.builtin.include_role"}:
        raise BoundaryViolation(f"{source} contains an unexpected playbook action")
    if task["ansible.builtin.include_role"] != {
        "name": "pki_host_local_certificate",
        "tasks_from": expected_tasks_from,
    }:
        raise BoundaryViolation(
            f"{source} does not structurally pin {expected_tasks_from}"
        )


def assert_registry_pki_boundary(repo_root: Path) -> None:
    role_dir = repo_root / "roles/pki_host_local_certificate"
    defaults = _load_yaml(role_dir / "defaults/main.yml")
    tasks = _load_yaml(role_dir / "tasks/main.yml")
    validation_tasks = _load_yaml(role_dir / "tasks/validate.yml")

    assert defaults["pki_host_local_certificate_profile"] == "server-p384-sha384-v1"
    assert (
        defaults["pki_host_local_certificate_request_namespace"]
        == "platform-pki-csr-request-v1"
    )
    assert (
        defaults["pki_host_local_certificate_deployment_namespace"]
        == "platform-pki-csr-deployment-v1"
    )

    common = next(
        task
        for task in validation_tasks
        if task.get("name") == "Validate host-local certificate common contract"
    )
    common_assertions = common["ansible.builtin.assert"]["that"]
    required = {
        "pki_host_local_certificate_target == inventory_hostname",
        (
            "pki_host_local_certificate_requester_principal == "
            "pki_host_local_certificate_target"
        ),
        "pki_host_local_certificate_profile == 'server-p384-sha384-v1'",
        (
            "pki_host_local_certificate_deployment_signing_key_path == "
            "'/etc/ssh/ssh_host_ed25519_key'"
        ),
    }
    missing = required.difference(common_assertions)
    if missing:
        raise BoundaryViolation(
            f"host-local common contract assertions missing: {sorted(missing)}"
        )

    if len(tasks) != 1 or set(tasks[0]) != {"name", "ansible.builtin.fail"}:
        raise BoundaryViolation(
            "implicit host-local role execution is not one unconditional failure"
        )

    site = (repo_root / "playbooks/site.yml").read_text(encoding="utf-8")
    operator_playbooks = (
        (repo_root / "playbooks/registry-pki-request.yml", "request"),
        (repo_root / "playbooks/registry-pki-activate.yml", "activate"),
        (repo_root / "playbooks/registry-pki-trust.yml", "trust"),
    )
    for playbook, _ in operator_playbooks:
        if playbook.name in site:
            raise BoundaryViolation(
                f"normal site convergence imports operator-only playbook {playbook.name}"
            )

    for directory in (role_dir / "tasks", role_dir / "handlers"):
        if not directory.is_dir():
            continue
        for executable in sorted((*directory.rglob("*.yml"), *directory.rglob("*.yaml"))):
            for task in _load_yaml(executable):
                _validate_task(task, executable)

    meta_dir = role_dir / "meta"
    if meta_dir.is_dir():
        for meta_path in sorted((*meta_dir.rglob("*.yml"), *meta_dir.rglob("*.yaml"))):
            if (_load_yaml(meta_path) or {}).get("dependencies"):
                raise BoundaryViolation(
                    f"host-local role dependencies are forbidden: {meta_path}"
                )

    for playbook, tasks_from in operator_playbooks:
        _validate_operator_playbook(_load_yaml(playbook), tasks_from, playbook)

    trust_helper = role_dir / "files/platform-pki-host-local-trust"
    action_plugin = repo_root / "plugins/action/platform_pki_trust_ingress.py"
    if not trust_helper.is_file() or not trust_helper.stat().st_mode & 0o111:
        raise BoundaryViolation(
            "dedicated target trust helper is missing or not executable"
        )
    if not action_plugin.is_file():
        raise BoundaryViolation(
            "pinned controller trust ingress action plugin is missing"
        )

    trust_tasks = (role_dir / "tasks/trust.yml").read_text(encoding="utf-8")
    request_tasks = (role_dir / "tasks/request.yml").read_text(encoding="utf-8")
    request_apply_tasks = (role_dir / "tasks/request_apply.yml").read_text(
        encoding="utf-8"
    )
    if "platform-pki-host-local-trust" not in trust_tasks:
        raise BoundaryViolation(
            "trust action does not structurally dispatch the dedicated helper"
        )
    if "platform_pki_trust_ingress" not in trust_tasks:
        raise BoundaryViolation(
            "trust action does not structurally dispatch the pinned ingress action"
        )
    action_plugin_text = action_plugin.read_text(encoding="utf-8")
    for fragment in (
        "O_NOFOLLOW",
        "source.recheck()",
        "self._transfer_data",
        "REPOSITORY_ROOT",
    ):
        if fragment not in action_plugin_text:
            raise BoundaryViolation(
                f"pinned ingress action is missing required boundary logic: {fragment}"
            )
    if "trust_sources" in request_tasks or "trust_sources" in request_apply_tasks:
        raise BoundaryViolation(
            "request action attempts to source or install controller trust"
        )
    for forbidden in ("tls.key", "request_signing_key", "private_key"):
        if forbidden in trust_tasks:
            raise BoundaryViolation(
                f"trust action references forbidden private-key material: {forbidden}"
            )


def test_registry_pki_source_boundary(repo_root: Path) -> None:
    assert_registry_pki_boundary(repo_root)


@pytest.mark.parametrize(
    "bad_task",
    [
        {"name": "short action", "copy": {"src": "tls.key"}},
        {"name": "foreign action", "community.crypto.openssl_privatekey": {}},
        {"name": "dynamic action", "action": "copy src=tls.key dest=/tmp/key"},
        {
            "name": "nested action",
            "block": [{"ansible.builtin.copy": {"src": "tls.key"}}],
        },
        {
            "name": "concealed private transfer",
            "ansible.builtin.copy": {"content": "private", "dest": "/tmp/tls.key"},
        },
        {
            "name": "Install host-local certificate request helper",
            "ansible.builtin.copy": {
                "content": "{{ pki_host_local_certificate_request_signing_key }}",
                "dest": "{{ pki_host_local_certificate_request_helper_path }}",
                "owner": "root",
                "group": "root",
                "mode": "0755",
            },
            "when": "not ansible_check_mode",
        },
        {
            "name": "foreign argv command",
            "ansible.builtin.command": {"argv": ["/bin/true"]},
        },
        {"name": "foreign custom action", "unsafe_local_action": {}},
        {
            "name": "misnamed trust ingress",
            "platform_pki_trust_ingress": {
                "sources": {},
                "sha256": {},
                "ingress_root": "/tmp",
            },
        },
        {"name": "foreign import", "ansible.builtin.import_tasks": "mutate.yml"},
        {
            "name": "controller lookup",
            "ansible.builtin.assert": {"that": ["lookup('pipe', 'id')"]},
        },
        {
            "name": "parenthesized lookup",
            "ansible.builtin.assert": {"that": ["(lookup)('pipe', 'id')"]},
        },
        {
            "name": "parenthesized query",
            "ansible.builtin.assert": {"that": ["(query)('pipe', 'id')"]},
        },
        {
            "name": "parenthesized q",
            "ansible.builtin.assert": {"that": ["(q)('pipe', 'id')"]},
        },
        {
            "name": "ignored failure",
            "ansible.builtin.fail": {"msg": "stop"},
            "ignore_errors": True,
        },
        {
            "name": "skipped assertion",
            "ansible.builtin.assert": {"that": [True]},
            "when": False,
        },
    ],
    ids=lambda task: str(task["name"]),
)
def test_registry_pki_task_scanner_rejects_unsafe_examples(
    bad_task: dict[str, Any],
) -> None:
    with pytest.raises(BoundaryViolation):
        _validate_task(bad_task, "scanner self-test")


@pytest.mark.parametrize(
    "bad_playbook",
    [
        [{"import_playbook": "mutate.yml"}],
        [{"hosts": "registry", "gather_facts": False, "roles": ["mutating_role"]}],
        [
            {"hosts": "registry", "gather_facts": False, "tasks": []},
            {
                "hosts": "registry",
                "gather_facts": False,
                "roles": ["mutating_role"],
            },
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
    ],
)
def test_registry_pki_playbook_scanner_rejects_unsafe_examples(
    bad_playbook: list[dict[str, Any]],
) -> None:
    with pytest.raises(BoundaryViolation):
        _validate_operator_playbook(bad_playbook, "request", "scanner self-test")


def test_registry_pki_check_mode_boundaries(
    repo_root: Path,
    command_runner: CommandRunner,
) -> None:
    command_runner.run(
        [
            "ansible-playbook",
            "--check",
            "-i",
            "localhost,",
            str(repo_root / "tests/fixtures/registry-pki-boundary/integration.yml"),
        ],
        timeout=120,
    ).assert_success()
