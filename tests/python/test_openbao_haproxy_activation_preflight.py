from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from conftest import CommandRunner


ROLE = "roles/openbao_haproxy"
PREFLIGHT = "activation_preflight.yml"


@pytest.fixture
def activation_fixture(repo_root: Path, tmp_path: Path) -> tuple[dict, Path]:
    role = tmp_path / "roles/openbao_haproxy"
    shutil.copytree(repo_root / ROLE, role)
    path = role / "tasks" / PREFLIGHT
    tasks = yaml.safe_load(path.read_text())
    # Only unrelated target artifact reads are synthetic. Validation, the Python
    # import command, fact publication, and the active role guard remain real.
    for task in tasks:
        if "ansible.builtin.stat" in task:
            task.clear()
            task["ansible.builtin.set_fact"] = {
                "openbao_haproxy_activation_artifact_stats": {"results": [
                    {"stat": {"exists": True, "isreg": True, "pw_name": "root",
                              "mode": "0640", "checksum": "a" * 64}},
                ] * 3},
            }
        elif task.get("ansible.builtin.command", {}).get("argv", [None])[0] == "rpm":
            task.clear()
            task["ansible.builtin.set_fact"] = {
                "openbao_haproxy_activation_installed_nevra": {
                    "stdout": "{{ openbao_haproxy_package_nevra }}",
                },
            }
        elif task.get("name") == "Validate staged OpenBao HAProxy configuration":
            task.clear()
            task["ansible.builtin.debug"] = {"msg": "Synthetic staged configuration is valid"}
    path.write_text(yaml.safe_dump(tasks), encoding="utf-8")

    (tmp_path / "firewall.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "root = Path(os.environ['HAPROXY_TEST_ROOT'])\n"
        "with (root / 'imports').open('a') as log:\n"
        "    log.write('import firewall\\n')\n"
        "if (root / 'missing').exists():\n"
        "    raise ModuleNotFoundError('No module named firewall (fixture)')\n",
        encoding="utf-8",
    )
    play = {
        "hosts": "localhost", "gather_facts": True,
        "vars": {
            "openbao_haproxy_enabled": True,
            "openbao_haproxy_package_nevra": "haproxy-0:3.0.5-6.el10_2.1.x86_64",
            "openbao_haproxy_backend_health_host": "bao.example.invalid",
            "openbao_haproxy_client_allowed_sources": ["198.51.100.0/24"],
            "openbao_cluster_members": [
                {"name": f"bao-{i}", "address": f"192.0.2.{i}",
                 "dns": f"bao-{i}.example.invalid"} for i in range(1, 4)
            ],
        },
        "environment": {"PYTHONPATH": str(tmp_path), "HAPROXY_TEST_ROOT": str(tmp_path)},
        "tasks": [],
    }
    return play, role


@pytest.mark.parametrize("case", [
    "ready", "missing", "stale-missing", "unmanaged", "stale-unmanaged", "recheck-missing",
])
def test_activation_firewall_readiness(
    case: str, activation_fixture: tuple[dict, Path], repo_root: Path,
    tmp_path: Path, command_runner: CommandRunner,
) -> None:
    play, role = activation_fixture
    include = {"ansible.builtin.include_role": {"name": str(role), "tasks_from": PREFLIGHT}}
    managed = "unmanaged" not in case
    missing = "missing" in case
    if not managed:
        play["vars"]["openbao_haproxy_firewalld_manage"] = False
    if case.startswith("stale-"):
        play["tasks"].append({"ansible.builtin.set_fact": {"firewalld_dependencies_ready": True}})
    else:
        play["tasks"].append({"ansible.builtin.assert": {
            "that": "firewalld_dependencies_ready is undefined",
        }})
    if case == "recheck-missing":
        play["tasks"] += [include, {"ansible.builtin.assert": {
            "that": "firewalld_dependencies_ready is sameas true",
        }}, {"ansible.builtin.copy": {
            "dest": str(tmp_path / "missing"), "content": "missing", "mode": "0600",
        }}]
    elif missing:
        (tmp_path / "missing").touch()

    plays = [play]
    if missing:
        play["tasks"].append({
            "block": [include, {"ansible.builtin.fail": {"msg": "UNEXPECTED APPROVAL REACHED"}}],
            "rescue": [
                {"ansible.builtin.assert": {"that": [
                    "firewalld_dependencies_ready is sameas false",
                    "ansible_failed_result.rc | default(0) != 0",
                    "'import firewall' in ansible_failed_result.cmd | default([])",
                ]}},
                {"ansible.builtin.fail": {"msg": "Bindings rejected with readiness false before approval"}},
            ],
        })
    else:
        play["tasks"] += [include, include, {"ansible.builtin.assert": {
            "that": f"firewalld_dependencies_ready is sameas {str(managed).lower()}",
        }}]
        if managed:
            main = yaml.safe_load((repo_root / ROLE / "tasks/main.yml").read_text())
            guard = next(task for task in main[0]["block"] if task["name"] ==
                         "Assert managed firewall dependencies are ready before activation")
            # Exercise the consumer in a separate play, as the activation caller does.
            plays.append({
                "hosts": "localhost", "gather_facts": False,
                "vars": {"openbao_haproxy_service_state": "started",
                         "openbao_haproxy_firewalld_manage": True,
                         "firewalld_service_state": "started"},
                "tasks": [guard],
            })
    playbook = tmp_path / "preflight.yml"
    playbook.write_text(yaml.safe_dump(plays), encoding="utf-8")
    result = command_runner.run(
        ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)], timeout=90,
    )
    if missing:
        result.assert_failure()
        assert "Bindings rejected with readiness false before approval" in result.stdout, result.diagnostics()
        assert "UNEXPECTED APPROVAL REACHED" not in result.stdout, result.diagnostics()
    else:
        result.assert_success()
        assert "changed=0" in result.stdout
    imports = tmp_path / "imports"
    if managed:
        assert imports.read_text().splitlines() == ["import firewall"] * (
            2 if case in {"ready", "recheck-missing"} else 1
        )
    else:
        assert not imports.exists()


def test_activation_preflight_command_and_caller_contract(repo_root: Path) -> None:
    tasks = yaml.safe_load((repo_root / ROLE / "tasks" / PREFLIGHT).read_text())
    command = next(task for task in tasks if "import firewall" in
                   task.get("ansible.builtin.command", {}).get("argv", []))
    assert command["ansible.builtin.command"]["argv"] == [
        "{{ ansible_facts.python.executable }}", "-c", "import firewall",
    ]
    assert command["changed_when"] is False
    assert command["check_mode"] is False
    assert "delegate_to" not in command
    defaults = yaml.safe_load((repo_root / ROLE / "defaults/main.yml").read_text())
    assert defaults["openbao_haproxy_firewalld_manage"] is True
    assert "firewalld_dependencies_ready" not in defaults
    assert yaml.safe_load((repo_root / ROLE / "meta/main.yml").read_text())["dependencies"] == []
    plays = yaml.safe_load((repo_root / "playbooks/maintenance/openbao-haproxy-activate.yml").read_text())
    for play in plays[:2]:
        assert play["gather_facts"] is True
        includes = [task["ansible.builtin.include_role"] for task in play["tasks"]
                    if "ansible.builtin.include_role" in task]
        assert {"name": "openbao_haproxy", "tasks_from": PREFLIGHT} in includes
        assert not any(include["name"] == "firewalld" for include in includes)
    first = plays[0]["tasks"]
    preflight = next(i for i, task in enumerate(first) if task.get("ansible.builtin.include_role") ==
                     {"name": "openbao_haproxy", "tasks_from": PREFLIGHT})
    approval = next(i for i, task in enumerate(first) if "ansible.builtin.pause" in task)
    assert preflight < approval
