from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
import yaml

from conftest import CommandRunner


ROLES = ("rke2_kube_vip", "rke2_gitlab_runner")
CA = b"-----BEGIN CERTIFICATE-----\nsynthetic-public-ca\n-----END CERTIFICATE-----\n"


def role_inputs(repo_root: Path, role: str) -> tuple[dict, list, dict]:
    defaults = yaml.safe_load((repo_root / f"roles/{role}/defaults/main.yml").read_text())
    tasks = yaml.safe_load((repo_root / f"roles/{role}/tasks/main.yml").read_text())
    variables = defaults | {
        f"{role}_enabled": True,
        "rke2_kube_vip_api_vip": "192.0.2.72",
        "rke2_kube_vip_interface": "eth0",
        "rke2_tls_sans": ["192.0.2.72"],
        "rke2_gitlab_runner_gitlab_url": "https://gitlab.example.test",
        "rke2_gitlab_runner_token_src": "/synthetic/token",
        "rke2_gitlab_runner_tls_ca_cert_src": "/synthetic/gitlab-ca.pem",
        "rke2_gitlab_runner_tls_ca_cert_sha256": "0" * 64,
        "rke2_gitlab_runner_name": "synthetic-runner",
    }
    if role == "rke2_gitlab_runner":
        variables |= tasks[1]["vars"]
        variables["rke2_gitlab_runner_manager_image_tag"] = defaults[
            "rke2_gitlab_runner_manager_image"
        ].removeprefix("docker.io/gitlab/gitlab-runner:")
        role_tasks = tasks[1]["block"]
    else:
        role_tasks = tasks
    ca_block = next(t for t in role_tasks if t["name"].endswith("Helm repository CA on the controller"))
    # Run the real role prefix, retaining its guards, up to the first unrelated
    # task. No service, network, token, Kubernetes, or target-file operations run.
    end = role_tasks.index(ca_block) + 1
    if role == "rke2_gitlab_runner":
        prefix = [tasks[0], tasks[1] | {"block": role_tasks[:end]}]
    else:
        prefix = tasks[:end]
    return variables, prefix, ca_block


def run_play(
    directory: Path,
    runner: CommandRunner,
    variables: dict,
    tasks: list,
    *,
    check: bool = True,
):
    inventory = directory / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"children": {
        "rke2_servers": {"hosts": {"localhost": {"ansible_connection": "local"}}},
    }}}))
    playbook = directory / "repo-ca.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "rke2_servers", "gather_facts": False,
        "vars": variables, "tasks": tasks,
    }]))
    return runner.run(
        ["ansible-playbook", "-i", inventory, playbook, *(["--check"] if check else [])],
        timeout=90,
    )


def validation_case(variables: dict, tasks: list, accepted: bool, failure_task: str) -> dict:
    """Rescue expected assertions only; an earlier I/O/setup failure must fail."""
    return {
        "vars": variables,
        "block": [
            {"ansible.builtin.set_fact": {"accepted": False}},
            {"block": [*tasks, {"ansible.builtin.set_fact": {"accepted": True}}],
             "rescue": [{"ansible.builtin.assert": {"that": [
                 "ansible_failed_task.name == " + json.dumps(failure_task),
             ]}}]},
            {"ansible.builtin.assert": {"that": [f"accepted == {accepted}"]}},
        ],
    }


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("check", [False, True])
def test_repository_ca_validators_and_render_preserve_bytes(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    role: str, check: bool,
) -> None:
    variables, prefix, _ = role_inputs(repo_root, role)
    assert variables[f"{role}_chart_repo_ca_src"] == ""
    assert variables[f"{role}_chart_repo_ca_sha256"] == ""
    template = next((repo_root / f"roles/{role}/templates").glob("*helmchart.yaml.j2"))
    render = {"ansible.builtin.set_fact": {
        "rendered": "{{ lookup('ansible.builtin.template', " + json.dumps(str(template)) + ") | from_yaml }}",
    }}
    assertions = [
        f"rendered.spec.repo == {role}_chart_repo",
        "'insecureSkipTLSVerify' not in rendered.spec",
        "'plainHTTP' not in rendered.spec",
    ]
    if role == "rke2_gitlab_runner":
        assertions += [
            "(rendered.spec.valuesContent | from_yaml).certsSecretName == rke2_gitlab_runner_ca_secret_name",
        ]
    tasks = []
    sources = []
    # Empty both before and after configured variants catches stale registered
    # content leaking into an unconfigured chart within the same Ansible run.
    for index, content in enumerate([None, CA, CA.rstrip(b"\n"), CA.replace(b"\n", b"\r\n") + b"\r\n", CA + b" \n\n", None]):
        case_vars = {f"{role}_chart_repo_ca_src": "", f"{role}_chart_repo_ca_sha256": ""}
        if content is None:
            expected = "'repoCA' not in rendered.spec"
        else:
            source = isolated_test_dir / f"reviewed-{index}.pem"
            source.write_bytes(content)
            sources.append((source, content))
            case_vars |= {
                f"{role}_chart_repo_ca_src": str(source),
                f"{role}_chart_repo_ca_sha256": hashlib.sha256(content).hexdigest().upper(),
                "expected_base64": base64.b64encode(content).decode(),
            }
            expected = "rendered.spec.repoCA | b64encode == expected_base64"
        tasks.append({"name": f"CA byte variant {index}", "vars": case_vars, "block": [
            *prefix, render, {"ansible.builtin.assert": {"that": [*assertions, expected]}},
        ]})
    result = run_play(isolated_test_dir, command_runner, variables, tasks, check=check).assert_success()
    assert "changed=0" in result.stdout
    for source, content in sources:
        assert source.read_bytes() == content


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("check", [False, True])
def test_repository_ca_controller_reads_ignore_inventory_become(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    role: str, check: bool,
) -> None:
    variables, tasks, _ = role_inputs(repo_root, role)
    source = isolated_test_dir / "reviewed.pem"
    source.write_bytes(CA)
    variables |= {
        f"{role}_chart_repo_ca_src": str(source),
        f"{role}_chart_repo_ca_sha256": hashlib.sha256(CA).hexdigest(),
    }
    marker = isolated_test_dir / "sudo-invoked"
    sudo = isolated_test_dir / "false-sudo"
    sudo.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('unexpected controller escalation')\n"
        "raise SystemExit(97)\n"
    )
    sudo.chmod(0o700)
    group_vars = isolated_test_dir / "group_vars"
    group_vars.mkdir()
    (group_vars / "all.yml").write_text(yaml.safe_dump({
        "ansible_become": True,
        "ansible_become_method": "sudo",
        "ansible_become_user": "root" if os.geteuid() != 0 else "nobody",
        "ansible_become_exe": str(sudo),
    }))

    # Prove the inherited connection variable overrides the task keyword and
    # reaches only our failing helper, which never executes the supplied command.
    control = [{
        "ansible.builtin.command": {"argv": ["/usr/bin/true"]},
        "delegate_to": "localhost", "become": False, "check_mode": False,
    }]
    run_play(isolated_test_dir, command_runner, variables, control, check=check).assert_failure()
    assert marker.is_file(), "Synthetic inventory must activate the fake sudo helper"
    marker.unlink()

    result = run_play(isolated_test_dir, command_runner, variables, tasks, check=check)
    assert not marker.exists(), result.diagnostics()
    result.assert_success()
    assert "changed=0" in result.stdout
    assert "Helm repository CA content matches the pin" in result.stdout
    assert source.read_bytes() == CA


@pytest.mark.parametrize("role", ROLES)
def test_repository_ca_input_validation(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner, role: str,
) -> None:
    variables, prefix, _ = role_inputs(repo_root, role)
    role_tasks = prefix[1]["block"] if role == "rke2_gitlab_runner" else prefix
    validator = next(t for t in role_tasks if t["name"].endswith("Helm repository CA inputs"))
    pin = "a" * 64
    cases = [("", "", True), ("/safe-dir/.anchors/ca_1.pem", pin, True)]
    cases += [(path, pin, False) for path in (
        None, False, 42, [], {}, "", "relative.pem", "/", "/ca/", "//ca.pem",
        "/ca//file", "/ca/./file", "/ca/../file", "/ca/.", "/ca/..",
        "/ca file", "/ca\n", "/ca\r\n", "/ca\x00", "/ca;file", "/ca\\file",
    )]
    cases += [("/ca.pem", sha, False) for sha in (
        "", None, False, 64, [], {}, "a" * 63, "a" * 65, "g" * 64, pin + "\n",
    )]
    tasks = []
    for source, sha, accepted in cases:
        tasks.append(validation_case(
            {f"{role}_chart_repo_ca_src": source, f"{role}_chart_repo_ca_sha256": sha},
            [validator], accepted, validator["name"],
        ))
    run_play(isolated_test_dir, command_runner, variables, tasks).assert_success()


@pytest.mark.parametrize("role", ROLES)
def test_repository_ca_rejects_unsafe_or_unpinned_file_in_check_mode(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    role: str,
) -> None:
    variables, prefix, ca_block = role_inputs(repo_root, role)
    guard = next(t["name"] for t in ca_block["block"] if t["name"].endswith("CA source is reviewed"))
    tasks = []
    for case in ("missing", "empty", "directory", "symlink", "fifo", "oversized", "mismatch"):
        source = isolated_test_dir / f"{case}.pem"
        if case == "directory":
            source.mkdir()
        elif case == "symlink":
            real = isolated_test_dir / "real.pem"
            real.write_bytes(CA)
            source.symlink_to(real)
        elif case == "fifo":
            os.mkfifo(source)
        elif case == "oversized":
            source.write_bytes(b"a" * (1048576 + 1))
        elif case != "missing":
            source.write_bytes(b"" if case == "empty" else CA)
        pin = hashlib.sha256(CA).hexdigest()
        if case in ("empty", "oversized"):
            pin = hashlib.sha256(source.read_bytes()).hexdigest()
        tasks.append({"name": f"Reject {case} CA", **validation_case({
            f"{role}_chart_repo_ca_src": str(source),
            f"{role}_chart_repo_ca_sha256": "0" * 64 if case == "mismatch" else pin,
        }, prefix, False, guard)})
    result = run_play(isolated_test_dir, command_runner, variables, tasks).assert_success()
    assert "Helm repository CA source is reviewed" in result.stdout
    assert "changed=0" in result.stdout
    assert "Read RKE2" not in result.stdout


@pytest.mark.parametrize("role", ROLES)
def test_repository_ca_rechecks_exact_slurp_bytes_after_stat(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner, role: str,
) -> None:
    variables, tasks, ca_block = role_inputs(repo_root, role)
    source = isolated_test_dir / "reviewed.pem"
    source.write_bytes(CA)
    variables |= {
        f"{role}_chart_repo_ca_src": str(source),
        f"{role}_chart_repo_ca_sha256": hashlib.sha256(CA).hexdigest(),
    }
    # Change only the disposable fixture after the real stat assertion passed.
    # This must fail at the content hash, even in check mode.
    ca_block["block"].insert(2, {
        "ansible.builtin.copy": {"content": CA.decode() + "\n", "dest": str(source), "mode": "0600"},
        "check_mode": False,
    })
    result = run_play(isolated_test_dir, command_runner, variables, tasks).assert_failure()
    assert "Helm repository CA content matches the pin" in result.stdout


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("configured", [False, True])
def test_smoke_repository_ca_exact_hash_or_absence(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    role: str, configured: bool,
) -> None:
    filename = role.replace("_", "-") + "-smoke.yml"
    smoke = yaml.safe_load((repo_root / "playbooks" / filename).read_text())[0]
    task = next(t for t in smoke["tasks"] if t["name"].endswith(("Helm repository CA policy", "Helm repository and CA policy")))
    variables = {
        f"{role}_enabled": True,
        f"{role}_smoke_is_bootstrap": True,
        f"{role}_chart_repo": "https://charts.example.test/repository/helm",
    }
    # Missing inventory variables must have the same semantics as empty defaults.
    if configured:
        variables |= {
            f"{role}_chart_repo_ca_src": "/synthetic/reviewed.pem",
            f"{role}_chart_repo_ca_sha256": hashlib.sha256(CA).hexdigest(),
        }
    tasks = []
    for live in ("absent", "exact", "empty", "null", "changed", "trimmed"):
        spec = {"repo": variables[f"{role}_chart_repo"]}
        if live != "absent":
            spec["repoCA"] = {"exact": CA.decode(), "empty": "", "null": None,
                              "changed": CA.decode() + "\n", "trimmed": CA.decode().rstrip()}[live]
        accepted = (configured and live == "exact") or (not configured and live == "absent")
        tasks.append({"name": f"Live CA variant {live}", **validation_case(
            {f"{role}_smoke_helmchart": {"stdout": json.dumps({"spec": spec})}},
            [task], accepted, task["name"],
        )})
    run_play(isolated_test_dir, command_runner, variables, tasks).assert_success()


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("matching", [False, True])
def test_runner_smoke_checks_repository_with_correct_ca(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    configured: bool, matching: bool,
) -> None:
    smoke = yaml.safe_load((repo_root / "playbooks/rke2-gitlab-runner-smoke.yml").read_text())[0]
    task = next(t for t in smoke["tasks"] if t["name"] == "Assert RKE2 GitLab Runner Helm repository CA policy")
    expected = "https://charts.example.test/repository/helm" if configured else "https://charts.gitlab.io"
    variables = {
        "rke2_gitlab_runner_enabled": True,
        "rke2_gitlab_runner_smoke_is_bootstrap": True,
        "rke2_gitlab_runner_chart_repo_ca_src": "/synthetic/reviewed.pem",
        "rke2_gitlab_runner_chart_repo_ca_sha256": hashlib.sha256(CA).hexdigest(),
        "rke2_gitlab_runner_smoke_helmchart": {"stdout": json.dumps({"spec": {
            "repo": expected if matching else "https://wrong.example.test",
            "repoCA": CA.decode(),
        }})},
    }
    if configured:
        variables["rke2_gitlab_runner_chart_repo"] = expected
    result = run_play(isolated_test_dir, command_runner, variables, [task])
    if matching:
        result.assert_success()
    else:
        result.assert_failure()
        assert "rke2_gitlab_runner_smoke_helmchart_object.spec.repo" in result.stdout


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("matching", [False, True])
def test_kube_vip_smoke_checks_live_repository(
    repo_root: Path, isolated_test_dir: Path, command_runner: CommandRunner,
    configured: bool, matching: bool,
) -> None:
    smoke = yaml.safe_load((repo_root / "playbooks/rke2-kube-vip-smoke.yml").read_text())[0]
    read = next(t for t in smoke["tasks"] if t["name"] == "Confirm kube-vip HelmChart exists")
    assert "-o=json" in read["ansible.builtin.command"]["argv"]
    task = next(t for t in smoke["tasks"] if t["name"] == "Assert kube-vip Helm repository and CA policy")
    expected = "https://charts.example.test" if configured else "https://kube-vip.github.io/helm-charts"
    variables = {
        "rke2_kube_vip_smoke_is_bootstrap": True,
        "rke2_kube_vip_smoke_helmchart": {"stdout": json.dumps({"spec": {
            "repo": expected if matching else "https://wrong.example.test",
        }})},
    }
    if configured:
        variables["rke2_kube_vip_chart_repo"] = expected
    result = run_play(isolated_test_dir, command_runner, variables, [task])
    result.assert_success() if matching else result.assert_failure()
