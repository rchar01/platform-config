from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from conftest import CommandResult, CommandRunner


def _named(items: list[dict], name: str) -> dict:
    return next(item for item in items if item.get("name") == name)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _operation_fake_script() -> str:
    return """#!/usr/bin/env python3
import json
import os
import pathlib
import stat
import sys

name = pathlib.Path(sys.argv[0]).name
log = os.environ.get("PLATFORM_CONFIG_OPERATION_LOG")
if log:
    with pathlib.Path(log).open("a") as stream:
        stream.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
if name == "ansible-inventory":
    print(json.dumps({
        "rke2_cluster": {"hosts": ["server-a", "agent-a"]},
        "rke2_servers": {"hosts": ["server-a"]},
        "rke2_agents": {"hosts": ["agent-a"]},
        "openbao": {"hosts": ["openbao-a"]},
    }))
    raise SystemExit(0)

phase = os.environ["PLATFORM_CONFIG_OPERATION_PHASE"]
arguments = " ".join(sys.argv[1:])
summary_path = pathlib.Path(os.environ["PLATFORM_CONFIG_OPERATION_SUMMARY_PATH"])
if stat.S_IMODE(summary_path.stat().st_mode) != 0o600:
    raise SystemExit(96)
if stat.S_IMODE(summary_path.parent.stat().st_mode) != 0o700:
    raise SystemExit(96)
if "openbao" in arguments:
    hosts = ["openbao-a"]
elif "rke2_servers" in arguments:
    hosts = ["server-a"]
else:
    hosts = ["server-a", "agent-a"]
failure_match = os.environ.get("PLATFORM_CONFIG_FAIL_MATCH", "")
failure = bool(failure_match) and failure_match in arguments
with summary_path.open("a") as stream:
    for index, host in enumerate(hosts):
        stream.write(json.dumps({
            "schema": 1,
            "kind": "recap",
            "phase": phase,
            "host": host,
            "counters": {
                "ok": 1,
                "changed": 0,
                "failures": 1 if failure and index == 0 else 0,
                "unreachable": 0,
                "skipped": 0,
                "rescued": 0,
                "ignored": 0,
            },
        }, separators=(",", ":")) + "\\n")
raise SystemExit(1 if failure else 0)
"""


def test_rke2_playbook_is_serial_and_fatal(repo_root: Path) -> None:
    plays = yaml.safe_load((repo_root / "playbooks/rke2.yml").read_text())

    assert [play["hosts"] for play in plays] == ["rke2_servers", "rke2_agents"]
    assert all(play["serial"] == 1 for play in plays)
    assert all(play["any_errors_fatal"] is True for play in plays)


def test_rke2_composes_optional_registry_trust_and_fails_closed(
    repo_root: Path,
) -> None:
    dependencies = yaml.safe_load(
        (repo_root / "roles/rke2/meta/main.yml").read_text()
    )["dependencies"]
    defaults = yaml.safe_load(
        (repo_root / "roles/rke2/defaults/main.yml").read_text()
    )
    tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    mirror_tasks = yaml.safe_load(
        (repo_root / "roles/rke2/tasks/validate_registry_mirrors.yml").read_text()
    )
    rpm_source_tasks = yaml.safe_load(
        (repo_root / "roles/rke2/tasks/validate_rpm_sources.yml").read_text()
    )
    preflight = _named(tasks, "Assert RKE2 inputs are configured")
    mirror_inputs = _named(mirror_tasks, "Validate RKE2 registry mirror inputs")
    mirror_mappings = _named(mirror_tasks, "Validate RKE2 registry mirror mappings")
    mirror_endpoints = _named(mirror_tasks, "Validate RKE2 registry mirror endpoints")
    restart = _named(tasks, "Schedule RKE2 restart after system registry trust changes")
    registry_ca_removal = _named(
        tasks, "Remove RKE2 registry CA certificate when unused"
    )
    config_template = (repo_root / "roles/rke2/templates/config.yaml.j2").read_text()

    assert [dependency["role"] for dependency in dependencies] == [
        "rocky_repository_policy",
        "registry_ca_trust",
    ]
    assert dependencies[1]["registry_ca_trust_defer_marker_clear"] is True
    assert defaults["rke2_disable_default_registry_endpoint"] is False
    assert _named(tasks, "Validate RKE2 registry mirror configuration")[
        "ansible.builtin.import_tasks"
    ] == "validate_registry_mirrors.yml"
    assert _named(tasks, "Validate RKE2 RPM source configuration")[
        "ansible.builtin.import_tasks"
    ] == "validate_rpm_sources.yml"
    rpm_sources = _named(rpm_source_tasks, "Validate RKE2 RPM source URLs")
    assert rpm_sources["loop"] == [
        "{{ rke2_rpm_common_repository_url }}",
        "{{ rke2_rpm_version_repository_url }}",
        "{{ rke2_rpm_gpg_key_url }}",
    ]
    assertions = preflight["ansible.builtin.assert"]["that"]
    input_assertions = mirror_inputs["ansible.builtin.assert"]["that"]
    assert "'disable-default-registry-endpoint' not in rke2_extra_config" in assertions
    for registry in ("docker.io", "ghcr.io"):
        assert (
            f"'{registry}' not in rke2_registry_mirrors "
            "or rke2_disable_default_registry_endpoint"
        ) in input_assertions
    assert mirror_mappings["loop"] == "{{ rke2_registry_mirrors | dict2items }}"
    assert mirror_mappings["ansible.builtin.assert"]["that"] == [
        "item.key is string",
        "item.key | length > 0",
        "item.value is mapping",
    ]
    endpoint_assertions = mirror_endpoints["ansible.builtin.assert"]["that"]
    assert mirror_endpoints["loop"] == "{{ rke2_registry_mirrors | dict2items }}"
    assert "item.value.get('endpoint', []) is sequence" in endpoint_assertions
    assert "item.value.get('endpoint', []) is not string" in endpoint_assertions
    assert "item.value.get('endpoint', []) is not mapping" in endpoint_assertions
    assert any("reject('string')" in item for item in endpoint_assertions)
    assert any(
        "reject('match', '^https://[^/@\\s]+" in item
        for item in endpoint_assertions
    )
    assert restart["notify"] == "Restart RKE2"
    assert (
        "registry_ca_trust_refresh_required | default(false) | bool"
        in restart["when"]
    )
    assert tasks.index(restart) < next(
        index
        for index, task in enumerate(tasks)
        if task.get("name") == "Apply pending RKE2 restart before readiness checks"
    )
    complete = _named(tasks, "Complete RKE2 system registry trust convergence")
    assert complete["changed_when"] is False
    assert tasks.index(complete) > next(
        index
        for index, task in enumerate(tasks)
        if task.get("name") == "Wait for the converged RKE2 node to become Ready"
    )
    assert complete["ansible.builtin.file"] == {
        "path": "{{ registry_ca_trust_refresh_marker }}",
        "state": "absent",
    }
    assert "registry_ca_trust_source | default('') | length > 0" in complete["when"]
    assert "{% if rke2_disable_default_registry_endpoint | bool %}" in config_template
    assert "disable-default-registry-endpoint: true" in config_template
    assert registry_ca_removal["ansible.builtin.file"] == {
        "path": "{{ rke2_registry_ca_path }}",
        "state": "absent",
    }
    assert registry_ca_removal["when"] == [
        "rke2_registry_ca_src | length == 0",
        "rke2_registry_mirrors | length == 0",
        "rke2_registry_configs | length == 0",
    ]
    assert "notify" not in registry_ca_removal
    install = _named(tasks, "Install exact native RKE2 RPM packages")
    assert install["ansible.builtin.dnf"]["allow_downgrade"] is False


def _run_rke2_registry_mirror_validation(
    repo_root: Path,
    mirrors: object,
    disable_default_endpoint: bool,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            str(repo_root / "tests/fixtures/rke2-registry-mirrors/playbook.yml"),
            "--extra-vars",
            json.dumps(
                {
                    "rke2_registry_mirrors": mirrors,
                    "rke2_disable_default_registry_endpoint": disable_default_endpoint,
                }
            ),
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )


def _run_rke2_rpm_source_validation(
    repo_root: Path, source: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            str(repo_root / "tests/fixtures/rke2-rpm-sources/playbook.yml"),
            "--extra-vars",
            json.dumps(
                {
                    "rke2_rpm_common_repository_url": source,
                    "rke2_rpm_version_repository_url": (
                        "https://rpm.example.test/rke2/1.35/x86_64"
                    ),
                    "rke2_rpm_gpg_key_url": "https://rpm.example.test/public.key",
                }
            ),
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )


def test_rke2_rpm_source_validation_accepts_canonical_https_url(
    repo_root: Path,
) -> None:
    result = _run_rke2_rpm_source_validation(
        repo_root, "https://rpm.example.test:8443/rke2/common"
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "source",
    [
        "http://rpm.example.test/rke2/common",
        "https://user:password@rpm.example.test/rke2/common",
        "https://rpm..example.test/rke2/common",
        "https://rpm.example.test:0/rke2/common",
        "https://rpm.example.test:65536/rke2/common",
        "https://rpm.example.test/rke2/common?channel=stable",
        "https://rpm.example.test/rke2/common\nother",
    ],
)
def test_rke2_rpm_source_validation_rejects_unsafe_url(
    repo_root: Path, source: str
) -> None:
    result = _run_rke2_rpm_source_validation(repo_root, source)

    assert result.returncode != 0, result.stdout + result.stderr
    assert "password" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("mirrors", "disable_default_endpoint"),
    [
        ({"registry.example": {"endpoint": ["https://registry.example/v2"]}}, False),
        (
            {
                "docker.io": {"endpoint": ["https://nexus.example/docker/v2"]},
                "ghcr.io": {"endpoint": ["https://nexus.example/ghcr/v2"]},
            },
            True,
        ),
    ],
)
def test_rke2_registry_mirror_validation_accepts_supported_inputs(
    repo_root: Path,
    mirrors: object,
    disable_default_endpoint: bool,
) -> None:
    result = _run_rke2_registry_mirror_validation(
        repo_root, mirrors, disable_default_endpoint
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("mirrors", "disable_default_endpoint", "expected"),
    [
        (
            {"docker.io": {"endpoint": ["https://nexus.example/docker/v2"]}},
            False,
            "docker.io and ghcr.io mirrors require",
        ),
        (
            {"ghcr.io": {"endpoint": ["https://nexus.example/ghcr/v2"]}},
            False,
            "docker.io and ghcr.io mirrors require",
        ),
        ({"registry.example": []}, False, "values must be mappings"),
        (
            {"registry.example": {"endpoint": "https://registry.example/v2"}},
            False,
            "must define at least one credential-free HTTPS endpoint",
        ),
        (
            {"registry.example": {"endpoint": [42]}},
            False,
            "must define at least one credential-free HTTPS endpoint",
        ),
        (
            {"registry.example": {"endpoint": ["http://registry.example/v2"]}},
            False,
            "must define at least one credential-free HTTPS endpoint",
        ),
    ],
)
def test_rke2_registry_mirror_validation_rejects_unsafe_inputs(
    repo_root: Path,
    mirrors: object,
    disable_default_endpoint: bool,
    expected: str,
) -> None:
    result = _run_rke2_registry_mirror_validation(
        repo_root, mirrors, disable_default_endpoint
    )

    assert result.returncode != 0
    assert expected in result.stdout + result.stderr


def test_rke2_bootstrap_requires_clean_nodes(repo_root: Path) -> None:
    plays = yaml.safe_load(
        (repo_root / "playbooks/rke2-bootstrap-preflight.yml").read_text()
    )
    play = plays[0]
    tasks = play["tasks"]

    assert play["hosts"] == "rke2_cluster"
    assert play["any_errors_fatal"] is True
    topology = _named(tasks, "Require coherent RKE2 inventory groups")
    topology_assertions = topology["ansible.builtin.assert"]["that"]
    assert any("rke2_servers" in assertion for assertion in topology_assertions)
    assert any("rke2_agents" in assertion for assertion in topology_assertions)
    assert any("rke2_cluster" in assertion for assertion in topology_assertions)
    assert _named(tasks, "Check for existing RKE2 packages")["loop"] == [
        "rke2-server",
        "rke2-agent",
        "rke2-common",
        "rke2-selinux",
    ]
    state_paths = _named(tasks, "Check for existing RKE2 state")["loop"]
    assert "/etc/rancher/rke2" in state_paths
    assert "/var/lib/rancher/rke2" in state_paths
    assert "/usr/bin/rke2" in state_paths
    assert "/usr/local/bin/rke2" in state_paths
    assert "/opt/rke2" in state_paths
    pristine = _named(tasks, "Require pristine RKE2 nodes")
    assertions = pristine["ansible.builtin.assert"]["that"]
    assert any("difference([0, 1])" in assertion for assertion in assertions)


def test_rke2_core_health_is_separate_from_ingress(repo_root: Path) -> None:
    core_path = repo_root / "playbooks/rke2-core-health.yml"
    core = yaml.safe_load(core_path.read_text())
    smoke = yaml.safe_load((repo_root / "playbooks/rke2-smoke.yml").read_text())

    assert [play["hosts"] for play in core] == ["rke2_cluster", "rke2_servers"]
    assert all(play["any_errors_fatal"] is True for play in core)
    assert _named(core[0]["tasks"], "Require coherent RKE2 inventory groups")
    assert _named(core[0]["tasks"], "Check RKE2 service active state")
    assert _named(core[1]["tasks"], "Check RKE2 Kubernetes API readiness")
    assert _named(core[1]["tasks"], "Wait for all RKE2 nodes to become Ready")
    assert _named(core[1]["tasks"], "Assert expected RKE2 node count")

    normalized_core = core_path.read_text().lower()
    assert "traefik" not in normalized_core
    assert "kong" not in normalized_core
    assert "kube-vip" not in normalized_core
    assert smoke[0]["ansible.builtin.import_playbook"] == "rke2-core-health.yml"
    assert smoke[1]["hosts"] == "rke2_servers"
    assert _named(smoke[1]["tasks"], "Wait for bundled Traefik HelmCharts")


def test_rke2_convergence_preflight_is_secret_safe(repo_root: Path) -> None:
    play = yaml.safe_load(
        (repo_root / "playbooks/rke2-convergence-preflight.yml").read_text()
    )[0]
    tasks = play["tasks"]

    assert play["hosts"] == "rke2_cluster"
    assert play["gather_facts"] is False
    assert play["any_errors_fatal"] is True
    supplied = _named(tasks, "Read the supplied RKE2 cluster token")
    installed = _named(tasks, "Read the installed RKE2 cluster token")
    comparison = _named(tasks, "Compare RKE2 cluster tokens")
    equivalent = _named(tasks, "Require an unchanged RKE2 cluster token")
    assert supplied["delegate_to"] == "localhost"
    assert supplied["become"] is False
    assert supplied["no_log"] is True
    assert installed["no_log"] is True
    assert comparison["no_log"] is True
    comparison_value = comparison["ansible.builtin.set_fact"][
        "rke2_convergence_token_matches"
    ]
    assert "'\\r' not in rke2_convergence_source_value" in comparison_value
    assert "'\\n' not in rke2_convergence_source_value" in comparison_value
    assert "'\\r' not in rke2_convergence_installed_value" in comparison_value
    assert "'\\n' not in rke2_convergence_installed_normalized" in comparison_value
    assert equivalent["ansible.builtin.assert"]["that"] == [
        "rke2_convergence_token_matches | bool"
    ]

    role_tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    token_copy = _named(role_tasks, "Copy RKE2 cluster token")
    assert "src" not in token_copy["ansible.builtin.copy"]
    content = token_copy["ansible.builtin.copy"]["content"]
    assert "rstrip=false" in content
    assert "regex_replace('\\n\\Z', '')" in content
    assert content.endswith("\n")
    assert token_copy["no_log"] is True


def test_rke2_registry_removal_preflight_is_fixed_and_non_leaking(
    repo_root: Path,
) -> None:
    play = yaml.safe_load(
        (repo_root / "playbooks/rke2-convergence-preflight.yml").read_text()
    )[1]
    tasks = play["tasks"]
    workload = _named(tasks, "Inspect Kubernetes workload image references")
    workload_args = workload["ansible.builtin.command"]["argv"]
    image_jsonpath = play["vars"]["rke2_convergence_registry_image_jsonpath"]
    manifest_scan = _named(
        tasks, "Search RKE2 server manifests for registry.dev references"
    )

    assert play["hosts"] == "rke2_servers"
    assert play["gather_facts"] is False
    assert play["any_errors_fatal"] is True
    assert "rke2_convergence_registry_guard_required" not in play["vars"]
    for task in tasks:
        assert "rke2_registry_mirrors | default({}) | length == 0" in task["when"]
        assert "rke2_registry_configs | default({}) | length == 0" in task["when"]
    assert "run_once" not in workload
    assert (
        "inventory_hostname == rke2_convergence_registry_bootstrap_host"
        in workload["when"]
    )
    assert workload["check_mode"] is False
    assert workload["changed_when"] is False
    assert workload["failed_when"] is False
    assert workload["no_log"] is True
    assert (
        "pods,replicationcontrollers,deployments.apps,replicasets.apps,"
        "statefulsets.apps,daemonsets.apps,jobs.batch,cronjobs.batch"
    ) in workload_args
    for path in (
        ".spec.containers[*]",
        ".spec.initContainers[*]",
        ".spec.ephemeralContainers[*]",
        ".spec.template.spec.containers[*]",
        ".spec.template.spec.initContainers[*]",
        ".spec.template.spec.ephemeralContainers[*]",
        ".spec.jobTemplate.spec.template.spec.containers[*]",
        ".spec.jobTemplate.spec.template.spec.initContainers[*]",
        ".spec.jobTemplate.spec.template.spec.ephemeralContainers[*]",
    ):
        assert path in image_jsonpath
    assert manifest_scan["ansible.builtin.find"]["recurse"] is True
    assert manifest_scan["ansible.builtin.find"]["hidden"] is True
    assert manifest_scan["ansible.builtin.find"]["read_whole_file"] is True
    assert manifest_scan["no_log"] is True
    for task in tasks:
        fail_msg = task.get("ansible.builtin.assert", {}).get("fail_msg", "")
        assert "{{" not in fail_msg


def _run_rke2_registry_removal_preflight(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    *,
    workload_output: str = "",
    kubectl_status: int = 0,
    manifest_reference: bool = False,
    registry_configured: bool = False,
) -> tuple[CommandResult, Path]:
    source_token = isolated_test_dir / "source-token"
    source_token.write_bytes(b"registry-guard-token-secret")
    fake_kubectl = isolated_test_dir / "kubectl"
    kubectl_called = isolated_test_dir / "kubectl-called"
    kubeconfig = isolated_test_dir / "kubeconfig"
    kubeconfig.write_text("test fixture\n", encoding="utf-8")
    expected_kubectl_args = [
        "--kubeconfig",
        str(kubeconfig),
        "get",
        (
            "pods,replicationcontrollers,deployments.apps,replicasets.apps,"
            "statefulsets.apps,daemonsets.apps,jobs.batch,cronjobs.batch"
        ),
        "--all-namespaces",
        "-o",
    ]
    fake_kubectl.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib\n"
        "import sys\n"
        f"pathlib.Path({str(kubectl_called)!r}).touch()\n"
        f"expected = {expected_kubectl_args!r}\n"
        "if sys.argv[1:7] != expected or len(sys.argv) != 8:\n"
        "    raise SystemExit(97)\n"
        "required = ('.spec.containers[*]', '.spec.initContainers[*]', "
        "'.spec.ephemeralContainers[*]', '.spec.template.spec.containers[*]', "
        "'.spec.jobTemplate.spec.template.spec.containers[*]')\n"
        "if not sys.argv[7].startswith('jsonpath=') or "
        "not all(item in sys.argv[7] for item in required):\n"
        "    raise SystemExit(98)\n"
        f"print({workload_output!r}, file=sys.stderr if {kubectl_status} else sys.stdout)\n"
        f"raise SystemExit({kubectl_status})\n",
        encoding="utf-8",
    )
    fake_kubectl.chmod(0o755)
    hosts: dict[str, dict[str, object]] = {}
    manifest_dirs: dict[str, Path] = {}
    for name in ("server-a", "server-b"):
        installed_token = isolated_test_dir / f"{name}-token"
        installed_token.write_bytes(b"registry-guard-token-secret\n")
        manifest_dir = isolated_test_dir / f"{name}-manifests"
        manifest_dir.mkdir()
        manifest_dirs[name] = manifest_dir
        hosts[name] = {
            "ansible_connection": "local",
            "ansible_become": False,
            "rke2_token_path": str(installed_token),
            "rke2_server_manifest_dir": str(manifest_dir),
            "rke2_kubectl": str(fake_kubectl),
            "rke2_kubeconfig": str(kubeconfig),
        }
    if manifest_reference:
        hidden_dir = manifest_dirs["server-b"] / ".nested"
        hidden_dir.mkdir()
        (hidden_dir / "private-manifest-sentinel").write_text(
            "image: registry.dev/private/manifest-secret\n", encoding="utf-8"
        )
    inventory = isolated_test_dir / "inventory.yml"
    inventory.write_text(
        yaml.safe_dump(
            {
                "all": {
                    "children": {
                        "rke2_cluster": {
                            "children": {"rke2_servers": {"hosts": hosts}}
                        }
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    ansible_tmp = isolated_test_dir / "ansible-tmp"
    ansible_tmp.mkdir()
    extra_vars: dict[str, object] = {"rke2_token_src": str(source_token)}
    if registry_configured:
        extra_vars["rke2_registry_configs"] = {"registry.dev": {}}
    result = command_runner.run(
        [
            "ansible-playbook",
            "-i",
            inventory,
            repo_root / "playbooks/rke2-convergence-preflight.yml",
            "--extra-vars",
            json.dumps(extra_vars),
        ],
        environment={"ANSIBLE_LOCAL_TEMP": str(ansible_tmp)},
        redactions=(
            "registry-guard-token-secret",
            "registry.dev/private/workload-secret",
            "registry.dev/private/manifest-secret",
            "kubectl-private-error",
            "private-manifest-sentinel",
        ),
    )
    return result, kubectl_called


@pytest.mark.parametrize(
    ("case", "expected_message"),
    [
        ("clean", ""),
        (
            "workload-reference",
            "Kubernetes workloads still reference registry.dev/",
        ),
        (
            "kubectl-failure",
            "Unable to inspect Kubernetes workloads before removing RKE2",
        ),
        (
            "manifest-reference",
            "RKE2 server manifests still reference registry.dev/",
        ),
        ("registry-configured", ""),
    ],
)
def test_rke2_registry_removal_preflight_contract(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    case: str,
    expected_message: str,
) -> None:
    result, kubectl_called = _run_rke2_registry_removal_preflight(
        repo_root,
        isolated_test_dir,
        command_runner,
        workload_output=(
            "kubectl-private-error"
            if case == "kubectl-failure"
            else (
                "registry.dev/private/workload-secret"
                if case in ("workload-reference", "registry-configured")
                else ""
            )
        ),
        kubectl_status=2 if case == "kubectl-failure" else 0,
        manifest_reference=case == "manifest-reference",
        registry_configured=case == "registry-configured",
    )
    if expected_message:
        result.assert_failure()
        assert expected_message in result.stdout + result.stderr
    else:
        result.assert_success()
    output = result.stdout + result.stderr
    for sensitive in (
        "registry-guard-token-secret",
        "registry.dev/private/workload-secret",
        "registry.dev/private/manifest-secret",
        "kubectl-private-error",
        "private-manifest-sentinel",
    ):
        assert sensitive not in output
    assert kubectl_called.exists() is (case != "registry-configured")


def test_rke2_token_copy_is_canonical_and_idempotent(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    role_tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    copy_args = dict(
        _named(role_tasks, "Copy RKE2 cluster token")["ansible.builtin.copy"]
    )
    source_path = isolated_test_dir / "source-token"
    target_path = isolated_test_dir / "target-token"
    playbook = isolated_test_dir / "copy-token.yml"
    source_path.write_bytes(b"canonical-token-secret")
    target_path.write_bytes(b"canonical-token-secret")
    copy_args["dest"] = str(target_path)
    copy_args.pop("owner")
    copy_args.pop("group")
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "name": "Test canonical RKE2 token copy",
                    "hosts": "localhost",
                    "gather_facts": False,
                    "tasks": [
                        {
                            "name": "Copy RKE2 cluster token",
                            "ansible.builtin.copy": copy_args,
                            "no_log": True,
                        }
                    ],
                }
            ],
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    environment = {"ANSIBLE_LOCAL_TEMP": str(isolated_test_dir / "ansible-tmp")}
    (isolated_test_dir / "ansible-tmp").mkdir()
    command = [
        "ansible-playbook",
        "-i",
        "localhost,",
        "-c",
        "local",
        playbook,
        "--extra-vars",
        json.dumps({"rke2_token_src": str(source_path)}),
    ]

    command_runner.run(command, environment=environment).assert_success()
    assert target_path.read_bytes() == b"canonical-token-secret\n"
    second = command_runner.run(command, environment=environment).assert_success()
    assert "changed=0" in second.stdout
    assert "canonical-token-secret" not in second.stdout + second.stderr


@pytest.mark.parametrize(
    ("source", "installed", "expected_success"),
    [
        (b"cluster-token-secret", b"cluster-token-secret", True),
        (b"cluster-token-secret", b"cluster-token-secret\n", True),
        (b"cluster-token-secret\n", b"cluster-token-secret\n", False),
        (b"cluster-token-secret", b"cluster-token-secret\nextra", False),
        (b"cluster-token-secret\r", b"cluster-token-secret", False),
        (b"cluster-token-secret", b"cluster-token-secret\r", False),
        (b"cluster-token-secret", b"cluster-token-secret\n\n", False),
        (b"cluster-token-secret", b"different-token-secret\n", False),
    ],
    ids=(
        "exact",
        "installed-final-lf",
        "source-final-lf",
        "installed-embedded-lf",
        "source-cr",
        "installed-cr",
        "installed-double-final-lf",
        "mismatch",
    ),
)
def test_rke2_convergence_preflight_token_contract(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    source: bytes,
    installed: bytes,
    expected_success: bool,
) -> None:
    source_path = isolated_test_dir / "source-token"
    installed_path = isolated_test_dir / "installed-token"
    inventory = isolated_test_dir / "inventory.yml"
    source_path.write_bytes(source)
    installed_path.write_bytes(installed)
    inventory.write_text(
        """---
all:
  children:
    rke2_cluster:
      hosts:
        rke2-test:
          ansible_connection: local
          ansible_become: false
""",
        encoding="utf-8",
    )
    (isolated_test_dir / "ansible-local-tmp").mkdir()
    (isolated_test_dir / "ansible-remote-tmp").mkdir()
    result = command_runner.run(
        [
            "ansible-playbook",
            "-i",
            inventory,
            repo_root / "playbooks/rke2-convergence-preflight.yml",
            "--limit",
            "rke2_cluster",
            "--extra-vars",
            json.dumps(
                {
                    "rke2_token_src": str(source_path),
                    "rke2_token_path": str(installed_path),
                }
            ),
        ],
        environment={
            "ANSIBLE_LOCAL_TEMP": str(isolated_test_dir / "ansible-local-tmp"),
            "ANSIBLE_REMOTE_TEMP": str(isolated_test_dir / "ansible-remote-tmp"),
        },
        redactions=(source.decode(errors="replace"), installed.decode(errors="replace")),
    )
    if expected_success:
        result.assert_success()
    else:
        result.assert_failure()
    output = result.stdout + result.stderr
    assert "cluster-token-secret" not in output
    assert "different-token-secret" not in output
    if not expected_success:
        assert "RKE2 cluster token is unavailable, malformed" in output


def test_rke2_uses_pinned_native_rpm_repositories(repo_root: Path) -> None:
    defaults = yaml.safe_load(
        (repo_root / "roles/rke2/defaults/main.yml").read_text()
    )
    tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    rpm_source_tasks = yaml.safe_load(
        (repo_root / "roles/rke2/tasks/validate_rpm_sources.yml").read_text()
    )
    preflight = _named(tasks, "Assert RKE2 inputs are configured")
    key_download = _named(tasks, "Download the RKE2 RPM signing key")
    key_import = _named(tasks, "Import the verified RKE2 RPM signing key")
    repositories = [
        _named(tasks, "Configure the disabled RKE2 common RPM repository"),
        _named(tasks, "Configure the disabled RKE2 version RPM repository"),
    ]
    install = _named(tasks, "Install exact native RKE2 RPM packages")
    names = [task.get("name") for task in tasks]

    assert defaults["rke2_rpm_common_repository_url"] == ""
    assert defaults["rke2_rpm_version_repository_url"] == ""
    assert defaults["rke2_rpm_package_release"] == ""
    assert defaults["rke2_rpm_selinux_package_nevra"] == ""
    assert defaults["rke2_rpm_gpg_key_url"] == ""
    assert defaults["rke2_rpm_gpg_key_sha256"] == ""
    assert defaults["rke2_rpm_gpg_key_fingerprint"] == ""

    assertions = preflight["ansible.builtin.assert"]["that"]
    rpm_sources = _named(rpm_source_tasks, "Validate RKE2 RPM source URLs")
    assert any(
        "item is match(rke2_rpm_source_url_pattern)" in assertion
        for assertion in rpm_sources["ansible.builtin.assert"]["that"]
    )
    assert "ansible_distribution_major_version == rke2_rpm_el_major" in assertions
    assert "ansible_architecture == rke2_rpm_arch" in assertions
    assert "rke2_rpm_gpg_key_sha256 is match('^[0-9a-f]{64}$')" in assertions
    assert (
        "rke2_rpm_gpg_key_fingerprint is match('^[0-9A-F]{40}$')" in assertions
    )
    assert any(
        "hostvars[rke2_bootstrap_host].ansible_ssh_private_key_file" in assertion
        for assertion in assertions
    )
    assert "ansible_ssh_private_key_file" in preflight["ansible.builtin.assert"][
        "fail_msg"
    ]

    assert key_download["ansible.builtin.get_url"]["checksum"] == (
        "sha256:{{ rke2_rpm_gpg_key_sha256 }}"
    )
    assert key_import["ansible.builtin.rpm_key"]["fingerprint"] == [
        "{{ rke2_rpm_gpg_key_fingerprint }}"
    ]
    for repository in repositories:
        settings = repository["ansible.builtin.yum_repository"]
        assert settings["enabled"] is False
        assert settings["gpgcheck"] is True
        assert settings["repo_gpgcheck"] is True
        assert settings["gpgkey"] == "file://{{ rke2_rpm_gpg_key_path }}"

    assert install["ansible.builtin.dnf"]["name"] == [
        "{{ rke2_rpm_selinux_package_nevra }}",
        "{{ rke2_rpm_node_package_nevra }}",
    ]
    assert install["ansible.builtin.dnf"]["enablerepo"] == [
        "{{ rke2_rpm_common_repository_id }}",
        "{{ rke2_rpm_version_repository_id }}",
    ]
    assert install["ansible.builtin.dnf"]["allow_downgrade"] is False
    assert "Download RKE2 install script" not in names
    assert "Install RKE2" not in names


def test_rke2_flushes_restart_before_readiness(repo_root: Path) -> None:
    tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    names = [task.get("name") for task in tasks]
    ordered = [
        "Manage RKE2 cluster firewalld rich rules",
        "Manage RKE2 API firewalld rich rules",
        "Manage RKE2 service",
        "Apply pending RKE2 restart before readiness checks",
        "Wait for the local RKE2 service after convergence",
        "Wait for RKE2 supervisor on server nodes",
        "Wait for the local RKE2 server API after convergence",
        "Wait for the converged RKE2 node to become Ready",
    ]

    assert [names.index(name) for name in ordered] == sorted(
        names.index(name) for name in ordered
    )
    assert _named(tasks, "Apply pending RKE2 restart before readiness checks")[
        "ansible.builtin.meta"
    ] == "flush_handlers"

    service = _named(tasks, "Wait for the local RKE2 service after convergence")
    assert "{{ rke2_service_name }}" in service["ansible.builtin.command"]["argv"]
    assert service["changed_when"] is False

    api = _named(tasks, "Wait for the local RKE2 server API after convergence")
    assert "--raw=/readyz" in api["ansible.builtin.command"]["argv"]
    assert "rke2_node_role == 'server'" in api["when"]

    node = _named(tasks, "Wait for the converged RKE2 node to become Ready")
    assert node["delegate_to"] == "{{ rke2_bootstrap_host }}"
    assert "{{ rke2_node_name }}" in node["ansible.builtin.command"]["argv"]
    assert node["changed_when"] is False
    assert "firewalld_dependencies_ready | default(true)" not in node["when"]

    api_firewall = _named(tasks, "Manage RKE2 API firewalld rich rules")
    assert "firewalld_dependencies_ready | default(true)" in api_firewall["when"]
    for name in (
        "Verify an existing RKE2 node is Ready before prerequisite reboot",
        "Wait for an existing RKE2 node to return Ready after reboot",
        "Wait for the converged RKE2 node to become Ready",
    ):
        task = _named(tasks, name)
        assert task["delegate_to"] == "{{ rke2_bootstrap_host }}"
        assert task["vars"]["ansible_ssh_private_key_file"].strip() == (
            "{{ hostvars[rke2_bootstrap_host].ansible_ssh_private_key_file }}"
        )


def test_fresh_rke2_check_mode_skips_children_of_simulated_directories(
    repo_root: Path,
) -> None:
    tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
    config_condition = "not ansible_check_mode or rke2_config_dir_stat.stat.exists"
    manifest_condition = (
        "not ansible_check_mode or rke2_server_manifest_dir_stat.stat.exists"
    )

    for name in (
        "Copy RKE2 cluster token",
        "Write RKE2 configuration",
        "Write RKE2 registries configuration",
    ):
        when = _named(tasks, name)["when"]
        conditions = when if isinstance(when, list) else [when]
        assert config_condition in conditions
    traefik = _named(tasks, "Configure bundled Traefik NodePorts on the bootstrap server")
    assert manifest_condition in traefik["when"]
    template_validation = _named(
        tasks, "Validate fresh-node RKE2 templates in check mode"
    )
    assert template_validation["no_log"] is True
    assert "ansible_check_mode" in template_validation["when"]
    report = _named(tasks, "Report fresh-node RKE2 bootstrap changes in check mode")
    assert report["changed_when"] is True
    assert "rke2_rpm_node_package_nevra" in report["ansible.builtin.debug"]["msg"]


def test_rke2_delegation_uses_bootstrap_host_identity(repo_root: Path) -> None:
    fixture = repo_root / "tests/fixtures/rke2-delegated-identity"
    result = subprocess.run(
        [
            "ansible-playbook",
            "-i",
            str(fixture / "inventory.yml"),
            str(fixture / "playbook.yml"),
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_rke2_egress_matrix_tracks_pinned_inputs(repo_root: Path) -> None:
    matrix = (repo_root / "docs/rke2-egress.md").read_text()
    normalized_matrix = " ".join(matrix.split())
    inventory = yaml.safe_load(
        (repo_root / "inventories/dev/group_vars/rke2_cluster.yml.example").read_text()
    )
    kube_vip_defaults = yaml.safe_load(
        (repo_root / "roles/rke2_kube_vip/defaults/main.yml").read_text()
    )
    rke2_defaults = yaml.safe_load(
        (repo_root / "roles/rke2/defaults/main.yml").read_text()
    )
    effective_inputs = rke2_defaults | kube_vip_defaults | inventory

    for name in (
        "rke2_rpm_common_repository_url",
        "rke2_rpm_version_repository_url",
        "rke2_rpm_gpg_key_url",
        "rke2_rpm_gpg_key_sha256",
        "rke2_rpm_gpg_key_fingerprint",
    ):
        assert f"`{name}`" in matrix
    assert "config/files/registry/<environment>/ca-bundle.crt" in matrix
    assert "repodata/repomd.xml.asc" in matrix
    assert "artifact-affecting `rke2_extra_config`" in normalized_matrix
    assert "requires regenerating and requalifying the matrix" in normalized_matrix

    for name in (
        "rke2_registry_mirrors",
        "rke2_disable_default_registry_endpoint",
        "registry_ca_trust_source",
        "registry_ca_trust_sha256",
        "registry_ca_trust_target",
    ):
        assert f"`{name}`" in matrix
    assert "https://nexus.example.test/repository/docker-ghcr/v2" in matrix
    assert "does not proxy the kube-vip Helm index or chart archive" in normalized_matrix
    assert "developer build chain is not separately qualified" in normalized_matrix
    assert "does not inspect or verify preinstalled trust" in matrix

    for name in (
        "rke2_version",
        "rke2_rpm_common_repository_url",
        "rke2_rpm_version_repository_url",
        "rke2_rpm_el_major",
        "rke2_rpm_arch",
        "rke2_rpm_package_release",
        "rke2_rpm_selinux_package_nevra",
        "rke2_rpm_gpg_key_url",
        "rke2_rpm_gpg_key_sha256",
        "rke2_rpm_gpg_key_fingerprint",
        "rke2_cni",
        "platform_ingress_controller",
        "rke2_kube_vip_chart_repo",
        "rke2_kube_vip_chart_version",
        "rke2_kube_vip_image_tag",
    ):
        assert str(effective_inputs[name]) in matrix

    rpm_version = (
        inventory["rke2_version"]
        .removeprefix("v")
        .replace("+", "~")
        .replace("-", "~")
    )
    package_suffix = (
        f"{rpm_version}-{inventory['rke2_rpm_package_release']}."
        f"{inventory['rke2_rpm_arch']}.rpm"
    )
    version_repo = inventory["rke2_rpm_version_repository_url"]
    for package in ("rke2-server", "rke2-agent", "rke2-common"):
        assert f"{version_repo}/{package}-{package_suffix}" in matrix

    common_repo = inventory["rke2_rpm_common_repository_url"]
    assert f"{common_repo}/{inventory['rke2_rpm_selinux_package_nevra']}.rpm" in matrix

    operational_image = (
        "ghcr.io/ansible/community-ansible-dev-tools:v26.8.0@"
        "sha256:70f705fee2386deb320598ea011812292598111cca85f0107ee9479062628e79"
    )
    assert operational_image in matrix
    assert "Ansible Core `2.21.x`" in normalized_matrix
    assert "`ansible.posix` `2.2.2`" in matrix
    assert "requires no external collection" in normalized_matrix
    assert "does not build or publish an operational image" in normalized_matrix


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown"],
        ["rke2-plan"],
        ["rke2-bootstrap-plan", "--inventory", "relative.yml", "--controller-vars", "/tmp/x"],
        ["rke2-converge-plan", "--inventory", "/tmp/inventory", "--limit", "host"],
    ],
)
def test_operation_launcher_rejects_unsafe_arguments(
    repo_root: Path, command_runner: CommandRunner, argv: list[str]
) -> None:
    result = command_runner.run(
        [repo_root / "scripts/platform-config-operation", *argv]
    ).assert_failure()


@pytest.mark.parametrize(
    ("operation", "commands"),
    [
        (
            "rke2-bootstrap-plan",
            [
                ["ansible-inventory", "-i", "{inventory}", "--list", "--extra-vars", "@{vars}"],
                ["ansible", "-i", "{inventory}", "rke2_cluster", "-m", "ansible.builtin.ping", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-bootstrap-preflight.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--check", "--diff", "--extra-vars", "@{vars}"],
            ],
        ),
        (
            "rke2-converge-plan",
            [
                ["ansible-inventory", "-i", "{inventory}", "--list", "--extra-vars", "@{vars}"],
                ["ansible", "-i", "{inventory}", "rke2_cluster", "-m", "ansible.builtin.ping", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-core-health.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-convergence-preflight.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--check", "--diff", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-kube-vip.yml", "--limit", "rke2_servers", "--check", "--diff", "--extra-vars", "@{vars}"],
            ],
        ),
        (
            "rke2-bootstrap",
            [
                ["ansible-inventory", "-i", "{inventory}", "--list", "--extra-vars", "@{vars}"],
                ["ansible", "-i", "{inventory}", "rke2_cluster", "-m", "ansible.builtin.ping", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-bootstrap-preflight.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-kube-vip.yml", "--limit", "rke2_servers", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-smoke.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-kube-vip-smoke.yml", "--limit", "rke2_servers", "--extra-vars", "@{vars}"],
            ],
        ),
        (
            "rke2-deploy",
            [
                ["ansible-inventory", "-i", "{inventory}", "--list", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-core-health.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-convergence-preflight.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-kube-vip.yml", "--limit", "rke2_servers", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-smoke.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-kube-vip-smoke.yml", "--limit", "rke2_servers", "--extra-vars", "@{vars}"],
            ],
        ),
        (
            "openbao-status",
            [
                ["ansible-inventory", "-i", "{inventory}", "--list", "--extra-vars", "@{vars}"],
                ["ansible", "-i", "{inventory}", "openbao", "-m", "ansible.builtin.ping", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/maintenance/openbao-status.yml", "--limit", "openbao", "--extra-vars", "@{vars}"],
            ],
        ),
    ],
)
def test_operation_launcher_uses_fixed_commands(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
    operation: str,
    commands: list[list[str]],
) -> None:
    inventory = isolated_test_dir / "hosts.yml"
    extra_vars = isolated_test_dir / "connection.yml"
    log = isolated_test_dir / "commands.jsonl"
    inventory.write_text("all: {}\n", encoding="utf-8")
    extra_vars.write_text("---\n{}\n", encoding="utf-8")
    extra_vars.chmod(0o600)

    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir()
    fake_content = _operation_fake_script()
    for name in ("ansible", "ansible-inventory", "ansible-playbook"):
        _write_executable(fake_bin / name, fake_content)

    environment = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "PLATFORM_CONFIG_OPERATION_LOG": str(log),
    }
    result = command_runner.run(
        [
            repo_root / "scripts/platform-config-operation",
            operation,
            "--inventory",
            inventory,
            "--controller-vars",
            extra_vars,
        ],
        environment=environment,
    ).assert_success()
    assert "PLATFORM CONFIG OPERATION SUMMARY" in result.stdout
    assert "Overall: PASS" in result.stdout
    assert "Execution context: GitLab Runner" in result.stdout
    assert not list((isolated_test_dir / "tmp").glob("platform-config-operation.*"))

    observed = [json.loads(line) for line in log.read_text().splitlines()]
    expected = [
        [
            value.format(inventory=inventory, vars=extra_vars, repo=repo_root)
            for value in command
        ]
        for command in commands
    ]
    assert observed == expected


def test_operation_launcher_stops_after_failed_core_health(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    inventory = isolated_test_dir / "hosts.yml"
    extra_vars = isolated_test_dir / "connection.yml"
    log = isolated_test_dir / "commands"
    inventory.write_text("all: {}\n", encoding="utf-8")
    extra_vars.write_text("---\n{}\n", encoding="utf-8")
    extra_vars.chmod(0o600)

    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir()
    for name in ("ansible", "ansible-inventory", "ansible-playbook"):
        _write_executable(fake_bin / name, _operation_fake_script())

    result = command_runner.run(
        [
            repo_root / "scripts/platform-config-operation",
            "rke2-converge-plan",
            "--inventory",
            inventory,
            "--controller-vars",
            extra_vars,
        ],
        environment={
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "PLATFORM_CONFIG_OPERATION_LOG": str(log),
            "PLATFORM_CONFIG_FAIL_MATCH": "rke2-core-health.yml",
        },
    ).assert_failure()

    observed = log.read_text(encoding="utf-8")
    assert "rke2-core-health.yml" in observed
    assert "playbooks/rke2.yml" not in observed
    assert "rke2-kube-vip.yml" not in observed
    assert "PLATFORM CONFIG OPERATION SUMMARY" in result.stdout
    assert "Overall: FAIL" in result.stdout
    assert not list((isolated_test_dir / "tmp").glob("platform-config-operation.*"))


@pytest.mark.parametrize(
    ("signal_number", "expected_status"),
    [
        (signal.SIGHUP, 129),
        (signal.SIGINT, 130),
        (signal.SIGTERM, 143),
    ],
)
def test_operation_launcher_stops_active_child_on_signal(
    repo_root: Path,
    isolated_test_dir: Path,
    signal_number: signal.Signals,
    expected_status: int,
) -> None:
    inventory = isolated_test_dir / "hosts.yml"
    extra_vars = isolated_test_dir / "connection.yml"
    fake_bin = isolated_test_dir / "bin"
    started = isolated_test_dir / "started"
    terminated = isolated_test_dir / "terminated"
    inventory.write_text("all: {}\n", encoding="utf-8")
    extra_vars.write_text("---\n{}\n", encoding="utf-8")
    extra_vars.chmod(0o600)
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "ansible-inventory",
        """#!/bin/sh
set -eu
printf started >"$PLATFORM_CONFIG_STARTED"
trap 'printf terminated >"$PLATFORM_CONFIG_TERMINATED"; exit 0' TERM
while :; do sleep 1; done
""",
    )
    for name in ("ansible", "ansible-playbook"):
        _write_executable(fake_bin / name, "#!/bin/sh\nexit 99\n")
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "PLATFORM_CONFIG_STARTED": str(started),
            "PLATFORM_CONFIG_TERMINATED": str(terminated),
            "TMPDIR": str(isolated_test_dir),
        }
    )
    process = subprocess.Popen(
        [
            repo_root / "scripts/platform-config-operation",
            "rke2-bootstrap-plan",
            "--inventory",
            inventory,
            "--controller-vars",
            extra_vars,
        ],
        cwd=repo_root,
        env=environment,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert started.exists()
        os.kill(process.pid, signal_number)
        assert process.wait(timeout=5) == expected_status
        assert terminated.read_text(encoding="utf-8") == "terminated"
        assert not list(isolated_test_dir.glob("platform-config-operation.*"))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
