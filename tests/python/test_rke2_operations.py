from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from conftest import CommandRunner


def _named(items: list[dict], name: str) -> dict:
    return next(item for item in items if item.get("name") == name)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


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
    preflight = _named(tasks, "Assert RKE2 inputs are configured")
    mirror_inputs = _named(mirror_tasks, "Validate RKE2 registry mirror inputs")
    mirror_mappings = _named(mirror_tasks, "Validate RKE2 registry mirror mappings")
    mirror_endpoints = _named(mirror_tasks, "Validate RKE2 registry mirror endpoints")
    restart = _named(tasks, "Schedule RKE2 restart after system registry trust changes")
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
    assertions = preflight["ansible.builtin.assert"]["that"]
    assert "'disable-default-registry-endpoint' not in rke2_extra_config" in assertions
    input_assertions = mirror_inputs["ansible.builtin.assert"]["that"]
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


def test_rke2_uses_pinned_native_rpm_repositories(repo_root: Path) -> None:
    defaults = yaml.safe_load(
        (repo_root / "roles/rke2/defaults/main.yml").read_text()
    )
    tasks = yaml.safe_load((repo_root / "roles/rke2/tasks/main.yml").read_text())
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
    assert "rke2_rpm_common_repository_url is match('^https://.+$')" in assertions
    assert "rke2_rpm_version_repository_url is match('^https://.+$')" in assertions
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
    assert "Download RKE2 install script" not in names
    assert "Install RKE2" not in names


def test_operational_image_pins_ansible_toolchain(repo_root: Path) -> None:
    containerfile = (repo_root / "Containerfile.ci").read_text(encoding="utf-8")
    requirements = (repo_root / "requirements-ci.txt").read_text(encoding="utf-8")
    collections = yaml.safe_load((repo_root / "requirements.yml").read_text())

    assert requirements == "ansible-core==2.20.0\n"
    assert "ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections" in containerfile
    assert "COPY requirements-ci.txt requirements.yml" in containerfile
    assert "ansible-galaxy collection install" in containerfile
    assert collections == {
        "collections": [
            {"name": "ansible.posix", "version": "2.2.2"},
            {"name": "community.general", "version": "12.6.0"},
        ]
    }


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

    containerfile = (repo_root / "Containerfile.ci").read_text()
    base_image = containerfile.splitlines()[0].removeprefix("FROM ")
    assert base_image in matrix

    ci_requirements = (repo_root / "requirements-ci.txt").read_text().splitlines()
    assert all(requirement in matrix for requirement in ci_requirements)

    collections = yaml.safe_load((repo_root / "requirements.yml").read_text())[
        "collections"
    ]
    assert all(
        collection["name"] in matrix and collection["version"] in matrix
        for collection in collections
    )


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown"],
        ["rke2-plan"],
        ["rke2-plan", "--inventory", "relative.yml", "--controller-vars", "/tmp/x"],
        ["rke2-plan", "--inventory", "/tmp/inventory", "--limit", "host"],
    ],
)
def test_operation_launcher_rejects_unsafe_arguments(
    repo_root: Path, command_runner: CommandRunner, argv: list[str]
) -> None:
    command_runner.run(
        [repo_root / "scripts/platform-config-operation", *argv]
    ).assert_failure()


@pytest.mark.parametrize(
    ("operation", "commands"),
    [
        (
            "rke2-plan",
            [
                ["ansible-inventory", "-i", "{inventory}", "--list", "--extra-vars", "@{vars}"],
                ["ansible", "-i", "{inventory}", "rke2_cluster", "-m", "ansible.builtin.ping", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--syntax-check", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--check", "--diff", "--extra-vars", "@{vars}"],
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
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-smoke.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
                ["ansible-playbook", "-i", "{inventory}", "{repo}/playbooks/rke2-smoke.yml", "--limit", "rke2_cluster", "--extra-vars", "@{vars}"],
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

    fake_bin = isolated_test_dir / "bin"
    fake_bin.mkdir()
    fake_content = (
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

with pathlib.Path(os.environ["PLATFORM_CONFIG_OPERATION_LOG"]).open("a") as stream:
    stream.write(json.dumps([pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]) + "\\n")
"""
    )
    for name in ("ansible", "ansible-inventory", "ansible-playbook"):
        _write_executable(fake_bin / name, fake_content)

    environment = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "PLATFORM_CONFIG_OPERATION_LOG": str(log),
    }
    command_runner.run(
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

    observed = [json.loads(line) for line in log.read_text().splitlines()]
    expected = [
        [
            value.format(inventory=inventory, vars=extra_vars, repo=repo_root)
            for value in command
        ]
        for command in commands
    ]
    assert observed == expected


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
        }
    )
    process = subprocess.Popen(
        [
            repo_root / "scripts/platform-config-operation",
            "rke2-plan",
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
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
