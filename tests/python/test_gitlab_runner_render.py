from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from ansible_test_helpers import assert_failed_with, run_playbook
from conftest import CommandRunner


ALPINE_IMAGE = (
    "docker.io/library/alpine:3.22.1@"
    "sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
)
HELPER_IMAGE = (
    "registry.gitlab.com/gitlab-org/gitlab-runner/gitlab-runner-helper:"
    "x86_64-v18.11.3@"
    "sha256:571952e633d345c74af6458eda2948da99cf5315ce9017e1cab22a4c2226887c"
)


@pytest.fixture
def rendered_gitlab_runner(
    repo_root: Path, command_runner: CommandRunner, isolated_test_dir: Path
) -> dict[str, str]:
    fixture = repo_root / "tests/fixtures/gitlab-runner/render.yml"
    outputs = {
        "shell": isolated_test_dir / "gitlab-runner-shell.container",
        "docker": isolated_test_dir / "gitlab-runner-docker.container",
    }
    run_playbook(
        command_runner,
        fixture,
        extra_vars=({"gitlab_runner_test_output_path": str(outputs["shell"])},),
    ).assert_success()
    run_playbook(
        command_runner,
        fixture,
        extra_vars=(
            {
                "gitlab_runner_test_output_path": str(outputs["docker"]),
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_extra_hosts": [
                    "gitlab.example.invalid:192.0.2.10"
                ],
                "podman_host_storage_contract_enabled": True,
                "podman_host_storage_mountpoint": "/var/lib/containers",
            },
        ),
    ).assert_success()
    return {
        name: path.read_text(encoding="utf-8") for name, path in outputs.items()
    }


def test_gitlab_runner_defaults_remain_socket_free(repo_root: Path) -> None:
    defaults = (repo_root / "roles/gitlab_runner/defaults/main.yml").read_text(
        encoding="utf-8"
    )
    for line in (
        "gitlab_runner_executor: shell",
        "gitlab_runner_podman_socket_enabled: false",
        'gitlab_runner_docker_image: ""',
        'gitlab_runner_docker_helper_image: ""',
        "gitlab_runner_docker_pull_policy: always",
        "gitlab_runner_docker_network_per_build: true",
        "gitlab_runner_docker_extra_hosts: []",
    ):
        assert re.search(rf"^{re.escape(line)}$", defaults, re.MULTILINE)


def test_gitlab_runner_shell_quadlet_has_no_socket(
    rendered_gitlab_runner: dict[str, str],
) -> None:
    quadlet = rendered_gitlab_runner["shell"]
    assert "/run/podman/podman.sock" not in quadlet
    assert "/var/run/docker.sock" not in quadlet
    assert "SecurityLabelDisable=" not in quadlet
    assert "RequiresMountsFor=/etc/gitlab-runner /var/lib/gitlab-runner\n" in quadlet
    assert quadlet.count("Volume=") == 2


def test_gitlab_runner_docker_quadlet_mounts_manager_socket_only(
    rendered_gitlab_runner: dict[str, str],
) -> None:
    quadlet = rendered_gitlab_runner["docker"]
    assert (
        "Volume=/run/podman/podman.sock:/run/podman/podman.sock\n" in quadlet
    )
    assert "Volume=/run/podman/podman.sock:/run/podman/podman.sock:Z" not in quadlet
    assert "SecurityLabelDisable=true\n" in quadlet
    assert (
        "RequiresMountsFor=/etc/gitlab-runner /var/lib/gitlab-runner "
        "/var/lib/containers\n"
        "Requires=podman.socket\n"
        "After=podman.socket\n"
    ) in quadlet
    assert quadlet.count("Volume=") == 3


def test_gitlab_runner_registration_uses_typed_docker_arguments(repo_root: Path) -> None:
    tasks = (repo_root / "roles/gitlab_runner/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    for argument in (
        "'--docker-host', gitlab_runner_docker_host",
        "'--docker-image', gitlab_runner_docker_image",
        "'--docker-helper-image', gitlab_runner_docker_helper_image",
        "'--docker-privileged=false'",
        "'--docker-services_privileged=false'",
        "'--docker-pull-policy', gitlab_runner_docker_pull_policy",
        "'--feature-flags', 'FF_NETWORK_PER_BUILD:'",
        "['--docker-extra-hosts'] | product(gitlab_runner_docker_extra_hosts)",
        "['--docker-volumes'] | product(gitlab_runner_docker_volumes)",
    ):
        assert argument in tasks
    assert ".docker.extra_hosts == gitlab_runner_docker_extra_hosts" in tasks


def test_gitlab_runner_pins_outside_git_ca_bytes(repo_root: Path) -> None:
    validate = (repo_root / "roles/gitlab_runner/tasks/validate.yml").read_text(
        encoding="utf-8"
    )
    preflight = (repo_root / "roles/gitlab_runner/tasks/preflight.yml").read_text(
        encoding="utf-8"
    )
    assert "gitlab_runner_tls_ca_cert_sha256 is match('^[0-9a-f]{64}$')" in validate
    assert "checksum_algorithm: sha256" in preflight
    assert (
        "gitlab_runner_tls_ca_cert_src_stat.stat.checksum == gitlab_runner_tls_ca_cert_sha256"
        in preflight
    )
    main = (repo_root / "roles/gitlab_runner/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    assert "Check installed GitLab Runner TLS CA certificate" in main
    assert (
        "gitlab_runner_tls_ca_cert_installed_stat.stat.checksum == gitlab_runner_tls_ca_cert_sha256"
        in main
    )


def test_gitlab_runner_executor_migration_fails_closed(repo_root: Path) -> None:
    tasks = (repo_root / "roles/gitlab_runner/tasks/preflight.yml").read_text(
        encoding="utf-8"
    )
    for contract in (
        "Require one exact host for forced GitLab Runner registration",
        "ansible_limit is defined",
        "ansible_limit == inventory_hostname",
        "Read existing GitLab Runner contract for migration safety",
        "Validate existing GitLab Runner contract before migration",
        "gitlab_runner_existing_identities_command.stdout | from_json | length == 1",
        ".docker.privileged == false",
        ".docker.helper_image == gitlab_runner_docker_helper_image",
        ".docker.services_privileged == false",
        ".docker.extra_hosts == gitlab_runner_docker_extra_hosts",
        ".docker.volumes == gitlab_runner_docker_volumes",
        ".network_per_build == true",
        "gitlab_runner_force_register=true",
    ):
        assert contract in tasks


@pytest.mark.parametrize(
    ("case_id", "extra_vars", "message"),
    [
        (
            "socket-with-shell",
            {
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
            },
            "requires the Docker executor",
        ),
        (
            "mutable-manager-image",
            {"gitlab_runner_test_image": "docker.io/gitlab/gitlab-runner:latest"},
            "documented types and required values",
        ),
        (
            "ca-without-digest",
            {"gitlab_runner_test_tls_ca_cert_src": "/outside-git/ca.crt"},
            "documented types and required values",
        ),
        (
            "digest-without-ca",
            {"gitlab_runner_test_tls_ca_cert_sha256": "a" * 64},
            "documented types and required values",
        ),
        (
            "docker-without-socket",
            {"gitlab_runner_test_executor": "docker"},
            "requires the manager-only Podman socket",
        ),
        (
            "host-socket-disabled",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
            },
            "requires the Docker executor",
        ),
        (
            "mutable-image",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": "docker.io/library/alpine:latest",
            },
            "requires the manager-only Podman socket",
        ),
        (
            "mutable-helper-image",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_helper_image": "registry.gitlab.com/example/helper:latest",
            },
            "requires the manager-only Podman socket",
        ),
        (
            "mismatched-endpoint",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_host": "unix:///var/run/docker.sock",
            },
            "requires the manager-only Podman socket",
        ),
        (
            "invalid-extra-host",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_extra_hosts": [
                    "gitlab.example.invalid:300.1.1.1"
                ],
            },
            "hostname:IPv4 mappings",
        ),
        (
            "duplicate-extra-host",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_extra_hosts": [
                    "gitlab.example.invalid:192.0.2.10",
                    "gitlab.example.invalid:192.0.2.10",
                ],
            },
            "unique static host mappings",
        ),
        (
            "host-bind-volume",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_volumes": ["/host:/container"],
            },
            "container-only absolute paths",
        ),
        (
            "job-socket-volume",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_docker_volumes": ["/run/podman/podman.sock"],
            },
            "container-only absolute paths",
        ),
        (
            "privileged-override",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_registration_extra_args": [
                    "--docker-privileged"
                ],
            },
            "managed by typed role variables",
        ),
        (
            "privileged-equals-override",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_registration_extra_args": [
                    "--docker-privileged=true"
                ],
            },
            "managed by typed role variables",
        ),
        (
            "volume-equals-override",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_registration_extra_args": [
                    "--docker-volumes=/host:/container"
                ],
            },
            "managed by typed role variables",
        ),
        (
            "feature-flags-equals-override",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_registration_extra_args": [
                    "--feature-flags=FF_NETWORK_PER_BUILD:false"
                ],
            },
            "managed by typed role variables",
        ),
        (
            "executor-equals-override",
            {
                "gitlab_runner_test_registration_extra_args": [
                    "--executor=docker"
                ],
            },
            "managed by typed role variables",
        ),
        (
            "token-short-override",
            {"gitlab_runner_test_registration_extra_args": ["-tmalicious"]},
            "managed by typed role variables",
        ),
        (
            "registration-token-override",
            {
                "gitlab_runner_test_registration_extra_args": [
                    "--registration-token=malicious"
                ]
            },
            "managed by typed role variables",
        ),
        (
            "url-short-override",
            {
                "gitlab_runner_test_registration_extra_args": [
                    "-u=https://malicious.invalid"
                ]
            },
            "managed by typed role variables",
        ),
        (
            "config-short-override",
            {"gitlab_runner_test_registration_extra_args": ["-c/tmp/other"]},
            "managed by typed role variables",
        ),
        (
            "description-override",
            {
                "gitlab_runner_test_registration_extra_args": [
                    "--description=other"
                ]
            },
            "managed by typed role variables",
        ),
        (
            "network-disabled",
            {
                "gitlab_runner_test_executor": "docker",
                "gitlab_runner_test_socket_enabled": True,
                "gitlab_runner_test_podman_socket_enabled": True,
                "gitlab_runner_test_docker_image": ALPINE_IMAGE,
                "gitlab_runner_test_network_per_build": False,
            },
            "requires the manager-only Podman socket",
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_gitlab_runner_rejects_unsafe_docker_input(
    case_id: str,
    extra_vars: dict[str, Any],
    message: str,
    repo_root: Path,
    command_runner: CommandRunner,
    isolated_test_dir: Path,
) -> None:
    output = isolated_test_dir / case_id
    result = run_playbook(
        command_runner,
        repo_root / "tests/fixtures/gitlab-runner/render.yml",
        extra_vars=(
            {
                "gitlab_runner_test_output_path": str(output),
                **extra_vars,
            },
        ),
    )
    assert_failed_with(result, message)
