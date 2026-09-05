from __future__ import annotations

import json
from pathlib import Path

import yaml

from conftest import CommandRunner


EXPECTED_DEFAULTS = {
    "rke2_gitlab_runner_enabled",
    "rke2_gitlab_runner_gitlab_url",
    "rke2_gitlab_runner_token_src",
    "rke2_gitlab_runner_tls_ca_cert_src",
    "rke2_gitlab_runner_tls_ca_cert_sha256",
    "rke2_gitlab_runner_name",
    "rke2_gitlab_runner_chart_version",
    "rke2_gitlab_runner_manager_image",
    "rke2_gitlab_runner_helper_image",
    "rke2_gitlab_runner_default_job_image",
}


def test_rke2_gitlab_runner_public_contract_is_minimal(repo_root: Path) -> None:
    defaults = yaml.safe_load(
        (repo_root / "roles/rke2_gitlab_runner/defaults/main.yml").read_text()
    )

    assert set(defaults) == EXPECTED_DEFAULTS
    assert defaults["rke2_gitlab_runner_enabled"] is False
    assert defaults["rke2_gitlab_runner_chart_version"] == "0.88.3"
    for name in (
        "rke2_gitlab_runner_manager_image",
        "rke2_gitlab_runner_helper_image",
        "rke2_gitlab_runner_default_job_image",
    ):
        assert "@sha256:" in defaults[name]


def test_rke2_gitlab_runner_disabled_role_skips_management(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    playbook = isolated_test_dir / "disabled.yml"
    playbook.write_text(
        """---
- hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: rke2_gitlab_runner
      rke2_gitlab_runner_enabled: false
""",
        encoding="utf-8",
    )

    result = command_runner.run(
        ["ansible-playbook", "-i", "localhost,", playbook, "--check"]
    ).assert_success()

    assert "changed=0" in result.stdout
    assert "failed=0" in result.stdout


def test_rke2_gitlab_runner_manifest_is_pinned_and_hardened(
    repo_root: Path,
    isolated_test_dir: Path,
    command_runner: CommandRunner,
) -> None:
    defaults_path = repo_root / "roles/rke2_gitlab_runner/defaults/main.yml"
    template_path = (
        repo_root
        / "roles/rke2_gitlab_runner/templates/gitlab-runner-helmchart.yaml.j2"
    )
    output = isolated_test_dir / "manifest.yml"
    playbook = isolated_test_dir / "render.yml"
    playbook.write_text(
        f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {json.dumps(str(defaults_path))}
  vars:
    rke2_gitlab_runner_gitlab_url: https://gitlab.example.test
    rke2_gitlab_runner_name: test-rke2-runner
    rke2_gitlab_runner_namespace: gitlab-runner
    rke2_gitlab_runner_release_name: rke2-gitlab-runner
    rke2_gitlab_runner_token_secret_name: rke2-gitlab-runner-token
    rke2_gitlab_runner_ca_secret_name: rke2-gitlab-runner-ca
    rke2_gitlab_runner_job_service_account: rke2-gitlab-runner-job
    rke2_gitlab_runner_manager_image_tag: alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e
  tasks:
    - ansible.builtin.copy:
        content: '{{{{ lookup("ansible.builtin.template", {json.dumps(str(template_path))}) }}}}'
        dest: {json.dumps(str(output))}
        mode: "0600"
""",
        encoding="utf-8",
    )

    command_runner.run(
        ["ansible-playbook", "-i", "localhost,", playbook]
    ).assert_success()

    manifest_text = output.read_text(encoding="utf-8")
    manifest = yaml.safe_load(manifest_text)
    values = yaml.safe_load(manifest["spec"]["valuesContent"])
    defaults = yaml.safe_load(defaults_path.read_text())

    assert manifest["metadata"] == {
        "name": "rke2-gitlab-runner",
        "namespace": "kube-system",
    }
    assert manifest["spec"]["targetNamespace"] == "gitlab-runner"
    assert manifest["spec"]["version"] == "0.88.3"
    assert values["certsSecretName"] == "rke2-gitlab-runner-ca"
    assert values["concurrent"] == 1
    assert values["rbac"]["clusterWideAccess"] is False
    assert values["runners"]["secret"] == "rke2-gitlab-runner-token"
    assert values["extraObjects"][0]["automountServiceAccountToken"] is False
    assert values["affinity"]["nodeAffinity"][
        "requiredDuringSchedulingIgnoredDuringExecution"
    ]["nodeSelectorTerms"][0]["matchExpressions"] == [
        {
            "key": "node-role.kubernetes.io/control-plane",
            "operator": "DoesNotExist",
        }
    ]

    rules = values["rbac"]["rules"]
    assert all("*" not in rule["resources"] for rule in rules)
    assert all("*" not in rule["verbs"] for rule in rules)
    config = values["runners"]["config"]
    assert defaults["rke2_gitlab_runner_helper_image"] in config
    assert defaults["rke2_gitlab_runner_default_job_image"] in config
    assert 'automount_service_account_token = false' in config
    assert 'privileged = false' in config
    assert 'node-role.kubernetes.io/control-plane' in config
    assert "glrt-test-secret" not in manifest_text


def test_rke2_gitlab_runner_role_keeps_secret_operations_redacted(
    repo_root: Path,
) -> None:
    tasks = yaml.safe_load(
        (repo_root / "roles/rke2_gitlab_runner/tasks/main.yml").read_text()
    )
    source = (repo_root / "roles/rke2_gitlab_runner/tasks/main.yml").read_text()
    smoke_source = (
        repo_root / "playbooks/rke2-gitlab-runner-smoke.yml"
    ).read_text()

    assert len(tasks) == 2
    assert "rke2_gitlab_runner_enabled | bool" in tasks[0]["when"]
    assert "rke2_gitlab_runner_enabled | bool" in tasks[1]["when"]
    assert "state: absent" not in source
    assert " delete\n" not in source
    assert "match('^glrt-[A-Za-z0-9_.-]+$')" in source
    assert "'replace' if rke2_gitlab_runner_current_secret else 'create'" in source
    assert "resourceVersion" in source
    assert "Wait for replacement RKE2 GitLab Runner Helm install Job" in source
    assert "helm-install-rke2-gitlab-runner" in source
    assert "Wait for RKE2 GitLab Runner Deployment creation" in smoke_source
    assert "rke2_gitlab_runner_smoke_expected_role_rules" in smoke_source
    assert "rke2_gitlab_runner_smoke_gitlab_host ~ '.crt'" in smoke_source
    for name in (
        "Read RKE2 GitLab Runner token source",
        "Decode RKE2 GitLab Runner token",
        "Read existing RKE2 GitLab Runner Secrets",
        "Reconcile RKE2 GitLab Runner Secrets",
    ):
        task = next(item for item in tasks[1]["block"] if item["name"] == name)
        assert task["no_log"] is True
