from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import CommandRunner


EXPECTED_ASSERTION_IDS = {
    "kubernetes_minor_supported",
    "source_checkout_exact",
    "image_digest_resolved",
    "image_revision_matches",
    "runtime_commit_matches",
    "chart_digest_resolved",
    "chart_source_matches",
    "deployment_available",
    "running_image_matches",
    "service_contract",
    "service_endpoints_ready",
    "network_policy_enabled",
    "network_policy_present",
    "network_policy_positive_path",
    "network_policy_negative_path",
    "health_proxy",
    "ready_proxy",
    "issue_contract",
    "bootstrap_identity",
    "bootstrap_group",
    "token_secret_present",
    "revoke_contract",
    "token_secret_absent",
    "credential_rejected",
    "admin_auth_healthy",
    "redaction_enforced",
}


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _task_by_name(tasks: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(task for task in tasks if task.get("name") == name)


def _assert_regex(text: str, pattern: str, message: str) -> None:
    assert re.search(pattern, text, re.MULTILINE), message


def _assert_not_regex(text: str, pattern: str, message: str) -> None:
    assert not re.search(pattern, text, re.MULTILINE), message


def _assert_fixed(text: str, fragment: str, message: str) -> None:
    assert fragment in text, message


@pytest.fixture(scope="module")
def staging_sources(repo_root: Path) -> dict[str, Path | str]:
    role = repo_root / "roles/bootstrap_token_issuer_staging"
    paths = {
        "main": role / "tasks/main.yml",
        "preflight": role / "tasks/preflight.yml",
        "validate": role / "tasks/validate.yml",
        "rollback": role / "tasks/rollback.yml",
        "cleanup": role / "tasks/cleanup.yml",
        "evidence": role / "tasks/evidence.yml",
        "deploy": role / "tasks/deploy.yml",
        "credential": role / "files/credential-contract.sh",
    }
    return {
        **paths,
        **{
            f"{name}_text": path.read_text(encoding="utf-8")
            for name, path in paths.items()
        },
    }


def test_modes_and_failure_lifecycle(staging_sources: dict[str, Path | str]) -> None:
    preflight = str(staging_sources["preflight_text"])
    main = str(staging_sources["main_text"])
    _assert_regex(
        preflight,
        r"\['preflight', 'rollback_rehearsal', 'validate'\]",
        "staging workflow does not enforce all explicit modes",
    )
    _assert_regex(main, r"^  rescue:$", "staging workflow lacks a rescue path")
    _assert_regex(main, r"^  always:$", "staging workflow lacks an always path")
    _assert_regex(
        main,
        "controlled_failure",
        "rollback rehearsal does not use the controlled failure guard",
    )


def test_immutable_public_artifacts(staging_sources: dict[str, Path | str]) -> None:
    preflight_path = Path(staging_sources["preflight"])
    preflight = str(staging_sources["preflight_text"])
    tasks = _load_yaml(preflight_path)
    input_task = _task_by_name(tasks, "Validate bootstrap token issuer staging inputs")
    input_assertions = input_task["ansible.builtin.assert"]["that"]
    expected_inputs = {
        "bootstrap_token_issuer_staging_source_tag == 'v0.3.1'",
        (
            "bootstrap_token_issuer_staging_source_commit == "
            "'4d5dc06fe485a5e33fceb49d1a195dac30ff4bb8'"
        ),
        "bootstrap_token_issuer_staging_version == '0.3.1'",
        (
            "bootstrap_token_issuer_staging_image_ref == "
            "'codeberg.org/rch/bootstrap-token-issuer:0.3.1'"
        ),
        (
            "bootstrap_token_issuer_staging_image_digest == "
            "'sha256:54d261dd1c9534c496ef30c5b9d4e4e45cc7385ef1343a8230df65db921a1c9e'"
        ),
        (
            "bootstrap_token_issuer_staging_chart_ref == "
            "'codeberg.org/rch/charts/bootstrap-token-issuer:0.3.1'"
        ),
        (
            "bootstrap_token_issuer_staging_chart_digest == "
            "'sha256:767c9ad9ef1e8ca58fa98f92f7f0890860778f4f72d43162eefaaa5e8ad41980'"
        ),
        (
            "bootstrap_token_issuer_staging_release_manifest_url == "
            "'https://codeberg.org/rch/bootstrap-token-issuer/releases/download/"
            "v0.3.1/release-manifest.json'"
        ),
    }
    assert expected_inputs.issubset(input_assertions)

    schema_task = _task_by_name(
        tasks, "Download pinned bootstrap token issuer staging evidence schema"
    )
    schema_download = schema_task["ansible.builtin.get_url"]
    assert schema_download["url"] == (
        "https://codeberg.org/rch/bootstrap-token-issuer/raw/tag/v0.3.1/"
        "docs/staging-validation-result.schema.json"
    )
    assert schema_download["checksum"] == (
        "sha256:e8c4d616d147c4cb6ca0b5acbb235ee207fe3732c1a3dae5453db15307df222e"
    )

    chart_task = _task_by_name(
        tasks, "Assert bootstrap token issuer chart release provenance"
    )
    chart_assertions = chart_task["ansible.builtin.assert"]["that"]
    assert (
        "bootstrap_token_issuer_staging_chart_checksum_command.stdout.split()[0] "
        "== 'eeeb71042de519387c5e992b261b6b0842f463ef2cedfa71b3b950ebc10c1028'"
        in chart_assertions
    )

    _assert_not_regex(
        preflight,
        r"v?0\.3\.0",
        "active preflight references the superseded v0.3.0 artifact",
    )
    _assert_regex(
        preflight,
        "skopeo inspect --raw",
        "OCI chart digest is not independently resolved",
    )
    _assert_regex(
        str(staging_sources["deploy_text"]),
        r"image\.tag=.*image_digest",
        "deployed image is not constrained by the supplied digest",
    )


def test_rollback_and_secret_safety(
    staging_sources: dict[str, Path | str], command_runner: CommandRunner
) -> None:
    rollback = str(staging_sources["rollback_text"])
    preflight = str(staging_sources["preflight_text"])
    validate = str(staging_sources["validate_text"])
    credential = str(staging_sources["credential_text"])

    for fragment, message in (
        ("helm_rollback", "existing-release rollback strategy is missing"),
        ("uninstall_candidate", "first-install uninstall strategy is missing"),
        (
            "Check every rendered first-install resource is absent",
            "first-install rollback does not verify rendered resource absence",
        ),
        (
            "Delete first-install supplemental bootstrap token issuer NetworkPolicy",
            "first-install rollback does not delete its supplemental NetworkPolicy",
        ),
        (
            "Restore previous supplemental bootstrap token issuer NetworkPolicy",
            "existing-release rollback does not restore its supplemental NetworkPolicy",
        ),
        (
            "Normalize restored supplemental bootstrap token issuer NetworkPolicy",
            "existing supplemental NetworkPolicy rollback is not normalized",
        ),
    ):
        _assert_regex(rollback, fragment, message)
    for fragment, message in (
        (
            "Check existing bootstrap token issuer rollback target health",
            "existing release rollback target health is not checked",
        ),
        (
            "Install secret-safe bootstrap token issuer credential validator",
            "cleanup helper is not armed before candidate mutation",
        ),
    ):
        _assert_regex(preflight, fragment, message)
    _assert_regex(
        validate,
        "Run secret-safe bootstrap token issue, authentication, and revoke checks",
        "secret-safe credential contract task is missing",
    )
    _assert_regex(
        validate,
        r"^  no_log: true$",
        "credential validation tasks are not protected with no_log",
    )
    for pattern, message in (
        (r'reason "manual-recovery"', "credential validation uses an unsupported reason"),
        (r"printf.*token_id.*token-id", "token ID is not persisted immediately"),
        ("cleanup_exact", "credential cleanup helper is not invoked"),
        (r"exit \$\?", "credential cleanup does not propagate cleanup failures"),
        ("mapfile -t issuer_pod_rows", "redaction does not enumerate issuer Pods"),
        ("restart_count > 0", "redaction does not require previous logs"),
        ("--previous", "redaction does not inspect previous issuer logs"),
    ):
        _assert_regex(credential, pattern, message)
    for fragment, message in (
        (
            '(.status.userInfo.groups | type) == "array"',
            "credential validation does not require a bootstrap group array",
        ),
        (
            "(.status.userInfo.groups | index($group)) != null",
            "credential validation does not parse bootstrap groups",
        ),
        (
            ":[0-9]{2}(\\\\.[0-9]{1,9})?Z\\\\z",
            "credential validation does not accept RFC3339 fractional seconds",
        ),
        (
            "expires_parts=\"$(date -u --date=\"$expires_at\" '+%s %N' "
            "2>/dev/null)\" || fail_check issue_contract",
            "credential validation does not preserve fractional seconds",
        ),
        (
            '[[ "$ttl_seconds" =~ ^[1-9][0-9]{0,8}$ ]]',
            "credential validation does not bound TTL arithmetic",
        ),
        (
            "expires_ns=$((10#$expires_ns))",
            "credential validation does not parse fractions as base 10",
        ),
        (
            "expires_epoch > upper_epoch",
            "credential validation does not bound expiration safely",
        ),
        (
            'secret_expires_at="${secret_expires_at%%.*}Z"',
            "credential validation does not normalize Secret expiration",
        ),
    ):
        _assert_fixed(credential, fragment, message)

    timestamp_pattern = re.compile(
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(\.[0-9]{1,9})?Z$"
    )
    valid_timestamps = (
        "2026-07-27T08:07:08Z",
        "2026-07-27T08:07:08.1Z",
        "2026-07-27T08:07:08.123456789Z",
        "9999-12-31T23:59:59.999999999Z",
    )
    invalid_timestamps = (
        "2026-07-27T08:07:08.Z",
        "2026-07-27T08:07:08.1234567890Z",
        "2026-07-27T08:07:08.123+00:00",
        "2026-07-27T08:07:08Z\n",
    )
    assert all(timestamp_pattern.fullmatch(value) for value in valid_timestamps)
    assert not any(timestamp_pattern.fullmatch(value) for value in invalid_timestamps)
    for timestamp in valid_timestamps:
        command_runner.run(["date", "-u", f"--date={timestamp}", "+%s%N"]).assert_success()
    for timestamp in (
        "2026-02-31T08:07:08Z",
        "2026-07-27T24:07:08Z",
        "2026-07-27T08:60:08Z",
        "2026-07-27T08:07:60Z",
    ):
        command_runner.run(["date", "-u", f"--date={timestamp}", "+%s%N"]).assert_failure()
    command_runner.run(
        ["bash", "-n", str(staging_sources["credential"])]
    ).assert_success()
    _assert_regex(
        validate,
        r'test "\$rc" = 28',
        "NetworkPolicy negative test accepts unexpected failures",
    )


def test_required_assertion_ids(staging_sources: dict[str, Path | str]) -> None:
    tasks = _load_yaml(Path(staging_sources["main"]))
    actual = set(
        tasks[0]["ansible.builtin.set_fact"][
            "bootstrap_token_issuer_staging_assertions"
        ]
    )
    assert actual == EXPECTED_ASSERTION_IDS

    validation_tasks = _load_yaml(Path(staging_sources["validate"]))
    secret_safe_tasks = {
        "Run secret-safe bootstrap token issue, authentication, and revoke checks",
        "Parse secret-safe bootstrap token issuer credential results",
        "Record separately tracked bootstrap token issuer credential assertions",
        "Run verified upstream aggregate staging validator",
    }
    for task in validation_tasks:
        if task.get("name") in secret_safe_tasks:
            assert task.get("no_log") is True, task["name"]

    evidence_tasks = _load_yaml(Path(staging_sources["evidence"]))
    result = next(
        task["ansible.builtin.set_fact"]["bootstrap_token_issuer_staging_result"]
        for task in evidence_tasks
        if task.get("name")
        == "Assemble redacted bootstrap token issuer staging evidence"
    )
    assert set(result) == {
        "schemaVersion",
        "outcome",
        "run",
        "candidate",
        "cluster",
        "assertions",
        "cleanup",
        "rollback",
    }
    assert result["assertions"] == "{{ bootstrap_token_issuer_staging_assertions }}"
    assert set(result["candidate"]) == {
        "sourceCommit",
        "imageRef",
        "imageDigest",
        "imageRevision",
        "runtimeCommit",
        "chartRef",
        "chartDigest",
        "chartVersion",
        "chartSourceCommit",
    }
    assert set(result["rollback"]) == {
        "mutationApplied",
        "triggered",
        "strategy",
        "result",
        "previousHelmRevision",
        "previousImageDigest",
        "rolloutHealthy",
        "runningImageMatchesTarget",
        "candidateResourcesAbsent",
    }


def test_controller_tasks_disable_inventory_become(
    staging_sources: dict[str, Path | str]
) -> None:
    for source_name in ("preflight", "evidence"):
        for task in _load_yaml(Path(staging_sources[source_name])):
            if task.get("delegate_to") == "localhost":
                assert task.get("become") is False, task.get("name")
                assert task.get("vars", {}).get("ansible_become") is False, task.get(
                    "name"
                )


def test_fail_closed_preflight_and_cleanup(
    staging_sources: dict[str, Path | str]
) -> None:
    preflight = str(staging_sources["preflight_text"])
    cleanup = str(staging_sources["cleanup_text"])
    validate = str(staging_sources["validate_text"])
    for pattern, message in (
        (
            "Assert existing bootstrap token issuer Secret RBAC",
            "existing shared issuer RBAC is not asserted",
        ),
        (
            r"rejectattr\('stdout', 'equalto', 'yes'\)",
            "existing issuer RBAC does not require affirmative can-i results",
        ),
        ("role_grants_required_secrets", "rendered issuer RBAC is not exact"),
        ("role_binding_matches", "rendered RoleBinding is not correlated"),
        (
            "Require conclusive supplemental bootstrap token issuer NetworkPolicy state",
            "supplemental NetworkPolicy lookup errors do not fail closed",
        ),
        (r"spec\.egress \| length", "NetworkPolicy egress count is not constrained"),
        (
            r"spec\.egress\[0\]\.to \| length",
            "NetworkPolicy allows unexpected egress peers",
        ),
        (
            r"--arg app_name.*bootstrap_token_issuer_staging_deployment_name",
            "NetworkPolicy selector is not tied to workload identity",
        ),
        (
            r"spec\.podSelector == .*\$app_name",
            "NetworkPolicy selector does not use expected identity",
        ),
        (
            "Reject supplemental bootstrap token issuer NetworkPolicy identity collision",
            "supplemental NetworkPolicy can collide with Helm output",
        ),
        (
            "mode != 'validate' or bootstrap_token_issuer_staging_run_upstream_validator",
            "validate mode can disable the aggregate validator",
        ),
    ):
        _assert_regex(preflight, pattern, message)

    tasks = _load_yaml(Path(staging_sources["preflight"]))
    network_policy = _task_by_name(
        tasks, "Require rendered bootstrap token issuer NetworkPolicy"
    )
    assert (
        "bootstrap_token_issuer_staging_render_contract.deployment_app_name "
        "== bootstrap_token_issuer_staging_deployment_name"
        in network_policy["ansible.builtin.assert"]["that"]
    )
    _assert_regex(
        cleanup,
        r"cleanup_helper\.stat\.exists",
        "post-mutation cleanup does not require the cleanup helper",
    )
    _assert_regex(
        cleanup,
        r"exact_cleanup_command\.rc.*default\(1\)",
        "unavailable exact cleanup does not fail closed",
    )
    _assert_regex(
        validate,
        "credential_results.csr_check == 'pass'",
        "validate mode does not require the CSR contract check",
    )


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _cleanup_environment(
    test_environment: dict[str, str],
    bin_dir: Path,
    jq_log: Path,
    kubectl: Path,
    kubectl_log: Path,
    state_dir: Path,
    mode: str,
) -> dict[str, str]:
    environment = dict(test_environment)
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "FAKE_JQ_LOG": str(jq_log),
            "FAKE_KUBECTL_LOG": str(kubectl_log),
            "KUBECTL_BIN": str(kubectl),
            "KUBE_CONTEXT": "test",
            "STAGING_NAMESPACE": "bastion-system",
            "STAGING_SERVICE_NAME": "bastion-token-issuer",
            "STAGING_SERVICE_PORT_NAME": "http",
            "STAGING_BOOTSTRAP_GROUP": "system:bootstrappers:platform-users",
            "STAGING_TTL_SECONDS": "60",
            "STAGING_REQUEST_TIMEOUT_SECONDS": "1",
            "STAGING_REVOKE_PROPAGATION_SECONDS": "1",
            "STAGING_STATE_DIR": str(state_dir),
            "STAGING_RUN_ID": "test",
            "FAKE_MODE": mode,
        }
    )
    return environment


def test_cleanup_failure_semantics(
    staging_sources: dict[str, Path | str],
    command_runner: CommandRunner,
    isolated_test_dir: Path,
    test_environment: dict[str, str],
) -> None:
    bin_dir = isolated_test_dir / "bin"
    bin_dir.mkdir()
    jq_log = isolated_test_dir / "jq.log"
    kubectl_log = isolated_test_dir / "kubectl.log"
    fake_jq = bin_dir / "jq"
    fake_kubectl = bin_dir / "kubectl"
    _write_executable(
        fake_jq,
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_JQ_LOG:?}"
if [[ "$#" -ne 5 || "$1" != -n || "$2" != --arg || "$3" != token_id || "$5" != '{tokenId: $token_id}' ]]; then
  printf '%s\n' 'unexpected jq invocation' >&2
  exit 2
fi
printf '{"tokenId":"%s"}\n' "$4"
""",
    )
    _write_executable(
        fake_kubectl,
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_KUBECTL_LOG:?}"
case " ${*} " in
  *" delete secret "*) [[ "${FAKE_MODE:-}" != secret-delete-failure ]] ;;
  *" get secret "*) exit 1 ;;
  *" delete certificatesigningrequest "*) [[ "${FAKE_MODE:-}" != csr-delete-failure ]] ;;
  *" get certificatesigningrequest "*) exit 1 ;;
esac
""",
    )
    credential = str(staging_sources["credential"])

    empty_state = isolated_test_dir / "empty"
    empty_state.mkdir()
    jq_log.write_text("", encoding="utf-8")
    kubectl_log.write_text("", encoding="utf-8")
    command_runner.run(
        ["bash", credential, "cleanup"],
        environment=_cleanup_environment(
            test_environment,
            bin_dir,
            jq_log,
            fake_kubectl,
            kubectl_log,
            empty_state,
            "success",
        ),
    ).assert_success()

    token_state = isolated_test_dir / "token"
    token_state.mkdir()
    (token_state / "token-id").write_text("abc123", encoding="utf-8")
    jq_log.write_text("", encoding="utf-8")
    kubectl_log.write_text("", encoding="utf-8")
    command_runner.run(
        ["bash", credential, "cleanup"],
        environment=_cleanup_environment(
            test_environment,
            bin_dir,
            jq_log,
            fake_kubectl,
            kubectl_log,
            token_state,
            "secret-delete-failure",
        ),
    ).assert_failure()
    assert "-n --arg token_id abc123 {tokenId: $token_id}" in jq_log.read_text(
        encoding="utf-8"
    )
    assert (
        "delete secret bootstrap-token-abc123 --ignore-not-found"
        in kubectl_log.read_text(encoding="utf-8")
    )

    csr_state = isolated_test_dir / "csr"
    csr_state.mkdir()
    (csr_state / "csr-name").write_text("staging-test-csr", encoding="utf-8")
    jq_log.write_text("", encoding="utf-8")
    kubectl_log.write_text("", encoding="utf-8")
    command_runner.run(
        ["bash", credential, "cleanup"],
        environment=_cleanup_environment(
            test_environment,
            bin_dir,
            jq_log,
            fake_kubectl,
            kubectl_log,
            csr_state,
            "csr-delete-failure",
        ),
    ).assert_failure()
    assert (
        "delete certificatesigningrequest staging-test-csr --ignore-not-found"
        in kubectl_log.read_text(encoding="utf-8")
    )


def test_source_assertion_is_mutation_sensitive(
    staging_sources: dict[str, Path | str]
) -> None:
    mutated = str(staging_sources["main_text"]).replace("  rescue:", "  recovery:", 1)
    with pytest.raises(AssertionError):
        _assert_regex(mutated, r"^  rescue:$", "staging workflow lacks a rescue path")
