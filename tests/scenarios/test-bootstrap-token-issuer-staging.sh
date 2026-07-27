#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ROLE_DIR="${ROOT_DIR}/roles/bootstrap_token_issuer_staging"
MAIN_TASKS="${ROLE_DIR}/tasks/main.yml"
PREFLIGHT_TASKS="${ROLE_DIR}/tasks/preflight.yml"
VALIDATE_TASKS="${ROLE_DIR}/tasks/validate.yml"
ROLLBACK_TASKS="${ROLE_DIR}/tasks/rollback.yml"
CREDENTIAL_SCRIPT="${ROLE_DIR}/files/credential-contract.sh"

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  if ! grep -qE -- "$pattern" "$file"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

test_modes_and_failure_lifecycle() {
  assert_contains "$PREFLIGHT_TASKS" "\['preflight', 'rollback_rehearsal', 'validate'\]" \
    'Staging workflow does not enforce all three explicit modes'
  assert_contains "$MAIN_TASKS" '^  rescue:$' \
    'Staging workflow does not define a rescue path'
  assert_contains "$MAIN_TASKS" '^  always:$' \
    'Staging workflow does not define an always cleanup path'
  assert_contains "$MAIN_TASKS" 'controlled_failure' \
    'Rollback rehearsal does not use the controlled failure guard'
}

test_immutable_public_artifacts() {
  assert_contains "$PREFLIGHT_TASKS" "image_ref == 'codeberg.org/rch/bootstrap-token-issuer:0.3.0'" \
    'Image input is not constrained to the public v0.3.0 artifact'
  assert_contains "$PREFLIGHT_TASKS" "chart_ref == 'codeberg.org/rch/charts/bootstrap-token-issuer:0.3.0'" \
    'Chart input is not constrained to the public v0.3.0 artifact'
  assert_contains "$PREFLIGHT_TASKS" 'skopeo inspect --raw' \
    'OCI chart digest is not independently resolved'
  assert_contains "${ROLE_DIR}/tasks/deploy.yml" 'image.tag=.*image_digest' \
    'Deployed image is not constrained by the supplied digest'
}

test_rollback_and_secret_safety() {
  assert_contains "$ROLLBACK_TASKS" 'helm_rollback' \
    'Existing-release rollback strategy is missing'
  assert_contains "$ROLLBACK_TASKS" 'uninstall_candidate' \
    'First-install uninstall strategy is missing'
  assert_contains "$ROLLBACK_TASKS" 'Check every rendered first-install resource is absent' \
    'First-install rollback does not verify rendered resource absence'
  assert_contains "$ROLLBACK_TASKS" 'Delete first-install supplemental bootstrap token issuer NetworkPolicy' \
    'First-install rollback does not delete its supplemental NetworkPolicy'
  assert_contains "$ROLLBACK_TASKS" 'Restore previous supplemental bootstrap token issuer NetworkPolicy' \
    'Existing-release rollback does not restore its supplemental NetworkPolicy'
  assert_contains "$ROLLBACK_TASKS" 'Normalize restored supplemental bootstrap token issuer NetworkPolicy' \
    'Existing supplemental NetworkPolicy rollback is not compared after normalization'
  assert_contains "$PREFLIGHT_TASKS" 'Check existing bootstrap token issuer rollback target health' \
    'Existing release rollback target health is not checked before mutation'
  assert_contains "$PREFLIGHT_TASKS" 'Install secret-safe bootstrap token issuer credential validator' \
    'Cleanup helper is not armed before candidate mutation'
  assert_contains "$VALIDATE_TASKS" 'Run secret-safe bootstrap token issue, authentication, and revoke checks' \
    'Secret-safe credential contract task is missing'
  assert_contains "$VALIDATE_TASKS" '^  no_log: true$' \
    'Credential validation tasks are not protected with no_log'
  assert_contains "$CREDENTIAL_SCRIPT" 'reason "manual-recovery"' \
    'Credential validation does not use an issuer-supported reason'
  assert_contains "$CREDENTIAL_SCRIPT" 'printf.*token_id.*token-id' \
    'Credential validation does not persist the token ID for cleanup immediately after parsing'
  assert_contains "$CREDENTIAL_SCRIPT" 'cleanup_exact' \
    'Credential cleanup helper is not invoked'
  assert_contains "$CREDENTIAL_SCRIPT" 'exit \$\?' \
    'Credential cleanup does not propagate exact cleanup failures'
  assert_contains "$CREDENTIAL_SCRIPT" 'mapfile -t issuer_pod_rows' \
    'Credential redaction does not enumerate every issuer Pod'
  assert_contains "$CREDENTIAL_SCRIPT" 'restart_count > 0' \
    'Credential redaction does not require previous logs after issuer restarts'
  assert_contains "$CREDENTIAL_SCRIPT" '--previous' \
    'Credential redaction does not inspect previous issuer logs'
  assert_contains "$VALIDATE_TASKS" 'test "\$rc" = 28' \
    'NetworkPolicy negative test accepts failures other than an expected timeout'
  bash -n "$CREDENTIAL_SCRIPT"
}

test_required_assertion_ids() {
  python3 - "$MAIN_TASKS" "$VALIDATE_TASKS" "${ROLE_DIR}/tasks/evidence.yml" <<'PY'
import sys
import yaml

expected = {
    "kubernetes_minor_supported", "source_checkout_exact", "image_digest_resolved",
    "image_revision_matches", "runtime_commit_matches", "chart_digest_resolved",
    "chart_source_matches", "deployment_available", "running_image_matches",
    "service_contract", "service_endpoints_ready", "network_policy_enabled",
    "network_policy_present", "network_policy_positive_path",
    "network_policy_negative_path", "health_proxy", "ready_proxy", "issue_contract",
    "bootstrap_identity", "bootstrap_group", "token_secret_present", "revoke_contract",
    "token_secret_absent", "credential_rejected", "admin_auth_healthy",
    "redaction_enforced",
}

with open(sys.argv[1], encoding="utf-8") as stream:
    tasks = yaml.safe_load(stream)
actual = set(tasks[0]["ansible.builtin.set_fact"]["bootstrap_token_issuer_staging_assertions"])
if actual != expected:
    raise SystemExit(f"assertion ID mismatch: missing={sorted(expected-actual)} extra={sorted(actual-expected)}")

with open(sys.argv[2], encoding="utf-8") as stream:
    validation_tasks = yaml.safe_load(stream)
secret_safe_tasks = {
    "Run secret-safe bootstrap token issue, authentication, and revoke checks",
    "Parse secret-safe bootstrap token issuer credential results",
    "Record separately tracked bootstrap token issuer credential assertions",
    "Run verified upstream aggregate staging validator",
}
for task in validation_tasks:
    if task.get("name") in secret_safe_tasks and task.get("no_log") is not True:
        raise SystemExit(f"secret-handling task lacks no_log: {task['name']}")

with open(sys.argv[3], encoding="utf-8") as stream:
    evidence_tasks = yaml.safe_load(stream)
result = next(
    task["ansible.builtin.set_fact"]["bootstrap_token_issuer_staging_result"]
    for task in evidence_tasks
    if task.get("name") == "Assemble redacted bootstrap token issuer staging evidence"
)
if set(result) != {"schemaVersion", "outcome", "run", "candidate", "cluster", "assertions", "cleanup", "rollback"}:
    raise SystemExit("redacted evidence top-level fields drifted from the upstream schema")
if result["assertions"] != "{{ bootstrap_token_issuer_staging_assertions }}":
    raise SystemExit("evidence assertions must come only from the initialized stable assertion map")
if set(result["candidate"]) != {"sourceCommit", "imageRef", "imageDigest", "imageRevision", "runtimeCommit", "chartRef", "chartDigest", "chartVersion", "chartSourceCommit"}:
    raise SystemExit("redacted candidate evidence fields drifted from the upstream schema")
if set(result["rollback"]) != {"mutationApplied", "triggered", "strategy", "result", "previousHelmRevision", "previousImageDigest", "rolloutHealthy", "runningImageMatchesTarget", "candidateResourcesAbsent"}:
    raise SystemExit("redacted rollback evidence fields drifted from the upstream schema")
PY
}

test_controller_tasks_disable_inventory_become() {
  python3 - "$PREFLIGHT_TASKS" "${ROLE_DIR}/tasks/evidence.yml" <<'PY'
import sys
import yaml

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as stream:
        tasks = yaml.safe_load(stream)
    for task in tasks:
        if task.get("delegate_to") != "localhost":
            continue
        if task.get("become") is not False or task.get("vars", {}).get("ansible_become") is not False:
            raise SystemExit(f"delegated localhost task inherits inventory become: {task.get('name')}")
PY
}

test_fail_closed_preflight_and_cleanup() {
  assert_contains "$PREFLIGHT_TASKS" 'Assert existing bootstrap token issuer Secret RBAC' \
    'Existing shared issuer RBAC is not asserted'
  assert_contains "$PREFLIGHT_TASKS" "rejectattr\('stdout', 'equalto', 'yes'\)" \
    'Existing shared issuer RBAC does not require affirmative can-i results'
  assert_contains "$PREFLIGHT_TASKS" 'role_grants_required_secrets' \
    'Rendered issuer RBAC does not verify exact Secret permissions'
  assert_contains "$PREFLIGHT_TASKS" 'role_binding_matches' \
    'Rendered issuer RBAC does not correlate RoleBinding roleRef'
  assert_contains "$PREFLIGHT_TASKS" 'Require conclusive supplemental bootstrap token issuer NetworkPolicy state' \
    'Supplemental NetworkPolicy lookup errors do not fail preflight closed'
  assert_contains "$PREFLIGHT_TASKS" 'spec.egress \| length' \
    'Supplemental NetworkPolicy does not constrain its egress rule count'
  assert_contains "$PREFLIGHT_TASKS" 'spec.egress\[0\]\.to \| length' \
    'Supplemental NetworkPolicy does not reject unexpected egress peers'
  assert_contains "$PREFLIGHT_TASKS" 'Reject supplemental bootstrap token issuer NetworkPolicy identity collision' \
    'Supplemental NetworkPolicy can collide with a Helm-rendered resource'
  assert_contains "${ROLE_DIR}/tasks/cleanup.yml" 'cleanup_helper.stat.exists' \
    'Post-mutation cleanup does not require the cleanup helper'
  assert_contains "${ROLE_DIR}/tasks/cleanup.yml" 'exact_cleanup_command.rc.*default\(1\)' \
    'Unavailable exact cleanup does not fail closed'
  assert_contains "$VALIDATE_TASKS" "credential_results.csr_check == 'pass'" \
    'Validate mode does not require the requested CSR contract check'
  assert_contains "$PREFLIGHT_TASKS" "mode != 'validate' or bootstrap_token_issuer_staging_run_upstream_validator" \
    'Validate mode can disable the verified upstream aggregate validator'
}

test_cleanup_failure_semantics() {
  local tmpdir fake_kubectl rc
  mkdir -p "${ROOT_DIR}/.ansible/tests"
  tmpdir="$(mktemp -d "${ROOT_DIR}/.ansible/tests/credential-cleanup.XXXXXX")"
  fake_kubectl="${tmpdir}/kubectl"
  cat >"$fake_kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case " ${*} " in
  *" delete secret "*) [[ "${FAKE_MODE:-}" != secret-delete-failure ]] ;;
  *" get secret "*) exit 1 ;;
  *" delete certificatesigningrequest "*) [[ "${FAKE_MODE:-}" != csr-delete-failure ]] ;;
  *" get certificatesigningrequest "*) exit 1 ;;
esac
EOF
  chmod 0755 "$fake_kubectl"

  run_cleanup() {
    env \
      KUBECTL_BIN="$fake_kubectl" \
      KUBE_CONTEXT=test \
      STAGING_NAMESPACE=bastion-system \
      STAGING_SERVICE_NAME=bastion-token-issuer \
      STAGING_SERVICE_PORT_NAME=http \
      STAGING_BOOTSTRAP_GROUP=system:bootstrappers:platform-users \
      STAGING_TTL_SECONDS=60 \
      STAGING_REQUEST_TIMEOUT_SECONDS=1 \
      STAGING_REVOKE_PROPAGATION_SECONDS=1 \
      STAGING_STATE_DIR="$1" \
      STAGING_RUN_ID=test \
      FAKE_MODE="$2" \
      bash "$CREDENTIAL_SCRIPT" cleanup
  }

  mkdir -p "${tmpdir}/empty"
  run_cleanup "${tmpdir}/empty" success

  mkdir -p "${tmpdir}/token"
  printf '%s' abc123 >"${tmpdir}/token/token-id"
  set +e
  run_cleanup "${tmpdir}/token" secret-delete-failure
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || { printf '%s\n' 'Secret cleanup failure was masked' >&2; exit 1; }

  mkdir -p "${tmpdir}/csr"
  printf '%s' staging-test-csr >"${tmpdir}/csr/csr-name"
  set +e
  run_cleanup "${tmpdir}/csr" csr-delete-failure
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || { printf '%s\n' 'CSR cleanup failure was masked' >&2; exit 1; }

  rm -rf "$tmpdir"
}

test_modes_and_failure_lifecycle
test_immutable_public_artifacts
test_rollback_and_secret_safety
test_required_assertion_ids
test_controller_tasks_disable_inventory_become
test_fail_closed_preflight_and_cleanup
test_cleanup_failure_semantics

printf 'Bootstrap token issuer staging workflow check passed\n'
