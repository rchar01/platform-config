#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
USERS_TASKS="${ROOT_DIR}/roles/k8s_bastion_access/tasks/users.yml"

assert_contains() {
  local pattern="$1"
  local message="$2"

  if ! grep -qE -- "$pattern" "$USERS_TASKS"; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

assert_order() {
  local first="$1"
  local second="$2"
  local message="$3"
  local first_line second_line

  first_line="$(grep -nE -- "$first" "$USERS_TASKS" | sed -n '1s/:.*//p')"
  second_line="$(grep -nE -- "$second" "$USERS_TASKS" | sed -n '1s/:.*//p')"
  if [[ -z "$first_line" || -z "$second_line" || "$first_line" -ge "$second_line" ]]; then
    printf '%s\n' "$message" >&2
    exit 1
  fi
}

test_policy_demotion_uses_previous_manifest() {
  assert_contains 'manifest=\{\{ k8s_bastion_policy_access_managed_manifest_path \| quote \}\}' \
    'Policy reconciliation does not reference the managed policy access manifest'
  assert_contains 'yq -r '\''\(\.managedGroups // \[\]\) \| \.\[\]'\'' "\$manifest"' \
    'Policy reconciliation does not include previously managed groups'
  assert_contains 'printf '\''extra-membership %s %s\\n'\'' "\$member" "\$group"' \
    'Policy drift check does not report extra managed memberships'
  assert_contains 'gpasswd -d "\$member" "\$group"' \
    'Policy reconciliation does not remove stale group memberships'
  assert_contains 'select\('\''match'\'', '\''\^extra-membership '\''\)' \
    'Stale membership task changed_when is not tied to extra-membership drift'
}

test_reconcile_disabled_preserves_manifest_context() {
  assert_order 'Collect Kubernetes bastion current managed policy groups' 'Check Kubernetes bastion user group drift' \
    'Current managed groups must be collected before drift checks'
  assert_contains '- k8s_bastion_reconcile_policy_access' \
    'Managed policy access tasks are not gated by k8s_bastion_reconcile_policy_access'
  assert_order 'Revoke stale Kubernetes bastion admin kubeconfigs from policy' 'Write Kubernetes bastion managed policy access manifest' \
    'Managed policy access manifest should be updated after stale access cleanup tasks'
}

test_admin_kubeconfig_cleanup_is_precise() {
  assert_contains 'cmp -s "\$admin_kubeconfig" "\$config" \|\| continue' \
    'Admin cleanup does not verify user kubeconfig byte-matches managed source before removal'
  assert_contains 'USER_KEY="\$user" ADMIN_GROUP="\$admin_group" yq -e '\''\(\.users\[strenv\(USER_KEY\)\]\.ensureGroups // \[\]\) \| contains\(\[strenv\(ADMIN_GROUP\)\]\)'\'' "\$policy" >/dev/null 2>&1 && continue' \
    'Admin cleanup does not preserve users still in the configured admin group'
  assert_contains 'rm -f "\$config"' \
    'Admin cleanup does not remove stale managed admin kubeconfigs'
  assert_contains '--admin-group \{\{ k8s_bastion_admin_group \}\}' \
    'Admin bootstrap command does not pass the configured admin group'
}

test_policy_demotion_uses_previous_manifest
test_reconcile_disabled_preserves_manifest_context
test_admin_kubeconfig_cleanup_is_precise

printf 'Kubernetes bastion access reconciliation check passed\n'
