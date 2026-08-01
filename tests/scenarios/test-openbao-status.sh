#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ROLE_DIR="${ROOT_DIR}/roles/openbao_status"
TASKS_DIR="${ROLE_DIR}/tasks"
PLAYBOOK="${ROOT_DIR}/playbooks/maintenance/openbao-status.yml"
FIXTURE="${ROOT_DIR}/tests/fixtures/openbao-status/validate.yml"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  grep -qE -- "$pattern" "$file" || fail "$message"
}

assert_contains_fixed() {
  local file="$1"
  local text="$2"
  local message="$3"

  grep -qF -- "$text" "$file" || fail "$message"
}

assert_rejected() {
  local mode="$1"
  local expected="$2"
  local output

  if output="$(ansible-playbook "$FIXTURE" \
    --extra-vars "openbao_status_test_mode=${mode}" 2>&1)"; then
    fail "OpenBao status accepted ${mode} state"
  fi
  grep -qF -- "$expected" <<< "$output" \
    || fail "OpenBao status ${mode} rejection missed its strict gate"
}

assert_contains_fixed "${TASKS_DIR}/main.yml" "mode is match('^0?[46]00$')" \
  'OpenBao status token permissions are not owner-private'
assert_contains "${TASKS_DIR}/main.yml" 'validate_certs: true' \
  'OpenBao status does not require certificate validation'
assert_contains "${TASKS_DIR}/main.yml" 'follow_redirects: none' \
  'OpenBao health status can follow an unapproved redirect'
assert_contains "${TASKS_DIR}/observe_raft.yml" 'X-Vault-Token:' \
  'OpenBao Raft status does not use the documented token header'
assert_contains "${TASKS_DIR}/observe_raft.yml" 'no_log: true' \
  'OpenBao token-bearing Raft status output is not suppressed'
assert_contains "${TASKS_DIR}/observe_raft.yml" 'follow_redirects: none' \
  'OpenBao token-bearing Raft status can follow a redirect'
assert_contains "$PLAYBOOK" 'run_once: true' \
  'OpenBao cluster status is redundantly executed from every inventory host'

if grep -R -qE -- \
  'ansible[.]builtin[.](command|copy|file|service|shell|systemd_service|template):' \
  "$TASKS_DIR"; then
  fail 'OpenBao status role contains a mutating module'
fi

ansible-playbook "$FIXTURE" >/dev/null
assert_rejected sealed 'all initialized, unsealed'
assert_rejected split-cluster 'all initialized, unsealed'
assert_rejected empty-cluster-id 'all initialized, unsealed'
assert_rejected numeric-health 'all initialized, unsealed'
assert_rejected nonvoter 'three expected unique voters'
assert_rejected leader-mismatch 'three expected unique voters'
assert_rejected malformed-index 'three expected unique voters'
assert_rejected numeric-raft 'three expected unique voters'
assert_rejected swapped-address 'three expected unique voters'
assert_rejected unstable 'changed between strict status observations'

printf 'OpenBao strict status check passed\n'
