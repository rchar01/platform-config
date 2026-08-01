#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAYBOOK="${ROOT_DIR}/playbooks/maintenance/openbao-rolling-restart.yml"
ROLE_TASKS="${ROOT_DIR}/roles/openbao/tasks/main.yml"
SITE_PLAYBOOK="${ROOT_DIR}/playbooks/site.yml"
MAKEFILE="${ROOT_DIR}/Makefile"
DEV_INVENTORY="${ROOT_DIR}/inventories/dev/hosts.yml.example"
FIXTURE_INVENTORY="${ROOT_DIR}/tests/fixtures/openbao-rolling/inventory.yml"
FIXTURE_ROLES="${ROOT_DIR}/tests/fixtures/openbao-rolling/roles"
OUTPUT_DIR="$(mktemp -d)"

cleanup() {
  rm -rf -- "$OUTPUT_DIR"
}
trap cleanup EXIT

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

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"

  if grep -qE -- "$pattern" "$file"; then
    fail "$message"
  fi
}

assert_contains "$PLAYBOOK" 'openbao_rolling_restart_confirm' \
  'OpenBao rolling maintenance lacks explicit operator confirmation'
assert_contains "$PLAYBOOK" 'not ansible_check_mode' \
  'OpenBao rolling maintenance can run in check mode'
assert_contains "$PLAYBOOK" 'ansible_play_hosts_all.*groups[.]get' \
  'OpenBao rolling maintenance does not require the full cluster selection'
assert_contains "$PLAYBOOK" '^  order: inventory$' \
  'OpenBao rolling maintenance does not preserve its planned host order'
assert_contains "$PLAYBOOK" '^  serial: 1$' \
  'OpenBao rolling maintenance can converge multiple voters together'
assert_contains "$PLAYBOOK" 'openbao_rolling_expected_state: standby' \
  'OpenBao rolling maintenance does not queue standbys first'
assert_contains "$PLAYBOOK" 'openbao_rolling_expected_state: active' \
  'OpenBao rolling maintenance does not queue the active node last'
assert_contains "$PLAYBOOK" 'leadership changed after the rolling order' \
  'OpenBao rolling maintenance does not abort on leadership drift'
assert_contains "$PLAYBOOK" 'ansible[.]builtin[.]pause:' \
  'OpenBao rolling maintenance lacks the manual-unseal pause'
assert_contains "$PLAYBOOK" 'when: openbao_restart_required \| bool' \
  'OpenBao rolling maintenance pauses even when convergence is unchanged'
assert_contains "$ROLE_TASKS" 'openbao_restart_required:' \
  'OpenBao service convergence does not expose restart requirements'
assert_contains "$ROLE_TASKS" "openbao_service_state == 'started'" \
  'OpenBao restart tracking is not restricted to an active service'
assert_contains "$MAKEFILE" '^roll-openbao:' \
  'OpenBao rolling maintenance lacks an explicit Make target'
assert_not_contains "$SITE_PLAYBOOK" 'openbao-rolling-restart' \
  'Routine site convergence imports manual OpenBao maintenance'
assert_not_contains "$PLAYBOOK" '^  strategy: free$' \
  'OpenBao rolling maintenance allows hosts to advance independently'

status_gate_count="$(grep -c 'name: openbao_status' "$PLAYBOOK")"
((status_gate_count >= 3)) \
  || fail 'OpenBao rolling maintenance lacks baseline, recovery, or final status gates'

ansible-playbook -i "$DEV_INVENTORY" "$PLAYBOOK" --syntax-check >/dev/null

output=''
if output="$(ansible-playbook -i "$DEV_INVENTORY" "$PLAYBOOK" \
  --limit openbao-example-01 2>&1)"; then
  fail 'OpenBao rolling maintenance ran without explicit confirmation'
fi
grep -qF 'requires explicit confirmation' <<< "$output" \
  || fail 'OpenBao rolling maintenance did not fail at its explicit guard'

run_mocked_rolling() {
  ANSIBLE_ROLES_PATH="${FIXTURE_ROLES}:${ROOT_DIR}/roles" \
    ansible-playbook -i "$FIXTURE_INVENTORY" "$PLAYBOOK" \
    --extra-vars '{"openbao_rolling_restart_confirm":true}' \
    --extra-vars "openbao_test_order_path=${OUTPUT_DIR}/order" \
    "$@"
}

run_mocked_rolling >/dev/null
mapfile -t rolling_order < "${OUTPUT_DIR}/order"
[[ "${rolling_order[*]}" == 'bao-test-2 bao-test-3 bao-test-1' ]] \
  || fail 'OpenBao rolling maintenance did not execute standbys before active'

rm -f -- "${OUTPUT_DIR}/order"
if run_mocked_rolling \
  --extra-vars openbao_test_disabled_host=bao-test-3 \
  >"${OUTPUT_DIR}/disabled.out" 2>&1; then
  fail 'OpenBao rolling maintenance accepted a disabled voter contract'
fi
[[ ! -e "${OUTPUT_DIR}/order" ]] \
  || fail 'OpenBao rolling maintenance converged before validating every voter'
grep -qF 'enabled and started service contract on this node' \
  "${OUTPUT_DIR}/disabled.out" \
  || fail 'OpenBao rolling maintenance missed the per-voter service guard'

rm -f -- "${OUTPUT_DIR}/order"
if run_mocked_rolling --limit bao-test-2 \
  >"${OUTPUT_DIR}/partial.out" 2>&1; then
  fail 'OpenBao rolling maintenance accepted a confirmed partial limit'
fi
[[ ! -e "${OUTPUT_DIR}/order" ]] \
  || fail 'OpenBao rolling maintenance converged after a partial limit'
grep -qF 'all three OpenBao inventory hosts' "${OUTPUT_DIR}/partial.out" \
  || fail 'OpenBao rolling maintenance missed the full-cluster guard'

rm -f -- "${OUTPUT_DIR}/order"
if run_mocked_rolling \
  --extra-vars openbao_test_drift_after=bao-test-2 \
  --extra-vars openbao_test_drift_to=bao-test-2 \
  >"${OUTPUT_DIR}/drift.out" 2>&1; then
  fail 'OpenBao rolling maintenance continued after leadership drift'
fi
mapfile -t drift_order < "${OUTPUT_DIR}/order"
[[ "${drift_order[*]}" == 'bao-test-2' ]] \
  || fail 'OpenBao leadership drift did not abort before the next voter'
grep -qF 'leadership changed after the rolling order' "${OUTPUT_DIR}/drift.out" \
  || fail 'OpenBao rolling maintenance missed the leadership-drift guard'

printf 'OpenBao rolling maintenance safety check passed\n'
