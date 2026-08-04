#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAYBOOK="${ROOT_DIR}/playbooks/openbao.yml"
FIXTURE_DIR="${ROOT_DIR}/tests/fixtures/openbao-orchestration"
FIXTURE_INVENTORY="${FIXTURE_DIR}/inventory.yml"
FIXTURE_TWO_INVENTORY="${FIXTURE_DIR}/inventory-two.yml"
FIXTURE_ROLES="${FIXTURE_DIR}/roles"
HOMELAB_INVENTORY="${ROOT_DIR}/inventories/homelab/hosts.yml.example"
OUTPUT_DIR="$(mktemp -d)"
MARKER="${OUTPUT_DIR}/converged"

cleanup() {
  rm -rf -- "$OUTPUT_DIR"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

run_mocked() {
  ANSIBLE_ROLES_PATH="${FIXTURE_ROLES}:${ROOT_DIR}/roles" \
    ansible-playbook -i "$FIXTURE_INVENTORY" "$PLAYBOOK" \
    --extra-vars "openbao_test_marker_path=${MARKER}" "$@"
}

assert_rejected_before_convergence() {
  local message="$1"
  local expected="$2"
  shift 2

  rm -f -- "$MARKER"
  if run_mocked "$@" >"${OUTPUT_DIR}/rejected.out" 2>&1; then
    fail "$message"
  fi
  [[ ! -e $MARKER ]] || fail "${message}: convergence started before rejection"
  grep -qF -- "$expected" "${OUTPUT_DIR}/rejected.out" \
    || fail "${message}: expected guard was not reached"
}

grep -q 'openbao_orchestration_ready' "$PLAYBOOK" \
  || fail 'OpenBao orchestration lacks an explicit readiness gate'
grep -q 'ansible_play_hosts_all' "$PLAYBOOK" \
  || fail 'OpenBao orchestration lacks a full-cluster selection gate'
grep -q '^    - firewalld$' "$PLAYBOOK" \
  || fail 'OpenBao orchestration does not run firewalld first'
grep -q '^    - keepalived_vip$' "$PLAYBOOK" \
  || fail 'OpenBao orchestration does not run Keepalived last'
grep -q 'Inspect existing OpenBao HA services' "$PLAYBOOK" \
  || fail 'OpenBao orchestration does not inspect existing service state'
grep -q 'Disable and stop existing OpenBao HA edge services' "$PLAYBOOK" \
  || fail 'OpenBao orchestration does not quiesce HAProxy and Keepalived'
grep -q 'Mask and stop an existing OpenBao service before staging' "$PLAYBOOK" \
  || fail 'OpenBao orchestration does not fail closed while staging OpenBao'
grep -q 'Unmask the successfully staged disabled OpenBao service' "$PLAYBOOK" \
  || fail 'OpenBao orchestration does not release its staging mask after convergence'
if grep -qE 'platform_external_probe|grafana_alloy|initialize|unseal' "$PLAYBOOK"; then
  fail 'OpenBao staging includes observer or custody operations'
fi

run_mocked >/dev/null
[[ $(<"$MARKER") == complete ]] \
  || fail 'OpenBao orchestration did not complete its exact mocked role order'

assert_rejected_before_convergence \
  'OpenBao orchestration accepted a partial host limit' \
  'requires all three OpenBao inventory hosts' \
  --limit bao-stage-1

rm -f -- "$MARKER"
if ANSIBLE_ROLES_PATH="${FIXTURE_ROLES}:${ROOT_DIR}/roles" \
  ansible-playbook -i "$FIXTURE_TWO_INVENTORY" "$PLAYBOOK" \
  --extra-vars "openbao_test_marker_path=${MARKER}" \
  >"${OUTPUT_DIR}/two-host.out" 2>&1; then
  fail 'OpenBao orchestration accepted a two-member inventory'
fi
[[ ! -e $MARKER ]] \
  || fail 'Two-member OpenBao inventory entered convergence'
grep -qF 'requires exactly three inventory members' "${OUTPUT_DIR}/two-host.out" \
  || fail 'Two-member OpenBao inventory missed the cardinality guard'

assert_rejected_before_convergence \
  'OpenBao orchestration accepted an unready contract' \
  'requires an explicit ready contract' \
  --extra-vars '{"openbao_orchestration_ready":false}'

assert_rejected_before_convergence \
  'OpenBao orchestration accepted disabled OpenBao ownership' \
  'requires an explicit ready contract' \
  --extra-vars '{"openbao_enabled":false}'

assert_rejected_before_convergence \
  'OpenBao orchestration accepted disabled HAProxy ownership' \
  'requires an explicit ready contract' \
  --extra-vars '{"openbao_haproxy_enabled":false}'

assert_rejected_before_convergence \
  'OpenBao orchestration accepted disabled Keepalived ownership' \
  'requires an explicit ready contract' \
  --extra-vars '{"keepalived_vip_enabled":false}'

assert_rejected_before_convergence \
  'OpenBao orchestration accepted invalid OpenBao inputs' \
  'Mocked OpenBao inputs are invalid' \
  --extra-vars openbao_test_invalid_component=openbao

assert_rejected_before_convergence \
  'OpenBao orchestration accepted invalid HAProxy inputs' \
  'Mocked OpenBao HAProxy inputs are invalid' \
  --extra-vars openbao_test_invalid_component=haproxy

assert_rejected_before_convergence \
  'OpenBao orchestration accepted invalid Keepalived inputs' \
  'Mocked Keepalived inputs are invalid' \
  --extra-vars openbao_test_invalid_component=keepalived

assert_rejected_before_convergence \
  'OpenBao orchestration accepted an active OpenBao service' \
  'stopped/disabled OpenBao, HAProxy, and Keepalived' \
  --extra-vars openbao_test_active_openbao=bao-stage-2

assert_rejected_before_convergence \
  'OpenBao orchestration accepted an active HAProxy service' \
  'stopped/disabled OpenBao, HAProxy, and Keepalived' \
  --extra-vars openbao_test_active_haproxy=bao-stage-2

assert_rejected_before_convergence \
  'OpenBao orchestration accepted an active Keepalived service' \
  'stopped/disabled OpenBao, HAProxy, and Keepalived' \
  --extra-vars openbao_test_active_keepalived=bao-stage-2

assert_rejected_before_convergence \
  'OpenBao orchestration accepted an unrelated-host limit' \
  'did not select the replacement service group' \
  --limit unrelated-stage

ansible-playbook -i "$HOMELAB_INVENTORY" "$PLAYBOOK" >/dev/null \
  || fail 'OpenBao orchestration blocked the unaffected homelab inventory'

printf 'OpenBao orchestration safety check passed\n'
