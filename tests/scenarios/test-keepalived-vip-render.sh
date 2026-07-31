#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${ROOT_DIR}/tests/fixtures/keepalived-vip/render.yml"
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

ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" >/dev/null

CONFIG="${OUTPUT_DIR}/keepalived.conf"
CHECK_SCRIPT="${OUTPUT_DIR}/check-service"
SERVICE_DROP_IN="${OUTPUT_DIR}/platform.conf"
DEFAULTS="${ROOT_DIR}/roles/keepalived_vip/defaults/main.yml"

assert_contains "$DEFAULTS" '^keepalived_vip_enabled: false$' \
  'Keepalived role is not disabled by default'
assert_contains "$DEFAULTS" '^keepalived_vip_service_enabled: false$' \
  'Keepalived service is enabled before acceptance'
assert_contains "$DEFAULTS" '^keepalived_vip_service_state: stopped$' \
  'Keepalived service starts before acceptance'

assert_contains "$CONFIG" '^[[:space:]]+state BACKUP$' \
  'Keepalived fixture does not force the initial BACKUP state'
assert_contains "$CONFIG" '^[[:space:]]+nopreempt$' \
  'Keepalived fixture does not disable automatic failback'
assert_contains "$CONFIG" '^[[:space:]]+unicast_src_ip 192[.]0[.]2[.]10$' \
  'Keepalived fixture does not render the unicast source'
assert_contains "$CONFIG" '^[[:space:]]+weight 0$' \
  'Keepalived fixture does not use hard-fault script weight'
assert_contains "$CONFIG" '^[[:space:]]+init_fail$' \
  'Keepalived fixture can advertise before its first successful health check'
assert_contains "$CONFIG" '^[[:space:]]+check_unicast_src$' \
  'Keepalived fixture does not reject unknown unicast sources'
assert_contains "$CONFIG" '^[[:space:]]+unicast_fault_no_peer$' \
  'Keepalived fixture does not fail closed without unicast peers'
assert_not_contains "$CONFIG" '^[[:space:]]+state MASTER$' \
  'Keepalived fixture permits a preempting initial MASTER state'

assert_contains "$CHECK_SCRIPT" '^#!/bin/bash$' \
  'Tracking script does not use an absolute Bash interpreter'
assert_contains "$CHECK_SCRIPT" 'systemctl is-active --quiet haproxy[.]service' \
  'Tracking script does not verify the local HAProxy service'
assert_contains "$CHECK_SCRIPT" 'ip link show up dev vrrp-test >/dev/null 2>&1' \
  'Tracking script does not silently verify the VRRP interface'
assert_contains "$CHECK_SCRIPT" 'sport = :8200" 2>/dev/null' \
  'Tracking script does not silently verify the required client listener'
assert_not_contains "$CHECK_SCRIPT" 'openbao|grafana|loki|mimir|postgres' \
  'Tracking script incorrectly couples VIP eligibility to an application backend'
assert_contains "$SERVICE_DROP_IN" '^After=network-online[.]target haproxy[.]service$' \
  'Keepalived service is not ordered after network readiness and HAProxy'

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_priority":255,"keepalived_vip_test_canonical_priority":255}' \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture accepted priority 255 with nopreempt'
fi

ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_priority":1,"keepalived_vip_test_canonical_priority":1}' \
  >/dev/null || fail 'Keepalived fixture rejected minimum priority 1'
ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_priority":254,"keepalived_vip_test_canonical_priority":254}' \
  >/dev/null || fail 'Keepalived fixture rejected maximum nopreempt priority 254'

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR} keepalived_vip_test_package_nevra=" \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture accepted an unpinned package'
fi

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars keepalived_vip_test_peer_2_router_id=test-node-01 \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture accepted duplicate cluster router IDs'
fi

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_peer_2_priority":150}' \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture accepted duplicate cluster priorities'
fi

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_peer_2_extra_instances":{"EXTRA_VIP":{"source_address":"192.0.2.21","priority":120}}}' \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture accepted mismatched canonical instance names'
fi

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_peer_2_priority":255}' \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture accepted an out-of-range remote cluster priority'
fi

if ansible-playbook "$FIXTURE" \
  --extra-vars "keepalived_vip_test_output_dir=${OUTPUT_DIR}" \
  --extra-vars '{"keepalived_vip_test_canonical_priority":"150.9"}' \
  >/dev/null 2>&1; then
  fail 'Keepalived fixture coerced a non-integer canonical priority'
fi

printf 'Keepalived VIP render check passed\n'
