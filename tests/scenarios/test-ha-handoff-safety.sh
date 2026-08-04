#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DEV_INVENTORY="${ROOT_DIR}/inventories/dev/hosts.yml.example"
HOMELAB_INVENTORY="${ROOT_DIR}/inventories/homelab/hosts.yml.example"
INVENTORY_FIXTURE="${ROOT_DIR}/tests/fixtures/ha-handoff/validate-public-inventory.yml"
STORAGE_FIXTURE="${ROOT_DIR}/tests/fixtures/ha-handoff/validate-storage-layout.yml"
STORAGE_DUPLICATE_FIXTURE="${ROOT_DIR}/tests/fixtures/ha-handoff/validate-storage-mixed-duplicate.yml"
EMPTY_INVENTORY="${ROOT_DIR}/tests/fixtures/ha-handoff/empty-inventory.yml"
LEGACY_OPENBAO_INVENTORY="${ROOT_DIR}/tests/fixtures/ha-handoff/legacy-openbao-inventory.yml"
OPENBAO_PLAYBOOK="${ROOT_DIR}/playbooks/openbao.yml"
OPENBAO_STATUS_PLAYBOOK="${ROOT_DIR}/playbooks/maintenance/openbao-status.yml"
MONITORING_PLAYBOOK="${ROOT_DIR}/playbooks/monitoring.yml"
MONITORING_SMOKE_PLAYBOOK="${ROOT_DIR}/playbooks/monitoring-smoke.yml"
SITE_PLAYBOOK="${ROOT_DIR}/playbooks/site.yml"
MAKEFILE="${ROOT_DIR}/Makefile"

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

assert_playbook_blocked() {
  local inventory="$1"
  local playbook="$2"
  local message="$3"
  local limit="${4:-}"
  local -a command=(ansible-playbook -i "$inventory" "$playbook")
  local output

  if [[ -n $limit ]]; then
    command+=(--limit "$limit")
  fi

  if output="$("${command[@]}" 2>&1)"; then
    fail "${message}: playbook exited successfully"
  fi

  grep -qE 'OpenBao staging|Strict OpenBao HA status requires|HA implementation is unavailable|HA smoke checks are not implemented' <<< "$output" \
    || fail "${message}: expected blocking failure was not reached"
}

assert_playbook_succeeds() {
  local inventory="$1"
  local playbook="$2"
  local message="$3"

  ansible-playbook -i "$inventory" "$playbook" >/dev/null \
    || fail "$message"
}

test_obsolete_service_paths_are_blocked() {
  assert_contains "$OPENBAO_PLAYBOOK" '^  hosts: openbao$' \
    'OpenBao playbook does not target the replacement openbao group'
  assert_contains "$OPENBAO_PLAYBOOK" 'openbao_orchestration_ready' \
    'OpenBao staging playbook lacks its explicit readiness gate'
  assert_contains "$OPENBAO_PLAYBOOK" 'ansible_play_hosts_all' \
    'OpenBao staging playbook permits partial cluster convergence'
  assert_not_contains "$OPENBAO_PLAYBOOK" 'hosts: vault|initialize|unseal' \
    'OpenBao staging playbook includes a legacy or custody path'

  assert_contains "$MONITORING_PLAYBOOK" 'ansible[.]builtin[.]fail:' \
    'Monitoring transition playbook is not fail-closed'
  assert_not_contains "$MONITORING_PLAYBOOK" 'monitoring_stack|grafana_alloy|node_exporter' \
    'Monitoring transition playbook still invokes an obsolete role'

  assert_not_contains "$SITE_PLAYBOOK" 'initialize|reset|restore|failure' \
    'Routine site convergence imports an operational or destructive workflow'
  assert_not_contains "$OPENBAO_STATUS_PLAYBOOK" 'validate_certs: false|initialize|unseal' \
    'OpenBao status weakens TLS or includes a custody operation'
  assert_contains "$MAKEFILE" 'legacy check is blocked' \
    'Legacy smoke targets are not explicitly blocked'

  assert_playbook_blocked "$EMPTY_INVENTORY" "$OPENBAO_PLAYBOOK" \
    'OpenBao playbook did not fail with an empty replacement inventory'
  assert_playbook_blocked "$EMPTY_INVENTORY" "$OPENBAO_STATUS_PLAYBOOK" \
    'OpenBao status playbook did not fail with an empty replacement inventory'
  assert_playbook_blocked "$EMPTY_INVENTORY" "$MONITORING_PLAYBOOK" \
    'Monitoring playbook did not fail with an empty replacement inventory'
  assert_playbook_blocked "$EMPTY_INVENTORY" "$MONITORING_SMOKE_PLAYBOOK" \
    'Monitoring smoke playbook did not fail with an empty replacement inventory'
  assert_playbook_blocked "$DEV_INVENTORY" "$OPENBAO_PLAYBOOK" \
    'OpenBao playbook did not fail with a service-host limit' openbao-example-01
  assert_playbook_blocked "$DEV_INVENTORY" "$OPENBAO_STATUS_PLAYBOOK" \
    'OpenBao status playbook did not fail with a service-host limit' openbao-example-01
  assert_playbook_blocked "$DEV_INVENTORY" "$MONITORING_PLAYBOOK" \
    'Monitoring playbook did not fail with a service-host limit' monitoring-example-01
  assert_playbook_blocked "$DEV_INVENTORY" "$MONITORING_SMOKE_PLAYBOOK" \
    'Monitoring smoke playbook did not fail with a service-host limit' monitoring-example-01
  assert_playbook_blocked "$DEV_INVENTORY" "$OPENBAO_PLAYBOOK" \
    'OpenBao playbook did not reject an unrelated-host limit' k8s-bastion-example
  assert_playbook_blocked "$DEV_INVENTORY" "$OPENBAO_STATUS_PLAYBOOK" \
    'OpenBao status playbook did not reject an unrelated-host limit' k8s-bastion-example
  assert_playbook_blocked "$DEV_INVENTORY" "$MONITORING_PLAYBOOK" \
    'Monitoring playbook did not reject an unrelated-host limit' k8s-bastion-example
  assert_playbook_blocked "$DEV_INVENTORY" "$MONITORING_SMOKE_PLAYBOOK" \
    'Monitoring smoke playbook did not reject an unrelated-host limit' k8s-bastion-example
  assert_playbook_blocked "$LEGACY_OPENBAO_INVENTORY" "$OPENBAO_PLAYBOOK" \
    'OpenBao playbook did not reject a limited legacy vault host' legacy-openbao-example
  assert_playbook_blocked "$LEGACY_OPENBAO_INVENTORY" "$OPENBAO_STATUS_PLAYBOOK" \
    'OpenBao status playbook did not reject a limited legacy vault host' legacy-openbao-example
  assert_playbook_succeeds "$HOMELAB_INVENTORY" "$OPENBAO_PLAYBOOK" \
    'OpenBao transition playbook blocked the unaffected homelab inventory'
  assert_playbook_succeeds "$HOMELAB_INVENTORY" "$MONITORING_PLAYBOOK" \
    'Monitoring transition playbook blocked the unaffected homelab inventory'
}

test_public_inventory_and_storage_contracts() {
  ansible-playbook -i "$DEV_INVENTORY" "$INVENTORY_FIXTURE" >/dev/null
  ansible-playbook "$STORAGE_FIXTURE" >/dev/null
}

test_storage_overallocation_fails_closed() {
  local output

  if output="$(ansible-playbook "$STORAGE_FIXTURE" \
    --extra-vars '{"test_capacity_gib":13}' 2>&1)"; then
    fail 'Overallocated storage layout passed validation'
  fi

  grep -q 'allocations and required free space' <<< "$output" \
    || fail 'Overallocated storage layout did not reach the capacity gate'
}

test_mixed_storage_definition_collision_fails_closed() {
  local output

  if output="$(ansible-playbook "$STORAGE_DUPLICATE_FIXTURE" 2>&1)"; then
    fail 'Mixed legacy/layout VG/LV collision passed validation'
  fi

  grep -q 'unique VG/LV pairs' <<< "$output" \
    || fail 'Mixed legacy/layout VG/LV collision did not reach the uniqueness gate'
}

test_public_examples_are_sanitized() {
  assert_not_contains "$DEV_INVENTORY" 'vault:' \
    'Public dev inventory still exposes the legacy vault group'

  if grep -R -qE -- \
    'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|client-certificate-data:|token: [A-Za-z0-9]' \
    "${ROOT_DIR}/inventories/dev/group_vars/openbao.yml.example" \
    "${ROOT_DIR}/inventories/dev/group_vars/monitoring.yml.example" \
    "${ROOT_DIR}/inventories/dev/host_vars/openbao-example-"*.yml.example \
    "${ROOT_DIR}/inventories/dev/host_vars/monitoring-example-"*.yml.example; then
    fail 'Public HA examples contain credential-shaped data'
  fi
}

test_obsolete_service_paths_are_blocked
test_public_inventory_and_storage_contracts
test_storage_overallocation_fails_closed
test_mixed_storage_definition_collision_fails_closed
test_public_examples_are_sanitized

printf 'HA handoff safety check passed\n'
