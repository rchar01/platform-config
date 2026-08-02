#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

run_test() {
  local name="$1"
  local script="$2"

  printf '==> %s\n' "$name"
  "$script"
}

main() {
  run_test "HA handoff safety" "${SCRIPT_DIR}/scenarios/test-ha-handoff-safety.sh"
  run_test "Keepalived VIP render" "${SCRIPT_DIR}/scenarios/test-keepalived-vip-render.sh"
  run_test "Platform external probe render" "${SCRIPT_DIR}/scenarios/test-platform-external-probe-render.sh"
  run_test "OpenBao HAProxy render" "${SCRIPT_DIR}/scenarios/test-openbao-haproxy-render.sh"
  run_test "Monitoring HAProxy contract" "${SCRIPT_DIR}/scenarios/test-monitoring-haproxy-contract.sh"
  run_test "OpenBao HA render" "${SCRIPT_DIR}/scenarios/test-openbao-render.sh"
  run_test "OpenBao strict status" "${SCRIPT_DIR}/scenarios/test-openbao-status.sh"
  run_test "OpenBao rolling maintenance" "${SCRIPT_DIR}/scenarios/test-openbao-rolling.sh"
  run_test "Kubernetes bastion Phase 1 safety" "${SCRIPT_DIR}/scenarios/test-k8s-bastion-phase1-safety.sh"
  run_test "Kubernetes bastion access reconciliation" "${SCRIPT_DIR}/scenarios/test-k8s-bastion-access-reconciliation.sh"
  run_test "Bootstrap token issuer staging workflow" "${SCRIPT_DIR}/scenarios/test-bootstrap-token-issuer-staging.sh"
}

main "$@"
