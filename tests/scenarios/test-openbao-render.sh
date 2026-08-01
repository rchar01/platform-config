#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${ROOT_DIR}/tests/fixtures/openbao/render.yml"
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

run_invalid_fixture() {
  local message="$1"
  shift

  if ansible-playbook "$FIXTURE" \
    --extra-vars "openbao_test_output_dir=${OUTPUT_DIR}" \
    "$@" >/dev/null 2>&1; then
    fail "$message"
  fi
}

ansible-playbook "$FIXTURE" \
  --extra-vars "openbao_test_output_dir=${OUTPUT_DIR}" >/dev/null

CONFIG="${OUTPUT_DIR}/openbao.hcl"
QUADLET="${OUTPUT_DIR}/openbao.container"
VALIDATOR="${OUTPUT_DIR}/validate-config"
DEFAULTS="${ROOT_DIR}/roles/openbao/defaults/main.yml"

assert_contains "$DEFAULTS" '^openbao_enabled: false$' \
  'OpenBao role is not disabled by default'
assert_contains "$DEFAULTS" '^openbao_service_enabled: false$' \
  'OpenBao service is enabled before acceptance'
assert_contains "$DEFAULTS" '^openbao_service_state: stopped$' \
  'OpenBao service starts before acceptance'
assert_not_contains "$DEFAULTS" '^openbao_require_separate_mounts:' \
  'OpenBao role exposes a deployment bypass for storage mount validation'

assert_contains "$CONFIG" '^api_addr = "https://bao[.]example[.]invalid:8200"$' \
  'OpenBao does not advertise the shared client endpoint'
assert_contains "$CONFIG" '^cluster_addr = "https://bao-1[.]internal[.]invalid:8201"$' \
  'OpenBao does not advertise its direct cluster endpoint'
assert_contains "$CONFIG" '^  address = "192[.]0[.]2[.]10:18200"$' \
  'OpenBao does not bind the direct backend listener'
assert_contains "$CONFIG" '^  cluster_address = "192[.]0[.]2[.]10:8201"$' \
  'OpenBao does not bind the direct cluster listener'
assert_contains "$CONFIG" '^  performance_multiplier = 1$' \
  'OpenBao does not render the approved Raft performance multiplier'
assert_contains "$CONFIG" 'leader_api_addr = "https://bao-2[.]internal[.]invalid:18200"' \
  'OpenBao does not render peer two retry-join'
assert_contains "$CONFIG" 'leader_api_addr = "https://bao-3[.]internal[.]invalid:18200"' \
  'OpenBao does not render peer three retry-join'
assert_contains "$CONFIG" 'leader_ca_cert_file = "/openbao/config/tls/ca[.]crt"' \
  'OpenBao retry-join does not verify the issuing CA'
assert_contains "$CONFIG" 'leader_tls_servername = "bao-2[.]internal[.]invalid"' \
  'OpenBao retry-join does not verify the peer DNS identity'
assert_contains "$CONFIG" '^telemetry \{$' \
  'OpenBao telemetry is not configured structurally'
assert_not_contains "$CONFIG" '^disable_mlock' \
  'OpenBao renders the unsupported legacy disable_mlock field'
assert_not_contains "$CONFIG" '^seal ' \
  'OpenBao renders an Auto Unseal stanza instead of manual Shamir'
assert_not_contains "$CONFIG" 'leader_api_addr = "https://bao-1[.]internal[.]invalid' \
  'OpenBao retry-join includes the local node'
assert_not_contains "$CONFIG" 'leader_api_addr = "https://bao[.]example[.]invalid' \
  'OpenBao retry-join incorrectly uses the shared endpoint'
assert_not_contains "$CONFIG" '192[.]0[.]2[.]100' \
  'OpenBao configuration incorrectly depends on the VIP'

assert_contains "$QUADLET" '^Image=ghcr[.]io/openbao/openbao@sha256:15e90b' \
  'OpenBao Quadlet does not use the approved immutable image'
assert_contains "$QUADLET" '^User=100:1000$' \
  'OpenBao Quadlet does not preserve the pinned non-root identity'
assert_contains "$QUADLET" '^Network=host$' \
  'OpenBao Quadlet does not use host networking'
assert_contains "$QUADLET" '^Environment=SKIP_CHOWN=true$' \
  'OpenBao image entrypoint can recursively change mounted files'
assert_contains "$QUADLET" '^MemorySwapMax=0$' \
  'OpenBao Quadlet does not disable service swap'
assert_not_contains "$QUADLET" '^PublishPort=' \
  'OpenBao Quadlet still publishes container ports'
assert_not_contains "$QUADLET" '^\[Install\]$|^WantedBy=' \
  'OpenBao Quadlet is enabled before acceptance'

assert_contains "$VALIDATOR" '^#!/bin/bash$' \
  'OpenBao validator does not use an absolute interpreter'
assert_contains "$VALIDATOR" '^  --network none \\$' \
  'OpenBao validator has network access'
assert_contains "$VALIDATOR" '^  --pull never \\$' \
  'OpenBao validator can resolve a mutable image'
assert_contains "$VALIDATOR" '^  operator validate-config -config=/tmp/openbao[.]hcl$' \
  'OpenBao validator does not use the native 2.6.1 command'

run_invalid_fixture \
  'OpenBao fixture accepted a mutable image reference' \
  --extra-vars openbao_test_image_digest=latest
run_invalid_fixture \
  'OpenBao fixture accepted duplicate node IDs' \
  --extra-vars openbao_test_peer_2_node_name=bao-1
run_invalid_fixture \
  'OpenBao fixture accepted shared and node DNS identity reuse' \
  --extra-vars openbao_test_peer_2_dns=bao.example.invalid
run_invalid_fixture \
  'OpenBao fixture accepted a backend/cluster port collision' \
  --extra-vars '{"openbao_test_cluster_port":18200}'
run_invalid_fixture \
  'OpenBao fixture accepted a local/canonical identity mismatch' \
  --extra-vars openbao_test_local_node_name=not-bao-1
run_invalid_fixture \
  'OpenBao fixture accepted an Auto Unseal mode' \
  --extra-vars openbao_test_seal_type=transit
run_invalid_fixture \
  'OpenBao fixture accepted contradictory service lifecycle controls' \
  --extra-vars '{"openbao_service_enabled":true}'
run_invalid_fixture \
  'OpenBao fixture accepted unrelated mount preflight paths' \
  --extra-vars '{"openbao_required_mounts":["/tmp/a","/tmp/b","/tmp/c","/tmp/d"]}'
run_invalid_fixture \
  'OpenBao fixture accepted an invalid backend source address' \
  --extra-vars '{"openbao_backend_allowed_sources":["999.51.100.1/32"]}'
run_invalid_fixture \
  'OpenBao fixture accepted fewer than three members' \
  --extra-vars '{"openbao_test_cluster_members":[{"name":"localhost","node_id":"bao-1","address":"192.0.2.10","dns":"bao-1.internal.invalid"},{"name":"test-node-02","node_id":"bao-2","address":"192.0.2.11","dns":"bao-2.internal.invalid"}]}'

printf 'OpenBao HA render check passed\n'
