#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${ROOT_DIR}/tests/fixtures/openbao-haproxy/render.yml"
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

render_fixture() {
  ansible-playbook "$FIXTURE" \
    --extra-vars "openbao_haproxy_test_output_dir=${OUTPUT_DIR}" \
    "$@" >/dev/null
}

render_fixture

DEFAULTS="${ROOT_DIR}/roles/openbao_haproxy/defaults/main.yml"
TASKS="${ROOT_DIR}/roles/openbao_haproxy/tasks/main.yml"
CONFIG="${OUTPUT_DIR}/haproxy.cfg"

assert_contains "$DEFAULTS" '^openbao_haproxy_enabled: false$' \
  'OpenBao HAProxy role is not disabled by default'
assert_contains "$DEFAULTS" '^openbao_haproxy_service_enabled: false$' \
  'OpenBao HAProxy service is enabled before acceptance'
assert_contains "$DEFAULTS" '^openbao_haproxy_service_state: stopped$' \
  'OpenBao HAProxy service starts before acceptance'
assert_contains "$TASKS" 'validate: >-' \
  'OpenBao HAProxy configuration is not candidate-validated atomically'
assert_contains "$TASKS" 'allow_downgrade: true' \
  'OpenBao HAProxy cannot reconcile to the exact package pin'

assert_contains "$CONFIG" '^frontend openbao_client$' \
  'OpenBao HAProxy client frontend is missing'
assert_contains "$CONFIG" '^  bind [*]:8200$' \
  'OpenBao HAProxy does not bind the fixed client port for pre-VIP staging'
assert_contains "$CONFIG" '^  mode tcp$' \
  'OpenBao HAProxy client path is not TCP passthrough'
assert_contains "$CONFIG" '^  acl openbao_client_source src 198[.]51[.]100[.]0/24$' \
  'OpenBao HAProxy client frontend is not source-restricted'
assert_contains "$CONFIG" '^  tcp-request connection reject unless openbao_client_source$' \
  'OpenBao HAProxy does not reject unauthorized client sources'
assert_contains "$CONFIG" '^  option httpchk$' \
  'OpenBao HAProxy backend does not use HTTP health checks'
assert_contains "$CONFIG" '^  http-check send meth GET uri /v1/sys/health ver HTTP/1[.]1 hdr Host bao[.]example[.]invalid$' \
  'OpenBao HAProxy health request does not use the approved path and Host'
assert_contains "$CONFIG" '^  http-check expect status 200$' \
  'OpenBao HAProxy health policy is not active-only'
assert_contains "$CONFIG" '^  server openbao-example-01 192[.]0[.]2[.]63:18200 check check-ssl check-sni bao-1[.]internal[.]invalid verify required ca-file /etc/openbao/tls/ca[.]crt verifyhost bao-1[.]internal[.]invalid$' \
  'OpenBao HAProxy backend 1 lacks strict check-plane TLS identity'
assert_contains "$CONFIG" '^  server openbao-example-02 192[.]0[.]2[.]64:18200 check check-ssl check-sni bao-2[.]internal[.]invalid verify required ca-file /etc/openbao/tls/ca[.]crt verifyhost bao-2[.]internal[.]invalid$' \
  'OpenBao HAProxy backend 2 lacks strict check-plane TLS identity'
assert_contains "$CONFIG" '^  server openbao-example-03 192[.]0[.]2[.]65:18200 check check-ssl check-sni bao-3[.]internal[.]invalid verify required ca-file /etc/openbao/tls/ca[.]crt verifyhost bao-3[.]internal[.]invalid$' \
  'OpenBao HAProxy backend 3 lacks strict check-plane TLS identity'
assert_not_contains "$CONFIG" 'server .*:18200 ssl([[:space:]]|$)|standbyok|:8201 check' \
  'OpenBao HAProxy terminates backend client TLS, accepts standbys, or uses the cluster port'

assert_contains "$CONFIG" '^frontend openbao_metrics$' \
  'OpenBao HAProxy metrics frontend is missing'
assert_contains "$CONFIG" '^  bind 192[.]0[.]2[.]63:8404$' \
  'OpenBao HAProxy metrics endpoint does not use its dedicated bind'
assert_contains "$CONFIG" '^  acl openbao_metrics_source src 192[.]0[.]2[.]128/25$' \
  'OpenBao HAProxy metrics endpoint is not source-restricted'
assert_contains "$CONFIG" '^  http-request use-service prometheus-exporter if \{ path -m str /metrics \}$' \
  'OpenBao HAProxy does not expose the built-in metrics service only at /metrics'
assert_contains "$CONFIG" '^  http-request deny deny_status 404$' \
  'OpenBao HAProxy metrics frontend does not deny other paths'

if render_fixture --extra-vars 'openbao_haproxy_test_package_nevra=' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted an unpinned package'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_service_enabled":true}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted incoherent service lifecycle controls'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_backend_port":8200}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted a frontend/backend port collision'
fi
if render_fixture --extra-vars 'openbao_haproxy_test_backend_2_dns=bao-1.internal.invalid' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted duplicate backend DNS identity'
fi
if render_fixture --extra-vars 'openbao_haproxy_test_backend_2_dns=-bao.internal.invalid' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted a malformed backend DNS identity'
fi
if render_fixture --extra-vars 'openbao_haproxy_test_backend_2_name=unsafe/name' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted an unsafe backend name'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_client_sources":["198.51.100.999/24"]}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted an invalid firewall source'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_stats_sources":[]}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted an unrestricted metrics endpoint'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_client_sources":["0.0.0.0/0"]}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted unrestricted client access'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_stats_sources":["0.0.0.0/0"]}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted unrestricted metrics access'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_client_sources":["198.51.100.1/24"]}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted a non-network-normalized client CIDR'
fi
if render_fixture --extra-vars 'openbao_haproxy_test_user=haproxy%0Aroot' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted an unsafe process user'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_maxconn":0}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted an invalid maxconn limit'
fi
if render_fixture --extra-vars 'openbao_haproxy_test_health_path=/v1/sys/health?standbyok=true' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted standby health policy'
fi
if render_fixture --extra-vars 'openbao_haproxy_test_health_host=.bao.example.invalid' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted a malformed health Host identity'
fi
if render_fixture --extra-vars '{"openbao_haproxy_test_workload_lb_enabled":true}' >/dev/null 2>&1; then
  fail 'OpenBao HAProxy fixture accepted conflicting workload HAProxy ownership'
fi

printf 'OpenBao HAProxy render check passed\n'
