#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${ROOT_DIR}/tests/fixtures/monitoring-haproxy-contract/validate.yml"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

validate_fixture() {
  ansible-playbook "$FIXTURE" "$@" >/dev/null
}

reject_fixture() {
  local message=$1
  shift

  if validate_fixture "$@"; then
    fail "$message"
  fi
}

validate_fixture

grep -qx 'monitoring_haproxy_enabled: false' \
  "${ROOT_DIR}/roles/monitoring_haproxy/defaults/main.yml" \
  || fail 'Monitoring HAProxy contract role is not disabled by default'
grep -qx 'monitoring_haproxy_service_enabled: false' \
  "${ROOT_DIR}/roles/monitoring_haproxy/defaults/main.yml" \
  || fail 'Monitoring HAProxy contract role enables the service by default'
grep -qx 'monitoring_haproxy_service_state: stopped' \
  "${ROOT_DIR}/roles/monitoring_haproxy/defaults/main.yml" \
  || fail 'Monitoring HAProxy contract role starts the service by default'

reject_fixture 'Monitoring HAProxy accepted an unready contract' \
  --extra-vars '{"monitoring_haproxy_test_contract_ready":false}'
reject_fixture 'Monitoring HAProxy coerced a non-boolean readiness gate' \
  --extra-vars '{"monitoring_haproxy_test_contract_ready":"true"}'
reject_fixture 'Monitoring HAProxy accepted service activation' \
  --extra-vars '{"monitoring_haproxy_test_service_enabled":true}'
reject_fixture 'Disabled monitoring HAProxy accepted service activation' \
  --extra-vars \
  '{"monitoring_haproxy_test_enabled":false,"monitoring_haproxy_test_service_enabled":true}'
reject_fixture 'Disabled monitoring HAProxy accepted a started service state' \
  --extra-vars \
  '{"monitoring_haproxy_test_enabled":false,"monitoring_haproxy_test_service_state":"started"}'
reject_fixture 'Monitoring HAProxy accepted an unpinned package' \
  --extra-vars 'monitoring_haproxy_test_package_nevra=haproxy'
reject_fixture 'Monitoring HAProxy accepted a different complete package NEVRA' \
  --extra-vars \
  'monitoring_haproxy_test_package_nevra=haproxy-0:3.0.6-1.el10.x86_64'
reject_fixture 'Monitoring HAProxy accepted a metrics/frontend port collision' \
  --extra-vars '{"monitoring_haproxy_test_metrics_port":443}'
reject_fixture 'Monitoring HAProxy coerced a string metrics port' \
  --extra-vars '{"monitoring_haproxy_test_metrics_port":"8405"}'
reject_fixture 'Monitoring HAProxy accepted a leading-zero metrics address' \
  --extra-vars 'monitoring_haproxy_test_metrics_address=192.168.001.83'
reject_fixture 'Monitoring HAProxy accepted duplicate service DNS' \
  --extra-vars \
  'monitoring_haproxy_test_alertmanager_dns=grafana.monitoring.example.invalid'
reject_fixture 'Monitoring HAProxy accepted an escaping-dependent subject DN' \
  --extra-vars \
  'monitoring_haproxy_test_writer_dn=CN=alloy\,loki,OU=telemetry,O=platform,C=XX'
reject_fixture 'Monitoring HAProxy accepted an unapproved identity role' \
  --extra-vars 'monitoring_haproxy_test_writer_role=arbitrary_admin'
reject_fixture 'Monitoring HAProxy accepted a wildcard route' \
  --extra-vars 'monitoring_haproxy_test_loki_query_path=/loki/api/v1/*'
reject_fixture 'Monitoring HAProxy accepted an empty route group' \
  --extra-vars '{"monitoring_haproxy_test_alertmanager_routes":[]}'
reject_fixture 'Monitoring HAProxy accepted duplicate routes' \
  --extra-vars \
  '{"monitoring_haproxy_test_alertmanager_routes":[{"method":"GET","path":"/alertmanager/api/v2/alerts"},{"method":"GET","path":"/alertmanager/api/v2/alerts"}]}'
reject_fixture 'Monitoring HAProxy accepted unrestricted HTTPS sources' \
  --extra-vars '{"monitoring_haproxy_test_https_sources":["0.0.0.0/0"]}'
reject_fixture 'Monitoring HAProxy accepted a non-normalized HTTPS source' \
  --extra-vars '{"monitoring_haproxy_test_https_sources":["198.51.100.1/24"]}'
reject_fixture 'Monitoring HAProxy accepted a leading-zero HTTPS source' \
  --extra-vars '{"monitoring_haproxy_test_https_sources":["198.051.100.0/24"]}'
reject_fixture 'Monitoring HAProxy accepted duplicate HTTPS sources' \
  --extra-vars \
  '{"monitoring_haproxy_test_https_sources":["198.51.100.0/24","198.51.100.0/24"]}'
reject_fixture 'Monitoring HAProxy accepted an overly broad HTTPS source' \
  --extra-vars '{"monitoring_haproxy_test_https_sources":["198.0.0.0/8"]}'
reject_fixture 'Monitoring HAProxy accepted empty operator sources' \
  --extra-vars '{"monitoring_haproxy_test_operator_sources":[]}'
reject_fixture 'Monitoring HAProxy accepted unrestricted operator sources' \
  --extra-vars '{"monitoring_haproxy_test_operator_sources":["0.0.0.0/0"]}'
reject_fixture 'Monitoring HAProxy accepted operator sources outside HTTPS policy' \
  --extra-vars '{"monitoring_haproxy_test_operator_sources":["192.0.2.0/28"]}'

printf 'Monitoring HAProxy contract check passed\n'
