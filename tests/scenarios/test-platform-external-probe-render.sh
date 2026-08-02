#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="${ROOT_DIR}/tests/fixtures/platform-external-probe/render.yml"
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
    --extra-vars "platform_external_probe_test_output_dir=${OUTPUT_DIR}" \
    "$@" >/dev/null
}

render_fixture

DEFAULTS="${ROOT_DIR}/roles/platform_external_probe/defaults/main.yml"
ALLOY_DEFAULTS="${ROOT_DIR}/roles/grafana_alloy/defaults/main.yml"
ALLOY_TASKS="${ROOT_DIR}/roles/grafana_alloy/tasks/main.yml"
FRAGMENT="${OUTPUT_DIR}/external-probe.alloy"
CONFIG="${OUTPUT_DIR}/config.alloy"
COLLECTOR="${OUTPUT_DIR}/collect-vip-ownership"
SERVICE="${OUTPUT_DIR}/platform-external-probe-ownership.service"
TIMER="${OUTPUT_DIR}/platform-external-probe-ownership.timer"

assert_contains "$DEFAULTS" '^platform_external_probe_enabled: false$' \
  'External probe role is not disabled by default'
assert_contains "$DEFAULTS" '^platform_external_probe_timer_enabled: false$' \
  'External probe ownership timer is enabled before acceptance'
assert_contains "$ALLOY_DEFAULTS" '^grafana_alloy_enabled: false$' \
  'Grafana Alloy process owner is not disabled by default'
assert_contains "$ALLOY_DEFAULTS" '^grafana_alloy_version: 1[.]18[.]0$' \
  'Grafana Alloy does not use the approved 1.18.0 release'
assert_contains "$ALLOY_DEFAULTS" '^grafana_alloy_download_checksum: sha256:d8800c642f97895a20b5d7b86b51fc8729b452708223efe72c27cd13004c37c0$' \
  'Grafana Alloy does not pin the official 1.18.0 RPM checksum'
assert_contains "$ALLOY_TASKS" 'grafana_alloy_config_validate_command' \
  'Grafana Alloy configuration is not natively candidate-validated'
assert_contains "$ALLOY_TASKS" 'allow_downgrade: true' \
  'Grafana Alloy cannot reconcile a newer package to the approved exact RPM'
for quadlet_root in /etc /run /usr/share; do
  assert_contains "$ALLOY_DEFAULTS" "^  - ${quadlet_root}/containers/systemd/alloy[.]container$" \
    "Grafana Alloy does not reject its Quadlet owner under ${quadlet_root}"
  assert_contains "$ALLOY_DEFAULTS" "^  - ${quadlet_root}/containers/systemd/monitoring-alloy[.]container$" \
    "Grafana Alloy does not reject the monitoring Quadlet owner under ${quadlet_root}"
done

assert_contains "$FRAGMENT" '^prometheus[.]exporter[.]blackbox "platform_external_probe"' \
  'External probe fragment does not configure the Alloy blackbox exporter'
assert_contains "$FRAGMENT" 'follow_redirects: false' \
  'External HTTPS probes follow redirects'
assert_contains "$FRAGMENT" 'fail_if_not_ssl: true' \
  'External probes do not require TLS'
assert_contains "$FRAGMENT" 'server_name: \\"bao[.]example[.]invalid\\"' \
  'External probes do not enforce the intended certificate identity'
assert_contains "$FRAGMENT" 'Host: \\"bao[.]example[.]invalid\\"' \
  'Literal-VIP probes do not send the intended HTTP Host identity'
assert_contains "$FRAGMENT" 'valid_status_codes: \[200\]' \
  'OpenBao probes do not require exact HTTP 200'
assert_contains "$FRAGMENT" 'observer[[:space:]]*=[[:space:]]*"monitoring-example-01"' \
  'Probe series do not carry a unique observer label'
assert_contains "$FRAGMENT" 'address_mode[[:space:]]*=[[:space:]]*"vip"' \
  'Probe series do not distinguish literal-VIP observations'
assert_contains "$FRAGMENT" '^prometheus[.]exporter[.]unix "platform_vip_ownership"' \
  'Alloy does not collect node-local VIP ownership textfile metrics'
assert_not_contains "$FRAGMENT" 'insecure_skip_verify: true|clustering' \
  'External probe fragment weakens TLS or shards observers'

assert_contains "$CONFIG" '^prometheus[.]remote_write "platform_metrics"' \
  'Alloy process owner does not provide the stable metrics receiver'
assert_contains "$CONFIG" 'follow_redirects = false' \
  'Prometheus remote write follows redirects'
assert_contains "$CONFIG" 'insecure_skip_verify = false' \
  'Prometheus remote write does not explicitly preserve TLS verification'
assert_contains "$CONFIG" '^prometheus[.]exporter[.]blackbox "platform_external_probe"' \
  'Alloy process owner did not compose the external probe contribution'

assert_contains "$COLLECTOR" '^#!/bin/bash$' \
  'VIP ownership collector does not use an absolute Bash interpreter'
assert_contains "$COLLECTOR" '^set -euo pipefail$' \
  'VIP ownership collector is not fail-fast'
assert_contains "$COLLECTOR" 'ip -o -4 address show dev eth0' \
  'VIP ownership collector does not inspect exact kernel address state'
assert_contains "$COLLECTOR" 'local_cidr%%/\*.*192[.]0[.]2[.]200' \
  'VIP ownership collector does not match only the kernel local-address field'
assert_contains "$COLLECTOR" 'mktemp .*metrics_dir.*/[.]vip-ownership' \
  'VIP ownership collector does not stage metrics in the target directory'
assert_contains "$COLLECTOR" 'mv -f -- .*metrics_path' \
  'VIP ownership collector does not publish metrics atomically'
assert_contains "$COLLECTOR" 'if \[\[ .*published.* -eq 0 \]\]' \
  'VIP ownership collector can preserve stale metrics after an unexpected failure'
assert_contains "$COLLECTOR" '^trap cleanup EXIT$' \
  'VIP ownership collector does not install fail-closed cleanup before staging'
assert_not_contains "$COLLECTOR" 'systemctl (start|stop|restart|reload)|ip address (add|del)|keepalived.*(reload|restart)' \
  'VIP ownership collector can mutate HA state'

assert_contains "$SERVICE" '^ProtectSystem=strict$' \
  'VIP ownership service does not protect the host filesystem'
assert_contains "$SERVICE" '^ReadWritePaths=/var/lib/alloy/platform-external-probe$' \
  'VIP ownership service has an unnecessarily broad write boundary'
assert_contains "$SERVICE" '^RestrictAddressFamilies=AF_UNIX AF_NETLINK$' \
  'VIP ownership service has unnecessary network access'
assert_contains "$TIMER" '^OnUnitActiveSec=5s$' \
  'VIP ownership timer does not use the approved observation interval'

if render_fixture \
  --extra-vars '{"platform_external_probe_test_target_2_name":"openbao_dns"}' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted duplicate target names'
fi

if render_fixture \
  --extra-vars 'platform_external_probe_test_target_2_address=http://192.0.2.200:8200/v1/sys/health' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted plaintext HTTP'
fi

if render_fixture \
  --extra-vars 'platform_external_probe_test_target_2_address=https://user:secret@192.0.2.200/v1/sys/health' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted URL credentials'
fi

if render_fixture \
  --extra-vars 'platform_external_probe_test_target_2_host_header=wrong.example.invalid' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted mismatched Host and TLS identities'
fi

if render_fixture \
  --extra-vars '{"platform_external_probe_test_required_body_regexes":[]}' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted a status-only success policy'
fi

if render_fixture \
  --extra-vars 'platform_external_probe_test_target_2_ca_file=' \
  --extra-vars 'platform_external_probe_test_target_2_client_cert_file=/run/secrets/probe.crt' \
  --extra-vars 'platform_external_probe_test_target_2_client_key_file=/run/secrets/probe.key' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted mTLS without a CA file'
fi

if render_fixture \
  --extra-vars 'platform_external_probe_test_vip=not-an-address' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted an invalid ownership address'
fi

if render_fixture \
  --extra-vars 'platform_external_probe_metrics_path=/tmp/vip-ownership.txt' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted a non-Prometheus textfile path'
fi

if render_fixture \
  --extra-vars '{"platform_external_probe_test_timer_enabled":true,"platform_external_probe_test_timer_state":"stopped"}' \
  >/dev/null 2>&1; then
  fail 'External probe fixture accepted an incoherent timer lifecycle'
fi

printf 'Platform external probe render check passed\n'
