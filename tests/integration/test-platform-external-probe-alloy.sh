#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/platform-external-probe/integration.yml
RPM_URL=https://github.com/grafana/alloy/releases/download/v1.18.1/alloy-1.18.1-1.amd64.rpm
RPM_SHA256=7dbdc068feae7feaafbc48fefb9b41b6c91af24984c13277bf0a9d1a298a4126
CACHE_LOCK_TIMEOUT="${PLATFORM_EXTERNAL_PROBE_CACHE_LOCK_TIMEOUT:-120}"
DOWNLOAD_TIMEOUT="${PLATFORM_EXTERNAL_PROBE_DOWNLOAD_TIMEOUT:-300}"
ARTIFACT_DIR="${ROOT_DIR}/.artifacts"
mkdir -p "$ARTIFACT_DIR"
RPM_PATH="${ARTIFACT_DIR}/alloy-1.18.1-1.amd64.rpm"
RPM_LOCK_PATH="${RPM_PATH}.lock"
RPM_TEMP_PATH=""
RPM_CONTAINER_PATH="/workspace/.artifacts/${RPM_PATH##*/}"
ROCKY_IMAGE="${PLATFORM_EXTERNAL_PROBE_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-external-probe-test-$$"

cleanup() {
  podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [[ -n "$RPM_TEMP_PATH" ]]; then
    rm -f -- "$RPM_TEMP_PATH"
  fi
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

if [[ ! "$CACHE_LOCK_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ ]] \
  || ((CACHE_LOCK_TIMEOUT > 3600)); then
  fail 'PLATFORM_EXTERNAL_PROBE_CACHE_LOCK_TIMEOUT must be an integer from 1 to 3600 seconds'
fi
if [[ ! "$DOWNLOAD_TIMEOUT" =~ ^[1-9][0-9]{0,3}$ ]] \
  || ((DOWNLOAD_TIMEOUT > 3600)); then
  fail 'PLATFORM_EXTERNAL_PROBE_DOWNLOAD_TIMEOUT must be an integer from 1 to 3600 seconds'
fi

exec 9>"$RPM_LOCK_PATH"
flock -w "$CACHE_LOCK_TIMEOUT" 9 \
  || fail "Timed out waiting for the Alloy RPM cache lock after ${CACHE_LOCK_TIMEOUT}s"
if ! printf '%s  %s\n' "$RPM_SHA256" "$RPM_PATH" \
  | sha256sum --check --status 2>/dev/null; then
  RPM_TEMP_PATH="$(mktemp "${ARTIFACT_DIR}/alloy-1.18.1-1.amd64.XXXXXX.rpm")"
  curl --connect-timeout 15 \
    --max-time "$DOWNLOAD_TIMEOUT" \
    --fail \
    --location \
    --silent \
    --show-error \
    --output "$RPM_TEMP_PATH" \
    "$RPM_URL"
  printf '%s  %s\n' "$RPM_SHA256" "$RPM_TEMP_PATH" | sha256sum --check --status \
    || fail 'Grafana Alloy 1.18.1 RPM checksum mismatch'
  mv -f -- "$RPM_TEMP_PATH" "$RPM_PATH"
  RPM_TEMP_PATH=""
fi
flock -u 9

run_playbook() {
  podman exec \
    --env ANSIBLE_COLLECTIONS_PATH=/workspace/.ansible/collections \
    --env ANSIBLE_ROLES_PATH=/workspace/roles \
    --workdir /workspace \
    "$CONTAINER" \
    ansible-playbook -i localhost, -c local "$FIXTURE" \
    --extra-vars "grafana_alloy_test_download_url=file://${RPM_CONTAINER_PATH}" \
    "$@"
}

assert_probe_result() {
  local module="$1"
  local target="$2"
  local expected="$3"
  local description="$4"
  local response

  response="$(podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
    --get \
    --data-urlencode "target=${target}" \
    --data-urlencode "module=${module}" \
    http://127.0.0.1:12345/api/v0/component/prometheus.exporter.blackbox.platform_external_probe/metrics)" \
    || fail "Alloy blackbox handler failed for ${description}"
  grep -qE "^probe_success ${expected}([.]0)?$" <<<"$response" \
    || fail "Alloy blackbox result for ${description} was not ${expected}"
}

wait_for_postgresql_probe_start() {
  local state=""

  for _ in {1..50}; do
    state="$(podman exec "$CONTAINER" systemctl show \
      --property=SubState --value \
      platform-external-probe-postgresql-primary.service)"
    if [[ "$state" == start ]]; then
      return 0
    fi
    sleep 0.1
  done
  podman exec "$CONTAINER" systemctl status --no-pager \
    platform-external-probe-postgresql-primary.service || true
  fail "PostgreSQL primary collector did not enter the in-flight state: ${state}"
}

podman run \
  --detach \
  --name "$CONTAINER" \
  --systemd=always \
  --cap-add NET_ADMIN \
  --workdir /workspace \
  --volume "${ROOT_DIR}:/workspace:ro,Z" \
  "$ROCKY_IMAGE" \
  bash -lc 'dnf -qy install systemd && exec /sbin/init' >/dev/null

for _ in {1..30}; do
  if podman exec "$CONTAINER" systemctl is-system-running --quiet 2>/dev/null; then
    break
  fi
  sleep 1
done
podman exec "$CONTAINER" systemctl is-system-running --quiet \
  || fail 'Disposable Rocky systemd did not become ready'

podman exec "$CONTAINER" dnf -qy install curl iproute openssl podman python3-pip rpm-build >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" ip link add vrrp-test type dummy
podman exec "$CONTAINER" ip address add 192.0.2.200/24 dev vrrp-test
podman exec "$CONTAINER" ip link set vrrp-test up

podman exec "$CONTAINER" mkdir -p /etc/platform-test-pki
podman exec "$CONTAINER" openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=platform-external-probe-test-ca \
  -keyout /etc/platform-test-pki/ca.key \
  -out /etc/platform-test-pki/ca.crt >/dev/null 2>&1
for identity in server wrong client; do
  common_name=monitoring.example.invalid
  extended_usage=serverAuth
  if [[ "$identity" == wrong ]]; then
    common_name=wrong.example.invalid
  elif [[ "$identity" == client ]]; then
    common_name=platform-external-probe-client
    extended_usage=clientAuth
  fi
  podman exec "$CONTAINER" openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=${common_name}" \
    -addext "subjectAltName=DNS:${common_name}" \
    -addext "extendedKeyUsage=${extended_usage}" \
    -keyout "/etc/platform-test-pki/${identity}.key" \
    -out "/etc/platform-test-pki/${identity}.csr" >/dev/null 2>&1
  podman exec "$CONTAINER" openssl x509 -req -days 1 \
    -in "/etc/platform-test-pki/${identity}.csr" \
    -CA /etc/platform-test-pki/ca.crt \
    -CAkey /etc/platform-test-pki/ca.key \
    -CAcreateserial \
    -copy_extensions copy \
    -out "/etc/platform-test-pki/${identity}.crt" >/dev/null 2>&1
done
podman exec "$CONTAINER" chmod 0600 /etc/platform-test-pki/ca.key \
  /etc/platform-test-pki/server.key /etc/platform-test-pki/wrong.key \
  /etc/platform-test-pki/client.key

# shellcheck disable=SC2016  # Expansion is deferred to the generated stub.
printf '%s\n' \
  '#!/bin/bash' \
  'set -euo pipefail' \
  'if [[ "${1:-}" == --version ]]; then printf "%s\n" "psql (PostgreSQL) 18.4"; exit 0; fi' \
  '[[ "$PGAPPNAME" == platform-external-probe ]]' \
  '[[ "$PGCONNECT_TIMEOUT" == 4 ]]' \
  '[[ -z "$PGPASSWORD" && "$PGPASSFILE" == /dev/null ]]' \
  '[[ "$PGGSSENCMODE" == disable && "$PGSSLMODE" == verify-full ]]' \
  '[[ "$PGSSLCERTMODE" == require && "$PGREQUIREAUTH" == none ]]' \
  '[[ "$PGSSLROOTCERT" == /etc/platform-test-pki/ca.crt ]]' \
  '[[ "$PGSSLCERT" == /etc/platform-test-pki/client.crt ]]' \
  '[[ "$PGSSLKEY" == /etc/platform-test-pki/client.key ]]' \
  '[[ "$PGOPTIONS" == "-c statement_timeout=3000 -c default_transaction_read_only=on -c search_path=" ]]' \
  '[[ "$*" == *"--host=postgres.example.invalid"* ]]' \
  '[[ "$*" == *"--port=5432"* && "$*" == *"--dbname=observer"* ]]' \
  '[[ "$*" == *"--username=monitoring_probe"* && "$*" == *"--no-password"* ]]' \
  '[[ "$*" == *"--command=SELECT NOT pg_catalog.pg_is_in_recovery();"* ]]' \
  'case "$(</tmp/postgresql-probe.state)" in' \
  '  primary) printf "%s\n" t ;;' \
  '  recovery) printf "%s\n" f ;;' \
  '  malformed) printf "%s\n" true ;;' \
  '  failure) exit 1 ;;' \
  '  slow) sleep 10; printf "%s\n" t ;;' \
  '  term-resistant) trap "" TERM; sleep 10; printf "%s\n" t ;;' \
  '  *) exit 2 ;;' \
  'esac' \
  | podman exec --interactive "$CONTAINER" tee \
    /usr/local/bin/platform-test-psql >/dev/null
podman exec "$CONTAINER" chmod 0755 /usr/local/bin/platform-test-psql
printf '%s\n' primary \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null

podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/platform-external-probe/https_fixture.py \
  --port 18443 \
  --cert /etc/platform-test-pki/server.crt \
  --key /etc/platform-test-pki/server.key \
  --expected-host monitoring.example.invalid \
  --expected-sni monitoring.example.invalid >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/platform-external-probe/https_fixture.py \
  --port 18444 \
  --cert /etc/platform-test-pki/wrong.crt \
  --key /etc/platform-test-pki/wrong.key \
  --expected-host monitoring.example.invalid \
  --expected-sni monitoring.example.invalid >/dev/null
podman exec --detach "$CONTAINER" python3 \
  /workspace/tests/fixtures/platform-external-probe/https_fixture.py \
  --port 18445 \
  --cert /etc/platform-test-pki/server.crt \
  --key /etc/platform-test-pki/server.key \
  --client-ca /etc/platform-test-pki/ca.crt \
  --expected-host monitoring.example.invalid \
  --expected-sni monitoring.example.invalid >/dev/null

for _ in {1..30}; do
  if podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
    --cacert /etc/platform-test-pki/ca.crt \
    --resolve monitoring.example.invalid:18443:127.0.0.1 \
    https://monitoring.example.invalid:18443/ready \
    -H 'Host: monitoring.example.invalid' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
  --cacert /etc/platform-test-pki/ca.crt \
  --resolve monitoring.example.invalid:18443:127.0.0.1 \
  https://monitoring.example.invalid:18443/ready \
  -H 'Host: monitoring.example.invalid' >/dev/null \
  || fail 'Controlled HTTPS probe fixture did not become ready'
podman exec "$CONTAINER" curl --fail --silent --show-error --insecure --noproxy '*' \
  --resolve monitoring.example.invalid:18444:127.0.0.1 \
  https://monitoring.example.invalid:18444/ready \
  -H 'Host: monitoring.example.invalid' >/dev/null \
  || fail 'Wrong-identity HTTPS probe fixture did not become ready'
podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
  --cacert /etc/platform-test-pki/ca.crt \
  --cert /etc/platform-test-pki/client.crt \
  --key /etc/platform-test-pki/client.key \
  --resolve monitoring.example.invalid:18445:127.0.0.1 \
  https://monitoring.example.invalid:18445/ready \
  -H 'Host: monitoring.example.invalid' >/dev/null \
  || fail 'Mutual-TLS HTTPS probe fixture did not become ready'

run_playbook --check >/dev/null
run_playbook >/dev/null

package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' alloy)"
[[ "$package_identity" == alloy-0:1.18.1-1.x86_64 ]] \
  || fail "Grafana Alloy package identity mismatch: ${package_identity}"
podman exec "$CONTAINER" /usr/bin/alloy --version | grep -q 'version v1[.]18[.]1' \
  || fail 'Grafana Alloy executable version mismatch'
podman exec "$CONTAINER" /usr/bin/alloy validate /etc/alloy/config.alloy \
  || fail 'Grafana Alloy rejected the composed configuration'

podman exec "$CONTAINER" rpmbuild -bb \
  --define '_topdir /tmp/rpmbuild' \
  /workspace/tests/fixtures/platform-external-probe/alloy-newer.spec >/dev/null
podman exec "$CONTAINER" dnf -qy --nogpgcheck install \
  /tmp/rpmbuild/RPMS/x86_64/alloy-99.0.0-1.x86_64.rpm >/dev/null
newer_package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' alloy)"
[[ "$newer_package_identity" == alloy-0:99.0.0-1.x86_64 ]] \
  || fail "Synthetic newer Alloy package was not installed: ${newer_package_identity}"
run_playbook >/dev/null
package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' alloy)"
[[ "$package_identity" == alloy-0:1.18.1-1.x86_64 ]] \
  || fail "Grafana Alloy did not downgrade to the approved identity: ${package_identity}"
podman exec "$CONTAINER" /usr/bin/alloy validate /etc/alloy/config.alloy \
  || fail 'Downgraded Grafana Alloy rejected the composed configuration'

if [[ "$(podman exec "$CONTAINER" systemctl is-enabled alloy.service 2>/dev/null)" != disabled ]]; then
  fail 'Grafana Alloy service became enabled in staged convergence'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet alloy.service; then
  fail 'Grafana Alloy service started before observer acceptance'
fi
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled platform-external-probe-ownership.timer 2>/dev/null)" != disabled ]]; then
  fail 'VIP ownership timer became enabled before observer acceptance'
fi
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled platform-external-probe-postgresql-primary.timer 2>/dev/null)" != disabled ]]; then
  fail 'PostgreSQL primary timer became enabled before observer acceptance'
fi

if ! podman exec "$CONTAINER" systemctl start \
  platform-external-probe-postgresql-primary.service; then
  podman exec "$CONTAINER" systemctl status --no-pager \
    platform-external-probe-postgresql-primary.service || true
  fail 'PostgreSQL primary collector service failed'
fi
postgresql_metrics="$(podman exec "$CONTAINER" /usr/bin/cat \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom)"
grep -q 'platform_postgresql_primary{service="postgresql",node="openbao-test-01",environment="test",endpoint="postgresql_primary",address_mode="vip"} 1' \
  <<<"$postgresql_metrics" \
  || fail 'PostgreSQL primary collector rejected the exact primary result'
grep -q 'platform_postgresql_primary_query_success{.*} 1' \
  <<<"$postgresql_metrics" \
  || fail 'PostgreSQL primary collector did not report successful exact parsing'

for state in recovery malformed failure; do
  printf '%s\n' "$state" \
    | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
  podman exec "$CONTAINER" systemctl start \
    platform-external-probe-postgresql-primary.service
  postgresql_metrics="$(podman exec "$CONTAINER" /usr/bin/cat \
    /var/lib/alloy/platform-external-probe/postgresql-primary.prom)"
  grep -q 'platform_postgresql_primary{.*} 0' <<<"$postgresql_metrics" \
    || fail "PostgreSQL primary collector accepted ${state} output"
  expected_query_success=0
  if [[ "$state" == recovery ]]; then
    expected_query_success=1
  fi
  grep -q "platform_postgresql_primary_query_success{.*} ${expected_query_success}" \
    <<<"$postgresql_metrics" \
    || fail "PostgreSQL primary collector misclassified ${state} query status"
done

printf '%s\n' slow \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
probe_started="$(date +%s)"
podman exec "$CONTAINER" systemctl start \
  platform-external-probe-postgresql-primary.service
probe_elapsed=$(($(date +%s) - probe_started))
((probe_elapsed <= 6)) \
  || fail "PostgreSQL primary collector exceeded its process timeout: ${probe_elapsed}s"
postgresql_metrics="$(podman exec "$CONTAINER" /usr/bin/cat \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom)"
grep -q 'platform_postgresql_primary_query_success{.*} 0' \
  <<<"$postgresql_metrics" \
  || fail 'PostgreSQL primary collector treated a timeout as query success'
printf '%s\n' term-resistant \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
probe_started="$(date +%s)"
podman exec "$CONTAINER" systemctl start \
  platform-external-probe-postgresql-primary.service
probe_elapsed=$(($(date +%s) - probe_started))
((probe_elapsed <= 7)) \
  || fail "PostgreSQL primary collector exceeded its hard timeout: ${probe_elapsed}s"
postgresql_metrics="$(podman exec "$CONTAINER" /usr/bin/cat \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom)"
grep -q 'platform_postgresql_primary_query_success{.*} 0' \
  <<<"$postgresql_metrics" \
  || fail 'PostgreSQL primary collector treated forced termination as query success'

printf '%s\n' primary \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
podman exec "$CONTAINER" systemctl start \
  platform-external-probe-postgresql-primary.service
printf '%s\n' slow \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
podman exec "$CONTAINER" systemctl start --no-block \
  platform-external-probe-postgresql-primary.service
wait_for_postgresql_probe_start
if podman exec "$CONTAINER" test -e \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom; then
  fail 'PostgreSQL primary collector preserved stale evidence before execution'
fi
podman exec "$CONTAINER" systemctl kill --kill-whom=all --signal=KILL \
  platform-external-probe-postgresql-primary.service
for _ in {1..30}; do
  if ! podman exec "$CONTAINER" systemctl is-active --quiet \
    platform-external-probe-postgresql-primary.service; then
    break
  fi
  sleep 0.1
done
if podman exec "$CONTAINER" test -e \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom; then
  fail 'Hard collector termination preserved stale PostgreSQL primary evidence'
fi
podman exec "$CONTAINER" systemctl reset-failed \
  platform-external-probe-postgresql-primary.service
printf '%s\n' primary \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null

if ! podman exec "$CONTAINER" systemctl start platform-external-probe-ownership.service; then
  podman exec "$CONTAINER" systemctl status --no-pager platform-external-probe-ownership.service || true
  podman exec "$CONTAINER" journalctl --no-pager -u platform-external-probe-ownership.service || true
  fail 'VIP ownership collector service failed'
fi
ownership_metrics="$(podman exec "$CONTAINER" /usr/bin/cat /var/lib/alloy/platform-external-probe/vip-ownership.prom)"
grep -q 'platform_vip_owned{service="openbao",node="openbao-test-01",environment="test",endpoint="openbao_vip",instance="OPENBAO",interface="vrrp-test",vip="192.0.2.200"} 1' <<<"$ownership_metrics" \
  || fail 'VIP ownership collector did not report the exact local address'
grep -q 'platform_vip_ownership_collection_success{service="openbao",node="openbao-test-01",environment="test",endpoint="openbao_vip",instance="OPENBAO",interface="vrrp-test",vip="192.0.2.200"} 1' <<<"$ownership_metrics" \
  || fail 'VIP ownership collector did not report successful interface inspection'
timestamp_line="$(grep -m1 'platform_vip_ownership_observation_timestamp_seconds{' <<<"$ownership_metrics")"
timestamp_before="${timestamp_line##* }"
timestamp_now="$(date +%s)"
if [[ ! "$timestamp_before" =~ ^[0-9]+$ ]] \
  || ((timestamp_before > timestamp_now || timestamp_before < timestamp_now - 10)); then
  fail 'VIP ownership collector did not publish a current observation timestamp'
fi

podman exec "$CONTAINER" ip address flush dev vrrp-test
podman exec "$CONTAINER" systemctl start platform-external-probe-ownership.service
ownership_metrics="$(podman exec "$CONTAINER" /usr/bin/cat /var/lib/alloy/platform-external-probe/vip-ownership.prom)"
grep -q 'platform_vip_owned{service="openbao",node="openbao-test-01",environment="test",endpoint="openbao_vip",instance="OPENBAO",interface="vrrp-test",vip="192.0.2.200"} 0' <<<"$ownership_metrics" \
  || fail 'VIP ownership collector reported an absent address as local'

podman exec "$CONTAINER" ip address add 192.0.2.199 peer 192.0.2.200 dev vrrp-test
podman exec "$CONTAINER" systemctl start platform-external-probe-ownership.service
ownership_metrics="$(podman exec "$CONTAINER" /usr/bin/cat /var/lib/alloy/platform-external-probe/vip-ownership.prom)"
grep -q 'platform_vip_owned{service="openbao",node="openbao-test-01",environment="test",endpoint="openbao_vip",instance="OPENBAO",interface="vrrp-test",vip="192.0.2.200"} 0' <<<"$ownership_metrics" \
  || fail 'VIP ownership collector mistook a peer address for local ownership'
podman exec "$CONTAINER" ip address flush dev vrrp-test
podman exec "$CONTAINER" ip address add 192.0.2.200/24 dev vrrp-test
sleep 1
podman exec "$CONTAINER" systemctl start platform-external-probe-ownership.service
ownership_metrics="$(podman exec "$CONTAINER" /usr/bin/cat /var/lib/alloy/platform-external-probe/vip-ownership.prom)"
timestamp_line="$(grep -m1 'platform_vip_ownership_observation_timestamp_seconds{' <<<"$ownership_metrics")"
timestamp_after="${timestamp_line##* }"
if [[ ! "$timestamp_after" =~ ^[0-9]+$ ]] || ((timestamp_after <= timestamp_before)); then
  fail 'VIP ownership observation timestamp did not advance'
fi

podman exec "$CONTAINER" cp -a /usr/bin/mktemp /tmp/mktemp.real
podman exec "$CONTAINER" ln -sf /bin/false /usr/bin/mktemp
if podman exec "$CONTAINER" systemctl start platform-external-probe-ownership.service >/dev/null 2>&1; then
  fail 'VIP ownership collector unexpectedly published after staging failed'
fi
if podman exec "$CONTAINER" test -e /var/lib/alloy/platform-external-probe/vip-ownership.prom; then
  fail 'VIP ownership staging failure preserved stale ownership evidence'
fi
podman exec "$CONTAINER" mv -f /tmp/mktemp.real /usr/bin/mktemp
podman exec "$CONTAINER" systemctl reset-failed platform-external-probe-ownership.service
podman exec "$CONTAINER" systemctl start platform-external-probe-ownership.service

podman exec "$CONTAINER" cp -a /usr/bin/mktemp /tmp/mktemp.real
podman exec "$CONTAINER" ln -sf /bin/false /usr/bin/mktemp
if podman exec "$CONTAINER" systemctl start \
  platform-external-probe-postgresql-primary.service >/dev/null 2>&1; then
  fail 'PostgreSQL primary collector unexpectedly published after staging failed'
fi
if podman exec "$CONTAINER" test -e \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom; then
  fail 'PostgreSQL primary staging failure preserved stale evidence'
fi
podman exec "$CONTAINER" mv -f /tmp/mktemp.real /usr/bin/mktemp
podman exec "$CONTAINER" systemctl reset-failed \
  platform-external-probe-postgresql-primary.service
podman exec "$CONTAINER" systemctl start \
  platform-external-probe-postgresql-primary.service

run_playbook >/dev/null
if podman exec "$CONTAINER" test -e \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom; then
  fail 'Staged convergence preserved manually generated PostgreSQL primary evidence'
fi
idempotent_output="$(run_playbook)"
if ! grep -qE 'changed=0.*failed=0' <<<"$idempotent_output"; then
  printf '%s\n' "$idempotent_output" >&2
  fail 'Second external probe and Alloy convergence was not idempotent'
fi

config_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/alloy/config.alloy)"
if run_playbook \
  --extra-vars platform_external_probe_test_address=https://192.0.2.202/ready \
  --extra-vars '{"grafana_alloy_test_extra_config":"unsupported_platform_option = true"}' \
  >/dev/null 2>&1; then
  fail 'Grafana Alloy role accepted a candidate rejected by its validator'
fi
config_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/alloy/config.alloy)"
[[ "$config_hash_before" == "$config_hash_after" ]] \
  || fail 'Rejected Alloy candidate replaced the last valid configuration'

for quadlet_root in /etc /run /usr/share; do
  podman exec "$CONTAINER" mkdir -p "${quadlet_root}/containers/systemd"
  for quadlet_name in alloy monitoring-alloy; do
    printf '%s\n' \
      '[Container]' \
      'Image=example.invalid/alloy:latest' \
      | podman exec --interactive "$CONTAINER" tee \
        "${quadlet_root}/containers/systemd/${quadlet_name}.container" >/dev/null
    if run_playbook >/dev/null 2>&1; then
      fail "Host-native Alloy accepted ${quadlet_root} ${quadlet_name} Quadlet ownership"
    fi
    podman exec "$CONTAINER" rm -f \
      "${quadlet_root}/containers/systemd/${quadlet_name}.container"
  done
done

run_playbook --extra-vars '{"platform_external_probe_test_active":true}' >/dev/null
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Role-driven Grafana Alloy activation failed'
podman exec "$CONTAINER" systemctl is-active --quiet platform-external-probe-ownership.timer \
  || fail 'Role-driven VIP ownership timer activation failed'
podman exec "$CONTAINER" systemctl is-active --quiet \
  platform-external-probe-postgresql-primary.timer \
  || fail 'Role-driven PostgreSQL primary timer activation failed'
active_output="$(run_playbook --extra-vars '{"platform_external_probe_test_active":true}')"
if ! grep -qE 'changed=0.*failed=0' <<<"$active_output"; then
  printf '%s\n' "$active_output" >&2
  fail 'Second active external probe and Alloy convergence was not idempotent'
fi

printf '%s\n' slow \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
podman exec "$CONTAINER" systemctl stop \
  platform-external-probe-postgresql-primary.timer
podman exec "$CONTAINER" systemctl stop \
  platform-external-probe-postgresql-primary.service
podman exec "$CONTAINER" systemctl reset-failed \
  platform-external-probe-postgresql-primary.service
podman exec "$CONTAINER" systemctl start --no-block \
  platform-external-probe-postgresql-primary.service
wait_for_postgresql_probe_start
run_playbook >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet \
  platform-external-probe-postgresql-primary.service; then
  fail 'Timer deactivation left the PostgreSQL primary collector running'
fi
if podman exec "$CONTAINER" test -e \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom; then
  fail 'Timer deactivation left stale PostgreSQL primary evidence'
fi
printf '%s\n' primary \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
run_playbook --extra-vars '{"platform_external_probe_test_active":true}' >/dev/null

for _ in {1..30}; do
  if podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
    http://127.0.0.1:12345/-/ready >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
  http://127.0.0.1:12345/-/ready >/dev/null \
  || fail 'Grafana Alloy HTTP endpoint did not become ready'

assert_probe_result monitoring_vip https://127.0.0.1:18443/ready 1 \
  'valid CA, certificate identity, SNI, Host, status, and body policy'
assert_probe_result monitoring_vip https://127.0.0.1:18444/ready 0 \
  'wrong certificate identity'
assert_probe_result monitoring_vip https://127.0.0.1:18443/redirect 0 \
  'redirect rejection'
assert_probe_result monitoring_vip https://127.0.0.1:18443/status 0 \
  'unexpected status rejection'
assert_probe_result monitoring_vip https://127.0.0.1:18443/missing-body 0 \
  'required body rejection'
assert_probe_result monitoring_vip https://127.0.0.1:18443/forbidden-body 0 \
  'forbidden body rejection'
assert_probe_result monitoring_mtls https://127.0.0.1:18445/ready 1 \
  'valid client certificate'
assert_probe_result monitoring_vip https://127.0.0.1:18445/ready 0 \
  'missing client certificate rejection'
assert_probe_result grafana_health https://127.0.0.1:18443/api/health 1 \
  'Grafana 13.1.3 database health profile'
assert_probe_result grafana_health https://127.0.0.1:18443/api/health-degraded 0 \
  'Grafana degraded database rejection'
assert_probe_result grafana_health https://127.0.0.1:18443/api/health-wrong-version 0 \
  'Grafana wrong version rejection'
assert_probe_result loki_ready https://127.0.0.1:18443/ready 1 \
  'Loki 3.7.6 readiness profile'
assert_probe_result loki_ready https://127.0.0.1:18443/ready-wrong-body 0 \
  'Loki non-ready body rejection'
assert_probe_result loki_ready https://127.0.0.1:18443/status 0 \
  'Loki HTTP 503 readiness rejection'
assert_probe_result mimir_ready https://127.0.0.1:18443/ready 1 \
  'Mimir 3.1.4 readiness profile'
assert_probe_result mimir_ready https://127.0.0.1:18443/ready-wrong-body 0 \
  'Mimir non-ready body rejection'
assert_probe_result mimir_ready https://127.0.0.1:18443/status 0 \
  'Mimir HTTP 503 readiness rejection'

# shellcheck disable=SC2016  # Expansion is deferred to the generated stub.
printf '%s\n' \
  '#!/bin/bash' \
  'if [[ "$1" == show ]]; then exit 42; fi' \
  'exec /usr/bin/systemctl "$@"' \
  | podman exec --interactive "$CONTAINER" tee /usr/local/bin/systemctl >/dev/null
podman exec "$CONTAINER" chmod 0755 /usr/local/bin/systemctl
drop_in_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/systemd/system/alloy.service.d/platform.conf)"
if run_playbook \
  --extra-vars '{"grafana_alloy_test_process_owner_only":true,"grafana_alloy_enabled":true}' \
  >/dev/null 2>&1; then
  fail 'Native Alloy convergence accepted failed systemd owner inspection'
fi
drop_in_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/systemd/system/alloy.service.d/platform.conf)"
[[ "$drop_in_hash_before" == "$drop_in_hash_after" ]] \
  || fail 'Failed enabled owner inspection replaced the native ownership drop-in'
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Failed enabled owner inspection stopped native Alloy'
if run_playbook \
  --extra-vars '{"grafana_alloy_test_process_owner_only":true,"grafana_alloy_enabled":false}' \
  >/dev/null 2>&1; then
  fail 'Native Alloy ownership release accepted failed systemd owner inspection'
fi
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Failed systemd owner inspection stopped native Alloy'
podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf \
  || fail 'Failed systemd owner inspection removed the native ownership drop-in'
podman exec "$CONTAINER" rm -f /usr/local/bin/systemctl

printf '%s\n' \
  '[Unit]' \
  'Description=Synthetic unknown Alloy owner' \
  '[Service]' \
  'ExecStart=/usr/bin/sleep infinity' \
  | podman exec --interactive "$CONTAINER" tee /etc/systemd/system/alloy.service >/dev/null
podman exec "$CONTAINER" systemctl daemon-reload
drop_in_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/systemd/system/alloy.service.d/platform.conf)"
if run_playbook \
  --extra-vars '{"grafana_alloy_test_process_owner_only":true,"grafana_alloy_enabled":true}' \
  >/dev/null 2>&1; then
  fail 'Native Alloy convergence accepted an unknown systemd owner'
fi
drop_in_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/systemd/system/alloy.service.d/platform.conf)"
[[ "$drop_in_hash_before" == "$drop_in_hash_after" ]] \
  || fail 'Unknown enabled owner inspection replaced the native ownership drop-in'
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Unknown enabled owner inspection stopped Alloy'
if run_playbook \
  --extra-vars '{"grafana_alloy_test_process_owner_only":true,"grafana_alloy_enabled":false}' \
  >/dev/null 2>&1; then
  fail 'Native Alloy ownership release accepted an unknown systemd owner'
fi
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Unknown systemd owner inspection stopped Alloy'
podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf \
  || fail 'Unknown systemd owner inspection removed the native ownership drop-in'
podman exec "$CONTAINER" rm -f /etc/systemd/system/alloy.service
podman exec "$CONTAINER" systemctl daemon-reload

# shellcheck disable=SC2016  # Expansion is deferred to the generated stub.
printf '%s\n' \
  '#!/bin/bash' \
  'printf "%s\n" "[Unit]" "SourcePath=/tmp/unrecognized-alloy.container" "[Service]" "ExecStart=/usr/bin/sleep infinity" >"${1}/alloy.service"' \
  | podman exec --interactive "$CONTAINER" tee \
    /usr/lib/systemd/system-generators/platform-test-alloy-generator >/dev/null
podman exec "$CONTAINER" chmod 0755 \
  /usr/lib/systemd/system-generators/platform-test-alloy-generator
podman exec "$CONTAINER" systemctl daemon-reload
fragment_path="$(podman exec "$CONTAINER" systemctl show --property=FragmentPath --value alloy.service)"
if [[ "$fragment_path" != /run/systemd/generator*/alloy.service ]]; then
  fail "Synthetic generator did not supersede the native Alloy unit: ${fragment_path}"
fi
if run_playbook \
  --extra-vars '{"grafana_alloy_test_process_owner_only":true,"grafana_alloy_enabled":false}' \
  >/dev/null 2>&1; then
  fail 'Native Alloy ownership release accepted an unrecognized generated owner'
fi
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Unrecognized generated owner inspection stopped Alloy'
podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf \
  || fail 'Unrecognized generated owner inspection removed the native ownership drop-in'
podman exec "$CONTAINER" rm -f \
  /usr/lib/systemd/system-generators/platform-test-alloy-generator
podman exec "$CONTAINER" systemctl daemon-reload

printf '%s\n' slow \
  | podman exec --interactive "$CONTAINER" tee /tmp/postgresql-probe.state >/dev/null
podman exec "$CONTAINER" systemctl stop \
  platform-external-probe-postgresql-primary.timer
podman exec "$CONTAINER" systemctl stop \
  platform-external-probe-postgresql-primary.service
podman exec "$CONTAINER" systemctl reset-failed \
  platform-external-probe-postgresql-primary.service
podman exec "$CONTAINER" systemctl start --no-block \
  platform-external-probe-postgresql-primary.service
wait_for_postgresql_probe_start
if ! disable_output="$(run_playbook \
  --extra-vars '{"platform_external_probe_enabled":false,"grafana_alloy_enabled":false}')"; then
  printf '%s\n' "$disable_output" >&2
  fail 'Disabled external probe and Alloy convergence failed'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet alloy.service; then
  fail 'Disabling the managed native Alloy role left its service running'
fi
if podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf; then
  fail 'Disabling the managed native Alloy role left its process-owner drop-in'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet platform-external-probe-ownership.timer; then
  fail 'Disabling external probes left the ownership timer running'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet \
  platform-external-probe-postgresql-primary.timer; then
  fail 'Disabling external probes left the PostgreSQL primary timer running'
fi
if podman exec "$CONTAINER" test -e /var/lib/alloy/platform-external-probe/vip-ownership.prom; then
  fail 'Disabling external probes left stale ownership evidence'
fi
if podman exec "$CONTAINER" test -e \
  /var/lib/alloy/platform-external-probe/postgresql-primary.prom; then
  fail 'Disabling external probes left stale PostgreSQL primary evidence'
fi

disabled_output="$(run_playbook \
  --extra-vars '{"platform_external_probe_enabled":false,"grafana_alloy_enabled":false}')"
if ! grep -qE 'changed=0.*failed=0' <<<"$disabled_output"; then
  printf '%s\n' "$disabled_output" >&2
  fail 'Second disabled external probe and Alloy convergence was not idempotent'
fi

run_playbook --extra-vars '{"platform_external_probe_test_active":true}' >/dev/null
podman exec "$CONTAINER" systemctl stop alloy.service
podman exec "$CONTAINER" dnf -qy remove alloy >/dev/null
podman exec "$CONTAINER" systemctl daemon-reload
load_state="$(podman exec "$CONTAINER" systemctl show --property=LoadState --value alloy.service)"
fragment_path="$(podman exec "$CONTAINER" systemctl show --property=FragmentPath --value alloy.service)"
if [[ "$load_state" != not-found || -n "$fragment_path" ]]; then
  fail "Removed native Alloy unit was not absent: ${load_state} ${fragment_path}"
fi
podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf \
  || fail 'Native package removal unexpectedly removed the platform drop-in'
run_playbook \
  --extra-vars '{"grafana_alloy_test_process_owner_only":true,"grafana_alloy_enabled":false}' \
  >/dev/null
if podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf; then
  fail 'Absent native unit convergence preserved a stale process-owner drop-in'
fi

run_playbook --extra-vars '{"platform_external_probe_test_active":true}' >/dev/null
podman exec "$CONTAINER" mkdir -p /etc/containers/systemd
printf '%s\n' \
  '[Container]' \
  'Image=example.invalid/alloy:latest' \
  | podman exec --interactive "$CONTAINER" tee /etc/containers/systemd/alloy.container >/dev/null
podman exec "$CONTAINER" systemctl daemon-reload
fragment_path="$(podman exec "$CONTAINER" systemctl show --property=FragmentPath --value alloy.service)"
if [[ "$fragment_path" != /run/systemd/generator*/alloy.service ]]; then
  fail "Quadlet did not supersede the native Alloy unit: ${fragment_path}"
fi
source_path="$(podman exec "$CONTAINER" systemctl show --property=SourcePath --value alloy.service)"
if [[ "$source_path" != /etc/containers/systemd/alloy.container ]]; then
  fail "Quadlet did not expose its approved source path: ${source_path}"
fi
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Quadlet handoff unexpectedly stopped the running Alloy unit'
run_playbook \
  --extra-vars '{"platform_external_probe_enabled":false,"grafana_alloy_enabled":false}' \
  >/dev/null
podman exec "$CONTAINER" systemctl is-active --quiet alloy.service \
  || fail 'Disabling native ownership stopped a superseding Quadlet unit'
if podman exec "$CONTAINER" test -e /etc/systemd/system/alloy.service.d/platform.conf; then
  fail 'Native-to-Quadlet handoff preserved the native process-owner drop-in'
fi
handoff_output="$(run_playbook \
  --extra-vars '{"platform_external_probe_enabled":false,"grafana_alloy_enabled":false}')"
if ! grep -qE 'changed=0.*failed=0' <<<"$handoff_output"; then
  printf '%s\n' "$handoff_output" >&2
  fail 'Second native-to-Quadlet handoff convergence was not idempotent'
fi

printf 'Platform external probe Alloy 1.18.1 integration check passed\n'
