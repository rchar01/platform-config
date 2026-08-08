#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/openbao-haproxy/integration.yml
ROCKY_IMAGE="${OPENBAO_HAPROXY_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-openbao-haproxy-test-$$"

cleanup() {
  podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

run_playbook() {
  podman exec \
    --env ANSIBLE_COLLECTIONS_PATH=/root/.ansible/collections \
    --env ANSIBLE_ROLES_PATH=/workspace/roles \
    --workdir /workspace \
    "$CONTAINER" \
    ansible-playbook -i localhost, -c local "$FIXTURE" "$@"
}

set_health_status() {
  local node="$1"
  local status="$2"

  printf '%s\n' "$status" \
    | podman exec --interactive "$CONTAINER" tee "/tmp/${node}.status" >/dev/null
}

query_shared_health() {
  podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
    --max-time 3 \
    --cacert /etc/openbao/tls/ca.crt \
    --resolve bao.example.invalid:8200:127.0.0.1 \
    -H 'Host: bao.example.invalid' \
    https://bao.example.invalid:8200/v1/sys/health
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

podman exec "$CONTAINER" dnf -qy install \
  curl iproute openssl python3-pip rpm-build >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" ansible-galaxy collection install \
  -r /workspace/requirements.yml \
  -p /root/.ansible/collections >/dev/null

podman exec "$CONTAINER" mkdir -p /etc/openbao/tls /etc/openbao-haproxy-test
podman exec "$CONTAINER" openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=openbao-haproxy-test-ca \
  -keyout /etc/openbao-haproxy-test/ca.key \
  -out /etc/openbao/tls/ca.crt >/dev/null 2>&1

for node in 1 2 3; do
  node_dns="bao-test-${node}.internal.invalid"
  cert_dns="$node_dns"
  if [[ "$node" == 3 ]]; then
    cert_dns=wrong-node.internal.invalid
  fi
  podman exec "$CONTAINER" openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=${cert_dns}" \
    -addext "subjectAltName=DNS:${cert_dns},DNS:bao.example.invalid" \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "/etc/openbao-haproxy-test/node${node}.key" \
    -out "/etc/openbao-haproxy-test/node${node}.csr" >/dev/null 2>&1
  podman exec "$CONTAINER" openssl x509 -req -days 1 \
    -in "/etc/openbao-haproxy-test/node${node}.csr" \
    -CA /etc/openbao/tls/ca.crt \
    -CAkey /etc/openbao-haproxy-test/ca.key \
    -CAcreateserial \
    -copy_extensions copy \
    -out "/etc/openbao-haproxy-test/node${node}.crt" >/dev/null 2>&1
done
podman exec "$CONTAINER" chmod 0600 \
  /etc/openbao-haproxy-test/ca.key \
  /etc/openbao-haproxy-test/node1.key \
  /etc/openbao-haproxy-test/node2.key \
  /etc/openbao-haproxy-test/node3.key

set_health_status node1 200
set_health_status node2 429
set_health_status node3 200
for node in 1 2 3; do
  address="127.0.0.$((node + 1))"
  node_dns="bao-test-${node}.internal.invalid"
  podman exec --detach "$CONTAINER" python3 \
    /workspace/tests/fixtures/openbao-haproxy/health_fixture.py \
    --bind "$address" \
    --port 18200 \
    --cert "/etc/openbao-haproxy-test/node${node}.crt" \
    --key "/etc/openbao-haproxy-test/node${node}.key" \
    --status-file "/tmp/node${node}.status" \
    --sni-log "/tmp/node${node}.sni" \
    --node "node${node}" \
    --expected-host bao.example.invalid \
    --expected-sni "$node_dns" \
    --expected-sni bao.example.invalid >/dev/null
done

for node in 1 2 3; do
  expected_status=200
  if [[ "$node" == 2 ]]; then
    expected_status=429
  fi
  observed_status=""
  for _ in {1..30}; do
    observed_status="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
      --output /dev/null \
      --write-out '%{http_code}' \
      --cacert /etc/openbao/tls/ca.crt \
      --resolve "bao.example.invalid:18200:127.0.0.$((node + 1))" \
      -H 'Host: bao.example.invalid' \
      https://bao.example.invalid:18200/v1/sys/health 2>/dev/null || true)"
    if [[ "$observed_status" == "$expected_status" ]]; then
      break
    fi
    sleep 1
  done
  [[ "$observed_status" == "$expected_status" ]] \
    || fail "OpenBao health fixture node${node} did not become ready"
done
if podman exec "$CONTAINER" openssl x509 \
  -in /etc/openbao-haproxy-test/node3.crt \
  -noout \
  -checkhost bao-test-3.internal.invalid >/dev/null 2>&1; then
  fail 'Wrong-identity backend fixture unexpectedly matches node 3 DNS'
fi

run_playbook --check >/dev/null
if podman exec "$CONTAINER" rpm -q haproxy >/dev/null 2>&1; then
  fail 'OpenBao HAProxy check mode installed the package'
fi
if podman exec "$CONTAINER" test -e /etc/haproxy/haproxy.cfg; then
  fail 'OpenBao HAProxy check mode wrote the configuration'
fi

run_playbook >/dev/null
package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' haproxy)"
[[ "$package_identity" == haproxy-0:3.0.5-6.el10_2.1.x86_64 ]] \
  || fail "OpenBao HAProxy package identity mismatch: ${package_identity}"
podman exec "$CONTAINER" /usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg \
  || fail 'HAProxy rejected the staged OpenBao configuration'
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled haproxy.service 2>/dev/null)" != disabled ]]; then
  fail 'OpenBao HAProxy service became enabled during staging'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'OpenBao HAProxy service started during staging'
fi

initial_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]0/24.*port="8200"' <<<"$initial_rules" \
  || fail 'OpenBao HAProxy client firewall policy was not staged'
grep -q '127[.]0[.]0[.]1/32.*port="8404"' <<<"$initial_rules" \
  || fail 'OpenBao HAProxy metrics firewall policy was not staged'

idempotent_output="$(run_playbook)"
grep -qE 'changed=0.*failed=0' <<<"$idempotent_output" \
  || fail 'Second staged OpenBao HAProxy convergence was not idempotent'

run_playbook --extra-vars openbao_haproxy_test_client_source=203.0.113.0/24 >/dev/null
updated_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '203[.]0[.]113[.]0/24.*port="8200"' <<<"$updated_rules" \
  || fail 'Replacement OpenBao HAProxy client firewall policy was not staged'
if grep -q '198[.]51[.]100[.]0/24.*port="8200"' <<<"$updated_rules"; then
  fail 'Stale OpenBao HAProxy client firewall policy remained staged'
fi

config_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/haproxy/haproxy.cfg)"
podman exec "$CONTAINER" cp -a /etc/openbao/tls/ca.crt /tmp/openbao-haproxy-ca.crt
printf '%s\n' 'not a certificate' \
  | podman exec --interactive "$CONTAINER" tee /etc/openbao/tls/ca.crt >/dev/null
if run_playbook \
  --extra-vars openbao_haproxy_test_client_source=203.0.113.0/24 \
  --extra-vars openbao_haproxy_backend_health_host=changed.example.invalid \
  >/dev/null 2>&1; then
  fail 'OpenBao HAProxy accepted a candidate rejected by native validation'
fi
podman exec "$CONTAINER" mv -f /tmp/openbao-haproxy-ca.crt /etc/openbao/tls/ca.crt
config_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/haproxy/haproxy.cfg)"
[[ "$config_hash_before" == "$config_hash_after" ]] \
  || fail 'Rejected OpenBao HAProxy candidate replaced the valid configuration'

podman exec "$CONTAINER" rpmbuild -bb \
  --define '_topdir /tmp/rpmbuild' \
  /workspace/tests/fixtures/openbao-haproxy/haproxy-newer.spec >/dev/null
if run_playbook \
  --extra-vars openbao_haproxy_test_package_nevra=haproxy-0:3.0.99-99.el10.x86_64 \
  >/dev/null 2>&1; then
  fail 'OpenBao HAProxy accepted an unavailable package NEVRA'
fi
package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' haproxy)"
[[ "$package_identity" == haproxy-0:3.0.5-6.el10_2.1.x86_64 ]] \
  || fail 'Unavailable package convergence changed the approved HAProxy package'

if run_playbook \
  --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32 \
  --extra-vars '{"openbao_haproxy_test_active":true}' \
  >/dev/null 2>&1; then
  fail 'OpenBao HAProxy activated while managed firewalld was stopped'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'Stopped-firewall readiness gate left OpenBao HAProxy active'
fi

if run_playbook \
  --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32 \
  --extra-vars '{"openbao_haproxy_test_active":true,"firewalld_dependencies_ready":false,"firewalld_enabled":true}' \
  >/dev/null 2>&1; then
  fail 'OpenBao HAProxy activated without managed firewall dependencies'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'Failed firewall readiness gate left OpenBao HAProxy active'
fi

run_playbook \
  --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32 \
  --extra-vars '{"openbao_haproxy_test_active":true,"firewalld_enabled":true}' >/dev/null
podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service \
  || fail 'Role-driven OpenBao HAProxy activation failed'
podman exec "$CONTAINER" firewall-cmd --state >/dev/null \
  || fail 'OpenBao HAProxy activated without live firewalld enforcement'
live_rules="$(podman exec "$CONTAINER" firewall-cmd --zone=public --list-rich-rules)"
grep -q '127[.]0[.]0[.]1/32.*port="8200"' <<<"$live_rules" \
  || fail 'OpenBao HAProxy client policy is absent from live firewalld state'
grep -q '127[.]0[.]0[.]1/32.*port="8404"' <<<"$live_rules" \
  || fail 'OpenBao HAProxy metrics policy is absent from live firewalld state'

for node in 1 2 3; do
  node_dns="bao-test-${node}.internal.invalid"
  for _ in {1..30}; do
    if podman exec "$CONTAINER" grep -qx "$node_dns" "/tmp/node${node}.sni" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  podman exec "$CONTAINER" grep -qx "$node_dns" "/tmp/node${node}.sni" \
    || fail "HAProxy did not send node-specific check SNI for node${node}"
done

shared_health=""
for _ in {1..30}; do
  shared_health="$(query_shared_health 2>/dev/null || true)"
  if grep -q '"node":"node1"' <<<"$shared_health"; then
    break
  fi
  sleep 1
done
grep -q '"node":"node1"' <<<"$shared_health" \
  || fail 'OpenBao HAProxy did not route to the sole active node'

podman exec "$CONTAINER" firewall-cmd --zone=public \
  --add-rich-rule='rule family="ipv4" source address="127.0.0.5/32" port port="8200" protocol="tcp" accept' \
  >/dev/null
if podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
  --interface 127.0.0.5 \
  --max-time 3 \
  --cacert /etc/openbao/tls/ca.crt \
  --resolve bao.example.invalid:8200:127.0.0.1 \
  -H 'Host: bao.example.invalid' \
  https://bao.example.invalid:8200/v1/sys/health >/dev/null 2>&1; then
  fail 'OpenBao HAProxy client ACL accepted a source permitted by firewalld only'
fi

for inactive_status in 501 503; do
  set_health_status node1 "$inactive_status"
  inactive_response=""
  for _ in {1..10}; do
    sleep 1
    inactive_response="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
      --max-time 3 \
      --cacert /etc/openbao/tls/ca.crt \
      --resolve bao.example.invalid:8200:127.0.0.1 \
      -H 'Host: bao.example.invalid' \
      --write-out $'\n%{http_code}' \
      https://bao.example.invalid:8200/v1/sys/health 2>/dev/null || true)"
    if [[ "${inactive_response##*$'\n'}" == 000 ]] \
      && ! grep -q '"node":"node1"' <<<"$inactive_response"; then
      break
    fi
  done
  [[ "${inactive_response##*$'\n'}" == 000 ]] \
    || fail "OpenBao HAProxy did not mark the ${inactive_status} backend unavailable"
  if grep -q '"node":"node1"' <<<"$inactive_response"; then
    fail "OpenBao HAProxy forwarded the backend ${inactive_status} response"
  fi
  set_health_status node1 200
  for _ in {1..10}; do
    if query_shared_health >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  query_shared_health >/dev/null \
    || fail "OpenBao HAProxy did not restore a backend after ${inactive_status}"
done

main_pid_before="$(podman exec "$CONTAINER" systemctl show --property=MainPID --value haproxy.service)"
podman exec "$CONTAINER" dnf -qy --nogpgcheck install \
  /tmp/rpmbuild/RPMS/x86_64/haproxy-99.0.0-1.x86_64.rpm >/dev/null
newer_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' haproxy)"
[[ "$newer_identity" == haproxy-0:99.0.0-1.x86_64 ]] \
  || fail "Synthetic newer HAProxy package was not installed: ${newer_identity}"
run_playbook \
  --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32 \
  --extra-vars '{"openbao_haproxy_test_active":true,"firewalld_enabled":true}' >/dev/null
package_identity="$(podman exec "$CONTAINER" rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' haproxy)"
[[ "$package_identity" == haproxy-0:3.0.5-6.el10_2.1.x86_64 ]] \
  || fail "OpenBao HAProxy did not downgrade to the approved identity: ${package_identity}"
podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service \
  || fail 'Active package reconciliation did not restore HAProxy service state'
main_pid_after="$(podman exec "$CONTAINER" systemctl show --property=MainPID --value haproxy.service)"
if [[ "$main_pid_after" == "$main_pid_before" || "$main_pid_after" == 0 ]]; then
  fail 'Active package reconciliation did not replace the running HAProxy process'
fi
shared_health="$(query_shared_health)"
grep -q '"node":"node1"' <<<"$shared_health" \
  || fail 'HAProxy package reconciliation lost the active OpenBao backend'

metrics="$(podman exec "$CONTAINER" curl --fail --silent --show-error --noproxy '*' \
  http://127.0.0.1:8404/metrics)"
grep -q '^haproxy_' <<<"$metrics" \
  || fail 'OpenBao HAProxy metrics endpoint returned no HAProxy metrics'
other_path_status="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
  --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8404/)"
[[ "$other_path_status" == 404 ]] \
  || fail "OpenBao HAProxy metrics listener exposed another path: ${other_path_status}"
denied_source_status="$(podman exec "$CONTAINER" curl --silent --show-error --noproxy '*' \
  --interface 127.0.0.2 \
  --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8404/metrics)"
[[ "$denied_source_status" == 403 ]] \
  || fail "OpenBao HAProxy metrics listener accepted a denied source: ${denied_source_status}"

set_health_status node1 429
set_health_status node2 200
for _ in {1..30}; do
  shared_health="$(query_shared_health 2>/dev/null || true)"
  if grep -q '"node":"node2"' <<<"$shared_health"; then
    break
  fi
  sleep 1
done
grep -q '"node":"node2"' <<<"$shared_health" \
  || fail 'OpenBao HAProxy did not switch to the new active node'

set_health_status node2 429
if query_shared_health >/dev/null 2>&1; then
  for _ in {1..10}; do
    sleep 1
    if ! query_shared_health >/dev/null 2>&1; then
      break
    fi
  done
fi
if query_shared_health >/dev/null 2>&1; then
  fail 'OpenBao HAProxy routed traffic while every identity-valid node was standby'
fi

active_output="$(run_playbook \
  --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32 \
  --extra-vars '{"openbao_haproxy_test_active":true,"firewalld_enabled":true}')"
if ! grep -qE 'changed=0.*failed=0' <<<"$active_output"; then
  printf '%s\n' "$active_output" >&2
  fail 'Second active OpenBao HAProxy convergence was not idempotent'
fi

run_playbook --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32 >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'OpenBao HAProxy remained active after staged deactivation'
fi
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled haproxy.service 2>/dev/null)" != disabled ]]; then
  fail 'OpenBao HAProxy remained enabled after staged deactivation'
fi
disabled_output="$(run_playbook \
  --extra-vars openbao_haproxy_test_client_source=127.0.0.1/32)"
grep -qE 'changed=0.*failed=0' <<<"$disabled_output" \
  || fail 'Second disabled OpenBao HAProxy convergence was not idempotent'

printf 'OpenBao HAProxy Rocky integration check passed\n'
