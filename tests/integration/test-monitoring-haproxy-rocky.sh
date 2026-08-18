#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/monitoring-haproxy/integration.yml
ROCKY_IMAGE="${MONITORING_HAPROXY_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-monitoring-haproxy-test-$$"

cleanup() {
  if [[ "${MONITORING_HAPROXY_KEEP_CONTAINER:-0}" == 1 ]]; then
    printf 'Retained monitoring HAProxy container: %s\n' "$CONTAINER" >&2
  else
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
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

current_bundle() {
  podman exec "$CONTAINER" readlink /etc/haproxy/monitoring-current
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
  curl firewalld openssl procps-ng python3-pip >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" ansible-galaxy collection install \
  -r /workspace/requirements.yml \
  -p /root/.ansible/collections >/dev/null

podman exec "$CONTAINER" mkdir -p /etc/monitoring-haproxy-test
podman exec "$CONTAINER" bash \
  /workspace/tests/fixtures/monitoring-haproxy/setup-pki.sh

run_playbook --check >/dev/null
if podman exec "$CONTAINER" rpm -q haproxy >/dev/null 2>&1; then
  fail 'Monitoring HAProxy check mode installed HAProxy'
fi
if podman exec "$CONTAINER" rpm -q python3-dnf-plugin-versionlock >/dev/null 2>&1; then
  fail 'Monitoring HAProxy check mode installed the versionlock provider'
fi
if podman exec "$CONTAINER" test -e /etc/haproxy/monitoring-current; then
  fail 'Monitoring HAProxy check mode published a bundle'
fi

podman exec "$CONTAINER" mkdir -p /etc/dnf/plugins
podman exec "$CONTAINER" sh -c \
  "printf '%s\n' '# retained lock' 'podman-7:5.8.2-4.el10_2.x86_64' 'haproxy-tools-0:1.0-1.el10.x86_64' > /etc/dnf/plugins/versionlock.list"
run_playbook >/dev/null

package_identity="$(podman exec "$CONTAINER" rpm -q \
  --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' haproxy)"
[[ "$package_identity" == haproxy-0:3.0.5-6.el10_2.1.x86_64 ]] \
  || fail "Monitoring HAProxy package identity mismatch: ${package_identity}"
[[ "$(podman exec "$CONTAINER" dnf -q versionlock list \
  | grep -Ec '^!?haproxy-[0-9]+:')" -eq 1 ]] \
  || fail 'Monitoring HAProxy versionlock count is invalid'
podman exec "$CONTAINER" dnf -q versionlock list \
  | grep -qx 'haproxy-0:3.0.5-6.el10_2.1.x86_64' \
  || fail 'Monitoring HAProxy versionlock identity is invalid'
podman exec "$CONTAINER" grep -qx '# retained lock' \
  /etc/dnf/plugins/versionlock.list \
  || fail 'Monitoring HAProxy removed an unrelated versionlock entry'
podman exec "$CONTAINER" grep -qx 'haproxy-tools-0:1.0-1.el10.x86_64' \
  /etc/dnf/plugins/versionlock.list \
  || fail 'Monitoring HAProxy removed a same-prefix versionlock entry'

initial_bundle="$(current_bundle)"
[[ "$initial_bundle" =~ ^/etc/haproxy/monitoring-bundles/[0-9a-f]{64}$ ]] \
  || fail "Monitoring HAProxy published an invalid bundle path: ${initial_bundle}"
podman exec "$CONTAINER" test -d "$initial_bundle" \
  || fail 'Monitoring HAProxy current bundle target is absent'
podman exec "$CONTAINER" /usr/sbin/haproxy -c \
  -f /etc/haproxy/monitoring-current/haproxy.cfg \
  || fail 'HAProxy rejected the installed monitoring bundle'
[[ "$(podman exec "$CONTAINER" stat -c '%a' "$initial_bundle/frontend.pem")" == 640 ]] \
  || fail 'Monitoring HAProxy frontend key material has unsafe permissions'
[[ "$(podman exec "$CONTAINER" stat -c '%a' "$initial_bundle/client-ca.crt")" == 644 ]] \
  || fail 'Monitoring HAProxy client CA has unexpected permissions'
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled haproxy.service 2>/dev/null)" != disabled ]]; then
  fail 'Monitoring HAProxy service became enabled during staged convergence'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'Monitoring HAProxy service started during staged convergence'
fi

staged_rules="$(podman exec "$CONTAINER" \
  firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '127[.]0[.]0[.]0/24.*port="443"' <<<"$staged_rules" \
  || fail 'Monitoring HAProxy HTTPS firewall policy was not staged'
grep -q '127[.]0[.]0[.]1/32.*port="18404"' <<<"$staged_rules" \
  || fail 'Monitoring HAProxy metrics firewall policy was not staged'

idempotent_output="$(run_playbook)"
grep -qE 'changed=0.*failed=0' <<<"$idempotent_output" \
  || fail 'Second staged monitoring HAProxy convergence was not idempotent'

check_bundle_before="$(current_bundle)"
check_versionlock_before="$(podman exec "$CONTAINER" sha256sum \
  /etc/dnf/plugins/versionlock.list)"
check_manifest_before="$(podman exec "$CONTAINER" sha256sum \
  /var/lib/platform-config/monitoring-haproxy-firewalld.yml)"
check_rules_before="$(podman exec "$CONTAINER" \
  firewall-offline-cmd --zone=public --list-rich-rules)"
check_bundles_before="$(podman exec "$CONTAINER" sh -c \
  'ls -1 /etc/haproxy/monitoring-bundles | sort')"
check_output="$(run_playbook --check \
  --extra-vars monitoring_haproxy_tenant=check-only-tenant \
  --extra-vars '{"monitoring_haproxy_https_allowed_sources":["127.0.0.1/32"]}' \
  )"
grep -qE 'changed=[1-9][0-9]*.*failed=0' <<<"$check_output" \
  || fail 'Monitoring HAProxy changed-input check mode predicted no change'
[[ "$(current_bundle)" == "$check_bundle_before" ]] \
  || fail 'Monitoring HAProxy changed the current bundle in converged check mode'
[[ "$(podman exec "$CONTAINER" sha256sum \
  /etc/dnf/plugins/versionlock.list)" == "$check_versionlock_before" ]] \
  || fail 'Monitoring HAProxy changed versionlocks in converged check mode'
[[ "$(podman exec "$CONTAINER" sha256sum \
  /var/lib/platform-config/monitoring-haproxy-firewalld.yml)" == "$check_manifest_before" ]] \
  || fail 'Monitoring HAProxy changed its firewall manifest in check mode'
[[ "$(podman exec "$CONTAINER" \
  firewall-offline-cmd --zone=public --list-rich-rules)" == "$check_rules_before" ]] \
  || fail 'Monitoring HAProxy changed firewalld policy in converged check mode'
[[ "$(podman exec "$CONTAINER" sh -c \
  'ls -1 /etc/haproxy/monitoring-bundles | sort')" == "$check_bundles_before" ]] \
  || fail 'Monitoring HAProxy published an orphan bundle in check mode'
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'Monitoring HAProxy check mode started a staged service'
fi

cp_output="$(podman exec "$CONTAINER" cp -a \
  /etc/monitoring-haproxy-test/client-ca/ca.crt \
  /tmp/monitoring-client-ca.crt 2>&1)" \
  || fail "Could not preserve monitoring client CA: ${cp_output}"
printf '%s\n' 'not a certificate' \
  | podman exec --interactive "$CONTAINER" tee \
    /etc/monitoring-haproxy-test/client-ca/ca.crt >/dev/null
if run_playbook --extra-vars monitoring_haproxy_tenant=rejected-tenant \
  >/dev/null 2>&1; then
  fail 'Monitoring HAProxy accepted a bundle with invalid PKI'
fi
podman exec "$CONTAINER" mv -f /tmp/monitoring-client-ca.crt \
  /etc/monitoring-haproxy-test/client-ca/ca.crt
[[ "$(current_bundle)" == "$initial_bundle" ]] \
  || fail 'Rejected monitoring HAProxy bundle changed the current pointer'

if run_playbook \
  --extra-vars '{"monitoring_haproxy_test_active":true}' \
  >/dev/null 2>&1; then
  fail 'Monitoring HAProxy activated while managed firewalld was stopped'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'Stopped-firewall readiness gate left monitoring HAProxy active'
fi

if run_playbook \
  --extra-vars '{"monitoring_haproxy_test_active":true}' \
  --extra-vars monitoring_haproxy_test_firewalld_state=started \
  >/dev/null 2>&1; then
  fail 'Monitoring HAProxy trusted false live-firewall readiness'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service; then
  fail 'False live-firewall readiness left monitoring HAProxy active'
fi

podman exec "$CONTAINER" systemctl enable --now firewalld.service >/dev/null
active_args=(
  --extra-vars '{"monitoring_haproxy_test_active":true}'
  --extra-vars monitoring_haproxy_test_firewalld_state=started
)
run_playbook "${active_args[@]}" >/dev/null
podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service \
  || fail 'Role-driven monitoring HAProxy activation failed'
podman exec "$CONTAINER" firewall-cmd --state >/dev/null \
  || fail 'Monitoring HAProxy activated without live firewalld enforcement'
metrics="$(podman exec "$CONTAINER" curl --fail --silent --show-error \
  --noproxy '*' http://127.0.0.1:18404/metrics)"
grep -q '^haproxy_' <<<"$metrics" \
  || fail 'Monitoring HAProxy metrics endpoint returned no metrics'

run_playbook "${active_args[@]}" \
  --extra-vars monitoring_haproxy_tenant=rotated-tenant >/dev/null
rotated_bundle="$(current_bundle)"
[[ "$rotated_bundle" != "$initial_bundle" ]] \
  || fail 'Monitoring HAProxy contract change did not rotate the bundle'
podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service \
  || fail 'Monitoring HAProxy bundle rotation stopped the service'
podman exec "$CONTAINER" grep -q 'set-header X-Scope-OrgID rotated-tenant' \
  /etc/haproxy/monitoring-current/haproxy.cfg \
  || fail 'Monitoring HAProxy did not activate the rotated contract'

rollback_pid="$(podman exec "$CONTAINER" systemctl show \
  --property=MainPID --value haproxy.service)"
rollback_workers="$(podman exec "$CONTAINER" pgrep -P "$rollback_pid" | sort)"
rollback_maxconn="$(podman exec "$CONTAINER" curl --fail --silent --show-error \
  --noproxy '*' http://127.0.0.1:18404/metrics \
  | grep '^haproxy_process_max_connections ')"
podman exec "$CONTAINER" mkdir -p /etc/systemd/system/haproxy.service.d
printf '%s\n' '[Service]' 'ExecReload=' 'ExecReload=/bin/false' \
  | podman exec --interactive "$CONTAINER" tee \
    /etc/systemd/system/haproxy.service.d/reject-reload.conf >/dev/null
podman exec "$CONTAINER" systemctl daemon-reload
if run_playbook "${active_args[@]}" \
  --extra-vars monitoring_haproxy_tenant=rollback-tenant \
  --extra-vars monitoring_haproxy_maxconn=8192 \
  >/dev/null 2>&1; then
  fail 'Monitoring HAProxy ignored a failed reload'
fi
[[ "$(current_bundle)" == "$rotated_bundle" ]] \
  || fail 'Monitoring HAProxy failed reload did not restore the prior pointer'
podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service \
  || fail 'Monitoring HAProxy failed reload stopped the previous process'
[[ "$(podman exec "$CONTAINER" systemctl show \
  --property=MainPID --value haproxy.service)" == "$rollback_pid" ]] \
  || fail 'Monitoring HAProxy failed reload replaced the prior process'
[[ "$(podman exec "$CONTAINER" pgrep -P "$rollback_pid" | sort)" == "$rollback_workers" ]] \
  || fail 'Monitoring HAProxy failed reload replaced the prior workers'
[[ "$(podman exec "$CONTAINER" curl --fail --silent --show-error \
  --noproxy '*' http://127.0.0.1:18404/metrics \
  | grep '^haproxy_process_max_connections ')" == "$rollback_maxconn" ]] \
  || fail 'Monitoring HAProxy failed reload changed the effective policy'
podman exec "$CONTAINER" rm \
  /etc/systemd/system/haproxy.service.d/reject-reload.conf
podman exec "$CONTAINER" systemctl daemon-reload

run_playbook "${active_args[@]}" \
  --extra-vars monitoring_haproxy_tenant=rollback-tenant >/dev/null
podman exec "$CONTAINER" systemctl is-active --quiet haproxy.service \
  || fail 'Monitoring HAProxy did not recover after reload rollback'

run_playbook "${active_args[@]}" \
  --extra-vars monitoring_haproxy_tenant=rollback-tenant \
  --extra-vars '{"monitoring_haproxy_https_allowed_sources":["127.0.0.1/32"]}' \
  >/dev/null
live_rules="$(podman exec "$CONTAINER" \
  firewall-cmd --zone=public --list-rich-rules)"
grep -q '127[.]0[.]0[.]1/32.*port="443"' <<<"$live_rules" \
  || fail 'Monitoring HAProxy replacement HTTPS firewall policy is absent'
if grep -q '127[.]0[.]0[.]0/24.*port="443"' <<<"$live_rules"; then
  fail 'Monitoring HAProxy stale HTTPS firewall policy remained live'
fi

final_output="$(run_playbook "${active_args[@]}" \
  --extra-vars monitoring_haproxy_tenant=rollback-tenant \
  --extra-vars '{"monitoring_haproxy_https_allowed_sources":["127.0.0.1/32"]}')"
grep -qE 'changed=0.*failed=0' <<<"$final_output" \
  || fail 'Final active monitoring HAProxy convergence was not idempotent'

printf '%s\n' \
  'Monitoring HAProxy Rocky lifecycle, rollback, firewall, and idempotency checks passed.'
