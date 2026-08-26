#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/openbao/integration.yml
ROCKY_IMAGE="${OPENBAO_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-openbao-test-$$"

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
    --env ANSIBLE_COLLECTIONS_PATH=/root/.ansible/collections:/workspace/.ansible/collections \
    --env ANSIBLE_ROLES_PATH=/workspace/roles \
    --workdir /workspace \
    "$CONTAINER" \
    ansible-playbook -i localhost, -c local "$FIXTURE" "$@"
}

podman run \
  --detach \
  --name "$CONTAINER" \
  --systemd=always \
  --privileged \
  --workdir /workspace \
  --volume /lib/modules:/lib/modules:ro \
  --volume "${ROOT_DIR}:/workspace:ro,Z" \
  "$ROCKY_IMAGE" \
  bash -lc 'dnf -qy install systemd && exec /sbin/init' >/dev/null

system_state=starting
for _ in {1..30}; do
  system_state="$(podman exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
  if [[ "$system_state" == running || "$system_state" == degraded ]]; then
    break
  fi
  sleep 1
done

if [[ "$system_state" == degraded ]]; then
  while read -r failed_unit _; do
    case "$failed_unit" in
      sys-kernel-config.mount|sys-kernel-debug.mount|sys-kernel-tracing.mount)
        ;;
      *)
        podman exec "$CONTAINER" systemctl --failed --no-pager >&2 || true
        fail "Disposable Rocky systemd has unexpected failed unit: ${failed_unit}"
        ;;
    esac
  done < <(
    podman exec "$CONTAINER" systemctl --failed --no-legend --plain
  )
elif [[ "$system_state" != running ]]; then
  fail "Disposable Rocky systemd did not become ready: ${system_state}"
fi

podman exec "$CONTAINER" dnf -qy install \
  iproute kmod openssl podman python3-pip util-linux-core >/dev/null
podman exec "$CONTAINER" modprobe --ignore-install overlay >/dev/null
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '[storage]' 'driver = \"vfs\"' 'runroot = \"/run/containers/storage\"' 'graphroot = \"/var/lib/containers/storage\"' > /etc/containers/storage.conf"
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" ansible-galaxy collection install \
  -r /workspace/requirements.yml \
  -p /root/.ansible/collections >/dev/null
podman exec "$CONTAINER" mkdir -p \
  /tmp/openbao-test \
  /var/lib/openbao \
  /var/log/openbao/audit-1 \
  /var/log/openbao/audit-2 \
  /var/lib/openbao-backup-staging
for mount_path in \
  /var/lib/openbao \
  /var/log/openbao/audit-1 \
  /var/log/openbao/audit-2 \
  /var/lib/openbao-backup-staging; do
  podman exec "$CONTAINER" mount \
    -t tmpfs \
    -o size=16m,nosuid,nodev \
    tmpfs \
    "$mount_path"
done
podman exec "$CONTAINER" openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 1 \
  -subj /CN=bao-test-1.internal.invalid \
  -addext subjectAltName=DNS:bao-test-1.internal.invalid,IP:127.0.0.1 \
  -keyout /tmp/openbao-test/tls.key \
  -out /tmp/openbao-test/tls.crt >/dev/null 2>&1
podman exec "$CONTAINER" cp \
  /tmp/openbao-test/tls.crt /tmp/openbao-test/ca.crt
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '127.0.0.1 bao-test-1.internal.invalid' >> /etc/hosts"

check_mode_output=""
if ! check_mode_output="$(run_playbook --check 2>&1)"; then
  printf '%s\n' "$check_mode_output" >&2
  fail 'OpenBao check-mode convergence failed'
fi
for check_mode_artifact in \
  /etc/openbao \
  /usr/local/libexec/platform/openbao-validate-config \
  /etc/containers/systemd/openbao.container \
  /var/lib/platform-config/openbao-firewalld.yml \
  /run/systemd/generator/openbao.service \
  /run/systemd/generator/multi-user.target.wants/openbao.service; do
  if podman exec "$CONTAINER" test -e "$check_mode_artifact"; then
    fail "OpenBao check mode created ${check_mode_artifact}"
  fi
done
staged_output=""
if ! staged_output="$(run_playbook \
  --extra-vars '{"openbao_test_expect_restart_required":false}' 2>&1)"; then
  printf '%s\n' "$staged_output" >&2
  fail 'OpenBao staged convergence failed'
fi

if podman exec "$CONTAINER" test -e \
  /run/systemd/generator/multi-user.target.wants/openbao.service; then
  fail 'OpenBao service became enabled in the staged configuration'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet openbao.service; then
  fail 'OpenBao service started before explicit activation'
fi

idempotent_output="$(run_playbook \
  --extra-vars '{"openbao_test_expect_restart_required":false}')"
if ! grep -qE 'changed=0.*failed=0' <<< "$idempotent_output"; then
  printf '%s\n' "$idempotent_output" >&2
  fail 'Second staged OpenBao role convergence was not idempotent'
fi

initial_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]1/32.*port="18200"' <<< "$initial_rules" \
  || fail 'OpenBao backend source rule was not staged'
grep -q '127[.]0[.]0[.]2/32.*port="8201"' <<< "$initial_rules" \
  || fail 'OpenBao cluster peer rule was not staged'

run_playbook \
  --extra-vars openbao_test_backend_source=198.51.100.2/32 \
  --extra-vars '{"openbao_test_expect_restart_required":false}' >/dev/null
updated_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]2/32.*port="18200"' <<< "$updated_rules" \
  || fail 'Replacement OpenBao backend source rule was not staged'
if grep -q '198[.]51[.]100[.]1/32.*port="18200"' <<< "$updated_rules"; then
  fail 'Obsolete OpenBao backend source rule remained staged'
fi

listener_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/openbao/listener.hcl)"
podman exec "$CONTAINER" cp \
  /etc/openbao/listener.hcl /tmp/openbao-test/invalid-listener.hcl
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'listener \"tcp\" {' >> /tmp/openbao-test/invalid-listener.hcl"
if podman exec "$CONTAINER" \
  /usr/local/libexec/platform/openbao-validate-config \
  listener /tmp/openbao-test/invalid-listener.hcl >/dev/null 2>&1; then
  fail 'OpenBao role validator accepted an invalid listener candidate'
fi
listener_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/openbao/listener.hcl)"
[[ "$listener_hash_before" == "$listener_hash_after" ]] \
  || fail 'Rejected OpenBao listener candidate replaced the active configuration'

base_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/openbao/openbao.hcl)"
podman exec "$CONTAINER" cp \
  /etc/openbao/openbao.hcl /tmp/openbao-test/invalid-openbao.hcl
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'storage \"raft\" {' >> /tmp/openbao-test/invalid-openbao.hcl"
if podman exec "$CONTAINER" \
  /usr/local/libexec/platform/openbao-validate-config \
  base /tmp/openbao-test/invalid-openbao.hcl >/dev/null 2>&1; then
  fail 'OpenBao role validator accepted an invalid base configuration candidate'
fi
base_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/openbao/openbao.hcl)"
[[ "$base_hash_before" == "$base_hash_after" ]] \
  || fail 'Rejected OpenBao base candidate replaced the active configuration'

podman exec "$CONTAINER" umount /var/lib/openbao-backup-staging
if run_playbook >/dev/null 2>&1; then
  fail 'OpenBao role accepted a required path that was not a separate mount'
fi
podman exec "$CONTAINER" mount \
  -t tmpfs \
  -o size=16m,nosuid,nodev \
  tmpfs \
  /var/lib/openbao-backup-staging

podman exec "$CONTAINER" mkdir -p \
  /var/lib/platform-config/pki/openbao \
  /var/lib/platform-config/pki/openbao-pending \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef \
  /usr/local/libexec
podman exec "$CONTAINER" cp \
  /workspace/tests/fixtures/openbao/openbao-custody-helper \
  /usr/local/libexec/platform-pki-host-local-lifecycle
podman exec "$CONTAINER" chmod 0755 \
  /usr/local/libexec/platform-pki-host-local-lifecycle
podman exec "$CONTAINER" cp \
  /tmp/openbao-test/tls.crt \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/tls.crt
podman exec "$CONTAINER" cp \
  /tmp/openbao-test/tls.crt \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/chain.crt
podman exec "$CONTAINER" cp \
  /tmp/openbao-test/tls.crt \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/fullchain.crt
podman exec "$CONTAINER" cp \
  /tmp/openbao-test/tls.key \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/tls.key
podman exec "$CONTAINER" cp \
  /tmp/openbao-test/tls.crt \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/artifact
podman exec "$CONTAINER" chown root:1000 \
  /etc/openbao/tls-versions \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/tls.key
podman exec "$CONTAINER" chmod 0750 \
  /etc/openbao/tls-versions \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef
podman exec "$CONTAINER" chmod 0640 \
  /etc/openbao/tls-versions/0123456789abcdef0123456789abcdef/tls.key
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' \
    'listener \"tcp\" {' \
    '  address = \"127.0.0.1:18200\"' \
    '  cluster_address = \"127.0.0.1:8201\"' \
    '  tls_cert_file = \"/openbao/config/tls-versions/0123456789abcdef0123456789abcdef/fullchain.crt\"' \
    '  tls_key_file = \"/openbao/config/tls-versions/0123456789abcdef0123456789abcdef/tls.key\"' \
    '  tls_min_version = \"tls12\"' \
    '  tls_max_version = \"tls13\"' \
    '  tls_disable_client_certs = true' \
    '  disable_unauthed_rekey_endpoints = true' \
    '  disable_unauthed_generate_root_endpoints = true' \
    '}' > /etc/openbao/listener.hcl"
podman exec "$CONTAINER" chown root:1000 /etc/openbao/listener.hcl
podman exec "$CONTAINER" chmod 0640 /etc/openbao/listener.hcl

podman exec "$CONTAINER" systemctl mask openbao.service >/dev/null
custody_output=""
if ! custody_output="$(run_playbook \
  --extra-vars '{"openbao_test_expect_restart_required":false}' 2>&1)"; then
  printf '%s\n' "$custody_output" >&2
  fail 'OpenBao masked custody resolution failed'
fi
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled openbao.service 2>/dev/null || true)" != masked ]]; then
  fail 'OpenBao custody resolution did not restore the fail-closed staging mask'
fi
podman exec "$CONTAINER" systemctl unmask openbao.service >/dev/null

active_output=""
if ! active_output="$(run_playbook \
  --extra-vars '{"openbao_test_service_started":true,"openbao_test_expect_restart_required":true}' \
  2>&1)"; then
  printf '%s\n' "$active_output" >&2
  podman exec "$CONTAINER" systemctl status openbao.service --no-pager >&2 || true
  podman exec "$CONTAINER" journalctl -u openbao.service --no-pager >&2 || true
  fail 'OpenBao authenticated host-local activation failed'
fi
podman exec "$CONTAINER" test -e \
  /run/systemd/generator/multi-user.target.wants/openbao.service \
  || fail 'OpenBao Quadlet did not gain its explicit activation target'
podman exec "$CONTAINER" systemctl is-active --quiet openbao.service \
  || fail 'OpenBao service did not start after explicit activation'

health_code="$(podman exec "$CONTAINER" curl \
  --cacert /tmp/openbao-test/ca.crt \
  --resolve bao-test-1.internal.invalid:18200:127.0.0.1 \
  --silent \
  --output /tmp/openbao-test/health.json \
  --write-out '%{http_code}' \
  https://bao-test-1.internal.invalid:18200/v1/sys/health)"
[[ "$health_code" == 501 ]] \
  || fail "Uninitialized OpenBao health returned ${health_code}, expected 501"
grep -q '"initialized":false' < <(
  podman exec "$CONTAINER" cat /tmp/openbao-test/health.json
) || fail 'OpenBao disposable node was unexpectedly initialized'

active_idempotent_output="$(run_playbook \
  --extra-vars '{"openbao_test_service_started":true,"openbao_test_expect_restart_required":false}')"
grep -qE 'changed=0.*failed=0' <<< "$active_idempotent_output" \
  || fail 'Second active OpenBao role convergence was not idempotent'

podman exec "$CONTAINER" systemctl mask --now openbao.service >/dev/null
if run_playbook \
  --extra-vars openbao_tls_ca_src=/tmp/openbao-test/absent-ca.crt \
  >/dev/null 2>&1; then
  fail 'OpenBao accepted a failed pre-Quadlet staging attempt'
fi
podman exec "$CONTAINER" systemctl daemon-reload
if podman exec "$CONTAINER" systemctl is-active --quiet openbao.service; then
  fail 'OpenBao restarted after a failed masked staging run'
fi
if [[ "$(podman exec "$CONTAINER" systemctl is-enabled openbao.service 2>/dev/null || true)" != masked ]]; then
  fail 'OpenBao lost its fail-closed mask after a failed staging run'
fi
podman exec "$CONTAINER" systemctl unmask openbao.service >/dev/null

podman exec "$CONTAINER" mkdir -p /etc/systemd/system/multi-user.target.wants
podman exec "$CONTAINER" ln -sfn \
  /run/systemd/generator/openbao.service \
  /etc/systemd/system/multi-user.target.wants/openbao.service
run_playbook \
  --extra-vars '{"openbao_test_expect_restart_required":false}' >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet openbao.service; then
  fail 'OpenBao service remained active after returning to staged state'
fi
if podman exec "$CONTAINER" test -e \
  /etc/systemd/system/multi-user.target.wants/openbao.service; then
  fail 'OpenBao service remained persistently enabled after returning to staged state'
fi
if podman exec "$CONTAINER" test -e \
  /run/systemd/generator/multi-user.target.wants/openbao.service; then
  fail 'OpenBao activation target remained after returning to staged state'
fi
disabled_idempotent_output="$(run_playbook \
  --extra-vars '{"openbao_test_expect_restart_required":false}')"
grep -qE 'changed=0.*failed=0' <<< "$disabled_idempotent_output" \
  || fail 'Second disabled OpenBao role convergence was not idempotent'

printf 'OpenBao HA Rocky integration check passed\n'
