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
    --env ANSIBLE_COLLECTIONS_PATH=/workspace/.ansible/collections \
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
  iproute openssl podman python3-pip util-linux-core >/dev/null
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '[storage]' 'driver = \"vfs\"' 'runroot = \"/run/containers/storage\"' 'graphroot = \"/var/lib/containers/storage\"' > /etc/containers/storage.conf"
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
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

run_playbook --check >/dev/null
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
run_playbook >/dev/null

if podman exec "$CONTAINER" test -e \
  /run/systemd/generator/multi-user.target.wants/openbao.service; then
  fail 'OpenBao service became enabled in the staged configuration'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet openbao.service; then
  fail 'OpenBao service started before explicit activation'
fi

idempotent_output="$(run_playbook)"
grep -qE 'changed=0.*failed=0' <<< "$idempotent_output" \
  || fail 'Second staged OpenBao role convergence was not idempotent'

initial_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]1/32.*port="18200"' <<< "$initial_rules" \
  || fail 'OpenBao backend source rule was not staged'
grep -q '127[.]0[.]0[.]2/32.*port="8201"' <<< "$initial_rules" \
  || fail 'OpenBao cluster peer rule was not staged'

run_playbook --extra-vars openbao_test_backend_source=198.51.100.2/32 >/dev/null
updated_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]2/32.*port="18200"' <<< "$updated_rules" \
  || fail 'Replacement OpenBao backend source rule was not staged'
if grep -q '198[.]51[.]100[.]1/32.*port="18200"' <<< "$updated_rules"; then
  fail 'Obsolete OpenBao backend source rule remained staged'
fi

config_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/openbao/openbao.hcl)"
if run_playbook \
  --extra-vars openbao_log_level=debug \
  --extra-vars 'openbao_config_validate_command=/bin/false %s' \
  >/dev/null 2>&1; then
  fail 'OpenBao role accepted a candidate rejected by its validator'
fi
config_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/openbao/openbao.hcl)"
[[ "$config_hash_before" == "$config_hash_after" ]] \
  || fail 'Rejected OpenBao candidate replaced the last valid configuration'

podman exec "$CONTAINER" umount /var/lib/openbao-backup-staging
if run_playbook >/dev/null 2>&1; then
  fail 'OpenBao role accepted a required path that was not a separate mount'
fi
podman exec "$CONTAINER" mount \
  -t tmpfs \
  -o size=16m,nosuid,nodev \
  tmpfs \
  /var/lib/openbao-backup-staging

run_playbook --extra-vars '{"openbao_test_service_started":true}' >/dev/null
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

active_idempotent_output="$(run_playbook --extra-vars '{"openbao_test_service_started":true}')"
grep -qE 'changed=0.*failed=0' <<< "$active_idempotent_output" \
  || fail 'Second active OpenBao role convergence was not idempotent'

run_playbook >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet openbao.service; then
  fail 'OpenBao service remained active after returning to staged state'
fi
if podman exec "$CONTAINER" test -e \
  /run/systemd/generator/multi-user.target.wants/openbao.service; then
  fail 'OpenBao activation target remained after returning to staged state'
fi
disabled_idempotent_output="$(run_playbook)"
grep -qE 'changed=0.*failed=0' <<< "$disabled_idempotent_output" \
  || fail 'Second disabled OpenBao role convergence was not idempotent'

printf 'OpenBao HA Rocky integration check passed\n'
