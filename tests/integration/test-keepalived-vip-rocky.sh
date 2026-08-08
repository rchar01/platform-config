#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/keepalived-vip/integration.yml
ROCKY_IMAGE="${KEEPALIVED_VIP_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-keepalived-test-$$"

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

podman exec "$CONTAINER" dnf -qy install iproute python3-pip >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" ip link add vrrp-test type dummy
podman exec "$CONTAINER" ip address add 192.0.2.10/24 dev vrrp-test
podman exec "$CONTAINER" ip link set vrrp-test up

run_playbook --check >/dev/null
run_playbook >/dev/null

if [[ "$(podman exec "$CONTAINER" systemctl is-enabled keepalived.service 2>/dev/null)" != disabled ]]; then
  fail 'Keepalived service became enabled in the staged configuration'
fi
if podman exec "$CONTAINER" systemctl is-active --quiet keepalived.service; then
  fail 'Keepalived service started and could advertise the fixture VIP'
fi

idempotent_output="$(run_playbook)"
grep -qE 'changed=0.*failed=0' <<< "$idempotent_output" \
  || fail 'Second Keepalived role convergence was not idempotent'

initial_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '192[.]0[.]2[.]12/32' <<< "$initial_rules" \
  || fail 'Initial Keepalived peer rule was not staged'

run_playbook --extra-vars keepalived_vip_test_peer=192.0.2.13 >/dev/null
updated_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '192[.]0[.]2[.]13/32' <<< "$updated_rules" \
  || fail 'Replacement Keepalived peer rule was not staged'
if grep -q '192[.]0[.]2[.]12/32' <<< "$updated_rules"; then
  fail 'Obsolete Keepalived peer rule remained staged'
fi

podman exec "$CONTAINER" ip link add wrong-vrrp type dummy
podman exec "$CONTAINER" ip address add 192.0.2.100/24 dev wrong-vrrp
podman exec "$CONTAINER" ip link set wrong-vrrp up
if run_playbook --extra-vars keepalived_vip_test_peer=192.0.2.13 >/dev/null 2>&1; then
  fail 'Keepalived role accepted a locally owned VIP on the wrong interface'
fi
podman exec "$CONTAINER" ip link delete wrong-vrrp

podman exec "$CONTAINER" ip address add 192.0.2.100/32 dev vrrp-test
if run_playbook \
  --extra-vars keepalived_vip_test_peer=192.0.2.13 \
  --extra-vars keepalived_vip_test_vip=192.0.2.100/3 \
  >/dev/null 2>&1; then
  fail 'Keepalived role accepted a prefix substring instead of the exact owned VIP CIDR'
fi
podman exec "$CONTAINER" ip address delete 192.0.2.100/32 dev vrrp-test

config_hash_before="$(podman exec "$CONTAINER" sha256sum /etc/keepalived/keepalived.conf)"
if run_playbook \
  --extra-vars '{"keepalived_vip_test_priority":149,"keepalived_vip_config_validate_command":"/bin/false %s"}' \
  >/dev/null 2>&1; then
  fail 'Keepalived role accepted a candidate rejected by its native validator'
fi
config_hash_after="$(podman exec "$CONTAINER" sha256sum /etc/keepalived/keepalived.conf)"
[[ "$config_hash_before" == "$config_hash_after" ]] \
  || fail 'Rejected Keepalived candidate replaced the last valid configuration'

if run_playbook \
  --extra-vars keepalived_vip_test_package_nevra=keepalived-0:0-0.el10.x86_64 \
  >/dev/null 2>&1; then
  fail 'Keepalived role accepted an unavailable package NEVRA'
fi

printf 'Keepalived VIP Rocky integration check passed\n'
