#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/monitoring-etcd-convergence/integration.yml
ROCKY_IMAGE="${MONITORING_ETCD_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
CONTAINER="platform-config-monitoring-etcd-role-test-$$"
DATA_DIR=/srv/monitoring/etcd
CURRENT_LINK=/etc/monitoring/etcd/current
QUADLET=/etc/containers/systemd/monitoring-etcd.container
MANIFEST=/var/lib/platform-config/monitoring-etcd-firewalld.yml
STALE_CANDIDATE=/etc/monitoring/etcd/bundles/.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.candidate

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
    ansible-playbook -i "localhost," -c local "$FIXTURE" "$@"
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
if [[ "$system_state" != running && "$system_state" != degraded ]]; then
  fail "Disposable Rocky systemd did not become ready: ${system_state}"
fi

podman exec "$CONTAINER" dnf -qy install \
  firewalld iproute openssl podman-7:5.8.2-5.el10_2.x86_64 \
  python3-pip python3-firewall util-linux-core >/dev/null
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '[storage]' 'driver = \"vfs\"' 'runroot = \"/run/containers/storage\"' 'graphroot = \"/var/lib/containers/storage\"' > /etc/containers/storage.conf"
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" ansible-galaxy collection install \
  -r /workspace/requirements.yml \
  -p /root/.ansible/collections >/dev/null

podman exec "$CONTAINER" mkdir -p /tmp/monitoring-etcd-test "$DATA_DIR"
podman exec "$CONTAINER" mount \
  -t tmpfs -o size=16m,nosuid,nodev tmpfs "$DATA_DIR"
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' preserved-before-convergence > '${DATA_DIR}/sentinel'"
podman exec "$CONTAINER" openssl req \
  -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=monitoring-etcd-test-ca \
  -addext basicConstraints=critical,CA:TRUE \
  -keyout /tmp/monitoring-etcd-test/ca.key \
  -out /tmp/monitoring-etcd-test/ca.crt >/dev/null 2>&1
podman exec "$CONTAINER" openssl req \
  -newkey rsa:2048 -nodes \
  -subj /CN=etcd-test-1.internal.invalid \
  -addext subjectAltName=DNS:etcd-test-1.internal.invalid,IP:127.0.0.1 \
  -keyout /tmp/monitoring-etcd-test/tls.key \
  -out /tmp/monitoring-etcd-test/tls.csr >/dev/null 2>&1
podman exec "$CONTAINER" openssl x509 -req -days 1 \
  -in /tmp/monitoring-etcd-test/tls.csr \
  -CA /tmp/monitoring-etcd-test/ca.crt \
  -CAkey /tmp/monitoring-etcd-test/ca.key \
  -CAcreateserial -copy_extensions copyall \
  -out /tmp/monitoring-etcd-test/tls.crt >/dev/null 2>&1

check_output=""
if ! check_output="$(run_playbook --check 2>&1)"; then
  printf '%s\n' "$check_output" >&2
  fail 'Initial monitoring etcd check-mode convergence failed'
fi
for artifact in /etc/monitoring/etcd /usr/local/libexec/platform/monitoring-etcd-validate-config "$QUADLET" "$MANIFEST"; do
  if podman exec "$CONTAINER" test -e "$artifact"; then
    fail "Monitoring etcd check mode created ${artifact}"
  fi
done

podman exec "$CONTAINER" mkdir -p "${STALE_CANDIDATE}/pki"
podman exec "$CONTAINER" chown -R 0:10001 /etc/monitoring/etcd
podman exec "$CONTAINER" chmod 0750 \
  /etc/monitoring/etcd /etc/monitoring/etcd/bundles \
  "$STALE_CANDIDATE" "${STALE_CANDIDATE}/pki"
podman exec "$CONTAINER" bash -c \
  "umask 027 && printf '%s\n' retired-private-key > '${STALE_CANDIDATE}/pki/tls.key'"

convergence_output=""
if ! convergence_output="$(run_playbook 2>&1)"; then
  printf '%s\n' "$convergence_output" >&2
  fail 'Initial monitoring etcd convergence failed'
fi
podman exec "$CONTAINER" test ! -e "$STALE_CANDIDATE" \
  || fail 'Monitoring etcd retained an interrupted candidate private key'
podman exec "$CONTAINER" test "$(podman exec "$CONTAINER" cat "${DATA_DIR}/sentinel")" = preserved-before-convergence
[[ "$(podman exec "$CONTAINER" find "$DATA_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n')" == sentinel ]] \
  || fail 'Monitoring etcd convergence initialized or altered the data mount'
current_target="$(podman exec "$CONTAINER" readlink -f "$CURRENT_LINK")"
[[ "$current_target" =~ ^/etc/monitoring/etcd/bundles/[0-9a-f]{64}$ ]] \
  || fail "Monitoring etcd current pointer is invalid: ${current_target}"
podman exec "$CONTAINER" test -f "${CURRENT_LINK}/bundle-contract.json"
podman exec "$CONTAINER" test -f "${CURRENT_LINK}/etcd.yml"
[[ "$(podman exec "$CONTAINER" stat -c '%a' "${CURRENT_LINK}/pki/tls.key")" == 640 ]] \
  || fail 'Monitoring etcd private key mode is not 0640'
podman exec "$CONTAINER" systemctl cat monitoring-etcd.service >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet monitoring-etcd.service; then
  fail 'Monitoring etcd service started during inactive convergence'
fi
if podman exec "$CONTAINER" test -e /etc/systemd/system/multi-user.target.wants/monitoring-etcd.service; then
  fail 'Monitoring etcd service became persistently enabled'
fi
enablement_state="$(podman exec "$CONTAINER" systemctl is-enabled monitoring-etcd.service 2>/dev/null || true)"
[[ "$enablement_state" == generated || "$enablement_state" == static ]] \
  || fail "Monitoring etcd service has unexpected enablement state: ${enablement_state}"
podman exec "$CONTAINER" test -f "$MANIFEST"
initial_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]10/32.*port="2379"' <<< "$initial_rules" \
  || fail 'Monitoring etcd additional client source rule is absent'
grep -q '127[.]0[.]0[.]2/32.*port="2380"' <<< "$initial_rules" \
  || fail 'Monitoring etcd peer source rule is absent'

podman exec "$CONTAINER" mkdir -p /etc/systemd/system/multi-user.target.wants
podman exec "$CONTAINER" ln -s \
  /run/systemd/generator/monitoring-etcd.service \
  /etc/systemd/system/multi-user.target.wants/monitoring-etcd.service
run_playbook >/dev/null
if podman exec "$CONTAINER" test -e /etc/systemd/system/multi-user.target.wants/monitoring-etcd.service; then
  fail 'Monitoring etcd convergence retained seeded persistent enablement'
fi

idempotent_output="$(run_playbook)"
grep -qE 'changed=0.*failed=0' <<< "$idempotent_output" \
  || fail "Monitoring etcd second convergence was not idempotent: ${idempotent_output}"

check_pointer="$(podman exec "$CONTAINER" readlink "$CURRENT_LINK")"
check_manifest="$(podman exec "$CONTAINER" sha256sum "$MANIFEST")"
check_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
existing_check_output=""
if ! existing_check_output="$(run_playbook --check \
  --extra-vars monitoring_etcd_test_client_source=198.51.100.11/32 2>&1)"; then
  printf '%s\n' "$existing_check_output" >&2
  fail 'Existing monitoring etcd check-mode convergence failed'
fi
[[ "$(podman exec "$CONTAINER" readlink "$CURRENT_LINK")" == "$check_pointer" ]] \
  || fail 'Monitoring etcd changed its bundle pointer in check mode'
[[ "$(podman exec "$CONTAINER" sha256sum "$MANIFEST")" == "$check_manifest" ]] \
  || fail 'Monitoring etcd changed its firewall manifest in check mode'
[[ "$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)" == "$check_rules" ]] \
  || fail 'Monitoring etcd changed firewall policy in check mode'

run_playbook \
  --extra-vars monitoring_etcd_test_client_source=198.51.100.11/32 >/dev/null
updated_rules="$(podman exec "$CONTAINER" firewall-offline-cmd --zone=public --list-rich-rules)"
grep -q '198[.]51[.]100[.]11/32.*port="2379"' <<< "$updated_rules" \
  || fail 'Monitoring etcd replacement client source rule is absent'
if grep -q '198[.]51[.]100[.]10/32.*port="2379"' <<< "$updated_rules"; then
  fail 'Monitoring etcd stale client source rule remained enabled'
fi

old_bundle="$(podman exec "$CONTAINER" readlink "$CURRENT_LINK")"
podman exec "$CONTAINER" openssl x509 -req -days 1 -set_serial 2 \
  -in /tmp/monitoring-etcd-test/tls.csr \
  -CA /tmp/monitoring-etcd-test/ca.crt \
  -CAkey /tmp/monitoring-etcd-test/ca.key \
  -copy_extensions copyall \
  -out /tmp/monitoring-etcd-test/tls.crt >/dev/null 2>&1
run_playbook \
  --extra-vars monitoring_etcd_test_client_source=198.51.100.11/32 >/dev/null
new_bundle="$(podman exec "$CONTAINER" readlink "$CURRENT_LINK")"
[[ "$new_bundle" != "$old_bundle" ]] \
  || fail 'Monitoring etcd valid certificate rotation did not switch bundles'
podman exec "$CONTAINER" test ! -e "$old_bundle" \
  || fail 'Monitoring etcd retained an obsolete private-key bundle'
podman exec "$CONTAINER" bash -c \
  'shopt -s nullglob; bundles=(/etc/monitoring/etcd/bundles/*); ((${#bundles[@]} == 1))' \
  || fail 'Monitoring etcd retained an unexpected number of immutable bundles'

pointer_before="$(podman exec "$CONTAINER" readlink "$CURRENT_LINK")"
podman exec "$CONTAINER" cp \
  /tmp/monitoring-etcd-test/tls.crt /tmp/monitoring-etcd-test/tls.crt.valid
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' invalid-certificate > /tmp/monitoring-etcd-test/tls.crt"
if run_playbook >/dev/null 2>&1; then
  fail 'Monitoring etcd accepted an invalid candidate certificate'
fi
[[ "$(podman exec "$CONTAINER" readlink "$CURRENT_LINK")" == "$pointer_before" ]] \
  || fail 'Rejected monitoring etcd candidate changed the current pointer'
podman exec "$CONTAINER" mv \
  /tmp/monitoring-etcd-test/tls.crt.valid /tmp/monitoring-etcd-test/tls.crt

podman exec "$CONTAINER" cp "${CURRENT_LINK}/etcd.yml" /tmp/monitoring-etcd-test/etcd.yml.valid
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '# corruption' >> '${CURRENT_LINK}/etcd.yml'"
if run_playbook >/dev/null 2>&1; then
  fail 'Monitoring etcd accepted corrupted immutable configuration'
fi
podman exec "$CONTAINER" mv \
  /tmp/monitoring-etcd-test/etcd.yml.valid "${CURRENT_LINK}/etcd.yml"

podman exec "$CONTAINER" chmod 0770 "$new_bundle"
if run_playbook >/dev/null 2>&1; then
  fail 'Monitoring etcd accepted a group-writable immutable bundle'
fi
podman exec "$CONTAINER" chmod 0750 "$new_bundle"

podman exec "$CONTAINER" cp "$MANIFEST" /tmp/monitoring-etcd-test/firewalld.yml.valid
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'zone: public' 'rich_rules:' '  - rule family=\"ipv4\" source address=\"192.0.2.1/32\" port port=\"22\" protocol=\"tcp\" accept' > '${MANIFEST}'"
if run_playbook >/dev/null 2>&1; then
  fail 'Monitoring etcd accepted an out-of-grammar previous firewall rule'
fi
podman exec "$CONTAINER" mv \
  /tmp/monitoring-etcd-test/firewalld.yml.valid "$MANIFEST"

podman exec "$CONTAINER" umount "$DATA_DIR"
if run_playbook >/dev/null 2>&1; then
  fail 'Monitoring etcd accepted a data path that was not a separate mount'
fi

printf 'Monitoring etcd inactive Rocky convergence check passed\n'
