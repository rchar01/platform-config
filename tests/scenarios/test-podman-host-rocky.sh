#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/podman-host/integration.yml
ROCKY_IMAGE="${PODMAN_HOST_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
PODMAN_NEVRA=podman-7:5.8.2-5.el10_2.x86_64
CONTAINER="platform-config-podman-host-test-$$"
CONTAINER_CREATED=false

cleanup() {
  if [[ "$CONTAINER_CREATED" == true ]]; then
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
CONTAINER_CREATED=true

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

podman exec "$CONTAINER" dnf -qy install python3-pip >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'

run_playbook --check >/dev/null
if podman exec "$CONTAINER" rpm -q podman >/dev/null 2>&1; then
  fail 'Podman host check mode installed Podman'
fi
if podman exec "$CONTAINER" test -e /etc/containers/systemd; then
  fail 'Podman host check mode created the Quadlet directory'
fi

run_playbook >/dev/null
package_identity="$(podman exec "$CONTAINER" \
  rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' podman)"
[[ "$package_identity" == "$PODMAN_NEVRA" ]] \
  || fail "Unexpected Podman package identity: ${package_identity}"
[[ "$(podman exec "$CONTAINER" stat -c '%U:%G:%a' /etc/containers/systemd)" == root:root:755 ]] \
  || fail 'Podman host role did not create the expected Quadlet directory'
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Podman socket is not disabled'
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Podman socket is active'
fi

podman exec "$CONTAINER" systemctl enable --now podman.socket >/dev/null
if ! check_output="$(run_playbook --check 2>&1)"; then
  printf '%s\n' "$check_output" >&2
  fail 'Podman host check mode failed with an active socket'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == enabled ]] \
  || fail 'Podman host check mode disabled the Podman socket'
podman exec "$CONTAINER" systemctl is-active --quiet podman.socket \
  || fail 'Podman host check mode stopped the Podman socket'
run_playbook >/dev/null
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Podman socket was not disabled after convergence'
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Podman socket remained active after convergence'
fi

podman exec "$CONTAINER" bash -c "cat > /etc/containers/systemd/qualification.container <<'EOF'
[Unit]
Description=Podman host qualification

[Container]
Image=localhost/qualification:latest
Exec=/bin/true

[Install]
WantedBy=multi-user.target
EOF"
podman exec "$CONTAINER" systemctl daemon-reload
podman exec "$CONTAINER" systemctl cat qualification.service >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet qualification.service; then
  fail 'Quadlet qualification service started unexpectedly'
fi

if ! idempotent_output="$(run_playbook 2>&1)"; then
  printf '%s\n' "$idempotent_output" >&2
  fail 'Second Podman host role convergence failed'
fi
if ! grep -qE 'changed=0.*failed=0' <<< "$idempotent_output"; then
  printf '%s\n' "$idempotent_output" >&2
  fail 'Second Podman host role convergence was not idempotent'
fi

printf '%s\n' "Podman host Rocky qualification passed (${package_identity})"
