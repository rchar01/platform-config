#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/podman-host/integration.yml
ROCKY_IMAGE="${PODMAN_HOST_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
PODMAN_NEVRA=podman-7:5.8.2-5.el10_2.x86_64
PODMAN_DOWNGRADE_NEVRA=podman-7:5.8.2-4.el10_2.x86_64
CONTAINER="platform-config-podman-host-test-$$"
CONTAINER_CREATED=false
OVERLAY_DENY_PATH=/etc/modprobe.d/99-external-overlay-deny.conf
OVERLAY_LATE_ALLOW_PATH=/etc/modprobe.d/zz-overlay-allow.conf
OVERLAY_UNIT_PATH=/etc/systemd/system/platform-container-runtime-overlayfs-exception.service
OVERLAY_DENY_CONTENT=$'blacklist overlay\ninstall overlay /bin/false'
OVERLAY_UNIT_CONTENT=$'[Unit]\nDescription=Platform container runtime OverlayFS policy exception\nDocumentation=man:modprobe(8)\nDefaultDependencies=no\nConflicts=shutdown.target\nBefore=sysinit.target shutdown.target\n\n[Service]\nType=oneshot\nExecStart=/usr/sbin/modprobe --ignore-install overlay\nRemainAfterExit=yes\n\n[Install]\nWantedBy=sysinit.target'

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

assert_external_deny_preserved() {
  [[ "$(podman exec "$CONTAINER" stat -c '%U:%G:%a' "$OVERLAY_DENY_PATH")" == root:root:600 ]] \
    || fail 'External OverlayFS deny policy metadata changed'
  [[ "$(podman exec "$CONTAINER" cat "$OVERLAY_DENY_PATH")" == "$OVERLAY_DENY_CONTENT" ]] \
    || fail 'External OverlayFS deny policy content changed'
}

assert_enabled_overlay_exception() {
  [[ "$(podman exec "$CONTAINER" stat -c '%U:%G:%a' "$OVERLAY_UNIT_PATH")" == root:root:644 ]] \
    || fail 'Managed OverlayFS exception unit metadata is invalid'
  [[ "$(podman exec "$CONTAINER" cat "$OVERLAY_UNIT_PATH")" == "$OVERLAY_UNIT_CONTENT" ]] \
    || fail 'Managed OverlayFS exception unit content is invalid'
  [[ "$(podman exec "$CONTAINER" systemctl is-enabled platform-container-runtime-overlayfs-exception.service)" == enabled ]] \
    || fail 'Managed OverlayFS exception unit is not enabled'
  podman exec "$CONTAINER" systemctl is-active --quiet platform-container-runtime-overlayfs-exception.service \
    || fail 'Managed OverlayFS exception unit is not active'
  podman exec "$CONTAINER" test -d /sys/module/overlay \
    || fail 'OverlayFS is not loaded'
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

podman exec "$CONTAINER" dnf -qy install kmod python3-pip >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'

podman exec "$CONTAINER" install -d -m 0755 /etc/modprobe.d
podman exec "$CONTAINER" bash -c \
  "umask 077 && printf '%s\n' 'blacklist overlay' 'install overlay /bin/false' > '$OVERLAY_DENY_PATH'"
podman exec "$CONTAINER" bash -c \
  "umask 077 && printf '%s\n' 'install overlay /bin/true' > '$OVERLAY_LATE_ALLOW_PATH'"

normal_overlay_resolution="$(podman exec "$CONTAINER" modprobe --show-depends overlay)"
[[ "$normal_overlay_resolution" =~ ^install[[:space:]]+/bin/false[[:space:]]*$ ]] \
  || fail 'A later modprobe install rule unexpectedly overrode the external deny rule'
ignore_install_resolution="$(podman exec "$CONTAINER" modprobe --show-depends --ignore-install overlay)"
[[ "$ignore_install_resolution" != install* ]] \
  || fail 'modprobe --ignore-install still resolved an install policy command'
podman exec "$CONTAINER" modprobe --ignore-install overlay \
  || fail 'Direct modprobe --ignore-install could not load OverlayFS'
assert_external_deny_preserved
overlay_module_before_check="$(podman exec "$CONTAINER" test -d /sys/module/overlay && printf loaded || printf absent)"

run_playbook --check >/dev/null
if podman exec "$CONTAINER" rpm -q podman >/dev/null 2>&1; then
  fail 'Podman host check mode installed Podman'
fi
if podman exec "$CONTAINER" rpm -q python3-dnf-plugin-versionlock >/dev/null 2>&1; then
  fail 'Podman host check mode installed the versionlock provider'
fi
if podman exec "$CONTAINER" test -e /etc/containers/systemd; then
  fail 'Podman host check mode created the Quadlet directory'
fi
if podman exec "$CONTAINER" test -e "$OVERLAY_UNIT_PATH"; then
  fail 'Podman host check mode created the OverlayFS exception unit'
fi
[[ "$(podman exec "$CONTAINER" test -d /sys/module/overlay && printf loaded || printf absent)" == "$overlay_module_before_check" ]] \
  || fail 'Podman host check mode changed the OverlayFS module state'
assert_external_deny_preserved

if bare_output="$(run_playbook -e podman_host_package_nevra=podman 2>&1)"; then
  fail 'Podman host role accepted a bare package name'
fi
grep -q 'requires one exact x86_64 Podman NEVRA' <<< "$bare_output" \
  || fail 'Podman host role did not explain exact-NEVRA rejection'
if podman exec "$CONTAINER" rpm -q python3-dnf-plugin-versionlock >/dev/null 2>&1; then
  fail 'Rejected Podman input installed the versionlock provider'
fi

podman exec "$CONTAINER" dnf -qy install python3-dnf-plugin-versionlock >/dev/null
podman exec "$CONTAINER" rm -f /etc/dnf/plugins/versionlock.list
podman exec "$CONTAINER" touch /tmp/unsafe-versionlock.list
podman exec "$CONTAINER" ln -s /tmp/unsafe-versionlock.list /etc/dnf/plugins/versionlock.list
if unsafe_symlink_output="$(run_playbook 2>&1)"; then
  fail 'Podman host role accepted a symlink versionlock path'
fi
if ! grep -q 'versionlock list is not a safe regular file' <<< "$unsafe_symlink_output"; then
  printf '%s\n' "$unsafe_symlink_output" >&2
  fail 'Podman host role did not explain symlink versionlock rejection'
fi
podman exec "$CONTAINER" rm /etc/dnf/plugins/versionlock.list
podman exec "$CONTAINER" mkdir /etc/dnf/plugins/versionlock.list
if unsafe_directory_output="$(run_playbook 2>&1)"; then
  fail 'Podman host role accepted a directory versionlock path'
fi
if ! grep -qE 'versionlock list is not a safe regular file|Unable to read version lock configuration' <<< "$unsafe_directory_output"; then
  printf '%s\n' "$unsafe_directory_output" >&2
  fail 'Podman host role did not explain directory versionlock rejection'
fi
if podman exec "$CONTAINER" rpm -q podman >/dev/null 2>&1; then
  fail 'Unsafe versionlock path allowed Podman installation'
fi
podman exec "$CONTAINER" rmdir /etc/dnf/plugins/versionlock.list
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '# retained lock' 'haproxy-0:3.0.6-1.el10.x86_64' '!podman-7:5.8.2-3.el10_2.x86_64' 'podman-7:5.8.2-4.el10_2.x86_64' > /etc/dnf/plugins/versionlock.list"
versionlock_checksum_before_check="$(podman exec "$CONTAINER" sha256sum /etc/dnf/plugins/versionlock.list)"
run_playbook --check >/dev/null
[[ "$(podman exec "$CONTAINER" sha256sum /etc/dnf/plugins/versionlock.list)" == "$versionlock_checksum_before_check" ]] \
  || fail 'Podman host check mode changed the versionlock list'

if ! convergence_output="$(run_playbook 2>&1)"; then
  printf '%s\n' "$convergence_output" >&2
  fail 'Initial Podman host role convergence failed'
fi
podman exec "$CONTAINER" rpm -q kmod >/dev/null \
  || fail 'Container runtime kernel role did not install kmod'
package_identity="$(podman exec "$CONTAINER" \
  rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' podman)"
[[ "$package_identity" == "$PODMAN_NEVRA" ]] \
  || fail "Unexpected Podman package identity: ${package_identity}"
mapfile -t podman_locks < <(
  podman exec "$CONTAINER" dnf -q versionlock list | grep -E '^!?podman(-|$)'
)
[[ "${#podman_locks[@]}" -eq 1 && "${podman_locks[0]}" == "$PODMAN_NEVRA" ]] \
  || fail 'Podman versionlock is not the exact approved NEVRA'
grep -qx '# retained lock' < <(podman exec "$CONTAINER" cat /etc/dnf/plugins/versionlock.list) \
  || fail 'Podman convergence removed an unrelated versionlock comment'
grep -qx 'haproxy-0:3.0.6-1.el10.x86_64' < <(podman exec "$CONTAINER" cat /etc/dnf/plugins/versionlock.list) \
  || fail 'Podman convergence removed an unrelated versionlock'
[[ "$(podman exec "$CONTAINER" stat -c '%U:%G:%a' /etc/containers/systemd)" == root:root:755 ]] \
  || fail 'Podman host role did not create the expected Quadlet directory'
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Podman socket is not disabled'
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Podman socket is active'
fi
assert_enabled_overlay_exception
assert_external_deny_preserved

run_playbook -e "podman_host_package_nevra=$PODMAN_DOWNGRADE_NEVRA" >/dev/null
downgraded_identity="$(podman exec "$CONTAINER" \
  rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' podman)"
[[ "$downgraded_identity" == "$PODMAN_DOWNGRADE_NEVRA" ]] \
  || fail "Podman role did not converge an intentional downgrade: ${downgraded_identity}"
upgrade_preview="$(podman exec "$CONTAINER" dnf -q upgrade --assumeno podman 2>&1 || true)"
if grep -qE '^Upgrading:[[:space:]]*$|[[:space:]]podman[[:space:]]+x86_64[[:space:]]+7:5[.]8[.]2-5' <<< "$upgrade_preview"; then
  printf '%s\n' "$upgrade_preview" >&2
  fail 'Normal DNF upgrade preview bypassed the Podman versionlock'
fi
run_playbook >/dev/null
package_identity="$(podman exec "$CONTAINER" \
  rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' podman)"
[[ "$package_identity" == "$PODMAN_NEVRA" ]] \
  || fail "Podman role did not restore the approved identity: ${package_identity}"

podman exec "$CONTAINER" bash -c "printf '%s\n' '# drift' >> '$OVERLAY_UNIT_PATH'"
podman exec "$CONTAINER" systemctl disable --now \
  platform-container-runtime-overlayfs-exception.service >/dev/null
overlay_unit_drift_checksum="$(podman exec "$CONTAINER" sha256sum "$OVERLAY_UNIT_PATH")"
if ! overlay_drift_check_output="$(run_playbook --check 2>&1)"; then
  printf '%s\n' "$overlay_drift_check_output" >&2
  fail 'Podman host check mode failed while reporting OverlayFS exception drift'
fi
if ! grep -qE 'changed=3.*failed=0' <<< "$overlay_drift_check_output"; then
  printf '%s\n' "$overlay_drift_check_output" >&2
  fail 'Podman host check mode did not report all OverlayFS exception drift'
fi
[[ "$(podman exec "$CONTAINER" sha256sum "$OVERLAY_UNIT_PATH")" == "$overlay_unit_drift_checksum" ]] \
  || fail 'Podman host check mode changed the drifted OverlayFS exception unit'
[[ "$(podman exec "$CONTAINER" systemctl is-enabled platform-container-runtime-overlayfs-exception.service 2>/dev/null)" == disabled ]] \
  || fail 'Podman host check mode enabled the drifted OverlayFS exception unit'
if podman exec "$CONTAINER" systemctl is-active --quiet \
  platform-container-runtime-overlayfs-exception.service; then
  fail 'Podman host check mode started the drifted OverlayFS exception unit'
fi
assert_external_deny_preserved
run_playbook >/dev/null
assert_enabled_overlay_exception
assert_external_deny_preserved

podman exec "$CONTAINER" systemctl enable --now podman.socket >/dev/null
overlay_unit_checksum_before_check="$(podman exec "$CONTAINER" sha256sum "$OVERLAY_UNIT_PATH")"
if ! check_output="$(run_playbook --check 2>&1)"; then
  printf '%s\n' "$check_output" >&2
  fail 'Podman host check mode failed with an active socket'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == enabled ]] \
  || fail 'Podman host check mode disabled the Podman socket'
podman exec "$CONTAINER" systemctl is-active --quiet podman.socket \
  || fail 'Podman host check mode stopped the Podman socket'
[[ "$(podman exec "$CONTAINER" sha256sum "$OVERLAY_UNIT_PATH")" == "$overlay_unit_checksum_before_check" ]] \
  || fail 'Podman host check mode changed the OverlayFS exception unit'
assert_enabled_overlay_exception
assert_external_deny_preserved
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
assert_enabled_overlay_exception
assert_external_deny_preserved

if disabled_denied_output="$(run_playbook -e container_runtime_overlayfs_policy_exception_enabled=false 2>&1)"; then
  printf '%s\n' "$disabled_denied_output" >&2
  fail 'Disabled mode removed the exception despite denied normal module policy'
fi
grep -q 'Normal OverlayFS loading cannot be proven' <<< "$disabled_denied_output" \
  || fail 'Disabled mode did not report the normal-policy denial'
assert_enabled_overlay_exception
assert_external_deny_preserved

printf '%s\n' "Podman host Rocky qualification passed (${package_identity})"
