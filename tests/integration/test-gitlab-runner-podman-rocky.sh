#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/gitlab-runner/integration.yml
ROCKY_IMAGE="${GITLAB_RUNNER_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
RUNNER_IMAGE=docker.io/gitlab/gitlab-runner:alpine-v18.11.3@sha256:904cc94dc8417152685f62c4c1a1add19ad2d82947ca7aead844895e16128f1e
CONTAINER="platform-config-gitlab-runner-test-$$"
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
  --security-opt label=disable \
  --workdir /workspace \
  --volume "${ROOT_DIR}:/workspace:ro" \
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
if [[ "$system_state" != running && "$system_state" != degraded ]]; then
  fail "Disposable Rocky systemd did not become ready: ${system_state}"
fi

podman exec "$CONTAINER" dnf -qy install kmod python3-pip >/dev/null
podman exec "$CONTAINER" python3 -m pip -q install \
  --root-user-action=ignore \
  'ansible-core>=2.20,<2.21'
podman exec "$CONTAINER" install -d -m 0755 /etc/modprobe.d
podman exec "$CONTAINER" bash -c \
  "umask 077 && printf '%s\n' 'blacklist overlay' 'install overlay /bin/false' > /etc/modprobe.d/99-external-overlay-deny.conf"
podman exec "$CONTAINER" install -d -m 0755 /etc/containers
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' '[storage]' 'driver = \"vfs\"' 'runroot = \"/run/containers/storage\"' 'graphroot = \"/var/lib/containers/storage\"' > /etc/containers/storage.conf"
podman exec "$CONTAINER" install -d -m 0750 /etc/gitlab-runner
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'glrt-disposable-invalid' > /tmp/gitlab-runner-test.token && chmod 0600 /tmp/gitlab-runner-test.token"
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'concurrent = 1' '[[runners]]' '  name = \"disposable-docker-runner\"' '  url = \"https://127.0.0.1:1\"' '  token = \"glrt-disposable-invalid\"' '  executor = \"docker\"' '  [runners.feature_flags]' '    FF_NETWORK_PER_BUILD = true' '  [runners.docker]' '    host = \"unix:///run/podman/podman.sock\"' '    image = \"docker.io/library/alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1\"' '    privileged = false' '    services_privileged = false' '    pull_policy = \"always\"' '    volumes = [\"/cache\"]' > /etc/gitlab-runner/config.toml && chmod 0600 /etc/gitlab-runner/config.toml"

run_playbook --check >/dev/null
if podman exec "$CONTAINER" rpm -q podman >/dev/null 2>&1; then
  fail 'GitLab Runner check mode installed Podman'
fi
if podman exec "$CONTAINER" test -e /etc/containers/systemd/gitlab-runner.container; then
  fail 'GitLab Runner check mode wrote its Quadlet'
fi

if ! convergence_output="$(run_playbook 2>&1)"; then
  printf '%s\n' "$convergence_output" >&2
  fail 'Initial GitLab Runner role convergence failed'
fi
podman exec "$CONTAINER" systemctl is-active --quiet podman.socket \
  || fail 'Role-managed rootful Podman socket is not active'
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == enabled ]] \
  || fail 'Role-managed rootful Podman socket is not enabled'
podman exec "$CONTAINER" test -S /run/podman/podman.sock \
  || fail 'Role-managed rootful Podman socket is missing'
podman exec "$CONTAINER" systemctl is-active --quiet gitlab-runner.service \
  || fail 'GitLab Runner manager Quadlet is not active'

quadlet="$(podman exec "$CONTAINER" python3 -c 'from pathlib import Path; print(Path("/etc/containers/systemd/gitlab-runner.container").read_text(), end="")')"
grep -q '^Volume=/run/podman/podman.sock:/run/podman/podman.sock$' <<< "$quadlet" \
  || fail 'Manager Quadlet does not contain the exact Podman socket mount'
grep -q '^SecurityLabelDisable=true$' <<< "$quadlet" \
  || fail 'Manager Quadlet does not disable its SELinux label for API access'

mounts="$(podman exec "$CONTAINER" podman inspect gitlab-runner --format '{{range .Mounts}}{{println .Source .Destination}}{{end}}')"
grep -q '^/run/podman/podman.sock /run/podman/podman.sock$' <<< "$mounts" \
  || fail 'Manager container does not have the role-managed Podman socket mount'
podman exec "$CONTAINER" podman exec gitlab-runner test -S /run/podman/podman.sock \
  || fail 'Manager container cannot access the role-managed Podman socket'

quadlet_checksum="$(podman exec "$CONTAINER" sha256sum /etc/containers/systemd/gitlab-runner.container)"
if late_output="$(run_playbook \
  --extra-vars '{"gitlab_runner_quadlet_restart_policy":"on-failure","gitlab_runner_service_state":"invalid"}' 2>&1)"; then
  fail 'Late GitLab Runner service failure unexpectedly converged'
fi
if ! grep -q 'Transactional rollback was attempted' <<< "$late_output"; then
  printf '%s\n' "$late_output" >&2
  fail 'Late GitLab Runner service failure did not run outer restoration'
fi
[[ "$(podman exec "$CONTAINER" sha256sum /etc/containers/systemd/gitlab-runner.container)" == "$quadlet_checksum" ]] \
  || fail 'Late GitLab Runner service failure did not restore the exact Quadlet'
podman exec "$CONTAINER" systemctl is-active --quiet podman.socket \
  || fail 'Late GitLab Runner service failure changed the Podman socket'
podman exec "$CONTAINER" systemctl is-active --quiet gitlab-runner.service \
  || fail 'Late GitLab Runner service failure stopped the manager'

config_checksum="$(podman exec "$CONTAINER" sha256sum /etc/gitlab-runner/config.toml)"
if inverse_output="$(run_playbook \
  --extra-vars '{"gitlab_runner_test_docker_enabled":false,"gitlab_runner_force_register":true}' 2>&1)"; then
  fail 'Forced Docker-to-shell migration unexpectedly succeeded against the invalid endpoint'
fi
grep -q 'Automatic rollback was attempted' <<< "$inverse_output" \
  || fail 'Failed forced Docker-to-shell migration did not restore the runner'
[[ "$(podman exec "$CONTAINER" sha256sum /etc/gitlab-runner/config.toml)" == "$config_checksum" ]] \
  || fail 'Failed forced Docker-to-shell migration did not restore Docker config'
podman exec "$CONTAINER" systemctl is-active --quiet podman.socket \
  || fail 'Failed forced Docker-to-shell migration did not reactivate the Podman socket'
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == enabled ]] \
  || fail 'Failed forced Docker-to-shell migration did not re-enable the Podman socket'
podman exec "$CONTAINER" systemctl is-active --quiet gitlab-runner.service \
  || fail 'Failed forced Docker-to-shell migration did not restart the Docker manager'
podman exec "$CONTAINER" podman exec gitlab-runner test -S /run/podman/podman.sock \
  || fail 'Restored Docker manager cannot access the restored Podman socket'
if inverse_backups="$(podman exec "$CONTAINER" bash -c 'compgen -G "/etc/gitlab-runner/.config.toml.ansible-*" || true')" && [[ -n "$inverse_backups" ]]; then
  printf '%s\n' "$inverse_output" "$inverse_backups" >&2
  fail 'Failed forced Docker-to-shell migration retained a temporary backup'
fi

if force_output="$(run_playbook \
  --extra-vars '{"gitlab_runner_force_register":true}' 2>&1)"; then
  fail 'Forced registration unexpectedly succeeded against the invalid endpoint'
fi
if ! grep -q 'Automatic rollback was attempted' <<< "$force_output"; then
  printf '%s\n' "$force_output" >&2
  fail 'Failed forced registration did not report restoration'
fi
[[ "$(podman exec "$CONTAINER" sha256sum /etc/gitlab-runner/config.toml)" == "$config_checksum" ]] \
  || fail 'Failed forced registration did not restore the exact configuration'
podman exec "$CONTAINER" systemctl is-active --quiet gitlab-runner.service \
  || fail 'Failed forced registration did not restart the previous manager'
if force_backups="$(podman exec "$CONTAINER" bash -c 'compgen -G "/etc/gitlab-runner/.config.toml.ansible-*" || true')" && [[ -n "$force_backups" ]]; then
  printf '%s\n' "$force_output" "$force_backups" >&2
  fail 'Failed forced registration retained a temporary configuration backup'
fi

podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'not valid toml = [' > /etc/gitlab-runner/config.toml && chmod 0600 /etc/gitlab-runner/config.toml"
malformed_checksum="$(podman exec "$CONTAINER" sha256sum /etc/gitlab-runner/config.toml)"
if malformed_output="$(run_playbook \
  --extra-vars '{"gitlab_runner_force_register":true}' 2>&1)"; then
  fail 'Forced registration with malformed existing TOML unexpectedly succeeded'
fi
if ! grep -q 'Automatic rollback was attempted' <<< "$malformed_output"; then
  printf '%s\n' "$malformed_output" >&2
  fail 'Force mode parsed malformed TOML before creating a recovery backup'
fi
[[ "$(podman exec "$CONTAINER" sha256sum /etc/gitlab-runner/config.toml)" == "$malformed_checksum" ]] \
  || fail 'Failed force migration did not restore malformed original TOML'
podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'concurrent = 1' '[[runners]]' '  name = \"disposable-docker-runner\"' '  url = \"https://127.0.0.1:1\"' '  token = \"glrt-disposable-invalid\"' '  executor = \"docker\"' '  [runners.feature_flags]' '    FF_NETWORK_PER_BUILD = true' '  [runners.docker]' '    host = \"unix:///run/podman/podman.sock\"' '    image = \"docker.io/library/alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1\"' '    privileged = false' '    services_privileged = false' '    pull_policy = \"always\"' '    volumes = [\"/cache\"]' > /etc/gitlab-runner/config.toml && chmod 0600 /etc/gitlab-runner/config.toml"

podman exec "$CONTAINER" python3 -c \
  'from pathlib import Path; path = Path("/etc/gitlab-runner/config.toml"); path.write_text(path.read_text().replace("privileged = false", "privileged = true"))'
if unsafe_output="$(run_playbook 2>&1)"; then
  fail 'GitLab Runner accepted an unsafe persisted Docker contract'
fi
grep -q 'does not contain the one declared executor contract' <<< "$unsafe_output" \
  || fail 'Unsafe persisted Docker contract did not fail closed'
podman exec "$CONTAINER" python3 -c \
  'from pathlib import Path; path = Path("/etc/gitlab-runner/config.toml"); path.write_text(path.read_text().replace("privileged = true", "privileged = false"))'

if opt_out_output="$(run_playbook --check \
  --extra-vars '{"gitlab_runner_test_docker_enabled":false}' 2>&1)"; then
  fail 'GitLab Runner accepted socket opt-out with a persisted Docker registration'
fi
grep -q 'does not contain the one declared executor contract' <<< "$opt_out_output" \
  || fail 'Socket opt-out with a Docker registration did not fail closed'
podman exec "$CONTAINER" systemctl is-active --quiet podman.socket \
  || fail 'Failed socket opt-out preflight stopped the active Podman socket'
podman exec "$CONTAINER" podman exec gitlab-runner test -S /run/podman/podman.sock \
  || fail 'Failed socket opt-out preflight changed the manager mount'

podman exec "$CONTAINER" bash -c \
  "printf '%s\n' 'concurrent = 1' '[[runners]]' '  name = \"disposable-docker-runner\"' '  url = \"https://127.0.0.1:1\"' '  token = \"glrt-disposable-invalid\"' '  executor = \"shell\"' > /etc/gitlab-runner/config.toml && chmod 0600 /etc/gitlab-runner/config.toml"

run_playbook --extra-vars '{"gitlab_runner_test_docker_enabled":false}' >/dev/null
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Podman socket remained active after opt-out'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Podman socket remained enabled after opt-out'
opted_out_quadlet="$(podman exec "$CONTAINER" python3 -c 'from pathlib import Path; print(Path("/etc/containers/systemd/gitlab-runner.container").read_text(), end="")')"
if grep -q 'podman.sock\|SecurityLabelDisable' <<< "$opted_out_quadlet"; then
  fail 'GitLab Runner manager Quadlet retained socket access after opt-out'
fi
opted_out_mounts="$(podman exec "$CONTAINER" podman inspect gitlab-runner --format '{{range .Mounts}}{{println .Source .Destination}}{{end}}')"
if grep -q 'podman.sock' <<< "$opted_out_mounts"; then
  fail 'GitLab Runner manager retained its Podman socket mount after opt-out'
fi
grep -q 'executor = "shell"' < <(podman exec "$CONTAINER" python3 -c 'from pathlib import Path; print(Path("/etc/gitlab-runner/config.toml").read_text(), end="")') \
  || fail 'Socket opt-out did not retain the migrated shell registration'

idempotent_output="$(run_playbook \
  --extra-vars '{"gitlab_runner_test_docker_enabled":false}')"
grep -qE 'changed=0.*failed=0' <<< "$idempotent_output" \
  || fail 'Second socket-free GitLab Runner convergence was not idempotent'

if forced_migration_output="$(run_playbook \
  --extra-vars '{"gitlab_runner_force_register":true}' 2>&1)"; then
  fail 'Forced shell-to-Docker migration unexpectedly reached the invalid endpoint'
fi
grep -q 'Automatic rollback was attempted' <<< "$forced_migration_output" \
  || fail 'Failed forced shell-to-Docker migration did not restore the runner'
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Failed forced shell-to-Docker migration left the Podman socket active'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Failed forced shell-to-Docker migration left the Podman socket enabled'
forced_rollback_quadlet="$(podman exec "$CONTAINER" python3 -c 'from pathlib import Path; print(Path("/etc/containers/systemd/gitlab-runner.container").read_text(), end="")')"
if grep -q 'podman.sock\|SecurityLabelDisable' <<< "$forced_rollback_quadlet"; then
  fail 'Failed forced shell-to-Docker migration changed the manager Quadlet'
fi
grep -q 'executor = "shell"' < <(podman exec "$CONTAINER" python3 -c 'from pathlib import Path; print(Path("/etc/gitlab-runner/config.toml").read_text(), end="")') \
  || fail 'Failed forced shell-to-Docker migration did not restore shell config'

if migration_output="$(run_playbook 2>&1)"; then
  fail 'Shell-to-Docker migration unexpectedly converged without force'
fi
grep -q 'does not contain the one declared executor contract' <<< "$migration_output" \
  || fail 'Shell-to-Docker migration did not fail in preflight'
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Failed shell-to-Docker preflight activated the Podman socket'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Failed shell-to-Docker preflight enabled the Podman socket'

podman exec "$CONTAINER" systemctl disable --now gitlab-runner.service >/dev/null
podman exec "$CONTAINER" rm -f \
  /etc/gitlab-runner/config.toml \
  /etc/containers/systemd/gitlab-runner.container
podman exec "$CONTAINER" systemctl daemon-reload
if initial_output="$(run_playbook 2>&1)"; then
  fail 'Initial Docker registration unexpectedly reached the invalid endpoint'
fi
grep -q 'registration failed' <<< "$initial_output" \
  || fail 'Initial Docker registration failure was not reported'
if podman exec "$CONTAINER" systemctl is-active --quiet podman.socket; then
  fail 'Failed initial Docker registration left the Podman socket active'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled podman.socket 2>/dev/null)" == disabled ]] \
  || fail 'Failed initial Docker registration left the Podman socket enabled'
if podman exec "$CONTAINER" test -e /etc/gitlab-runner/config.toml; then
  fail 'Failed initial Docker registration retained partial configuration'
fi
[[ "$(podman exec "$CONTAINER" systemctl is-enabled platform-container-runtime-overlayfs-exception.service)" == enabled ]] \
  || fail 'Failed Runner registration reverted the shared OverlayFS prerequisite'
podman exec "$CONTAINER" systemctl is-active --quiet \
  platform-container-runtime-overlayfs-exception.service \
  || fail 'Failed Runner registration stopped the shared OverlayFS prerequisite'

printf '%s\n' 'GitLab Runner Podman socket Rocky qualification passed'
