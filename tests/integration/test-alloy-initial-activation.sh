#!/usr/bin/env bash
# Opt-in native initial-start qualification; see the fixture README for scope.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
IMAGE="${PLATFORM_ALLOY_TEST_IMAGE:?select an immutable prebuilt config-dev image}"
ROCKY="${PLATFORM_ALLOY_TEST_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
TOOLS="${PLATFORM_TOOLS_TEST_SOURCE:-}"
ZIPAPP="${PLATFORM_ALLOY_TEST_PKI_ZIPAPP:-}"
RPM_SHA=7dbdc068feae7feaafbc48fefb9b41b6c91af24984c13277bf0a9d1a298a4126
RPM_NAME=alloy-1.18.1-1.amd64.rpm
FIXTURE=/workspace/tests/fixtures/alloy-initial-activation
[[ $# == 0 && ( $IMAGE =~ ^sha256:[0-9a-f]{64}$ || $IMAGE =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ) ]] || exit 2
[[ $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || {
  printf '%s\n' 'This disposable privileged lane requires rootless Podman' >&2
  exit 2
}
inputs=()
if [[ -n $TOOLS ]]; then
  [[ $TOOLS == /* && -f $TOOLS/scripts/build-platform-pki-zipapp.py && -z $ZIPAPP ]] || exit 2
  inputs+=(--volume "$TOOLS:/tools:ro")
elif [[ $ZIPAPP == /* && -f $ZIPAPP && ! -L $ZIPAPP ]]; then
  inputs+=(--volume "$ZIPAPP:/input/platform-pki:ro")
else
  printf '%s\n' 'Select exactly one reviewed public tools source or generated zipapp' >&2
  exit 2
fi
RUN="$(mktemp -d /tmp/platform-alloy-initial.XXXXXXXX)"
cleanup() {
  local status=$? cid file
  trap - EXIT
  for file in "$RUN/target.cid" "$RUN/preparer.cid"; do
    if [[ -f $file && ! -L $file ]]; then
      IFS= read -r cid < "$file" || true
      if [[ $cid =~ ^[0-9a-f]{64}$ ]]; then
        if ((status != 0)) && [[ $file == "$RUN/target.cid" ]]; then
          podman logs "$cid" >&2 || true
          podman exec "$cid" timeout --kill-after=5s 15s journalctl -u alloy.service --no-pager -n 40 >&2 || true
        fi
        if podman rm -f "$cid" >/dev/null; then
          printf 'Removed disposable container %s\n' "$cid"
        else
          status=1
        fi
      fi
    fi
  done
  rm -f -- "$RUN/target.cid" "$RUN/preparer.cid" "$RUN/fixture.tar"
  rmdir -- "$RUN" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
podman run --detach --cidfile "$RUN/preparer.cid" --pull=never --network=none --stop-signal=SIGKILL \
  --user 0 --security-opt=no-new-privileges --env PYTHONDONTWRITEBYTECODE=1 \
  --volume "$ROOT:/workspace:ro" "${inputs[@]}" "$IMAGE" sleep infinity >/dev/null
IFS= read -r PREPARER < "$RUN/preparer.cid" || [[ $PREPARER =~ ^[0-9a-f]{64}$ ]]
if [[ -n $TOOLS ]]; then
  podman exec "$PREPARER" timeout --kill-after=5s 60s \
    python3 /tools/scripts/build-platform-pki-zipapp.py --verify
  ARTIFACT=/tools/bin/platform-pki
else
  ARTIFACT=/input/platform-pki
fi
podman exec "$PREPARER" timeout --kill-after=5s 120s \
  python3 "$FIXTURE/build.py" "$ARTIFACT"
podman cp "$PREPARER:/tmp/native-fixture.tar" "$RUN/fixture.tar"
podman run --detach --cidfile "$RUN/target.cid" --systemd=always --privileged \
  --volume "$ROOT:/workspace:ro" "$ROCKY" \
  bash -lc 'timeout --kill-after=5s 180s dnf -qy install systemd && exec /sbin/init' >/dev/null
IFS= read -r TARGET < "$RUN/target.cid" || [[ $TARGET =~ ^[0-9a-f]{64}$ ]]
native() { podman exec "$TARGET" timeout --kill-after=5s 240s "$@"; }
native bash -c '
  for ((i=0;i<60;i++)); do
    state=$(systemctl is-system-running 2>/dev/null || true)
    if [[ $state == running || $state == degraded ]]; then break; fi
    sleep 1
  done
  [[ $state == running ]] && exit 0
  [[ $state == degraded ]] || exit 1
  failed=$(systemctl --failed --no-legend --plain) || exit 1
  while read -r unit _; do
    case "$unit" in
      sys-kernel-config.mount|sys-kernel-debug.mount|sys-kernel-tracing.mount) ;;
      *) printf "Unexpected failed unit: %s\n" "$unit" >&2; exit 1 ;;
    esac
  done <<< "$failed"
'
# These are the existing helper prerequisites, supplied by Rocky packages. No pip
# install, new project dependency, container build, or runtime code vendoring.
native dnf -qy install curl python3-cryptography openssh-clients openssl tar >/dev/null
if [[ -f $ROOT/.artifacts/$RPM_NAME ]]; then
  native cp "/workspace/.artifacts/$RPM_NAME" /tmp/alloy.rpm
else
  native curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 \
    "https://github.com/grafana/alloy/releases/download/v1.18.1/$RPM_NAME" -o /tmp/alloy.rpm
fi
native bash -c 'printf "%s  /tmp/alloy.rpm\n" "$1" | sha256sum --check --status' _ "$RPM_SHA"
native dnf -qy --nogpgcheck install /tmp/alloy.rpm >/dev/null
native systemctl disable --now alloy.service
podman cp "$RUN/fixture.tar" "$TARGET:/tmp/fixture.tar"
native tar --extract --file /tmp/fixture.tar --directory / --same-owner --same-permissions
# Match role-owned ancestor metadata after RPM scripts create alloy-owned paths.
native install -d -o root -g root -m 0755 /etc/alloy /var/lib/alloy/data \
  /etc/systemd/system/alloy.service.d /var/log/journal
native systemctl daemon-reload
native python3 "$FIXTURE/native.py"
printf '%s\n' 'Alloy 1.18.1 native initial-only qualification passed; readiness is not ingestion.'
