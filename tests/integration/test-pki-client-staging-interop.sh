#!/usr/bin/env bash
# Explicit opt-in; not part of either repository's default test suite.
# Usage:
#   PLATFORM_TOOLS_TEST_SOURCE=/absolute/public/platform-tools \
#   PLATFORM_PKI_INTEROP_TEST_IMAGE=sha256:<reviewed-local-image-id> \
#     bash tests/integration/test-pki-client-staging-interop.sh
# The prebuilt image needs Python, pytest, PyYAML, cryptography, OpenSSL,
# ssh-keygen and unshare (e.g. the config dev image selected by immutable ID).
# The tools-only test image currently lacks cryptography. No build/install here.
set -euo pipefail

config_source="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tools_source="${PLATFORM_TOOLS_TEST_SOURCE:?select the reviewed public platform-tools source root}"
image="${PLATFORM_PKI_INTEROP_TEST_IMAGE:?select an immutable prebuilt test image}"
[[ $# == 0 && $tools_source == /* && -f $tools_source/tests/pki/test_client_target_interop.py ]] || {
  printf '%s\n' 'Expected no arguments and an absolute PLATFORM_TOOLS_TEST_SOURCE containing the interop test' >&2
  exit 2
}
[[ $image =~ ^sha256:[0-9a-f]{64}$ || $image =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'PLATFORM_PKI_INTEROP_TEST_IMAGE must be a full sha256 image ID or digest-pinned reference' >&2
  exit 2
}
run_dir="$(mktemp -d "${TMPDIR:-/tmp}/platform-pki-client-interop.XXXXXXXX")"
container="${run_dir##*/}"
cleanup() {
  local container_id=''
  if [[ -f $run_dir/container.cid && ! -L $run_dir/container.cid ]]; then
    IFS= read -r container_id < "$run_dir/container.cid" || true
    if [[ $container_id =~ ^[0-9a-f]{64}$ ]]; then
      podman rm -f "$container_id" >/dev/null 2>&1 || true
    fi
  fi
  rm -f -- "$run_dir/container.cid"
  rmdir -- "$run_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

podman run --rm --name "$container" --cidfile "$run_dir/container.cid" --pull=never \
  --userns=keep-id --security-opt=no-new-privileges --network=none \
  --read-only --tmpfs /tmp:rw,exec,mode=1777 \
  --env HOME=/tmp/platform-interop-home \
  --env PYTHONPATH=/workspace --env PYTHONDONTWRITEBYTECODE=1 \
  --env PLATFORM_PKI_TEST_CONFIG_SOURCE=/config-source \
  --volume "$tools_source:/workspace:ro" \
  --volume "$config_source:/config-source:ro" \
  --workdir /workspace "$image" \
  timeout --signal=TERM --kill-after=5s 595s \
  sh -c 'mkdir -m 700 "$HOME" && exec python3 -m pytest -n 0 -p no:cacheprovider -x -v --durations=5 tests/pki/test_client_target_interop.py'
