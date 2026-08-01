#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/openbao/render.yml
IMAGE='ghcr.io/openbao/openbao@sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0'
EXPECTED_DIGEST='sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0'
OUTPUT_DIR="$(mktemp -d "${ROOT_DIR}/.openbao-image-test.XXXXXXXX")"
CONTAINER_OUTPUT_DIR="/workspace/${OUTPUT_DIR#"${ROOT_DIR}/"}"

cleanup() {
  rm -rf -- "$OUTPUT_DIR"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

"${ROOT_DIR}/scripts/in-container" ansible-playbook "$FIXTURE" \
  --extra-vars "openbao_test_output_dir=${CONTAINER_OUTPUT_DIR}" >/dev/null

podman pull --quiet "$IMAGE" >/dev/null

image_digest="$(podman image inspect --format '{{.Digest}}' "$IMAGE")"
[[ "$image_digest" == "$EXPECTED_DIGEST" ]] \
  || fail "OpenBao image digest mismatch: ${image_digest}"

image_architecture="$(podman image inspect --format '{{.Architecture}}' "$IMAGE")"
[[ "$image_architecture" == amd64 ]] \
  || fail "OpenBao image architecture mismatch: ${image_architecture}"

version_output="$(podman run --rm "$IMAGE" version)"
[[ "$version_output" == 'OpenBao v2.6.1 '* ]] \
  || fail "OpenBao image version mismatch: ${version_output}"

identity_output="$(podman run --rm --entrypoint /usr/bin/id "$IMAGE" openbao)"
[[ "$identity_output" == 'uid=100(openbao) gid=1000(openbao)'* ]] \
  || fail "OpenBao image identity mismatch: ${identity_output}"

"${OUTPUT_DIR}/validate-config" "${OUTPUT_DIR}/openbao.hcl"

cp "${OUTPUT_DIR}/openbao.hcl" "${OUTPUT_DIR}/invalid-openbao.hcl"
printf '\nunsupported_platform_option = true\n' >> "${OUTPUT_DIR}/invalid-openbao.hcl"
if "${OUTPUT_DIR}/validate-config" "${OUTPUT_DIR}/invalid-openbao.hcl" \
  >/dev/null 2>&1; then
  fail 'OpenBao native validator accepted an unsupported configuration field'
fi

printf 'OpenBao 2.6.1 image validation check passed\n'
