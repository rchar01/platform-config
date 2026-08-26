#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/openbao/render.yml
IMAGE='ghcr.io/openbao/openbao@sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0'
EXPECTED_DIGEST='sha256:15e90b578c970ae57b596ed51295380cd54f93860fe36758f05b455d71aae0e0'
OUTPUT_DIR="$(mktemp -d "${ROOT_DIR}/.openbao-image-test.XXXXXXXX")"
CONTAINER_OUTPUT_DIR="/workspace/${OUTPUT_DIR#"${ROOT_DIR}/"}"
RUNTIME_CONTAINER="platform-config-openbao-image-$$"

cleanup() {
  podman rm -f "$RUNTIME_CONTAINER" >/dev/null 2>&1 || true
  podman unshare chown -R 0:0 "$OUTPUT_DIR" >/dev/null 2>&1 || true
  rm -rf -- "$OUTPUT_DIR"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

"${ROOT_DIR}/scripts/in-container" ansible-playbook "$FIXTURE" \
  --extra-vars "openbao_test_output_dir=${CONTAINER_OUTPUT_DIR}" \
  --extra-vars "openbao_test_validator_base_path=${OUTPUT_DIR}/openbao.hcl" \
  --extra-vars "openbao_test_validator_listener_path=${OUTPUT_DIR}/listener.hcl" >/dev/null

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

"${OUTPUT_DIR}/validate-config" listener "${OUTPUT_DIR}/listener.hcl"
"${OUTPUT_DIR}/validate-config" audit "${OUTPUT_DIR}/audit.hcl"

cp "${OUTPUT_DIR}/audit.hcl" "${OUTPUT_DIR}/invalid-audit.hcl"
printf '\naudit "file" {\n' >> "${OUTPUT_DIR}/invalid-audit.hcl"
if "${OUTPUT_DIR}/validate-config" audit "${OUTPUT_DIR}/invalid-audit.hcl" \
  >/dev/null 2>&1; then
  fail 'OpenBao native validator accepted an invalid audit configuration candidate'
fi

cp "${OUTPUT_DIR}/listener.hcl" "${OUTPUT_DIR}/invalid-listener.hcl"
printf '\nlistener "tcp" {\n' >> "${OUTPUT_DIR}/invalid-listener.hcl"
if "${OUTPUT_DIR}/validate-config" listener "${OUTPUT_DIR}/invalid-listener.hcl" \
  >/dev/null 2>&1; then
  fail 'OpenBao native validator accepted an unsupported configuration field'
fi

cp "${OUTPUT_DIR}/openbao.hcl" "${OUTPUT_DIR}/valid-openbao.hcl"
printf '\nstorage "raft" {\n' >> "${OUTPUT_DIR}/openbao.hcl"
if "${OUTPUT_DIR}/validate-config" listener "${OUTPUT_DIR}/listener.hcl" \
  >/dev/null 2>&1; then
  fail 'OpenBao native validator did not validate the stable base and candidate listener together'
fi
mv "${OUTPUT_DIR}/valid-openbao.hcl" "${OUTPUT_DIR}/openbao.hcl"

cp "${OUTPUT_DIR}/openbao.hcl" "${OUTPUT_DIR}/invalid-openbao.hcl"
printf '\nstorage "raft" {\n' >> "${OUTPUT_DIR}/invalid-openbao.hcl"
if "${OUTPUT_DIR}/validate-config" base "${OUTPUT_DIR}/invalid-openbao.hcl" \
  >/dev/null 2>&1; then
  fail 'OpenBao native validator accepted an invalid base configuration candidate'
fi

REQUEST_ID=0123456789abcdef0123456789abcdef
RUNTIME_ROOT="${OUTPUT_DIR}/runtime"
CONFIG_ROOT="${RUNTIME_ROOT}/config"
VERSION_ROOT="${CONFIG_ROOT}/tls-versions/${REQUEST_ID}"
DATA_ROOT="${RUNTIME_ROOT}/data"
mkdir -p "$VERSION_ROOT" "${CONFIG_ROOT}/tls" "$DATA_ROOT"
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 1 \
  -subj /CN=bao-image.internal.invalid \
  -addext subjectAltName=DNS:bao-image.internal.invalid,IP:127.0.0.1 \
  -keyout "${VERSION_ROOT}/tls.key" \
  -out "${VERSION_ROOT}/fullchain.crt" >/dev/null 2>&1
cp "${VERSION_ROOT}/fullchain.crt" "${RUNTIME_ROOT}/ca.crt"
cp "${VERSION_ROOT}/fullchain.crt" "${CONFIG_ROOT}/tls/ca.crt"
cp "${OUTPUT_DIR}/openbao.hcl" "${CONFIG_ROOT}/openbao.hcl"
cp "${OUTPUT_DIR}/listener.hcl" "${CONFIG_ROOT}/listener.hcl"
cp "${OUTPUT_DIR}/audit.hcl" "${CONFIG_ROOT}/audit.hcl"
perl -0pi -e 's/192[.]0[.]2[.]10/0.0.0.0/g' \
  "${CONFIG_ROOT}/listener.hcl"
perl -0pi -e \
  "s#/openbao/config/tls/tls[.]crt#/openbao/config/tls-versions/${REQUEST_ID}/fullchain.crt#; s#/openbao/config/tls/tls[.]key#/openbao/config/tls-versions/${REQUEST_ID}/tls.key#" \
  "${CONFIG_ROOT}/listener.hcl"

chmod 0750 "$CONFIG_ROOT" "${CONFIG_ROOT}/tls" \
  "${CONFIG_ROOT}/tls-versions" "$VERSION_ROOT" "$DATA_ROOT"
chmod 0640 "${CONFIG_ROOT}/openbao.hcl" "${CONFIG_ROOT}/listener.hcl" \
  "${CONFIG_ROOT}/audit.hcl" \
  "${VERSION_ROOT}/tls.key"
chmod 0644 "${VERSION_ROOT}/fullchain.crt"
podman unshare chown 0:1000 \
  "$CONFIG_ROOT" "${CONFIG_ROOT}/tls" \
  "${CONFIG_ROOT}/tls-versions" "$VERSION_ROOT" \
  "${CONFIG_ROOT}/openbao.hcl" "${CONFIG_ROOT}/listener.hcl" \
  "${CONFIG_ROOT}/audit.hcl" \
  "${VERSION_ROOT}/tls.key"
podman unshare chown 0:0 \
  "${CONFIG_ROOT}/tls/ca.crt" "${VERSION_ROOT}/fullchain.crt"
podman unshare chown 100:1000 "$DATA_ROOT"

podman run --rm \
  --network none \
  --read-only \
  --user 100:1000 \
  --security-opt no-new-privileges \
  --entrypoint /bin/sh \
  --volume "${CONFIG_ROOT}:/material:ro,Z" \
  "$IMAGE" \
  -c "test -r /material/tls-versions/${REQUEST_ID}/tls.key" \
  || fail 'UID 100/GID 1000 could not read the mode 0640 host-local key through mode 0750 ancestors'

podman run \
  --detach \
  --name "$RUNTIME_CONTAINER" \
  --publish 127.0.0.1::18200 \
  --read-only \
  --user 100:1000 \
  --security-opt no-new-privileges \
  --entrypoint /usr/bin/bao \
  --volume "${CONFIG_ROOT}:/openbao/config:ro,Z" \
  --volume "${DATA_ROOT}:/openbao/data:Z" \
  "$IMAGE" \
  server -config=/openbao/config >/dev/null

HOST_PORT="$(podman port "$RUNTIME_CONTAINER" 18200/tcp)"
HOST_PORT="${HOST_PORT##*:}"
health_code=000
for _ in {1..30}; do
  health_code="$(curl \
    --cacert "${RUNTIME_ROOT}/ca.crt" \
    --resolve "bao-image.internal.invalid:${HOST_PORT}:127.0.0.1" \
    --silent \
    --output "${RUNTIME_ROOT}/health.json" \
    --write-out '%{http_code}' \
    "https://bao-image.internal.invalid:${HOST_PORT}/v1/sys/health" || true)"
  [[ "$health_code" == 501 ]] && break
  sleep 1
done
if [[ "$health_code" != 501 ]]; then
  podman logs "$RUNTIME_CONTAINER" >&2 || true
  fail "Pristine OpenBao health returned ${health_code}, expected 501"
fi
grep -q '"initialized":false' "${RUNTIME_ROOT}/health.json" \
  || fail 'Pristine OpenBao health did not report initialized=false'
grep -q '"sealed":true' "${RUNTIME_ROOT}/health.json" \
  || fail 'Pristine OpenBao health did not report sealed=true'
grep -q '"standby":true' "${RUNTIME_ROOT}/health.json" \
  || fail 'Pristine OpenBao health did not report standby=true'
grep -q '"version":"2.6.1"' "${RUNTIME_ROOT}/health.json" \
  || fail 'Pristine OpenBao health did not report version 2.6.1'

printf 'OpenBao 2.6.1 image validation check passed\n'
