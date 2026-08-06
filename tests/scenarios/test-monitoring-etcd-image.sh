#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${ROOT_DIR}/tests/fixtures/monitoring-etcd/etcd.yml"
IMAGE_REPOSITORY=gcr.io/etcd-development/etcd
IMAGE_TAG="${IMAGE_REPOSITORY}:v3.6.14"
EXPECTED_INDEX_DIGEST=sha256:a491baeaa0cb0c9cd89c0062ac44ece53886e3e5bddad18d2daf36678ce665b6
EXPECTED_AMD64_DIGEST=sha256:6efdcd9a81c9063554d107d0c163523e8bc1984d1245d914b56065f614d4d67b
IMAGE="${IMAGE_REPOSITORY}@${EXPECTED_INDEX_DIGEST}"
CONTAINER="platform-config-monitoring-etcd-test-$$"
CONTAINER_CREATED=false
INVALID_CONFIG="$(mktemp)"
VALID_CONFIG="$(mktemp)"
INDEX_MANIFEST="$(mktemp)"
DATA_DIR="$(mktemp -d)"
REGISTRY_TIMEOUT="${MONITORING_ETCD_REGISTRY_TIMEOUT:-60}"
PULL_TIMEOUT="${MONITORING_ETCD_PULL_TIMEOUT:-300}"
RUNTIME_TIMEOUT="${MONITORING_ETCD_RUNTIME_TIMEOUT:-60}"

cleanup() {
  if [[ "$CONTAINER_CREATED" == true ]]; then
    podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -f -- "$INDEX_MANIFEST" "$INVALID_CONFIG" "$VALID_CONFIG"
  rm -rf -- "$DATA_DIR"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

for command in curl jq podman sha256sum skopeo timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done

timeout "$REGISTRY_TIMEOUT" skopeo inspect --raw "docker://${IMAGE_TAG}" \
  > "$INDEX_MANIFEST"
read -r observed_index_digest _ < <(sha256sum "$INDEX_MANIFEST")
[[ "sha256:${observed_index_digest}" == "$EXPECTED_INDEX_DIGEST" ]] \
  || fail "etcd v3.6.14 index digest mismatch: sha256:${observed_index_digest}"

observed_amd64_digest="$(jq -r \
  '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' \
  "$INDEX_MANIFEST")"
[[ "$observed_amd64_digest" == "$EXPECTED_AMD64_DIGEST" ]] \
  || fail "etcd v3.6.14 linux/amd64 digest mismatch: ${observed_amd64_digest}"

timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 "$IMAGE" >/dev/null
image_digest="$(podman image inspect --format '{{.Digest}}' "$IMAGE")"
[[ "$image_digest" == "$EXPECTED_INDEX_DIGEST" ]] \
  || fail "Pulled etcd image digest mismatch: ${image_digest}"
image_platform="$(podman image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")"
[[ "$image_platform" == linux/amd64 ]] \
  || fail "Pulled etcd image platform mismatch: ${image_platform}"
image_user="$(podman image inspect --format '{{.Config.User}}' "$IMAGE")"
[[ "$image_user" == 0 ]] \
  || fail "Unexpected upstream etcd image user metadata: ${image_user}"

version_output="$(timeout "$RUNTIME_TIMEOUT" podman run --rm \
  --network none \
  --read-only \
  --user 10001:10001 \
  --cap-drop all \
  --security-opt no-new-privileges \
  "$IMAGE" /usr/local/bin/etcd --version)"
grep -q '^etcd Version: 3[.]6[.]14$' <<< "$version_output" \
  || fail "etcd image version mismatch: ${version_output}"
grep -q '^Go OS/Arch: linux/amd64$' <<< "$version_output" \
  || fail "etcd image runtime platform mismatch: ${version_output}"

cp "$CONFIG" "$VALID_CONFIG"
chmod 0644 "$VALID_CONFIG"
cp "$VALID_CONFIG" "$INVALID_CONFIG"
printf '\ninvalid-yaml: [\n' >> "$INVALID_CONFIG"
chmod 0644 "$INVALID_CONFIG"
chmod 0700 "$DATA_DIR"
invalid_status=0
invalid_output="$(timeout 10 podman run --rm \
  --network none \
  --read-only \
  --userns=keep-id:uid=10001,gid=10001 \
  --user 10001:10001 \
  --cap-drop all \
  --security-opt no-new-privileges \
  --volume "${DATA_DIR}:/etcd-data:Z" \
  --volume "${INVALID_CONFIG}:/etc/etcd/etcd.yml:ro,Z" \
  "$IMAGE" /usr/local/bin/etcd --config-file /etc/etcd/etcd.yml \
  2>&1)" || invalid_status=$?
[[ "$invalid_status" == 1 ]] \
  || fail "etcd malformed configuration check exited ${invalid_status}: ${invalid_output}"
grep -Fq 'failed to verify flags' <<< "$invalid_output" \
  || fail "etcd did not report flag verification failure: ${invalid_output}"
grep -Fq 'error converting YAML to JSON' <<< "$invalid_output" \
  || fail "etcd did not report YAML parsing failure: ${invalid_output}"

timeout "$RUNTIME_TIMEOUT" podman run \
  --detach \
  --name "$CONTAINER" \
  --read-only \
  --userns=keep-id:uid=10001,gid=10001 \
  --user 10001:10001 \
  --cap-drop all \
  --security-opt no-new-privileges \
  --volume "${DATA_DIR}:/etcd-data:Z" \
  --volume "${VALID_CONFIG}:/etc/etcd/etcd.yml:ro,Z" \
  --publish 127.0.0.1::2379 \
  "$IMAGE" /usr/local/bin/etcd --config-file /etc/etcd/etcd.yml >/dev/null
CONTAINER_CREATED=true

[[ "$(podman inspect --format '{{.Config.User}}' "$CONTAINER")" == 10001:10001 ]] \
  || fail 'etcd qualification container is not configured for UID/GID 10001'
[[ "$(podman inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER")" == true ]] \
  || fail 'etcd qualification container root filesystem is writable'

host_endpoint="$(podman port "$CONTAINER" 2379/tcp)"
ready_response=
for _ in {1..60}; do
  if ready_response="$(curl -fsS --connect-timeout 2 --max-time 3 \
    "http://${host_endpoint}/readyz?verbose" 2>/dev/null)"; then
    break
  fi
  sleep 1
done
if [[ -z "$ready_response" ]]; then
  podman logs "$CONTAINER" >&2 || true
  fail 'etcd did not become ready'
fi
grep -q '^ok$' <<< "$ready_response" \
  || fail "Unexpected etcd readiness response: ${ready_response}"
[[ "$(curl -fsS --connect-timeout 2 --max-time 3 \
  "http://${host_endpoint}/livez")" == ok ]] \
  || fail 'etcd liveness endpoint did not return ok'
health_response="$(curl -fsS --connect-timeout 2 --max-time 3 \
  "http://${host_endpoint}/health")"
[[ "$(jq -r '.health' <<< "$health_response")" == true ]] \
  || fail "etcd legacy health endpoint was not healthy: ${health_response}"

timeout "$RUNTIME_TIMEOUT" podman exec \
  --env ETCDCTL_ENDPOINTS=http://127.0.0.1:2379 \
  "$CONTAINER" \
  /usr/local/bin/etcdctl put qualification-key qualification-value >/dev/null
stored_value="$(timeout "$RUNTIME_TIMEOUT" podman exec \
  --env ETCDCTL_ENDPOINTS=http://127.0.0.1:2379 \
  "$CONTAINER" \
  /usr/local/bin/etcdctl get qualification-key --print-value-only)"
[[ "$stored_value" == qualification-value ]] \
  || fail "etcd disposable write/read mismatch: ${stored_value}"

printf '%s\n' \
  "Monitoring etcd 3.6.14 image qualification passed (${EXPECTED_INDEX_DIGEST})"
