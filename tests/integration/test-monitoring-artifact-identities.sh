#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="${MONITORING_ARTIFACT_LOCK:-${ROOT_DIR}/tests/fixtures/monitoring-artifacts/candidates.json}"
REGISTRY_TIMEOUT="${MONITORING_ARTIFACT_REGISTRY_TIMEOUT:-60}"
PULL_TIMEOUT="${MONITORING_ARTIFACT_PULL_TIMEOUT:-300}"
RUNTIME_TIMEOUT="${MONITORING_ARTIFACT_RUNTIME_TIMEOUT:-60}"
INDEX_MANIFEST="$(mktemp)"

cleanup() {
  rm -f -- "$INDEX_MANIFEST"
}
trap cleanup EXIT

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'Required command not found: python3'

python3 - "$LOCK" <<'PY' || fail 'Monitoring candidate lock failed identity preflight'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)

def require(condition):
    if not condition:
        raise SystemExit(1)

components = lock.get("components")
require(isinstance(components, dict))
require(set(components) == {"alloy", "garage", "grafana", "loki", "mimir"})
require(components["alloy"].get("kind") == "rpm")

images = {name: value for name, value in components.items() if value.get("kind") == "oci_image"}
require(set(images) == {"garage", "grafana", "loki", "mimir"})
for candidate in images.values():
    require(isinstance(candidate.get("version"), str) and candidate["version"])
    require(isinstance(candidate.get("repository"), str) and candidate["repository"].startswith("docker.io/"))
    require(isinstance(candidate.get("qualification_tag"), str) and candidate["qualification_tag"] != "latest")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", candidate.get("index_digest", "")))
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", candidate.get("linux_amd64_digest", "")))
    require(candidate.get("os") == "linux")
    require(candidate.get("architecture") == "amd64")
    require(isinstance(candidate.get("configured_user"), str))
    for field in ("entrypoint", "command", "version_command"):
        require(isinstance(candidate.get(field), list))
        require(all(isinstance(value, str) for value in candidate[field]))
    require(candidate["version_command"])
PY

for command in jq podman sha256sum skopeo timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done

while IFS= read -r component; do
  repository="$(jq -r --arg component "$component" \
    '.components[$component].repository' "$LOCK")"
  tag="$(jq -r --arg component "$component" \
    '.components[$component].qualification_tag' "$LOCK")"
  index_digest="$(jq -r --arg component "$component" \
    '.components[$component].index_digest' "$LOCK")"
  amd64_digest="$(jq -r --arg component "$component" \
    '.components[$component].linux_amd64_digest' "$LOCK")"
  configured_user="$(jq -r --arg component "$component" \
    '.components[$component].configured_user' "$LOCK")"
  image="${repository}@${index_digest}"

  timeout "$REGISTRY_TIMEOUT" skopeo inspect --raw \
    "docker://${repository}:${tag}" >"$INDEX_MANIFEST"
  read -r observed_index_digest _ < <(sha256sum "$INDEX_MANIFEST")
  [[ "sha256:${observed_index_digest}" == "$index_digest" ]] \
    || fail "${component} index digest mismatch: sha256:${observed_index_digest}"
  media_type="$(jq -r '.mediaType' "$INDEX_MANIFEST")"
  [[ "$media_type" == application/vnd.oci.image.index.v1+json \
    || "$media_type" == application/vnd.docker.distribution.manifest.list.v2+json ]] \
    || fail "${component} tag did not resolve to a supported image index: ${media_type}"
  amd64_count="$(jq \
    '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")] | length' \
    "$INDEX_MANIFEST")"
  [[ "$amd64_count" == 1 ]] \
    || fail "${component} image index contains ${amd64_count} linux/amd64 manifests"
  observed_amd64_digest="$(jq -r \
    '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' \
    "$INDEX_MANIFEST")"
  [[ "$observed_amd64_digest" == "$amd64_digest" ]] \
    || fail "${component} linux/amd64 digest mismatch: ${observed_amd64_digest}"

  timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 "$image" >/dev/null
  metadata="$(podman image inspect "$image")"
  [[ "$(jq -r '.[0].Digest' <<<"$metadata")" == "$index_digest" ]] \
    || fail "${component} pulled image digest mismatch"
  [[ "$(jq -r '.[0].Os + "/" + .[0].Architecture' <<<"$metadata")" == linux/amd64 ]] \
    || fail "${component} pulled image platform mismatch"
  [[ "$(jq -r '.[0].Config.User // ""' <<<"$metadata")" == "$configured_user" ]] \
    || fail "${component} configured image user mismatch"
  jq -e --arg component "$component" --argjson metadata "$metadata" '
    .components[$component].entrypoint == ($metadata[0].Config.Entrypoint // [])
    and .components[$component].command == ($metadata[0].Config.Cmd // [])
  ' "$LOCK" >/dev/null || fail "${component} entrypoint or command mismatch"

  mapfile -t version_command < <(jq -r --arg component "$component" \
    '.components[$component].version_command[]' "$LOCK")
  version="$(jq -r --arg component "$component" \
    '.components[$component].version' "$LOCK")"
  version_pattern="${version//./[.]}"
  version_output="$(timeout "$RUNTIME_TIMEOUT" podman run --rm \
    --pull never \
    --network none \
    --read-only \
    --cap-drop all \
    --security-opt no-new-privileges \
    --entrypoint "${version_command[0]}" \
    "$image" "${version_command[@]:1}" 2>&1)"
  grep -Eq "(^|[^0-9])${version_pattern}([^0-9]|$)" <<<"$version_output" \
    || fail "${component} version mismatch: ${version_output}"
  printf 'Verified identity for %s %s (%s)\n' \
    "$component" \
    "$version" \
    "$index_digest"
done < <(jq -r '.components | to_entries[] | select(.value.kind == "oci_image") | .key' \
  "$LOCK")
