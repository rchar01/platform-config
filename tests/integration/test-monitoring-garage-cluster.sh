#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="${ROOT_DIR}/tests/fixtures/monitoring-artifacts/candidates.json"
S3_CLIENT="${ROOT_DIR}/tests/fixtures/monitoring-garage/s3_sigv4.py"
LOKI_CONFIG="${ROOT_DIR}/tests/fixtures/monitoring-garage/loki.yaml"
LOKI_CLUSTER_CONFIG="${ROOT_DIR}/tests/fixtures/monitoring-garage/loki-cluster.yaml"
MIMIR_CONFIG="${ROOT_DIR}/tests/fixtures/monitoring-garage/mimir.yaml"
MIMIR_FALLBACK="${ROOT_DIR}/tests/fixtures/monitoring-garage/alertmanager-fallback.yaml"
REMOTE_WRITE_CLIENT="${ROOT_DIR}/tests/fixtures/monitoring-garage/remote_write.py"
TEST_DIR="$(mktemp -d)"
RUN_ID="platform-config-garage-${TEST_DIR##*/}"
LABEL="platform-config.garage-run=${RUN_ID}"
NETWORK="${RUN_ID}-network"
OPERATION_TIMEOUT="${MONITORING_GARAGE_OPERATION_TIMEOUT:-30}"
READY_TIMEOUT="${MONITORING_GARAGE_READY_TIMEOUT:-120}"
PULL_TIMEOUT="${MONITORING_GARAGE_PULL_TIMEOUT:-300}"
TEST_LOKI="${MONITORING_GARAGE_TEST_LOKI:-false}"
LOKI_READY_TIMEOUT="${MONITORING_GARAGE_LOKI_READY_TIMEOUT:-${READY_TIMEOUT}}"
LOKI_LIFECYCLE_TIMEOUT="${MONITORING_GARAGE_LOKI_LIFECYCLE_TIMEOUT:-360}"
TEST_LOKI_CLUSTER="${MONITORING_GARAGE_TEST_LOKI_CLUSTER:-false}"
TEST_MIMIR="${MONITORING_GARAGE_TEST_MIMIR:-false}"
MIMIR_READY_TIMEOUT="${MONITORING_GARAGE_MIMIR_READY_TIMEOUT:-240}"
MIMIR_LIFECYCLE_TIMEOUT="${MONITORING_GARAGE_MIMIR_LIFECYCLE_TIMEOUT:-360}"
MEMBERS=(garage-1 garage-2 garage-3)
CREATED_CONTAINERS=()
LAST_HEALTH=
LAST_STAGE=initialization
declare -A CONTAINERS=(
  [garage-1]="${RUN_ID}-garage-1"
  [garage-2]="${RUN_ID}-garage-2"
  [garage-3]="${RUN_ID}-garage-3"
)
declare -A NODE_IDS=()
declare -A S3_ENDPOINTS=()
LOKI_CLUSTER_MEMBERS=(loki-cluster-1 loki-cluster-2 loki-cluster-3)
LOKI_CLUSTER_NAMES_JSON='["loki-cluster-1","loki-cluster-2","loki-cluster-3"]'
LAST_LOKI_CLUSTER_STATE=
declare -A LOKI_CLUSTER_CONTAINERS=()
declare -A LOKI_CLUSTER_DATA_DIRS=()
declare -A LOKI_CLUSTER_ENDPOINTS=()
LOKI_CLUSTER_IPS=()
MIMIR_CLUSTER_MEMBERS=(mimir-cluster-1 mimir-cluster-2 mimir-cluster-3)
MIMIR_CLUSTER_NAMES_JSON='["mimir-cluster-1","mimir-cluster-2","mimir-cluster-3"]'
LAST_MIMIR_CLUSTER_STATE=
LAST_MIMIR_QUERY_RESPONSE=
declare -A MIMIR_CLUSTER_CONTAINERS=()
declare -A MIMIR_CLUSTER_DATA_DIRS=()
declare -A MIMIR_CLUSTER_ENDPOINTS=()
declare -A MIMIR_ACCESS_KEYS=()
declare -A MIMIR_SECRET_KEYS=()
MIMIR_CLUSTER_IPS=()

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=$?
  local cleanup_failed=false
  local container_id
  local -a containers=()

  trap - EXIT INT TERM
  if ((status != 0)); then
    printf '\nGarage qualification failed during: %s\n' "$LAST_STAGE" >&2
    for container_id in "${CREATED_CONTAINERS[@]}"; do
      printf '\n===== %s logs =====\n' "$container_id" >&2
      timeout 10 podman logs "$container_id" >&2 || true
    done
  fi
  for container_id in "${CREATED_CONTAINERS[@]}"; do
    timeout 20 podman rm -f "$container_id" >/dev/null 2>&1 || true
  done
  mapfile -t containers < <(
    timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null || true
  )
  if ((${#containers[@]})); then
    timeout 20 podman rm -f "${containers[@]}" >/dev/null 2>&1 || true
  fi
  mapfile -t containers < <(
    timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null || true
  )
  if ((${#containers[@]})); then
    printf 'Cleanup left labeled containers: %s\n' "${containers[*]}" >&2
    printf 'Preserved test directory for surviving containers: %s\n' "$TEST_DIR" >&2
    cleanup_failed=true
  else
    rm -rf -- "$TEST_DIR"
  fi
  timeout 10 podman network rm -f "$NETWORK" >/dev/null 2>&1 || true
  if timeout 10 podman network exists "$NETWORK" >/dev/null 2>&1; then
    printf 'Cleanup left network: %s\n' "$NETWORK" >&2
    cleanup_failed=true
  fi
  if ((${#containers[@]} == 0)) && [[ -e "$TEST_DIR" ]]; then
    printf 'Cleanup left test directory: %s\n' "$TEST_DIR" >&2
    cleanup_failed=true
  fi
  if [[ "$cleanup_failed" == true && "$status" == 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in cat cmp curl date find grep jq openssl podman python3 rm sha256sum sort timeout wc; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done
[[ -f "$S3_CLIENT" ]] || fail "SigV4 client not found: ${S3_CLIENT}"
[[ "$TEST_LOKI" == true || "$TEST_LOKI" == false ]] \
  || fail 'MONITORING_GARAGE_TEST_LOKI must be true or false'
[[ "$TEST_LOKI_CLUSTER" == true || "$TEST_LOKI_CLUSTER" == false ]] \
  || fail 'MONITORING_GARAGE_TEST_LOKI_CLUSTER must be true or false'
[[ "$TEST_MIMIR" == true || "$TEST_MIMIR" == false ]] \
  || fail 'MONITORING_GARAGE_TEST_MIMIR must be true or false'
for timeout_name in OPERATION_TIMEOUT READY_TIMEOUT PULL_TIMEOUT \
  LOKI_READY_TIMEOUT LOKI_LIFECYCLE_TIMEOUT MIMIR_READY_TIMEOUT \
  MIMIR_LIFECYCLE_TIMEOUT; do
  [[ "${!timeout_name}" =~ ^[1-9][0-9]*$ ]] \
    || fail "${timeout_name} must be a positive integer"
done
if [[ "$TEST_LOKI" == true ]]; then
  [[ -f "$LOKI_CONFIG" ]] || fail "Loki configuration not found: ${LOKI_CONFIG}"
fi
if [[ "$TEST_LOKI_CLUSTER" == true ]]; then
  [[ -f "$LOKI_CLUSTER_CONFIG" ]] \
    || fail "Loki cluster configuration not found: ${LOKI_CLUSTER_CONFIG}"
fi
[[ "$TEST_LOKI" != true || "$TEST_LOKI_CLUSTER" != true ]] \
  || fail 'Single-process and three-node Loki lanes cannot run together'
if [[ "$TEST_MIMIR" == true ]]; then
  for file in "$MIMIR_CONFIG" "$MIMIR_FALLBACK" "$REMOTE_WRITE_CLIENT"; do
    [[ -f "$file" ]] || fail "Mimir fixture not found: ${file}"
  done
fi

repository="$(jq -er '.components.garage.repository' "$LOCK")"
version="$(jq -er '.components.garage.version' "$LOCK")"
index_digest="$(jq -er '.components.garage.index_digest' "$LOCK")"
[[ "$version" == 2.3.0 ]] || fail "Unexpected Garage candidate version: ${version}"
IMAGE="${repository}@${index_digest}"
LOKI_IMAGE=
LOKI_VERSION=
if [[ "$TEST_LOKI" == true || "$TEST_LOKI_CLUSTER" == true ]]; then
  LOKI_IMAGE="$(jq -er '
    .components.loki.repository + "@" + .components.loki.index_digest
  ' "$LOCK")"
  LOKI_VERSION="$(jq -er '.components.loki.version' "$LOCK")"
  [[ "$LOKI_VERSION" == 3.7.6 ]] \
    || fail "Unexpected Loki candidate version: ${LOKI_VERSION}"
fi
MIMIR_IMAGE=
MIMIR_VERSION=
if [[ "$TEST_MIMIR" == true ]]; then
  MIMIR_IMAGE="$(jq -er '
    .components.mimir.repository + "@" + .components.mimir.index_digest
  ' "$LOCK")"
  MIMIR_VERSION="$(jq -er '.components.mimir.version' "$LOCK")"
  [[ "$MIMIR_VERSION" == 3.1.4 ]] \
    || fail "Unexpected Mimir candidate version: ${MIMIR_VERSION}"
fi

rpc_secret="$(openssl rand -hex 32)"
admin_token="$(openssl rand -hex 32)"
metrics_token="$(openssl rand -hex 32)"

garage_cli() {
  local member=$1
  shift

  timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
    /garage --config /etc/garage.toml "$@"
}

wait_for_node_id() {
  local member=$1
  local deadline=$((SECONDS + READY_TIMEOUT))
  local identity

  while ((SECONDS < deadline)); do
    if identity="$(garage_cli "$member" node id --quiet 2>/dev/null)" \
      && [[ "$identity" =~ ^[0-9a-f]{64}@${member}:3901$ ]]; then
      printf '%s\n' "$identity"
      return 0
    fi
    sleep 1
  done
  fail "Garage member ${member} did not expose a connectable node identity"
}

wait_for_health() {
  local expected=$1
  local deadline=$((SECONDS + READY_TIMEOUT))
  local member
  local member_health
  local all_healthy

  while ((SECONDS < deadline)); do
    if LAST_HEALTH="$(garage_cli garage-1 json-api GetClusterHealth 2>/dev/null)"; then
      case "$expected" in
        healthy)
          all_healthy=true
          for member in "${MEMBERS[@]}"; do
            if ! member_health="$(garage_cli "$member" json-api GetClusterHealth 2>/dev/null)" \
              || ! jq -e '
                .connectedNodes == 3
                and .knownNodes == 3
                and .storageNodes == 3
                and .storageNodesUp == 3
                and .partitions == 256
                and .partitionsAllOk == 256
                and .partitionsQuorum == 256
                and .status == "healthy"
              ' <<< "$member_health" >/dev/null; then
              LAST_HEALTH="${member}: ${member_health:-no response}"
              all_healthy=false
              break
            fi
          done
          if [[ "$all_healthy" == true ]]; then
            return 0
          fi
          ;;
        one-down)
          all_healthy=true
          for member in garage-1 garage-2; do
            if ! member_health="$(garage_cli "$member" json-api GetClusterHealth 2>/dev/null)" \
              || ! jq -e '
                .connectedNodes == 2
                and .knownNodes == 3
                and .storageNodes == 3
                and .storageNodesUp == 2
                and .partitions == 256
                and .partitionsAllOk < 256
                and .partitionsQuorum == 256
              ' <<< "$member_health" >/dev/null; then
              LAST_HEALTH="${member}: ${member_health:-no response}"
              all_healthy=false
              break
            fi
          done
          if [[ "$all_healthy" == true ]]; then
            return 0
          fi
          ;;
        no-quorum)
          if jq -e '
            .connectedNodes == 1
            and .knownNodes == 3
            and .storageNodes == 3
            and .storageNodesUp == 1
            and .partitions == 256
            and .partitionsQuorum < 256
          ' <<< "$LAST_HEALTH" >/dev/null; then
            return 0
          fi
          ;;
        *)
          fail "Unknown Garage health expectation: ${expected}"
          ;;
      esac
    fi
    sleep 1
  done
  fail "Garage cluster did not reach ${expected} health: ${LAST_HEALTH:-no response}"
}

s3_request() {
  local endpoint=$1
  local access_key=$2
  local secret_key=$3
  shift 3

  AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" \
    timeout "$OPERATION_TIMEOUT" python3 "$S3_CLIENT" \
      --endpoint "$endpoint" \
      --region garage \
      "$@"
}

wait_for_s3_metadata() {
  local access_key=$1
  shift
  local deadline=$((SECONDS + READY_TIMEOUT))
  local bucket
  local member
  local all_visible

  while ((SECONDS < deadline)); do
    all_visible=true
    for member in "${MEMBERS[@]}"; do
      if ! garage_cli "$member" key info "$access_key" >/dev/null 2>&1; then
        all_visible=false
        break
      fi
      for bucket in "$@"; do
        if ! garage_cli "$member" bucket info "$bucket" >/dev/null 2>&1; then
          all_visible=false
          break 2
        fi
      done
    done
    if [[ "$all_visible" == true ]]; then
      return 0
    fi
    sleep 1
  done
  fail 'Garage key and bucket metadata did not become visible on every node'
}

LAST_STAGE='image pull and network creation'
timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 "$IMAGE" >/dev/null
if [[ "$TEST_LOKI" == true || "$TEST_LOKI_CLUSTER" == true ]]; then
  timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 "$LOKI_IMAGE" >/dev/null
fi
if [[ "$TEST_MIMIR" == true ]]; then
  timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 "$MIMIR_IMAGE" >/dev/null
fi
timeout "$OPERATION_TIMEOUT" podman network create \
  --label "$LABEL" "$NETWORK" >/dev/null
[[ "$(timeout "$OPERATION_TIMEOUT" \
  podman network inspect --format '{{.Internal}}' "$NETWORK")" == false ]] \
  || fail 'Disposable Garage bridge network has an unexpected mode'
if [[ "$TEST_LOKI_CLUSTER" == true || "$TEST_MIMIR" == true ]]; then
  network_subnet="$(timeout "$OPERATION_TIMEOUT" \
    podman network inspect --format '{{(index .Subnets 0).Subnet}}' "$NETWORK")"
fi
if [[ "$TEST_LOKI_CLUSTER" == true ]]; then
  mapfile -t LOKI_CLUSTER_IPS < <(python3 - "$network_subnet" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1])
if network.num_addresses < 8:
    raise SystemExit("disposable Podman subnet is too small for stable Loki addresses")
for offset in (4, 3, 2):
    print(network[-offset])
PY
  )
  [[ "${#LOKI_CLUSTER_IPS[@]}" == 3 ]] \
    || fail 'Could not derive three stable Loki addresses from the disposable network'
fi
if [[ "$TEST_MIMIR" == true ]]; then
  mapfile -t MIMIR_CLUSTER_IPS < <(python3 - "$network_subnet" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1])
if network.num_addresses < 12:
    raise SystemExit("disposable Podman subnet is too small for stable Mimir addresses")
for offset in (7, 6, 5):
    print(network[-offset])
PY
  )
  [[ "${#MIMIR_CLUSTER_IPS[@]}" == 3 ]] \
    || fail 'Could not derive three stable Mimir addresses from the disposable network'
fi

LAST_STAGE='container creation'
for member in "${MEMBERS[@]}"; do
  node_dir="${TEST_DIR}/${member}"
  mkdir -p "$node_dir/meta" "$node_dir/data" "$node_dir/snapshots"
  cat > "${node_dir}/garage.toml" <<EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
metadata_snapshots_dir = "/var/lib/garage/snapshots"
db_engine = "sqlite"
replication_factor = 3
consistency_mode = "consistent"
rpc_bind_addr = "0.0.0.0:3901"
rpc_public_addr = "${member}:3901"
rpc_secret = "${rpc_secret}"

[s3_api]
api_bind_addr = "0.0.0.0:3900"
s3_region = "garage"

[admin]
api_bind_addr = "0.0.0.0:3903"
admin_token = "${admin_token}"
metrics_token = "${metrics_token}"
metrics_require_token = true
EOF
  chmod 0600 "${node_dir}/garage.toml"
  container_id="$(timeout "$OPERATION_TIMEOUT" podman run \
    --detach \
    --name "${CONTAINERS[$member]}" \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$NETWORK" \
    --network-alias "$member" \
    --hostname "$member" \
    --read-only \
    --userns=keep-id:uid=10001,gid=10001 \
    --user 10001:10001 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --env RUST_LOG=warn \
    --volume "${node_dir}/garage.toml:/etc/garage.toml:ro,Z" \
    --volume "${node_dir}/meta:/var/lib/garage/meta:Z" \
    --volume "${node_dir}/data:/var/lib/garage/data:Z" \
    --volume "${node_dir}/snapshots:/var/lib/garage/snapshots:Z" \
    --publish 127.0.0.1::3900 \
    --entrypoint /garage \
    "$IMAGE" \
    --config /etc/garage.toml server)"
  CREATED_CONTAINERS+=("$container_id")
  [[ "$(timeout "$OPERATION_TIMEOUT" \
    podman inspect --format '{{.Config.User}}' "$container_id")" == 10001:10001 ]] \
    || fail "Garage member ${member} is not configured for UID/GID 10001"
  [[ "$(timeout "$OPERATION_TIMEOUT" \
    podman inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_id")" == true ]] \
    || fail "Garage member ${member} root filesystem is writable"
  host_endpoint="$(timeout "$OPERATION_TIMEOUT" podman port "$container_id" 3900/tcp)"
  [[ "$host_endpoint" =~ ^127[.]0[.]0[.]1:[0-9]+$ ]] \
    || fail "Garage member ${member} has an unsafe S3 host endpoint: ${host_endpoint}"
  S3_ENDPOINTS[$member]="http://${host_endpoint}"
done

LAST_STAGE='node identity and peer connection'
for member in "${MEMBERS[@]}"; do
  identity="$(wait_for_node_id "$member")"
  NODE_IDS[$member]="${identity%%@*}"
done
[[ "$(printf '%s\n' "${NODE_IDS[@]}" | sort -u | wc -l)" == 3 ]] \
  || fail 'Garage members did not generate three unique node identities'

garage_cli garage-2 node connect "${NODE_IDS[garage-1]}@garage-1:3901" >/dev/null
garage_cli garage-3 node connect "${NODE_IDS[garage-1]}@garage-1:3901" >/dev/null
LAST_STAGE='RF=3 layout assignment and convergence'
for index in 1 2 3; do
  member="garage-${index}"
  garage_cli garage-1 layout assign \
    "${NODE_IDS[$member]}" \
    --zone "zone-${index}" \
    --capacity 1GB \
    --tag "$member" >/dev/null
done
garage_cli garage-1 layout apply --version 1 >/dev/null
wait_for_health healthy

layout="$(garage_cli garage-1 json-api GetClusterLayout)"
jq -e '
  .version == 1
  and ([.roles[].zone] | sort == ["zone-1", "zone-2", "zone-3"])
  and all(.roles[]; .capacity == 1000000000 and .storedPartitions == 256)
' <<< "$layout" >/dev/null \
  || fail "Garage RF=3 layout does not contain three distinct zones: ${layout}"

LAST_STAGE='bucket and access-key creation'
garage_cli garage-1 bucket create qualification >/dev/null
garage_cli garage-1 bucket create isolated >/dev/null
if [[ "$TEST_LOKI" == true ]]; then
  garage_cli garage-1 bucket create loki-compat >/dev/null
fi
if [[ "$TEST_LOKI_CLUSTER" == true ]]; then
  garage_cli garage-1 bucket create loki-cluster >/dev/null
fi
if [[ "$TEST_MIMIR" == true ]]; then
  for bucket in mimir-blocks mimir-ruler mimir-alertmanager; do
    garage_cli garage-1 bucket create "$bucket" >/dev/null
  done
fi
key_json="$(garage_cli garage-1 json-api CreateKey '{"name":"qualification-client"}')"
access_key="$(jq -er '.accessKeyId' <<< "$key_json")"
secret_key="$(jq -er '.secretAccessKey' <<< "$key_json")"
[[ "$access_key" =~ ^GK[0-9a-f]{24}$ ]] || fail 'Garage returned an invalid access-key ID'
[[ -n "$secret_key" ]] || fail 'Garage returned an empty secret access key'
isolated_key_json="$(garage_cli garage-1 json-api CreateKey '{"name":"isolated-verifier"}')"
isolated_access_key="$(jq -er '.accessKeyId' <<< "$isolated_key_json")"
isolated_secret_key="$(jq -er '.secretAccessKey' <<< "$isolated_key_json")"
[[ "$isolated_access_key" =~ ^GK[0-9a-f]{24}$ ]] \
  || fail 'Garage returned an invalid isolated-bucket access-key ID'
[[ -n "$isolated_secret_key" ]] || fail 'Garage returned an empty isolated-bucket secret key'
garage_cli garage-1 bucket allow \
  --read --write --owner qualification --key "$access_key" >/dev/null
garage_cli garage-1 bucket allow \
  --read --write --owner isolated --key "$isolated_access_key" >/dev/null
wait_for_s3_metadata "$access_key" qualification
wait_for_s3_metadata "$isolated_access_key" isolated
wait_for_health healthy

if [[ "$TEST_LOKI" == true ]]; then
  LAST_STAGE='Loki access-key creation'
  loki_key_json="$(garage_cli garage-1 json-api CreateKey '{"name":"loki-compat"}')"
  loki_access_key="$(jq -er '.accessKeyId' <<< "$loki_key_json")"
  loki_secret_key="$(jq -er '.secretAccessKey' <<< "$loki_key_json")"
  garage_cli garage-1 bucket allow \
    --read --write --owner loki-compat --key "$loki_access_key" >/dev/null
  wait_for_s3_metadata "$loki_access_key" loki-compat
fi
if [[ "$TEST_LOKI_CLUSTER" == true ]]; then
  LAST_STAGE='Loki cluster access-key creation'
  loki_cluster_key_json="$(garage_cli garage-1 json-api CreateKey \
    '{"name":"loki-cluster"}')"
  loki_cluster_access_key="$(jq -er '.accessKeyId' <<< "$loki_cluster_key_json")"
  loki_cluster_secret_key="$(jq -er '.secretAccessKey' <<< "$loki_cluster_key_json")"
  garage_cli garage-1 bucket allow --read --write --owner loki-cluster \
    --key "$loki_cluster_access_key" >/dev/null
  wait_for_s3_metadata "$loki_cluster_access_key" loki-cluster
fi
if [[ "$TEST_MIMIR" == true ]]; then
  LAST_STAGE='Mimir access-key creation'
  for purpose in blocks ruler alertmanager; do
    bucket="mimir-${purpose}"
    mimir_key_json="$(garage_cli garage-1 json-api CreateKey \
      "$(jq -nc --arg name "$bucket" '{name: $name}')")"
    MIMIR_ACCESS_KEYS[$purpose]="$(jq -er '.accessKeyId' <<< "$mimir_key_json")"
    MIMIR_SECRET_KEYS[$purpose]="$(jq -er '.secretAccessKey' <<< "$mimir_key_json")"
    [[ "${MIMIR_ACCESS_KEYS[$purpose]}" =~ ^GK[0-9a-f]{24}$ ]] \
      || fail "Garage returned an invalid Mimir ${purpose} access-key ID"
    [[ -n "${MIMIR_SECRET_KEYS[$purpose]}" ]] \
      || fail "Garage returned an empty Mimir ${purpose} secret key"
    garage_cli garage-1 bucket allow \
      --read --write --owner "$bucket" --key "${MIMIR_ACCESS_KEYS[$purpose]}" >/dev/null
    wait_for_s3_metadata "${MIMIR_ACCESS_KEYS[$purpose]}" "$bucket"
  done
fi

initial_body="${TEST_DIR}/initial-body"
during_loss_body="${TEST_DIR}/during-loss-body"
response_body="${TEST_DIR}/response-body"
printf '%s' 'garage-rf3-initial-canary' > "$initial_body"
printf '%s' 'garage-rf3-during-loss-canary' > "$during_loss_body"
object_key='qualification/encoded path+percent%25.txt'

LAST_STAGE='initial signed PUT'
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method PUT --bucket qualification --key "$object_key" \
  --body-file "$initial_body" --output "$response_body" --expect-status 200 >/dev/null
LAST_STAGE='cross-node signed GET'
s3_request "${S3_ENDPOINTS[garage-2]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --key "$object_key" \
  --output "$response_body" --expect-status 200 >/dev/null
cmp -- "$initial_body" "$response_body" \
  || fail 'Garage signed S3 GET did not return the initial object bytes'
LAST_STAGE='signed filtered ListObjectsV2'
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --query 'list-type=2' \
  --query 'prefix=qualification/' --output "$response_body" --expect-status 200 >/dev/null
grep -Fq '<Key>qualification/encoded path+percent%25.txt</Key>' "$response_body" \
  || fail 'Garage signed and filtered ListObjectsV2 omitted the initial object'
LAST_STAGE='signed range GET'
s3_request "${S3_ENDPOINTS[garage-3]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --key "$object_key" --range 'bytes=7-9' \
  --output "$response_body" --expect-status 206 >/dev/null
[[ "$(<"$response_body")" == rf3 ]] || fail 'Garage signed range request returned wrong bytes'
LAST_STAGE='wrong-secret rejection'
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" wrong-secret \
  --method GET --bucket qualification --key "$object_key" \
  --output "$response_body" --expect-status 403 >/dev/null
LAST_STAGE='bucket isolation rejection'
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method GET --bucket isolated --query 'list-type=2' \
  --output "$response_body" --expect-status 403 >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$isolated_access_key" "$isolated_secret_key" \
  --method PUT --bucket isolated --key 'protected.txt' \
  --body-file "$initial_body" --output "$response_body" --expect-status 200 >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method PUT --bucket isolated --key 'denied-put.txt' \
  --body-file "$during_loss_body" --output "$response_body" --expect-status 403 >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method DELETE --bucket isolated --key 'protected.txt' \
  --output "$response_body" --expect-status 403 >/dev/null
s3_request "${S3_ENDPOINTS[garage-2]}" "$isolated_access_key" "$isolated_secret_key" \
  --method GET --bucket isolated --key 'protected.txt' \
  --output "$response_body" --expect-status 200 >/dev/null
cmp -- "$initial_body" "$response_body" \
  || fail 'Denied cross-bucket DELETE changed the isolated object'
s3_request "${S3_ENDPOINTS[garage-2]}" "$isolated_access_key" "$isolated_secret_key" \
  --method GET --bucket isolated --key 'denied-put.txt' \
  --output "$response_body" --expect-status 404 >/dev/null

if [[ "$TEST_LOKI" == true ]]; then
  LAST_STAGE='Loki credential isolation'
  s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
    --method PUT --bucket loki-compat --key 'qualification-key-denied.txt' \
    --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-2]}" "$loki_access_key" "$loki_secret_key" \
    --method GET --bucket loki-compat --key 'qualification-key-denied.txt' \
    --output "$response_body" --expect-status 404 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-1]}" "$loki_access_key" "$loki_secret_key" \
    --method PUT --bucket qualification --key 'loki-key-denied.txt' \
    --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-2]}" "$access_key" "$secret_key" \
    --method GET --bucket qualification --key 'loki-key-denied.txt' \
    --output "$response_body" --expect-status 404 >/dev/null

  LAST_STAGE='Loki target-all startup'
  loki_data="${TEST_DIR}/loki-data"
  mkdir -p "$loki_data"
  loki_container="${RUN_ID}-loki"
  loki_container_id="$(timeout "$OPERATION_TIMEOUT" podman run \
    --detach \
    --name "$loki_container" \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$NETWORK" \
    --network-alias loki \
    --read-only \
    --userns=keep-id:uid=10001,gid=10001 \
    --user 10001:10001 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --env LOKI_S3_ACCESS_KEY_ID="$loki_access_key" \
    --env LOKI_S3_SECRET_ACCESS_KEY="$loki_secret_key" \
    --volume "${LOKI_CONFIG}:/etc/loki/loki.yaml:ro,Z" \
    --volume "${loki_data}:/loki:Z" \
    --publish 127.0.0.1::3100 \
    --entrypoint /usr/bin/loki \
    "$LOKI_IMAGE" \
    -config.file=/etc/loki/loki.yaml \
    -config.expand-env=true \
    -target=all)"
  CREATED_CONTAINERS+=("$loki_container_id")
  loki_host="$(timeout "$OPERATION_TIMEOUT" podman port "$loki_container_id" 3100/tcp)"
  loki_endpoint="http://${loki_host}"
  ready=false
  loki_deadline=$((SECONDS + LOKI_READY_TIMEOUT))
  while ((SECONDS < loki_deadline)); do
    if curl -fsS --connect-timeout 2 --max-time 3 "${loki_endpoint}/ready" >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ "$ready" == true ]] || fail 'Loki target-all process did not become ready'
  build_info="$(curl -fsS --connect-timeout 2 --max-time 5 \
    "${loki_endpoint}/loki/api/v1/status/buildinfo")"
  jq -e --arg version "$LOKI_VERSION" '.version == $version' <<< "$build_info" >/dev/null \
    || fail "Loki runtime version mismatch: ${build_info}"

  LAST_STAGE='Loki native push and query'
  loki_token="garage-loki-$RANDOM-$RANDOM"
  loki_timestamp="$(date +%s%N)"
  loki_start=$((loki_timestamp - 60000000000))
  loki_end=$((loki_timestamp + 60000000000))
  loki_payload="$(jq -nc --arg timestamp "$loki_timestamp" --arg token "$loki_token" '
    {streams: [{stream: {app: "garage-compat"}, values: [[$timestamp, $token]]}]}
  ')"
  curl -fsS --connect-timeout 2 --max-time 10 \
    -H 'Content-Type: application/json' \
    -X POST "${loki_endpoint}/loki/api/v1/push" \
    --data-binary "$loki_payload" >/dev/null
  loki_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
    --data-urlencode 'query={app="garage-compat"}' \
    --data-urlencode "start=${loki_start}" \
    --data-urlencode "end=${loki_end}" \
    --data-urlencode 'direction=forward' \
    --data-urlencode 'limit=10' \
    "${loki_endpoint}/loki/api/v1/query_range")"
  jq -e --arg token "$loki_token" '
    .status == "success" and any(.data.result[].values[]; .[1] == $token)
  ' <<< "$loki_query" >/dev/null || fail 'Loki immediate query omitted the pushed canary'

  LAST_STAGE='Loki flush and Garage object upload'
  curl -fsS --connect-timeout 2 --max-time 30 -X POST "${loki_endpoint}/flush" >/dev/null
  loki_objects=false
  loki_deadline=$((SECONDS + LOKI_READY_TIMEOUT))
  while ((SECONDS < loki_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" "$loki_access_key" "$loki_secret_key" \
      --method GET --bucket loki-compat --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    if grep -Fq '<Key>' "$response_body"; then
      loki_objects=true
      break
    fi
    sleep 1
  done
  [[ "$loki_objects" == true ]] || fail 'Loki flush produced no Garage objects'

  LAST_STAGE='Loki fresh-local-state Garage query'
  timeout 40 podman stop --time 30 "$loki_container" >/dev/null
  timeout "$OPERATION_TIMEOUT" podman rm "$loki_container" >/dev/null
  rm -rf -- "$loki_data"
  mkdir -p "$loki_data"
  loki_fresh_container="${RUN_ID}-loki-fresh"
  loki_fresh_id="$(timeout "$OPERATION_TIMEOUT" podman run \
    --detach \
    --name "$loki_fresh_container" \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$NETWORK" \
    --network-alias loki \
    --read-only \
    --userns=keep-id:uid=10001,gid=10001 \
    --user 10001:10001 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --env LOKI_S3_ACCESS_KEY_ID="$loki_access_key" \
    --env LOKI_S3_SECRET_ACCESS_KEY="$loki_secret_key" \
    --volume "${LOKI_CONFIG}:/etc/loki/loki.yaml:ro,Z" \
    --volume "${loki_data}:/loki:Z" \
    --publish 127.0.0.1::3100 \
    --entrypoint /usr/bin/loki \
    "$LOKI_IMAGE" \
    -config.file=/etc/loki/loki.yaml \
    -config.expand-env=true \
    -target=all)"
  CREATED_CONTAINERS+=("$loki_fresh_id")
  loki_fresh_host="$(timeout "$OPERATION_TIMEOUT" podman port "$loki_fresh_id" 3100/tcp)"
  loki_fresh_endpoint="http://${loki_fresh_host}"
  persisted_query=false
  loki_deadline=$((SECONDS + LOKI_READY_TIMEOUT))
  while ((SECONDS < loki_deadline)); do
    if curl -fsS --connect-timeout 2 --max-time 10 "${loki_fresh_endpoint}/ready" \
      >/dev/null 2>&1; then
      loki_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
        --data-urlencode 'query={app="garage-compat"}' \
        --data-urlencode "start=${loki_start}" \
        --data-urlencode "end=${loki_end}" \
        --data-urlencode 'direction=forward' \
        --data-urlencode 'limit=10' \
        "${loki_fresh_endpoint}/loki/api/v1/query_range" 2>/dev/null || true)"
      if jq -e --arg token "$loki_token" '
        .status == "success" and any(.data.result[].values[]; .[1] == $token)
      ' <<< "$loki_query" >/dev/null 2>&1; then
        persisted_query=true
        break
      fi
    fi
    sleep 1
  done
  [[ "$persisted_query" == true ]] \
    || fail 'Fresh-local-state Loki did not query the Garage-backed canary'
  timeout 40 podman stop --time 30 "$loki_fresh_container" >/dev/null
fi

if [[ "$TEST_LOKI_CLUSTER" == true ]]; then
  loki_cluster_metric_is() {
    local metrics=$1
    local name=$2
    local state=$3
    local value=$4

    grep -Eq "^loki_ring_members\\{name=\"${name}\",state=\"${state}\"\\} ${value}([.]0+)?$" \
      <<< "$metrics"
  }

  loki_cluster_compactor_state() {
    local metrics=$1
    local value=$2

    grep -Eq "^loki_boltdb_shipper_compactor_running ${value}([.]0+)?$" <<< "$metrics"
  }

  wait_for_loki_cluster() {
    local deadline=$((SECONDS + LOKI_READY_TIMEOUT))
    local member
    local memberlist_status
    local metrics
    local all_converged
    local active_compactors

    while ((SECONDS < deadline)); do
      all_converged=true
      active_compactors=0
      for member in "${LOKI_CLUSTER_MEMBERS[@]}"; do
        if ! curl -fsS --connect-timeout 2 --max-time 3 \
          "${LOKI_CLUSTER_ENDPOINTS[$member]}/ready" >/dev/null 2>&1; then
          LAST_LOKI_CLUSTER_STATE="${member}: not ready"
          all_converged=false
          break
        fi
        if ! memberlist_status="$(curl -fsS --connect-timeout 2 --max-time 5 \
          -H 'Accept: application/json' \
          "${LOKI_CLUSTER_ENDPOINTS[$member]}/memberlist" 2>/dev/null)" \
          || ! jq -e --argjson expected "$LOKI_CLUSTER_NAMES_JSON" \
            '[.SortedMembers[].Name] | sort == ($expected | sort)' \
            <<< "$memberlist_status" >/dev/null 2>&1; then
          LAST_LOKI_CLUSTER_STATE="${member}: memberlist=${memberlist_status:-no response}"
          all_converged=false
          break
        fi
        if ! metrics="$(curl -fsS --connect-timeout 2 --max-time 5 \
          "${LOKI_CLUSTER_ENDPOINTS[$member]}/metrics" 2>/dev/null)" \
          || ! loki_cluster_metric_is "$metrics" ingester ACTIVE 3 \
          || ! loki_cluster_metric_is "$metrics" scheduler ACTIVE 3 \
          || ! loki_cluster_metric_is "$metrics" ruler ACTIVE 3 \
          || ! loki_cluster_metric_is "$metrics" compactor ACTIVE 3; then
          LAST_LOKI_CLUSTER_STATE="${member}: $(grep -E \
            '^loki_ring_members|^loki_boltdb_shipper_compactor_running' \
            <<< "${metrics:-no metrics}" || true)"
          all_converged=false
          break
        fi
        if loki_cluster_compactor_state "$metrics" 1; then
          ((active_compactors += 1))
        elif ! loki_cluster_compactor_state "$metrics" 0; then
          LAST_LOKI_CLUSTER_STATE="${member}: compactor leader metric absent"
          all_converged=false
          break
        fi
      done
      if [[ "$all_converged" == true && "$active_compactors" == 1 ]]; then
        LAST_LOKI_CLUSTER_STATE=
        return 0
      fi
      if [[ "$all_converged" == true ]]; then
        LAST_LOKI_CLUSTER_STATE="active compactors observed: ${active_compactors}"
      fi
      sleep 1
    done
    return 1
  }

  wait_for_loki_loss() {
    local deadline=$((SECONDS + LOKI_READY_TIMEOUT))
    local member
    local metrics
    local loss_visible

    while ((SECONDS < deadline)); do
      loss_visible=true
      for member in loki-cluster-1 loki-cluster-2; do
        if ! metrics="$(curl -fsS --connect-timeout 2 --max-time 5 \
          "${LOKI_CLUSTER_ENDPOINTS[$member]}/metrics" 2>/dev/null)" \
          || ! loki_cluster_metric_is "$metrics" ingester ACTIVE 2 \
          || ! loki_cluster_metric_is "$metrics" ingester Unhealthy 1; then
          loss_visible=false
          break
        fi
      done
      if [[ "$loss_visible" == true ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  loki_cluster_push() {
    local endpoint=$1
    local timestamp=$2
    local token=$3
    local lifecycle=${4:-retained}
    local payload

    payload="$(jq -nc --arg timestamp "$timestamp" --arg token "$token" \
      --arg qualification "$loki_cluster_case" --arg lifecycle "$lifecycle" '
      {streams: [{stream: {app: "garage-loki-cluster", qualification: $qualification,
        lifecycle: $lifecycle},
        values: [[$timestamp, $token]]}]}
    ')"
    curl -fsS --connect-timeout 2 --max-time 10 \
      -H 'Content-Type: application/json' \
      -X POST "${endpoint}/loki/api/v1/push" --data-binary "$payload" >/dev/null
  }

  wait_for_loki_cluster_query() {
    local endpoint=$1
    local start=$2
    local end=$3
    shift 3
    local deadline=$((SECONDS + LOKI_READY_TIMEOUT))
    local response
    local token
    local all_found

    while ((SECONDS < deadline)); do
      response="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
        --data-urlencode \
          "query={app=\"garage-loki-cluster\",qualification=\"${loki_cluster_case}\"}" \
        --data-urlencode "start=${start}" \
        --data-urlencode "end=${end}" \
        --data-urlencode 'direction=forward' \
        --data-urlencode 'limit=20' \
        "${endpoint}/loki/api/v1/query_range" 2>/dev/null || true)"
      all_found=true
      for token in "$@"; do
        if ! jq -e --arg token "$token" '
          .status == "success" and any(.data.result[].values[]; .[1] == $token)
        ' <<< "$response" >/dev/null 2>&1; then
          all_found=false
          break
        fi
      done
      if [[ "$all_found" == true ]]; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  loki_metric_positive() {
    local metrics=$1
    local name=$2
    local labels=${3:-}

    grep -Eq "^${name}(\\{[^}]*${labels}[^}]*\\})? [1-9][0-9]*([.]0+)?$" \
      <<< "$metrics"
  }

  LAST_STAGE='Loki cluster credential isolation'
  s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
    --method PUT --bucket loki-cluster --key 'qualification-key-denied.txt' \
    --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-2]}" \
    "$loki_cluster_access_key" "$loki_cluster_secret_key" \
    --method GET --bucket loki-cluster --key 'qualification-key-denied.txt' \
    --output "$response_body" --expect-status 404 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-1]}" \
    "$loki_cluster_access_key" "$loki_cluster_secret_key" \
    --method PUT --bucket qualification --key 'loki-cluster-key-denied.txt' \
    --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-2]}" "$access_key" "$secret_key" \
    --method GET --bucket qualification --key 'loki-cluster-key-denied.txt' \
    --output "$response_body" --expect-status 404 >/dev/null

  LAST_STAGE='three-node Loki target-all startup'
  for index in 1 2 3; do
    member="loki-cluster-${index}"
    data_dir="${TEST_DIR}/${member}-data"
    container_name="${RUN_ID}-${member}"
    mkdir -p "$data_dir"
    LOKI_CLUSTER_DATA_DIRS[$member]="$data_dir"
    LOKI_CLUSTER_CONTAINERS[$member]="$container_name"
    container_id="$(timeout "$OPERATION_TIMEOUT" podman run \
      --detach \
      --name "$container_name" \
      --hostname "$member" \
      --label "$LABEL" \
      --platform linux/amd64 \
      --pull never \
      --network "$NETWORK" \
      --network-alias "$member" \
      --ip "${LOKI_CLUSTER_IPS[$((index - 1))]}" \
      --read-only \
      --userns=keep-id:uid=10001,gid=10001 \
      --user 10001:10001 \
      --cap-drop all \
      --security-opt no-new-privileges \
      --env LOKI_NODE_NAME="$member" \
      --env LOKI_DATA_DIR="/loki/${member}" \
      --env LOKI_CLUSTER_S3_ACCESS_KEY_ID="$loki_cluster_access_key" \
      --env LOKI_CLUSTER_S3_SECRET_ACCESS_KEY="$loki_cluster_secret_key" \
      --volume "${LOKI_CLUSTER_CONFIG}:/etc/loki/loki.yaml:ro,z" \
      --volume "${data_dir}:/loki/${member}:Z" \
      --publish 127.0.0.1::3100 \
      --entrypoint /usr/bin/loki \
      "$LOKI_IMAGE" \
      -config.file=/etc/loki/loki.yaml \
      -config.expand-env=true \
      -target=all)"
    CREATED_CONTAINERS+=("$container_id")
    inspect="$(timeout "$OPERATION_TIMEOUT" podman inspect "$container_id")"
    jq -e --arg hostname "$member" '
      .[0].Config.User == "10001:10001"
      and .[0].Config.Hostname == $hostname
      and .[0].HostConfig.ReadonlyRootfs == true
      and (([
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
        "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID",
        "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT"
      ] - (.[0].HostConfig.CapDrop // [])) | length == 0)
      and ((.[0].HostConfig.CapAdd // []) | length == 0)
      and ((.[0].HostConfig.SecurityOpt // [])
        | any(startswith("no-new-privileges")))
    ' <<< "$inspect" >/dev/null \
      || fail "Loki member ${member} does not have the required container hardening"
    loki_host="$(timeout "$OPERATION_TIMEOUT" podman port "$container_id" 3100/tcp)"
    [[ "$loki_host" =~ ^127[.]0[.]0[.]1:[0-9]+$ ]] \
      || fail "Loki member ${member} has an unsafe HTTP host endpoint: ${loki_host}"
    LOKI_CLUSTER_ENDPOINTS[$member]="http://${loki_host}"
  done
  [[ "$(printf '%s\n' "${LOKI_CLUSTER_DATA_DIRS[@]}" | sort -u | wc -l)" == 3 ]] \
    || fail 'Loki members do not have three distinct local-state directories'

  LAST_STAGE='initial Loki memberlist and ring convergence'
  wait_for_loki_cluster \
    || fail "Loki cluster did not reach three ready members and one active compactor: ${LAST_LOKI_CLUSTER_STATE}"
  for member in "${LOKI_CLUSTER_MEMBERS[@]}"; do
    build_info="$(curl -fsS --connect-timeout 2 --max-time 5 \
      "${LOKI_CLUSTER_ENDPOINTS[$member]}/loki/api/v1/status/buildinfo")"
    jq -e --arg version "$LOKI_VERSION" '.version == $version' \
      <<< "$build_info" >/dev/null \
      || fail "Loki member ${member} runtime version mismatch: ${build_info}"
  done

  LAST_STAGE='cross-node Loki push and query'
  loki_cluster_case="case-$RANDOM-$RANDOM"
  loki_cluster_expired_token="garage-loki-cluster-expired-$RANDOM-$RANDOM"
  loki_cluster_expired_timestamp="$(date -d '-23 hours -59 minutes' +%s%N)"
  loki_cluster_expired_start=$((loki_cluster_expired_timestamp - 60000000000))
  loki_cluster_expired_end=$((loki_cluster_expired_timestamp + 60000000000))
  loki_cluster_push "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-1]}" \
    "$loki_cluster_expired_timestamp" "$loki_cluster_expired_token" expired
  for member in "${LOKI_CLUSTER_MEMBERS[@]}"; do
    curl -fsS --connect-timeout 2 --max-time 30 -X POST \
      "${LOKI_CLUSTER_ENDPOINTS[$member]}/flush" >/dev/null
  done
  wait_for_loki_cluster_query "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-2]}" \
    "$loki_cluster_expired_start" "$loki_cluster_expired_end" \
    "$loki_cluster_expired_token" \
    || fail 'Cross-node Loki query omitted the pre-retention canary'
  loki_cluster_initial_token="garage-loki-cluster-initial-$RANDOM-$RANDOM"
  loki_cluster_initial_timestamp="$(date +%s%N)"
  loki_cluster_start=$((loki_cluster_initial_timestamp - 60000000000))
  loki_cluster_push "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-1]}" \
    "$loki_cluster_initial_timestamp" "$loki_cluster_initial_token"
  wait_for_loki_cluster_query "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-2]}" \
    "$loki_cluster_start" $((loki_cluster_initial_timestamp + 60000000000)) \
    "$loki_cluster_initial_token" \
    || fail 'Cross-node Loki query omitted the initial canary'

  loki_cluster_stopped_data="${LOKI_CLUSTER_DATA_DIRS[loki-cluster-3]}"
  for token_file in ingester.tokens compactor.tokens scheduler.tokens; do
    [[ -s "${loki_cluster_stopped_data}/${token_file}" ]] \
      || fail "Loki member 3 did not persist ${token_file}"
  done
  [[ -n "$(find "${loki_cluster_stopped_data}/wal" -type f -size +0c -print -quit)" ]] \
    || fail 'Loki member 3 WAL has no persisted canary data'
  loki_cluster_token_snapshot="$(sha256sum \
    "${loki_cluster_stopped_data}/ingester.tokens" \
    "${loki_cluster_stopped_data}/compactor.tokens" \
    "${loki_cluster_stopped_data}/scheduler.tokens")"
  loki_cluster_stopped_id="$(timeout "$OPERATION_TIMEOUT" podman inspect \
    --format '{{.Id}}' "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}")"

  LAST_STAGE='one-node Loki loss detection'
  timeout "$OPERATION_TIMEOUT" podman stop --time 0 \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}" >/dev/null
  wait_for_loki_loss || fail 'Surviving Loki members did not mark member 3 unhealthy'

  LAST_STAGE='one-node-loss Loki write and cross-node queries'
  loki_cluster_loss_token="garage-loki-cluster-loss-$RANDOM-$RANDOM"
  loki_cluster_loss_timestamp="$(date +%s%N)"
  loki_cluster_end=$((loki_cluster_loss_timestamp + 60000000000))
  loki_cluster_push "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-1]}" \
    "$loki_cluster_loss_timestamp" "$loki_cluster_loss_token"
  wait_for_loki_cluster_query "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-2]}" \
    "$loki_cluster_start" "$loki_cluster_end" \
    "$loki_cluster_initial_token" "$loki_cluster_loss_token" \
    || fail 'Surviving Loki query omitted a canary after one-node loss'

  LAST_STAGE='same-node Loki restart and ring convergence'
  timeout "$OPERATION_TIMEOUT" podman start \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}" >/dev/null
  [[ "$(timeout "$OPERATION_TIMEOUT" podman inspect --format '{{.Id}}' \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}")" == "$loki_cluster_stopped_id" ]] \
    || fail 'Loki member 3 was replaced instead of restarted'
  wait_for_loki_cluster \
    || fail "Restarted Loki member did not rejoin all rings without manual reconnection: ${LAST_LOKI_CLUSTER_STATE}"
  [[ "$(sha256sum \
    "${loki_cluster_stopped_data}/ingester.tokens" \
    "${loki_cluster_stopped_data}/compactor.tokens" \
    "${loki_cluster_stopped_data}/scheduler.tokens")" == "$loki_cluster_token_snapshot" ]] \
    || fail 'Restarted Loki member did not retain its persisted ring tokens'
  wait_for_loki_cluster_query "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-3]}" \
    "$loki_cluster_start" "$loki_cluster_end" \
    "$loki_cluster_initial_token" "$loki_cluster_loss_token" \
    || fail 'Restarted Loki member query omitted a qualification canary'

  LAST_STAGE='Loki cluster flush and Garage object upload'
  for member in "${LOKI_CLUSTER_MEMBERS[@]}"; do
    curl -fsS --connect-timeout 2 --max-time 30 -X POST \
      "${LOKI_CLUSTER_ENDPOINTS[$member]}/flush" >/dev/null
  done
  loki_cluster_objects=false
  loki_deadline=$((SECONDS + LOKI_READY_TIMEOUT))
  while ((SECONDS < loki_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" \
      "$loki_cluster_access_key" "$loki_cluster_secret_key" \
      --method GET --bucket loki-cluster --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    if grep -Fq '<Key>' "$response_body"; then
      loki_cluster_objects=true
      break
    fi
    sleep 1
  done
  [[ "$loki_cluster_objects" == true ]] \
    || fail 'Three-node Loki flush produced no objects in its dedicated Garage bucket'
  loki_cluster_initial_chunk_count="$(
    grep -Eo '<Key>fake/[^<]+</Key>' "$response_body" | wc -l || true
  )"
  ((loki_cluster_initial_chunk_count >= 2)) \
    || fail "Loki flush produced too few chunks to qualify retention: ${loki_cluster_initial_chunk_count}"

  LAST_STAGE='Loki compaction and retention'
  loki_lifecycle_deadline=$((SECONDS + LOKI_LIFECYCLE_TIMEOUT))
  loki_lifecycle_complete=false
  loki_compacted_index=false
  loki_compaction_succeeded=false
  loki_retention_marked=false
  loki_retention_swept=false
  while ((SECONDS < loki_lifecycle_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" \
      "$loki_cluster_access_key" "$loki_cluster_secret_key" \
      --method GET --bucket loki-cluster --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    loki_cluster_listing="$(<"$response_body")"
    loki_cluster_chunk_count="$(
      grep -Eo '<Key>fake/[^<]+</Key>' <<< "$loki_cluster_listing" \
        | wc -l || true
    )"
    loki_cluster_metrics=
    for member in "${LOKI_CLUSTER_MEMBERS[@]}"; do
      loki_cluster_metrics+="$(curl -fsS --connect-timeout 2 --max-time 5 \
        "${LOKI_CLUSTER_ENDPOINTS[$member]}/metrics" 2>/dev/null || true)"$'\n'
    done
    loki_expired_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
      --data-urlencode \
        "query={app=\"garage-loki-cluster\",qualification=\"${loki_cluster_case}\"}" \
      --data-urlencode "start=${loki_cluster_expired_start}" \
      --data-urlencode "end=${loki_cluster_expired_end}" \
      --data-urlencode 'direction=forward' \
      --data-urlencode 'limit=20' \
      "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-1]}/loki/api/v1/query_range" \
      2>/dev/null || true)"
    loki_current_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
      --data-urlencode \
        "query={app=\"garage-loki-cluster\",qualification=\"${loki_cluster_case}\"}" \
      --data-urlencode "start=${loki_cluster_start}" \
      --data-urlencode "end=${loki_cluster_end}" \
      --data-urlencode 'direction=forward' \
      --data-urlencode 'limit=20' \
      "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-2]}/loki/api/v1/query_range" \
      2>/dev/null || true)"
    loki_chunks_deleted=false
    loki_expired_absent=false
    loki_current_present=false
    grep -Eq \
      '<Key>index/index_[0-9]+/fake/[^<]*-compactor-[^<]*[.]tsdb([.]gz)?</Key>' \
      <<< "$loki_cluster_listing" && loki_compacted_index=true
    loki_metric_positive "$loki_cluster_metrics" \
      loki_boltdb_shipper_compact_tables_operation_total 'status="success"' \
      && loki_compaction_succeeded=true
    loki_metric_positive "$loki_cluster_metrics" \
      loki_boltdb_shipper_retention_marker_count_total \
      && loki_retention_marked=true
    loki_metric_positive "$loki_cluster_metrics" \
      loki_boltdb_shipper_retention_sweeper_marker_files_deleted_total \
      && loki_retention_swept=true
    ((loki_cluster_chunk_count < loki_cluster_initial_chunk_count)) \
      && loki_chunks_deleted=true
    jq -e --arg token "$loki_cluster_expired_token" '
        .status == "success"
        and all(.data.result[].values[]; .[1] != $token)
      ' <<< "$loki_expired_query" >/dev/null 2>&1 \
      && loki_expired_absent=true
    jq -e --arg initial "$loki_cluster_initial_token" \
      --arg loss "$loki_cluster_loss_token" '
        .status == "success"
        and any(.data.result[].values[]; .[1] == $initial)
        and any(.data.result[].values[]; .[1] == $loss)
      ' <<< "$loki_current_query" >/dev/null 2>&1 \
      && loki_current_present=true
    # Warm querier index state can retain an expired chunk reference after the
    # sweeper deletes the object. Cold-state absence is required below.
    if [[ "$loki_compacted_index" == true \
        && "$loki_compaction_succeeded" == true \
        && "$loki_retention_marked" == true \
        && "$loki_retention_swept" == true \
        && "$loki_chunks_deleted" == true \
        && "$loki_current_present" == true ]]; then
      loki_lifecycle_complete=true
      break
    fi
    sleep 2
  done
  if [[ "$loki_lifecycle_complete" != true ]]; then
    printf '%s\n' \
      "Loki lifecycle evidence: compacted_index=${loki_compacted_index}, compaction_succeeded=${loki_compaction_succeeded}, retention_marked=${loki_retention_marked}, retention_swept=${loki_retention_swept}, chunks=${loki_cluster_chunk_count}/${loki_cluster_initial_chunk_count}, expired_absent=${loki_expired_absent}, current_present=${loki_current_present}" \
      >&2
    grep -E '^loki_boltdb_shipper_(compact_tables_operation_total|retention_marker_count_total|retention_sweeper_marker_files_deleted_total)' \
      <<< "$loki_cluster_metrics" >&2 || true
    fail 'Loki did not compact its index and physically delete only the expired canary'
  fi

  LAST_STAGE='empty-local-state Loki cluster restart'
  timeout 40 podman stop --time 10 \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-1]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-2]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}" >/dev/null
  for member in "${LOKI_CLUSTER_MEMBERS[@]}"; do
    find "${LOKI_CLUSTER_DATA_DIRS[$member]}" -mindepth 1 -delete
  done
  timeout "$OPERATION_TIMEOUT" podman start \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-1]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-2]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}" >/dev/null
  wait_for_loki_cluster \
    || fail "Empty-local-state Loki cluster did not converge: ${LAST_LOKI_CLUSTER_STATE}"
  wait_for_loki_cluster_query "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-1]}" \
    "$loki_cluster_start" "$loki_cluster_end" \
    "$loki_cluster_initial_token" "$loki_cluster_loss_token" \
    || fail 'Empty-local-state Loki cluster did not query both Garage-backed canaries'
  loki_expired_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
    --data-urlencode \
      "query={app=\"garage-loki-cluster\",qualification=\"${loki_cluster_case}\"}" \
    --data-urlencode "start=${loki_cluster_expired_start}" \
    --data-urlencode "end=${loki_cluster_expired_end}" \
    --data-urlencode 'direction=forward' \
    --data-urlencode 'limit=20' \
    "${LOKI_CLUSTER_ENDPOINTS[loki-cluster-2]}/loki/api/v1/query_range")"
  jq -e --arg token "$loki_cluster_expired_token" '
    .status == "success"
    and all(.data.result[].values[]; .[1] != $token)
  ' <<< "$loki_expired_query" >/dev/null \
    || fail 'Empty-local-state Loki cluster recovered the expired Garage canary'

  LAST_STAGE='three-node Loki shutdown'
  timeout 40 podman stop --time 10 \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-1]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-2]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}" >/dev/null
fi

if [[ "$TEST_MIMIR" == true ]]; then
  LAST_STAGE='Mimir credential isolation'
  for purpose in blocks ruler alertmanager; do
    bucket="mimir-${purpose}"
    denied_key="qualification-key-denied-in-${purpose}.txt"
    s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
      --method PUT --bucket "$bucket" --key "$denied_key" \
      --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
    s3_request "${S3_ENDPOINTS[garage-2]}" \
      "${MIMIR_ACCESS_KEYS[$purpose]}" "${MIMIR_SECRET_KEYS[$purpose]}" \
      --method GET --bucket "$bucket" --key "$denied_key" \
      --output "$response_body" --expect-status 404 >/dev/null
    s3_request "${S3_ENDPOINTS[garage-1]}" \
      "${MIMIR_ACCESS_KEYS[$purpose]}" "${MIMIR_SECRET_KEYS[$purpose]}" \
      --method PUT --bucket qualification --key "mimir-${purpose}-key-denied.txt" \
      --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
    s3_request "${S3_ENDPOINTS[garage-2]}" "$access_key" "$secret_key" \
      --method GET --bucket qualification --key "mimir-${purpose}-key-denied.txt" \
      --output "$response_body" --expect-status 404 >/dev/null
  done
  for source_purpose in blocks ruler alertmanager; do
    for target_purpose in blocks ruler alertmanager; do
      [[ "$source_purpose" != "$target_purpose" ]] || continue
      denied_key="mimir-${source_purpose}-key-denied-in-${target_purpose}.txt"
      s3_request "${S3_ENDPOINTS[garage-1]}" \
        "${MIMIR_ACCESS_KEYS[$source_purpose]}" \
        "${MIMIR_SECRET_KEYS[$source_purpose]}" \
        --method PUT --bucket "mimir-${target_purpose}" --key "$denied_key" \
        --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
      s3_request "${S3_ENDPOINTS[garage-2]}" \
        "${MIMIR_ACCESS_KEYS[$target_purpose]}" \
        "${MIMIR_SECRET_KEYS[$target_purpose]}" \
        --method GET --bucket "mimir-${target_purpose}" --key "$denied_key" \
        --output "$response_body" --expect-status 404 >/dev/null
    done
  done

  mimir_cluster_metric_is() {
    local metrics=$1
    local name=$2
    local state=$3
    local value=$4

    grep -Eq "^cortex_ring_members\\{name=\"${name}\",state=\"${state}\"\\} ${value}([.]0+)?$" \
      <<< "$metrics"
  }

  wait_for_mimir_cluster() {
    local deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
    local member
    local memberlist_status
    local metrics
    local ring
    local all_converged

    while ((SECONDS < deadline)); do
      all_converged=true
      for member in "${MIMIR_CLUSTER_MEMBERS[@]}"; do
        if ! curl -fsS --connect-timeout 2 --max-time 3 \
          "${MIMIR_CLUSTER_ENDPOINTS[$member]}/ready" >/dev/null 2>&1; then
          LAST_MIMIR_CLUSTER_STATE="${member}: not ready"
          all_converged=false
          break
        fi
        if ! memberlist_status="$(curl -fsS --connect-timeout 2 --max-time 5 \
          -H 'Accept: application/json' \
          "${MIMIR_CLUSTER_ENDPOINTS[$member]}/memberlist" 2>/dev/null)" \
          || ! jq -e --argjson expected "$MIMIR_CLUSTER_NAMES_JSON" \
            '[.SortedMembers[].Name] | sort == ($expected | sort)' \
            <<< "$memberlist_status" >/dev/null 2>&1; then
          LAST_MIMIR_CLUSTER_STATE="${member}: memberlist=${memberlist_status:-no response}"
          all_converged=false
          break
        fi
        metrics="$(curl -fsS --connect-timeout 2 --max-time 5 \
          "${MIMIR_CLUSTER_ENDPOINTS[$member]}/metrics" 2>/dev/null || true)"
        for ring in ingester distributor store-gateway ruler compactor alertmanager; do
          if ! mimir_cluster_metric_is "$metrics" "$ring" ACTIVE 3; then
            LAST_MIMIR_CLUSTER_STATE="${member}: $(grep -E \
              '^cortex_ring_members' <<< "$metrics" || true)"
            all_converged=false
            break 2
          fi
        done
      done
      if [[ "$all_converged" == true ]]; then
        LAST_MIMIR_CLUSTER_STATE=
        return 0
      fi
      sleep 1
    done
    return 1
  }

  wait_for_mimir_loss() {
    local deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
    local member
    local metrics
    local loss_visible

    while ((SECONDS < deadline)); do
      loss_visible=true
      for member in mimir-cluster-1 mimir-cluster-2; do
        metrics="$(curl -fsS --connect-timeout 2 --max-time 5 \
          "${MIMIR_CLUSTER_ENDPOINTS[$member]}/metrics" 2>/dev/null || true)"
        if ! mimir_cluster_metric_is "$metrics" ingester ACTIVE 2 \
          || ! mimir_cluster_metric_is "$metrics" ingester Unhealthy 1; then
          loss_visible=false
          break
        fi
      done
      [[ "$loss_visible" == true ]] && return 0
      sleep 1
    done
    return 1
  }

  wait_for_mimir_query() {
    local endpoint=$1
    local start=$2
    local end=$3
    shift 3
    local deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
    local response
    local value
    local all_found

    while ((SECONDS < deadline)); do
      response="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
        --data-urlencode "query=${query_expression}" \
        --data-urlencode "start=${start}" \
        --data-urlencode "end=${end}" \
        --data-urlencode 'step=1' \
        "${endpoint}/prometheus/api/v1/query_range" 2>/dev/null || true)"
      LAST_MIMIR_QUERY_RESPONSE="$response"
      all_found=true
      for value in "$@"; do
        if ! jq -e --arg value "$value" '
          .status == "success" and any(.data.result[].values[]; .[1] == $value)
        ' <<< "$response" >/dev/null 2>&1; then
          all_found=false
          break
        fi
      done
      [[ "$all_found" == true ]] && return 0
      sleep 2
    done
    return 1
  }

  wait_for_mimir_alert() {
    local endpoint=$1
    local deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
    local response

    while ((SECONDS < deadline)); do
      response="$(curl -fsS --connect-timeout 2 --max-time 10 \
        "${endpoint}/alertmanager/api/v2/alerts" 2>/dev/null || true)"
      if jq -e --arg case "$metric_case" '
        any(.[]; .labels.alertname == "GarageCompatAlert" and .labels.case == $case)
      ' <<< "$response" >/dev/null 2>&1; then
        return 0
      fi
      sleep 2
    done
    return 1
  }

  wait_for_mimir_silence() {
    local endpoint=$1
    local silence_id=$2
    local deadline=$((SECONDS + MIMIR_READY_TIMEOUT))

    while ((SECONDS < deadline)); do
      if curl -fsS --connect-timeout 2 --max-time 10 \
        "${endpoint}/alertmanager/api/v2/silence/${silence_id}" 2>/dev/null \
        | jq -e --arg id "$silence_id" '.id == $id and .status.state == "active"' \
          >/dev/null 2>&1; then
        return 0
      fi
      sleep 2
    done
    return 1
  }

  mimir_metric_positive() {
    local metrics=$1
    local name=$2
    local labels=${3:-}

    grep -Eq "^${name}(\\{[^}]*${labels}[^}]*\\})? [1-9][0-9]*([.]0+)?$" \
      <<< "$metrics"
  }

  LAST_STAGE='three-node Mimir startup'
  for index in 1 2 3; do
    member="mimir-cluster-${index}"
    data_dir="${TEST_DIR}/${member}-data"
    container_name="${RUN_ID}-${member}"
    mkdir -p "$data_dir"
    MIMIR_CLUSTER_DATA_DIRS[$member]="$data_dir"
    MIMIR_CLUSTER_CONTAINERS[$member]="$container_name"
    container_id="$(timeout "$OPERATION_TIMEOUT" podman run \
      --detach --name "$container_name" --hostname "$member" --label "$LABEL" \
      --platform linux/amd64 --pull never --network "$NETWORK" \
      --network-alias "$member" --ip "${MIMIR_CLUSTER_IPS[$((index - 1))]}" \
      --read-only --userns=keep-id:uid=10001,gid=10001 --user 10001:10001 \
      --cap-drop all --security-opt no-new-privileges \
      --env MIMIR_NODE_NAME="$member" \
      --env MIMIR_NODE_IP="${MIMIR_CLUSTER_IPS[$((index - 1))]}" \
      --env MIMIR_ZONE="zone-${index}" \
      --env MIMIR_BLOCKS_S3_ACCESS_KEY_ID="${MIMIR_ACCESS_KEYS[blocks]}" \
      --env MIMIR_BLOCKS_S3_SECRET_ACCESS_KEY="${MIMIR_SECRET_KEYS[blocks]}" \
      --env MIMIR_RULER_S3_ACCESS_KEY_ID="${MIMIR_ACCESS_KEYS[ruler]}" \
      --env MIMIR_RULER_S3_SECRET_ACCESS_KEY="${MIMIR_SECRET_KEYS[ruler]}" \
      --env MIMIR_ALERTMANAGER_S3_ACCESS_KEY_ID="${MIMIR_ACCESS_KEYS[alertmanager]}" \
      --env MIMIR_ALERTMANAGER_S3_SECRET_ACCESS_KEY="${MIMIR_SECRET_KEYS[alertmanager]}" \
      --volume "${MIMIR_CONFIG}:/etc/mimir/mimir.yaml:ro,z" \
      --volume "${MIMIR_FALLBACK}:/etc/mimir/alertmanager-fallback.yaml:ro,z" \
      --volume "${data_dir}:/data:Z" --publish 127.0.0.1::8080 \
      --entrypoint /bin/mimir "$MIMIR_IMAGE" \
      -config.file=/etc/mimir/mimir.yaml -config.expand-env=true)"
    CREATED_CONTAINERS+=("$container_id")
    inspect="$(timeout "$OPERATION_TIMEOUT" podman inspect "$container_id")"
    jq -e --arg hostname "$member" '
      .[0].Config.User == "10001:10001"
      and .[0].Config.Hostname == $hostname
      and .[0].HostConfig.ReadonlyRootfs == true
      and ((.[0].HostConfig.CapAdd // []) | length == 0)
      and ((.[0].HostConfig.SecurityOpt // [])
        | any(startswith("no-new-privileges")))
    ' <<< "$inspect" >/dev/null \
      || fail "Mimir member ${member} does not have the required container hardening"
    mimir_host="$(timeout "$OPERATION_TIMEOUT" podman port "$container_id" 8080/tcp)"
    [[ "$mimir_host" =~ ^127[.]0[.]0[.]1:[0-9]+$ ]] \
      || fail "Mimir member ${member} has an unsafe HTTP host endpoint: ${mimir_host}"
    MIMIR_CLUSTER_ENDPOINTS[$member]="http://${mimir_host}"
  done
  [[ "$(printf '%s\n' "${MIMIR_CLUSTER_DATA_DIRS[@]}" | sort -u | wc -l)" == 3 ]] \
    || fail 'Mimir members do not have three distinct local-state directories'

  LAST_STAGE='initial Mimir memberlist and ring convergence'
  wait_for_mimir_cluster \
    || fail "Mimir cluster did not converge: ${LAST_MIMIR_CLUSTER_STATE}"
  LAST_STAGE='Mimir runtime identity'
  for member in "${MIMIR_CLUSTER_MEMBERS[@]}"; do
    build_info="$(curl -fsS --connect-timeout 2 --max-time 5 \
      "${MIMIR_CLUSTER_ENDPOINTS[$member]}/api/v1/status/buildinfo")"
    jq -e --arg version "$MIMIR_VERSION" \
      '.status == "success" and .data.version == $version' \
      <<< "$build_info" >/dev/null \
      || fail "Mimir member ${member} runtime version mismatch: ${build_info}"
  done

  LAST_STAGE='cross-node Mimir remote write and query'
  mimir_expired_metric="garage_mimir_retention_value"
  mimir_expired_case="expired-$RANDOM-$RANDOM"
  mimir_expired_query_expression="${mimir_expired_metric}{case=\"${mimir_expired_case}\"}"
  mimir_expired_value=21.5
  mimir_expired_timestamp_ms="$(date -d '-9 minutes' +%s%3N)"
  mimir_expired_start=$((mimir_expired_timestamp_ms / 1000 - 60))
  mimir_expired_end=$((mimir_expired_timestamp_ms / 1000 + 60))
  python3 "$REMOTE_WRITE_CLIENT" \
    --url "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/api/v1/push" \
    --metric "$mimir_expired_metric" --case "$mimir_expired_case" \
    --timestamp-ms "$mimir_expired_timestamp_ms" --value "$mimir_expired_value"
  query_expression="$mimir_expired_query_expression"
  wait_for_mimir_query "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" \
    "$mimir_expired_start" "$mimir_expired_end" "$mimir_expired_value" \
    || fail 'Cross-node Mimir query omitted the pre-retention canary'
  LAST_STAGE='pre-retention Mimir TSDB block upload'
  mimir_deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
  mimir_expired_block=false
  while ((SECONDS < mimir_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" \
      "${MIMIR_ACCESS_KEYS[blocks]}" "${MIMIR_SECRET_KEYS[blocks]}" \
      --method GET --bucket mimir-blocks --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    mimir_block_listing="$(<"$response_body")"
    mapfile -t mimir_meta_keys < <(
      grep -Eo 'garage-compat/[0-9A-Z]{26}/meta[.]json' <<< "$mimir_block_listing" \
        || true
    )
    for mimir_meta_key in "${mimir_meta_keys[@]}"; do
      mimir_block_id="${mimir_meta_key#garage-compat/}"
      mimir_block_id="${mimir_block_id%/meta.json}"
      if grep -Fq \
          "<Key>garage-compat/${mimir_block_id}/index</Key>" <<< "$mimir_block_listing" \
        && grep -Eq \
          "<Key>garage-compat/${mimir_block_id}/chunks/[^<]+</Key>" \
          <<< "$mimir_block_listing" \
        && s3_request "${S3_ENDPOINTS[garage-1]}" \
          "${MIMIR_ACCESS_KEYS[blocks]}" "${MIMIR_SECRET_KEYS[blocks]}" \
          --method GET --bucket mimir-blocks --key "$mimir_meta_key" \
          --output "$response_body" --expect-status 200 >/dev/null 2>&1 \
        && jq -e --argjson timestamp "$mimir_expired_timestamp_ms" '
          .minTime <= $timestamp
          and .maxTime == ($timestamp + 1)
          and .stats.numSeries == 1
          and .stats.numSamples > 0
        ' "$response_body" >/dev/null; then
        mimir_expired_block=true
        break 2
      fi
    done
    sleep 2
  done
  [[ "$mimir_expired_block" == true ]] \
    || fail 'Mimir produced no complete Garage TSDB block for the pre-retention canary'

  LAST_STAGE='cross-node Mimir remote write and query'
  metric="garage_mimir_compat_value"
  metric_case="case-$RANDOM-$RANDOM"
  query_expression="${metric}{case=\"${metric_case}\"}"
  metric_value=42.5
  metric_timestamp_ms="$(date +%s%3N)"
  metric_start=$((metric_timestamp_ms / 1000 - 60))
  metric_end=$((metric_timestamp_ms / 1000 + 60))
  python3 "$REMOTE_WRITE_CLIENT" \
    --url "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/api/v1/push" \
    --metric "$metric" --case "$metric_case" --timestamp-ms "$metric_timestamp_ms" \
    --value "$metric_value"
  wait_for_mimir_query "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" \
    "$metric_start" "$metric_end" "$metric_value" \
    || fail 'Cross-node Mimir query omitted the initial remote-write canary'

  LAST_STAGE='Mimir ruler and integrated Alertmanager replication'
  rule_file="${TEST_DIR}/mimir-rule.yaml"
  alert_file="${TEST_DIR}/mimir-alertmanager.yaml"
  cat > "$rule_file" <<EOF
name: garage-compat
interval: 2s
rules:
  - alert: GarageCompatAlert
    expr: ${query_expression} > 0
EOF
  cat > "$alert_file" <<'EOF'
alertmanager_config: |
  route:
    receiver: garage-persisted
  receivers:
    - name: garage-persisted
EOF
  curl -fsS --connect-timeout 2 --max-time 15 -X POST \
    -H 'Content-Type: application/yaml' --data-binary "@${rule_file}" \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/prometheus/config/v1/rules/garage-compat" \
    >/dev/null
  curl -fsS --connect-timeout 2 --max-time 15 -X POST \
    -H 'Content-Type: application/yaml' --data-binary "@${alert_file}" \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/api/v1/alerts" >/dev/null
  curl -fsS --connect-timeout 2 --max-time 10 \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}/prometheus/config/v1/rules/garage-compat/garage-compat" \
    | grep -Fq 'GarageCompatAlert'
  curl -fsS --connect-timeout 2 --max-time 10 \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-3]}/api/v1/alerts" \
    | grep -Fq 'receiver: garage-persisted'
  wait_for_mimir_alert "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" \
    || fail 'Integrated Alertmanager did not receive the ruler canary alert'

  silence_starts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  silence_ends="$(date -u -d '+1 hour' +'%Y-%m-%dT%H:%M:%SZ')"
  silence_payload="$(jq -nc --arg case "$metric_case" --arg starts "$silence_starts" \
    --arg ends "$silence_ends" '
      {matchers: [{name: "case", value: $case, isRegex: false}],
       startsAt: $starts, endsAt: $ends, createdBy: "garage-compat",
       comment: "Garage compatibility silence"}
    ')"
  silence_response="$(curl -fsS --connect-timeout 2 --max-time 15 -X POST \
    -H 'Content-Type: application/json' --data-binary "$silence_payload" \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/alertmanager/api/v2/silences")"
  silence_id="$(jq -er '.silenceID' <<< "$silence_response")"
  wait_for_mimir_silence "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" "$silence_id" \
    || fail 'Integrated Alertmanager did not replicate the qualification silence'

  mimir_stopped_data="${MIMIR_CLUSTER_DATA_DIRS[mimir-cluster-3]}"
  for token_file in ingester.tokens store-gateway.tokens; do
    [[ -s "${mimir_stopped_data}/${token_file}" ]] \
      || fail "Mimir member 3 did not persist ${token_file}"
  done
  mimir_token_snapshot="$(sha256sum \
    "${mimir_stopped_data}/ingester.tokens" \
    "${mimir_stopped_data}/store-gateway.tokens")"
  mimir_stopped_id="$(timeout "$OPERATION_TIMEOUT" podman inspect --format '{{.Id}}' \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}")"

  LAST_STAGE='one-node Mimir loss detection'
  timeout "$OPERATION_TIMEOUT" podman stop --time 0 \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}" >/dev/null
  wait_for_mimir_loss || fail 'Surviving Mimir members did not mark member 3 unhealthy'

  LAST_STAGE='one-node-loss Mimir write and query'
  loss_metric_value=84.5
  loss_metric_timestamp_ms="$(date +%s%3N)"
  metric_end=$((loss_metric_timestamp_ms / 1000 + 60))
  python3 "$REMOTE_WRITE_CLIENT" \
    --url "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/api/v1/push" \
    --metric "$metric" --case "$metric_case" --timestamp-ms "$loss_metric_timestamp_ms" \
    --value "$loss_metric_value"
  wait_for_mimir_query "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" \
    "$metric_start" "$metric_end" "$metric_value" "$loss_metric_value" \
    || fail 'Surviving Mimir query omitted a canary after one-node loss'
  wait_for_mimir_silence "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" "$silence_id" \
    || fail 'Surviving Alertmanager omitted the qualification silence'

  LAST_STAGE='same-node Mimir restart and ring convergence'
  timeout "$OPERATION_TIMEOUT" podman start \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}" >/dev/null
  [[ "$(timeout "$OPERATION_TIMEOUT" podman inspect --format '{{.Id}}' \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}")" == "$mimir_stopped_id" ]] \
    || fail 'Mimir member 3 was replaced instead of restarted'
  wait_for_mimir_cluster \
    || fail "Restarted Mimir member did not rejoin all rings: ${LAST_MIMIR_CLUSTER_STATE}"
  [[ "$(sha256sum \
    "${mimir_stopped_data}/ingester.tokens" \
    "${mimir_stopped_data}/store-gateway.tokens")" == "$mimir_token_snapshot" ]] \
    || fail 'Restarted Mimir member did not retain its persisted ring tokens'
  wait_for_mimir_query "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-3]}" \
    "$metric_start" "$metric_end" "$metric_value" "$loss_metric_value" \
    || fail 'Restarted Mimir member query omitted a qualification canary'
  wait_for_mimir_silence "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-3]}" "$silence_id" \
    || fail 'Restarted Alertmanager omitted the qualification silence'

  LAST_STAGE='Mimir TSDB block upload'
  mimir_deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
  mimir_later_block=false
  while ((SECONDS < mimir_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" \
      "${MIMIR_ACCESS_KEYS[blocks]}" "${MIMIR_SECRET_KEYS[blocks]}" \
      --method GET --bucket mimir-blocks --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    mimir_block_listing="$(<"$response_body")"
    mapfile -t mimir_meta_keys < <(
      grep -Eo 'garage-compat/[0-9A-Z]{26}/meta[.]json' <<< "$mimir_block_listing" \
        || true
    )
    for mimir_meta_key in "${mimir_meta_keys[@]}"; do
      mimir_block_id="${mimir_meta_key#garage-compat/}"
      mimir_block_id="${mimir_block_id%/meta.json}"
      if grep -Fq \
          "<Key>garage-compat/${mimir_block_id}/index</Key>" <<< "$mimir_block_listing" \
        && grep -Eq \
          "<Key>garage-compat/${mimir_block_id}/chunks/[^<]+</Key>" \
          <<< "$mimir_block_listing"; then
        s3_request "${S3_ENDPOINTS[garage-1]}" \
          "${MIMIR_ACCESS_KEYS[blocks]}" "${MIMIR_SECRET_KEYS[blocks]}" \
          --method GET --bucket mimir-blocks --key "$mimir_meta_key" \
          --output "$response_body" --expect-status 200 >/dev/null
        # Prometheus block maxTime is exclusive; this tenant has no later writes.
        if jq -e --argjson timestamp "$loss_metric_timestamp_ms" '
          .minTime <= $timestamp
          and .maxTime == ($timestamp + 1)
          and .stats.numSeries == 1
          and .stats.numSamples > 0
        ' "$response_body" >/dev/null; then
          mimir_later_block=true
          break 2
        fi
      fi
    done
    sleep 2
  done
  [[ "$mimir_later_block" == true ]] \
    || fail 'Mimir produced no complete Garage TSDB block ending at the node-loss canary'

  LAST_STAGE='Mimir compaction and retention'
  mimir_lifecycle_deadline=$((SECONDS + MIMIR_LIFECYCLE_TIMEOUT))
  mimir_lifecycle_complete=false
  mimir_compaction_succeeded=false
  mimir_retention_marked=false
  mimir_retention_cleaned=false
  mimir_retention_block_id=
  mimir_retention_block_deleted=false
  mimir_retention_delete_logged=false
  mimir_cluster_logs=
  for member in "${MIMIR_CLUSTER_MEMBERS[@]}"; do
    mimir_cluster_logs+="$(timeout "$OPERATION_TIMEOUT" podman logs \
      "${MIMIR_CLUSTER_CONTAINERS[$member]}" 2>&1 || true)"$'\n'
  done
  while ((SECONDS < mimir_lifecycle_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" \
      "${MIMIR_ACCESS_KEYS[blocks]}" "${MIMIR_SECRET_KEYS[blocks]}" \
      --method GET --bucket mimir-blocks --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    mimir_block_listing="$(<"$response_body")"
    mimir_cluster_metrics=
    for member in "${MIMIR_CLUSTER_MEMBERS[@]}"; do
      mimir_cluster_metrics+="$(curl -fsS --connect-timeout 2 --max-time 5 \
        "${MIMIR_CLUSTER_ENDPOINTS[$member]}/metrics" 2>/dev/null || true)"$'\n'
      mimir_cluster_logs+="$(timeout "$OPERATION_TIMEOUT" podman logs --since 5s \
        "${MIMIR_CLUSTER_CONTAINERS[$member]}" 2>&1 || true)"$'\n'
    done
    grep -Eq 'msg="compacted blocks" new_block_count=[1-9][0-9]*' \
      <<< "$mimir_cluster_logs" && mimir_compaction_succeeded=true
    mimir_metric_positive "$mimir_cluster_metrics" \
      cortex_compactor_blocks_cleaned_total \
      && mimir_retention_cleaned=true

    if [[ -z "$mimir_retention_block_id" ]]; then
      while IFS= read -r mimir_retention_line; do
        if [[ "$mimir_retention_line" =~ block=([0-9A-Z]{26}) ]]; then
          mimir_retention_block_id="${BASH_REMATCH[1]}"
          mimir_retention_marked=true
          break
        fi
      done < <(grep -E \
        "msg=\"applied retention: marking block for deletion\" block=[0-9A-Z]{26} maxTime=$((mimir_expired_timestamp_ms + 1))" \
        <<< "$mimir_cluster_logs" || true)
    fi

    if [[ -n "$mimir_retention_block_id" ]] \
      && grep -Fq \
        "msg=\"deleted block marked for deletion\" block=${mimir_retention_block_id}" \
        <<< "$mimir_cluster_logs"; then
      mimir_retention_delete_logged=true
    fi
    if [[ "$mimir_retention_delete_logged" == true \
        && "$mimir_retention_cleaned" == true ]] \
      && ! grep -Fq \
        "<Key>garage-compat/${mimir_retention_block_id}/" \
        <<< "$mimir_block_listing" \
      && ! grep -Fq \
        "<Key>garage-compat/markers/${mimir_retention_block_id}-deletion-mark.json</Key>" \
        <<< "$mimir_block_listing"; then
      mimir_retention_block_deleted=true
    fi

    mimir_expired_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
      --data-urlencode "query=${mimir_expired_query_expression}" \
      --data-urlencode "start=${mimir_expired_start}" \
      --data-urlencode "end=${mimir_expired_end}" \
      --data-urlencode 'step=1' \
      "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/prometheus/api/v1/query_range" \
      2>/dev/null || true)"
    mimir_current_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
      --data-urlencode "query=${query_expression}" \
      --data-urlencode "start=${metric_start}" \
      --data-urlencode "end=${metric_end}" \
      --data-urlencode 'step=1' \
      "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}/prometheus/api/v1/query_range" \
      2>/dev/null || true)"
    mimir_expired_absent=false
    mimir_current_present=false
    jq -e --arg value "$mimir_expired_value" '
      .status == "success"
      and all(.data.result[].values[]; .[1] != $value)
    ' <<< "$mimir_expired_query" >/dev/null 2>&1 \
      && mimir_expired_absent=true
    jq -e --arg initial "$metric_value" --arg loss "$loss_metric_value" '
      .status == "success"
      and any(.data.result[].values[]; .[1] == $initial)
      and any(.data.result[].values[]; .[1] == $loss)
    ' <<< "$mimir_current_query" >/dev/null 2>&1 \
      && mimir_current_present=true
    # Query-frontend retention hides expired samples before the longer
    # ingester-local block retention; cold-state absence is repeated below.
    if [[ "$mimir_compaction_succeeded" == true \
        && "$mimir_retention_marked" == true \
        && "$mimir_retention_cleaned" == true \
        && "$mimir_retention_delete_logged" == true \
        && "$mimir_retention_block_deleted" == true \
        && "$mimir_expired_absent" == true \
        && "$mimir_current_present" == true ]]; then
      mimir_lifecycle_complete=true
      break
    fi
    sleep 2
  done
  if [[ "$mimir_lifecycle_complete" != true ]]; then
    printf '%s\n' \
      "Mimir lifecycle evidence: compaction_succeeded=${mimir_compaction_succeeded}, retention_marked=${mimir_retention_marked}, retention_cleaned=${mimir_retention_cleaned}, retention_block=${mimir_retention_block_id:-none}, delete_logged=${mimir_retention_delete_logged}, block_deleted=${mimir_retention_block_deleted}, expired_absent=${mimir_expired_absent}, current_present=${mimir_current_present}" \
      >&2
    grep -E '^cortex_compactor_(group_compactions_total|blocks_marked_for_deletion_total|blocks_cleaned_total)' \
      <<< "$mimir_cluster_metrics" >&2 || true
    fail 'Mimir did not compact blocks and physically delete only the expired canary block'
  fi

  LAST_STAGE='empty-local-state Mimir cluster restart'
  timeout 60 podman stop --time 30 \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-1]}" \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-2]}" \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}" >/dev/null
  for member in "${MIMIR_CLUSTER_MEMBERS[@]}"; do
    find "${MIMIR_CLUSTER_DATA_DIRS[$member]}" -mindepth 1 -delete
  done
  timeout "$OPERATION_TIMEOUT" podman start \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-1]}" \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-2]}" \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}" >/dev/null
  wait_for_mimir_cluster \
    || fail "Empty-local-state Mimir cluster did not converge: ${LAST_MIMIR_CLUSTER_STATE}"
  wait_for_mimir_query "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" \
    "$metric_start" "$metric_end" "$metric_value" "$loss_metric_value" \
    || fail "Empty-local-state Mimir cluster did not query both Garage-backed canaries: ${LAST_MIMIR_QUERY_RESPONSE:-no response}"
  mimir_expired_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
    --data-urlencode "query=${mimir_expired_query_expression}" \
    --data-urlencode "start=${mimir_expired_start}" \
    --data-urlencode "end=${mimir_expired_end}" \
    --data-urlencode 'step=1' \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}/prometheus/api/v1/query_range")"
  jq -e --arg value "$mimir_expired_value" '
    .status == "success"
    and all(.data.result[].values[]; .[1] != $value)
  ' <<< "$mimir_expired_query" >/dev/null \
    || fail 'Empty-local-state Mimir cluster recovered the expired Garage canary'
  curl -fsS --connect-timeout 2 --max-time 10 \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-3]}/prometheus/config/v1/rules/garage-compat/garage-compat" \
    | grep -Fq 'GarageCompatAlert'
  curl -fsS --connect-timeout 2 --max-time 10 \
    "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}/api/v1/alerts" \
    | grep -Fq 'receiver: garage-persisted'
  wait_for_mimir_silence "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-1]}" "$silence_id" \
    || fail 'Empty-local-state Alertmanager did not recover the Garage-backed silence'
  wait_for_mimir_alert "${MIMIR_CLUSTER_ENDPOINTS[mimir-cluster-2]}" \
    || fail 'Empty-local-state ruler did not restore the canary alert'

  LAST_STAGE='three-node Mimir shutdown'
  timeout 60 podman stop --time 30 \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-1]}" \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-2]}" \
    "${MIMIR_CLUSTER_CONTAINERS[mimir-cluster-3]}" >/dev/null
fi

LAST_STAGE='one-node-loss continuity'
timeout "$OPERATION_TIMEOUT" podman stop --time 10 "${CONTAINERS[garage-3]}" >/dev/null
wait_for_health one-down
LAST_STAGE='one-node-loss signed GET'
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --key "$object_key" \
  --output "$response_body" --expect-status 200 >/dev/null
cmp -- "$initial_body" "$response_body" \
  || fail 'Garage lost the initial object with one node stopped'
LAST_STAGE='one-node-loss signed PUT'
s3_request "${S3_ENDPOINTS[garage-2]}" "$access_key" "$secret_key" \
  --method PUT --bucket qualification --key 'qualification/during-loss.txt' \
  --body-file "$during_loss_body" --output "$response_body" --expect-status 200 >/dev/null

LAST_STAGE='no-quorum write rejection'
timeout "$OPERATION_TIMEOUT" podman stop --time 10 "${CONTAINERS[garage-2]}" >/dev/null
wait_for_health no-quorum
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method PUT --bucket qualification --key 'qualification/no-quorum.txt' \
  --body-file "$initial_body" --output "$response_body" --expect-status 503 >/dev/null

LAST_STAGE='three-node restart convergence'
timeout "$OPERATION_TIMEOUT" podman start "${CONTAINERS[garage-2]}" >/dev/null
timeout "$OPERATION_TIMEOUT" podman start "${CONTAINERS[garage-3]}" >/dev/null
for member in garage-2 garage-3; do
  restored_identity="$(wait_for_node_id "$member")"
  [[ "${restored_identity%%@*}" == "${NODE_IDS[$member]}" ]] \
    || fail "Garage member ${member} changed identity after restart"
  garage_cli "$member" node connect "${NODE_IDS[garage-1]}@garage-1:3901" >/dev/null
done
wait_for_health healthy
s3_request "${S3_ENDPOINTS[garage-3]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --key 'qualification/during-loss.txt' \
  --output "$response_body" --expect-status 200 >/dev/null
cmp -- "$during_loss_body" "$response_body" \
  || fail 'Restarted Garage cluster did not preserve the acknowledged quorum write'
s3_request "${S3_ENDPOINTS[garage-3]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --key 'qualification/no-quorum.txt' \
  --output "$response_body" --expect-status 404 >/dev/null

LAST_STAGE='post-recovery object validation and cleanup'
garage_cli garage-1 stats --all-nodes >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method GET --bucket qualification --key 'qualification/no-quorum.txt' \
  --output "$response_body" --expect-status 404 >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method DELETE --bucket qualification --key "$object_key" \
  --output "$response_body" --expect-status 204 >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
  --method DELETE --bucket qualification --key 'qualification/during-loss.txt' \
  --output "$response_body" --expect-status 204 >/dev/null
s3_request "${S3_ENDPOINTS[garage-1]}" "$isolated_access_key" "$isolated_secret_key" \
  --method DELETE --bucket isolated --key 'protected.txt' \
  --output "$response_body" --expect-status 204 >/dev/null

printf '%s\n' \
  "Monitoring Garage ${version} RF=3 signed-S3 qualification passed (${index_digest})"
