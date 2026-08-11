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
TEST_LOKI_CLUSTER="${MONITORING_GARAGE_TEST_LOKI_CLUSTER:-false}"
TEST_MIMIR="${MONITORING_GARAGE_TEST_MIMIR:-false}"
MIMIR_READY_TIMEOUT="${MONITORING_GARAGE_MIMIR_READY_TIMEOUT:-240}"
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
  LOKI_READY_TIMEOUT MIMIR_READY_TIMEOUT; do
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
if [[ "$TEST_LOKI_CLUSTER" == true ]]; then
  network_subnet="$(timeout "$OPERATION_TIMEOUT" \
    podman network inspect --format '{{(index .Subnets 0).Subnet}}' "$NETWORK")"
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
  mimir_key_json="$(garage_cli garage-1 json-api CreateKey '{"name":"mimir-compat"}')"
  mimir_access_key="$(jq -er '.accessKeyId' <<< "$mimir_key_json")"
  mimir_secret_key="$(jq -er '.secretAccessKey' <<< "$mimir_key_json")"
  [[ "$mimir_access_key" =~ ^GK[0-9a-f]{24}$ ]] \
    || fail 'Garage returned an invalid Mimir access-key ID'
  [[ -n "$mimir_secret_key" ]] || fail 'Garage returned an empty Mimir secret key'
  for bucket in mimir-blocks mimir-ruler mimir-alertmanager; do
    garage_cli garage-1 bucket allow \
      --read --write --owner "$bucket" --key "$mimir_access_key" >/dev/null
  done
  wait_for_s3_metadata "$mimir_access_key" \
    mimir-blocks mimir-ruler mimir-alertmanager
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
    local payload

    payload="$(jq -nc --arg timestamp "$timestamp" --arg token "$token" \
      --arg qualification "$loki_cluster_case" '
      {streams: [{stream: {app: "garage-loki-cluster", qualification: $qualification},
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

  LAST_STAGE='three-node Loki shutdown'
  timeout 40 podman stop --time 10 \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-1]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-2]}" \
    "${LOKI_CLUSTER_CONTAINERS[loki-cluster-3]}" >/dev/null
fi

if [[ "$TEST_MIMIR" == true ]]; then
  LAST_STAGE='Mimir credential isolation'
  s3_request "${S3_ENDPOINTS[garage-1]}" "$access_key" "$secret_key" \
    --method PUT --bucket mimir-blocks --key 'qualification-key-denied.txt' \
    --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-2]}" "$mimir_access_key" "$mimir_secret_key" \
    --method GET --bucket mimir-blocks --key 'qualification-key-denied.txt' \
    --output "$response_body" --expect-status 404 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-1]}" "$mimir_access_key" "$mimir_secret_key" \
    --method PUT --bucket qualification --key 'mimir-key-denied.txt' \
    --body-file "$initial_body" --output "$response_body" --expect-status 403 >/dev/null
  s3_request "${S3_ENDPOINTS[garage-2]}" "$access_key" "$secret_key" \
    --method GET --bucket qualification --key 'mimir-key-denied.txt' \
    --output "$response_body" --expect-status 404 >/dev/null

  LAST_STAGE='Mimir monolith startup'
  mimir_data="${TEST_DIR}/mimir-data"
  mkdir -p "$mimir_data"
  start_mimir() {
    local name=$1
    timeout "$OPERATION_TIMEOUT" podman run \
      --detach --name "$name" --label "$LABEL" --platform linux/amd64 --pull never \
      --network "$NETWORK" --network-alias mimir --read-only \
      --userns=keep-id:uid=10001,gid=10001 --user 10001:10001 --cap-drop all \
      --security-opt no-new-privileges \
      --env MIMIR_S3_ACCESS_KEY_ID="$mimir_access_key" \
      --env MIMIR_S3_SECRET_ACCESS_KEY="$mimir_secret_key" \
      --volume "${MIMIR_CONFIG}:/etc/mimir/mimir.yaml:ro,Z" \
      --volume "${MIMIR_FALLBACK}:/etc/mimir/alertmanager-fallback.yaml:ro,Z" \
      --volume "${mimir_data}:/data:Z" \
      --publish 127.0.0.1::8080 --entrypoint /bin/mimir "$MIMIR_IMAGE" \
      -config.file=/etc/mimir/mimir.yaml -config.expand-env=true
  }
  mimir_name="${RUN_ID}-mimir"
  mimir_id="$(start_mimir "$mimir_name")"
  CREATED_CONTAINERS+=("$mimir_id")
  mimir_host="$(timeout "$OPERATION_TIMEOUT" podman port "$mimir_id" 8080/tcp)"
  mimir_endpoint="http://${mimir_host}"
  mimir_deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
  until curl -fsS --connect-timeout 2 --max-time 3 "${mimir_endpoint}/ready" >/dev/null 2>&1; do
    ((SECONDS < mimir_deadline)) || fail 'Mimir monolith did not become ready'
    sleep 1
  done

  LAST_STAGE='Mimir remote write and immediate query'
  metric="garage_mimir_compat_value"
  metric_case="case-$RANDOM-$RANDOM"
  metric_value=42.5
  metric_timestamp_ms="$(date +%s%3N)"
  metric_start=$((metric_timestamp_ms / 1000 - 60))
  metric_end=$((metric_timestamp_ms / 1000 + 60))
  python3 "$REMOTE_WRITE_CLIENT" --url "${mimir_endpoint}/api/v1/push" \
    --metric "$metric" --case "$metric_case" --timestamp-ms "$metric_timestamp_ms" \
    --value "$metric_value"
  query_expression="${metric}{case=\"${metric_case}\"}"
  mimir_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
    --data-urlencode "query=${query_expression}" \
    "${mimir_endpoint}/prometheus/api/v1/query")"
  jq -e --arg value "$metric_value" '
    .status == "success" and any(.data.result[]; .value[1] == $value)
  ' <<< "$mimir_query" >/dev/null || fail 'Mimir immediate query omitted the remote-write canary'

  rule_file="${TEST_DIR}/mimir-rule.yaml"
  alert_file="${TEST_DIR}/mimir-alertmanager.yaml"
  cat > "$rule_file" <<EOF
name: garage-compat
rules:
  - alert: GarageCompatAlert
    expr: ${metric} > 0
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
    "${mimir_endpoint}/prometheus/config/v1/rules/garage-compat" >/dev/null
  curl -fsS --connect-timeout 2 --max-time 15 -X POST \
    -H 'Content-Type: application/yaml' --data-binary "@${alert_file}" \
    "${mimir_endpoint}/api/v1/alerts" >/dev/null
  curl -fsS --connect-timeout 2 --max-time 10 \
    "${mimir_endpoint}/prometheus/config/v1/rules/garage-compat/garage-compat" \
    | grep -Fq 'GarageCompatAlert'
  curl -fsS --connect-timeout 2 --max-time 10 "${mimir_endpoint}/api/v1/alerts" \
    | grep -Fq 'receiver: garage-persisted'

  LAST_STAGE='Mimir TSDB block upload'
  mimir_deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
  mimir_blocks=false
  while ((SECONDS < mimir_deadline)); do
    s3_request "${S3_ENDPOINTS[garage-1]}" "$mimir_access_key" "$mimir_secret_key" \
      --method GET --bucket mimir-blocks --query 'list-type=2' \
      --output "$response_body" --expect-status 200 >/dev/null
    mapfile -t mimir_meta_keys < <(
      grep -Eo 'garage-compat/[0-9A-Z]{26}/meta[.]json' "$response_body" || true
    )
    for mimir_meta_key in "${mimir_meta_keys[@]}"; do
      mimir_block_id="${mimir_meta_key#garage-compat/}"
      mimir_block_id="${mimir_block_id%/meta.json}"
      if grep -Fq "<Key>garage-compat/${mimir_block_id}/index</Key>" "$response_body" \
        && grep -Eq \
          "<Key>garage-compat/${mimir_block_id}/chunks/[^<]+</Key>" "$response_body"; then
        mimir_blocks=true
        break 2
      fi
    done
    sleep 2
  done
  [[ "$mimir_blocks" == true ]] || fail 'Mimir produced no complete Garage TSDB block'

  LAST_STAGE='Mimir fresh-local-state recovery'
  timeout 40 podman stop --time 30 "$mimir_name" >/dev/null
  timeout "$OPERATION_TIMEOUT" podman rm "$mimir_name" >/dev/null
  rm -rf -- "$mimir_data"
  mkdir -p "$mimir_data"
  mimir_fresh_name="${RUN_ID}-mimir-fresh"
  mimir_fresh_id="$(start_mimir "$mimir_fresh_name")"
  CREATED_CONTAINERS+=("$mimir_fresh_id")
  mimir_fresh_host="$(timeout "$OPERATION_TIMEOUT" podman port "$mimir_fresh_id" 8080/tcp)"
  mimir_fresh_endpoint="http://${mimir_fresh_host}"
  mimir_deadline=$((SECONDS + MIMIR_READY_TIMEOUT))
  until curl -fsS --connect-timeout 2 --max-time 3 "${mimir_fresh_endpoint}/ready" >/dev/null 2>&1; do
    ((SECONDS < mimir_deadline)) || fail 'Fresh-local-state Mimir did not become ready'
    sleep 1
  done
  persisted=false
  while ((SECONDS < mimir_deadline)); do
    mimir_query="$(curl -fsS --get --connect-timeout 2 --max-time 10 \
      --data-urlencode "query=${query_expression}" \
      --data-urlencode "start=${metric_start}" \
      --data-urlencode "end=${metric_end}" \
      --data-urlencode 'step=1' \
      "${mimir_fresh_endpoint}/prometheus/api/v1/query_range" 2>/dev/null || true)"
    if jq -e --arg value "$metric_value" '
      .status == "success" and any(.data.result[].values[]; .[1] == $value)
    ' <<< "$mimir_query" >/dev/null 2>&1; then
      persisted=true
      break
    fi
    sleep 2
  done
  [[ "$persisted" == true ]] || fail 'Fresh-local-state Mimir did not query the Garage block'
  curl -fsS --connect-timeout 2 --max-time 10 \
    "${mimir_fresh_endpoint}/prometheus/config/v1/rules/garage-compat/garage-compat" \
    | grep -Fq 'GarageCompatAlert'
  curl -fsS --connect-timeout 2 --max-time 10 "${mimir_fresh_endpoint}/api/v1/alerts" \
    | grep -Fq 'receiver: garage-persisted'
  timeout 40 podman stop --time 30 "$mimir_fresh_name" >/dev/null
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
