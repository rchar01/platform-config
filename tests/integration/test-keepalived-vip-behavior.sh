#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE=/workspace/tests/fixtures/keepalived-vip/behavior.yml
CONTAINERFILE="${ROOT_DIR}/tests/fixtures/keepalived-vip/Containerfile.behavior"
IMAGE="${KEEPALIVED_VIP_BEHAVIOR_IMAGE:-platform-config-keepalived-behavior:rocky10.1-v1}"
TEST_DIR="$(mktemp -d)"
RUN_ID="platform-config-keepalived-behavior-${TEST_DIR##*/}"
LABEL="platform-config.keepalived-behavior-run=${RUN_ID}"
NETWORK="${RUN_ID}-network"
OPERATION_TIMEOUT="${KEEPALIVED_VIP_BEHAVIOR_OPERATION_TIMEOUT:-30}"
READY_TIMEOUT="${KEEPALIVED_VIP_BEHAVIOR_READY_TIMEOUT:-30}"
FAILBACK_TIMEOUT="${KEEPALIVED_VIP_BEHAVIOR_FAILBACK_TIMEOUT:-90}"
MEMBERS=(keepalived-1 keepalived-2 keepalived-3)
declare -A CONTAINERS=(
  [keepalived-1]="${RUN_ID}-keepalived-1"
  [keepalived-2]="${RUN_ID}-keepalived-2"
  [keepalived-3]="${RUN_ID}-keepalived-3"
)
declare -A IPS=()
CREATED_CONTAINERS=()
NETWORK_CREATED=false
LAST_OWNER=

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup_resources() {
  local container_id
  local -a labeled_containers=()

  for container_id in "${CREATED_CONTAINERS[@]}"; do
    timeout "$OPERATION_TIMEOUT" podman rm -f "$container_id" >/dev/null 2>&1 || true
  done
  mapfile -t labeled_containers < <(
    timeout "$OPERATION_TIMEOUT" podman ps -aq --filter "label=${LABEL}" 2>/dev/null || true
  )
  if ((${#labeled_containers[@]})); then
    timeout "$OPERATION_TIMEOUT" podman rm -f "${labeled_containers[@]}" >/dev/null 2>&1 || true
  fi
  if [[ "$NETWORK_CREATED" == true ]]; then
    timeout "$OPERATION_TIMEOUT" podman network rm -f "$NETWORK" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  local status=$?
  local container_id

  trap - EXIT INT TERM
  if ((status != 0)); then
    for container_id in "${CREATED_CONTAINERS[@]}"; do
      printf '\n===== %s logs =====\n' "$container_id" >&2
      timeout "$OPERATION_TIMEOUT" podman logs "$container_id" >&2 2>/dev/null || true
      timeout "$OPERATION_TIMEOUT" podman exec "$container_id" \
        journalctl --no-pager -u keepalived.service >&2 2>/dev/null || true
    done
  fi
  cleanup_resources
  rm -rf -- "$TEST_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in jq podman timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done

current_owner() {
  local member
  local owners=()

  for member in "${MEMBERS[@]}"; do
    if timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
      ip -o -4 address show dev eth0 2>/dev/null \
      | grep -Fq " ${VIP}/24 "; then
      owners+=("$member")
    fi
  done
  if ((${#owners[@]} == 0)); then
    LAST_OWNER=none
  else
    LAST_OWNER="${owners[*]}"
  fi
}

wait_for_owner() {
  local expected=$1
  local timeout_seconds=$2
  local description=$3
  local deadline=$((SECONDS + timeout_seconds))

  while ((SECONDS < deadline)); do
    current_owner
    if [[ "$LAST_OWNER" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  fail "${description}: expected ${expected}, observed ${LAST_OWNER}"
}

assert_owner_for() {
  local expected=$1
  local duration=$2
  local description=$3
  local deadline=$((SECONDS + duration))

  while ((SECONDS < deadline)); do
    current_owner
    [[ "$LAST_OWNER" == "$expected" ]] \
      || fail "${description}: expected ${expected}, observed ${LAST_OWNER}"
    sleep 1
  done
}

run_playbook() {
  local member=$1
  local priority=$2
  local source_address=$3
  local peers=$4
  local extra_vars
  local output

  extra_vars="$(jq -nc \
    --arg node_1_ip "${IPS[keepalived-1]}" \
    --arg node_2_ip "${IPS[keepalived-2]}" \
    --arg node_3_ip "${IPS[keepalived-3]}" \
    --arg source_address "$source_address" \
    --arg vip "$VIP" \
    --argjson priority "$priority" \
    --argjson peers "$peers" \
    '{
      keepalived_vip_test_node_1_ip: $node_1_ip,
      keepalived_vip_test_node_2_ip: $node_2_ip,
      keepalived_vip_test_node_3_ip: $node_3_ip,
      keepalived_vip_test_source_address: $source_address,
      keepalived_vip_test_priority: $priority,
      keepalived_vip_test_peers: $peers,
      keepalived_vip_test_vip: $vip
    }')"

  if ! output="$(timeout 180 podman exec \
    --env ANSIBLE_COLLECTIONS_PATH=/root/.ansible/collections \
    --env ANSIBLE_ROLES_PATH=/workspace/roles \
    --workdir /workspace \
    "${CONTAINERS[$member]}" \
    ansible-playbook -i "${member}," -c local "$FIXTURE" \
    --extra-vars "$extra_vars" 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "Keepalived behavior convergence failed on ${member}"
  fi
  printf '%s\n' "$output"
}

assert_observer_state() {
  local expected_owner=$1
  local member
  local expected_value
  local metrics
  local labels

  for member in "${MEMBERS[@]}"; do
    timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
      systemctl start platform-external-probe-ownership.service
    metrics="$(timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
      /usr/bin/cat /var/lib/alloy/platform-external-probe/vip-ownership.prom)"
    expected_value=0
    if [[ "$member" == "$expected_owner" ]]; then
      expected_value=1
    fi
    labels="service=\"monitoring\",node=\"${member}\",environment=\"test\",endpoint=\"monitoring_vip\",instance=\"TEST_VIP\",interface=\"eth0\",vip=\"${VIP}\""
    grep -Fqx "platform_vip_owned{${labels}} ${expected_value}" <<< "$metrics" \
      || fail "Ownership observer on ${member} did not report ${expected_value} for ${VIP}"
    grep -Fqx "platform_vip_ownership_collection_success{${labels}} 1" <<< "$metrics" \
      || fail "Ownership observer on ${member} did not report successful inspection"
  done
}

timeout 600 podman build \
  --file "$CONTAINERFILE" \
  --tag "$IMAGE" \
  "$ROOT_DIR" >/dev/null

timeout "$OPERATION_TIMEOUT" podman network create \
  --internal \
  --label "$LABEL" \
  "$NETWORK" >/dev/null
NETWORK_CREATED=true
network_internal="$(timeout "$OPERATION_TIMEOUT" \
  podman network inspect --format '{{.Internal}}' "$NETWORK")"
[[ "$network_internal" == true ]] || fail 'Disposable Keepalived network is not internal'
network_json="$(timeout "$OPERATION_TIMEOUT" podman network inspect "$NETWORK")"
subnet_cidr="$(jq -er '.[0].subnets[] | select(.subnet | contains(":") | not) | .subnet' \
  <<< "$network_json")"
[[ "$subnet_cidr" == */24 ]] \
  || fail "Disposable Keepalived network did not allocate an IPv4 /24: ${subnet_cidr}"
subnet_address="${subnet_cidr%/*}"
VIP="${subnet_address%.*}.250"

for member in "${MEMBERS[@]}"; do
  container_id="$(timeout "$OPERATION_TIMEOUT" podman run \
    --detach \
    --name "${CONTAINERS[$member]}" \
    --hostname "$member" \
    --label "$LABEL" \
    --systemd=always \
    --cap-add NET_ADMIN \
    --cap-add NET_BROADCAST \
    --cap-add NET_RAW \
    --network "$NETWORK" \
    --network-alias "$member" \
    --volume "${ROOT_DIR}:/workspace:ro,z" \
    "$IMAGE")"
  CREATED_CONTAINERS+=("$container_id")
done

for member in "${MEMBERS[@]}"; do
  ready=false
  deadline=$((SECONDS + READY_TIMEOUT))
  while ((SECONDS < deadline)); do
    if timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
      systemctl is-system-running --quiet 2>/dev/null; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ "$ready" == true ]] \
    || fail "Disposable systemd member did not become ready: ${member}"
  IPS[$member]="$(timeout "$OPERATION_TIMEOUT" podman inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "${CONTAINERS[$member]}")"
  [[ -n "${IPS[$member]}" && "${IPS[$member]}" != "$VIP" ]] \
    || fail "Disposable member has an invalid network address: ${member} ${IPS[$member]}"
  timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
    systemctl start platform-test-listeners.service
done

run_playbook keepalived-1 150 "${IPS[keepalived-1]}" \
  "$(jq -nc --arg first "${IPS[keepalived-2]}" --arg second "${IPS[keepalived-3]}" '[ $first, $second ]')" \
  >/dev/null
run_playbook keepalived-2 140 "${IPS[keepalived-2]}" \
  "$(jq -nc --arg first "${IPS[keepalived-1]}" --arg second "${IPS[keepalived-3]}" '[ $first, $second ]')" \
  >/dev/null
run_playbook keepalived-3 130 "${IPS[keepalived-3]}" \
  "$(jq -nc --arg first "${IPS[keepalived-1]}" --arg second "${IPS[keepalived-2]}" '[ $first, $second ]')" \
  >/dev/null

for member in "${MEMBERS[@]}"; do
  package_identity="$(timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
    rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' keepalived)"
  [[ "$package_identity" == keepalived-0:2.2.8-9.el10.x86_64 ]] \
    || fail "Keepalived package identity mismatch on ${member}: ${package_identity}"
done

wait_for_owner keepalived-1 "$READY_TIMEOUT" 'Initial preferred-node election failed'
assert_observer_state keepalived-1

timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-1]}" \
  systemctl stop keepalived.service
wait_for_owner keepalived-2 "$READY_TIMEOUT" 'Keepalived process loss did not move the VIP'

timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-1]}" \
  systemctl start keepalived.service
assert_owner_for keepalived-2 10 'Preferred-node restart bypassed delayed failback'
timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-1]}" \
  systemctl stop keepalived.service
assert_owner_for keepalived-2 5 'Repeated preferred-node failure disrupted the current owner'

failback_started=$SECONDS
timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-1]}" \
  systemctl start keepalived.service
wait_for_owner keepalived-1 "$FAILBACK_TIMEOUT" 'Preferred node did not automatically reclaim the VIP'
failback_elapsed=$((SECONDS - failback_started))
((failback_elapsed >= 55)) \
  || fail "Preferred node reclaimed the VIP before the 60-second delay: ${failback_elapsed}s"

timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-1]}" \
  systemctl stop platform-test-listeners.service
wait_for_owner keepalived-2 "$READY_TIMEOUT" 'Preferred-node hard fault did not move the VIP'
assert_observer_state keepalived-2

timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-2]}" \
  systemctl stop platform-test-listeners.service
wait_for_owner keepalived-3 "$READY_TIMEOUT" 'Second hard fault did not move the VIP to the final node'

timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[keepalived-3]}" \
  systemctl stop platform-test-listeners.service
wait_for_owner none "$READY_TIMEOUT" 'All-fault state retained a VIP owner'
assert_observer_state none

for member in "${MEMBERS[@]}"; do
  timeout "$OPERATION_TIMEOUT" podman exec "${CONTAINERS[$member]}" \
    systemctl start platform-test-listeners.service
done
wait_for_owner keepalived-1 "$FAILBACK_TIMEOUT" 'Recovered cluster did not elect one preferred owner'
assert_observer_state keepalived-1

cleanup_resources
CREATED_CONTAINERS=()
remaining_containers="$(timeout "$OPERATION_TIMEOUT" podman ps -aq \
  --filter "label=${LABEL}" 2>/dev/null || true)"
[[ -z "$remaining_containers" ]] \
  || fail 'Keepalived behavior check left invocation-owned containers'
if timeout "$OPERATION_TIMEOUT" podman network exists "$NETWORK"; then
  fail 'Keepalived behavior check left its invocation-owned network'
fi
NETWORK_CREATED=false

printf '%s\n' 'Keepalived 2.2.8 three-node behavior and ownership qualification passed'
