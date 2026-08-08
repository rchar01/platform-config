#!/usr/bin/env bash
set -euo pipefail
umask 077

IMAGE='gcr.io/etcd-development/etcd@sha256:a491baeaa0cb0c9cd89c0062ac44ece53886e3e5bddad18d2daf36678ce665b6'
TEST_DIR="$(mktemp -d)"
RUN_ID="platform-config-etcd-cluster-${TEST_DIR##*/}"
LABEL="platform-config.etcd-cluster-run=${RUN_ID}"
NETWORK="${RUN_ID}-network"
OPERATION_TIMEOUT="${MONITORING_ETCD_CLUSTER_OPERATION_TIMEOUT:-20}"
READY_TIMEOUT="${MONITORING_ETCD_CLUSTER_READY_TIMEOUT:-90}"
PULL_TIMEOUT="${MONITORING_ETCD_CLUSTER_PULL_TIMEOUT:-300}"
MEMBERS=(etcd-1 etcd-2 etcd-3)
ALL_ENDPOINTS='https://etcd-1:2379,https://etcd-2:2379,https://etcd-3:2379'
INITIAL_CLUSTER='etcd-1=https://etcd-1:2380,etcd-2=https://etcd-2:2380,etcd-3=https://etcd-3:2380'
declare -A CONTAINERS=(
  [etcd-1]="${RUN_ID}-etcd-1"
  [etcd-2]="${RUN_ID}-etcd-2"
  [etcd-3]="${RUN_ID}-etcd-3"
)
LAST_MEMBERS=
LAST_STATUS=
NETWORK_CREATED=false
CREATED_CONTAINERS=()

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=$?
  local container_id
  local -a containers=()

  trap - EXIT INT TERM
  if ((status != 0)); then
    for container_id in "${CREATED_CONTAINERS[@]}"; do
      printf '\n===== %s logs =====\n' "$container_id" >&2
      timeout 10 podman logs "$container_id" >&2 2>/dev/null || true
    done
  fi
  for container_id in "${CREATED_CONTAINERS[@]}"; do
    timeout 20 podman rm -f "$container_id" >/dev/null 2>&1 || true
  done
  # A timed-out --rm etcdctl invocation can outlive its Podman client. The
  # random label is owned by this invocation and cleans only those leftovers.
  mapfile -t containers < <(
    timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null || true
  )
  if ((${#containers[@]})); then
    # Labels constrain this list to resources created by this invocation.
    timeout 20 podman rm -f "${containers[@]}" >/dev/null 2>&1 || true
  fi
  if [[ "$NETWORK_CREATED" == true ]]; then
    timeout 10 podman network rm -f "$NETWORK" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TEST_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in jq openssl podman sed timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done

CA_DIR="${TEST_DIR}/ca"
CLIENT_DIR="${TEST_DIR}/client"
mkdir -p "$CA_DIR" "$CLIENT_DIR"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj "/CN=${RUN_ID}-ca" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${CA_DIR}/ca.key" \
  -out "${CA_DIR}/ca.crt" >/dev/null 2>&1

issue_certificate() {
  local name=$1
  local extended_usage=$2
  local subject_alt_name=${3:-}
  local certificate_dir="${TEST_DIR}/pki/${name}"
  local extensions="${certificate_dir}/extensions.cnf"

  mkdir -p "$certificate_dir"
  openssl req -newkey rsa:3072 -nodes -sha256 \
    -subj "/CN=${name}" \
    -keyout "${certificate_dir}/tls.key" \
    -out "${certificate_dir}/tls.csr" >/dev/null 2>&1
  {
    printf '%s\n' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature,keyEncipherment' \
      "extendedKeyUsage=${extended_usage}" \
      'subjectKeyIdentifier=hash' \
      'authorityKeyIdentifier=keyid,issuer'
    if [[ -n "$subject_alt_name" ]]; then
      printf 'subjectAltName=%s\n' "$subject_alt_name"
    fi
  } > "$extensions"
  openssl x509 -req -sha256 -days 1 \
    -in "${certificate_dir}/tls.csr" \
    -CA "${CA_DIR}/ca.crt" \
    -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -extfile "$extensions" \
    -out "${certificate_dir}/tls.crt" >/dev/null 2>&1
  cp "${CA_DIR}/ca.crt" "${certificate_dir}/ca.crt"
  chmod 0400 "${certificate_dir}/tls.key"
  chmod 0444 "${certificate_dir}/tls.crt" "${certificate_dir}/ca.crt"
}

for member in "${MEMBERS[@]}"; do
  issue_certificate "$member" 'serverAuth,clientAuth' "DNS:${member}"
done
issue_certificate qualification-client clientAuth
cp "${TEST_DIR}/pki/qualification-client/ca.crt" "$CLIENT_DIR/ca.crt"
cp "${TEST_DIR}/pki/qualification-client/tls.crt" "$CLIENT_DIR/tls.crt"
cp "${TEST_DIR}/pki/qualification-client/tls.key" "$CLIENT_DIR/tls.key"
[[ ! -e "${CLIENT_DIR}/ca.key" ]] || fail 'CA private key leaked into client material'

timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 "$IMAGE" >/dev/null
timeout "$OPERATION_TIMEOUT" podman network create \
  --internal --label "$LABEL" "$NETWORK" >/dev/null
NETWORK_CREATED=true
network_internal="$(timeout "$OPERATION_TIMEOUT" \
  podman network inspect --format '{{.Internal}}' "$NETWORK")"
[[ "$network_internal" == true ]] || fail 'Disposable etcd network is not internal'

for member in "${MEMBERS[@]}"; do
  data_dir="${TEST_DIR}/data/${member}"
  mkdir -p "$data_dir"
  chmod 0700 "$data_dir"
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
    --volume "${data_dir}:/var/lib/etcd:Z" \
    --volume "${TEST_DIR}/pki/${member}:/etc/etcd/pki:ro,Z" \
    --entrypoint /usr/local/bin/etcd \
    "$IMAGE" \
    --name "$member" \
    --data-dir /var/lib/etcd \
    --listen-client-urls https://0.0.0.0:2379 \
    --advertise-client-urls "https://${member}:2379" \
    --listen-peer-urls https://0.0.0.0:2380 \
    --initial-advertise-peer-urls "https://${member}:2380" \
    --initial-cluster "$INITIAL_CLUSTER" \
    --initial-cluster-token "$RUN_ID" \
    --initial-cluster-state new \
    --cert-file /etc/etcd/pki/tls.crt \
    --key-file /etc/etcd/pki/tls.key \
    --trusted-ca-file /etc/etcd/pki/ca.crt \
    --client-cert-auth \
    --peer-cert-file /etc/etcd/pki/tls.crt \
    --peer-key-file /etc/etcd/pki/tls.key \
    --peer-trusted-ca-file /etc/etcd/pki/ca.crt \
    --peer-client-cert-auth \
    --logger zap \
    --log-level warn \
    --log-outputs stderr)"
  CREATED_CONTAINERS+=("$container_id")
done

etcdctl() {
  local endpoints=$1
  shift

  timeout "$OPERATION_TIMEOUT" podman run --rm \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$NETWORK" \
    --read-only \
    --userns=keep-id:uid=10001,gid=10001 \
    --user 10001:10001 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --volume "${CLIENT_DIR}:/etc/etcdctl/pki:ro,Z" \
    --env ETCDCTL_DIAL_TIMEOUT=3s \
    --env ETCDCTL_COMMAND_TIMEOUT=8s \
    --entrypoint /usr/local/bin/etcdctl \
    "$IMAGE" \
    --endpoints="$endpoints" \
    --cacert=/etc/etcdctl/pki/ca.crt \
    --cert=/etc/etcdctl/pki/tls.crt \
    --key=/etc/etcdctl/pki/tls.key \
    "$@"
}

unauthenticated_etcdctl() {
  local endpoints=$1
  shift

  timeout "$OPERATION_TIMEOUT" podman run --rm \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$NETWORK" \
    --read-only \
    --userns=keep-id:uid=10001,gid=10001 \
    --user 10001:10001 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --volume "${CLIENT_DIR}/ca.crt:/etc/etcdctl/ca.crt:ro,Z" \
    --env ETCDCTL_DIAL_TIMEOUT=3s \
    --env ETCDCTL_COMMAND_TIMEOUT=8s \
    --entrypoint /usr/local/bin/etcdctl \
    "$IMAGE" \
    --endpoints="$endpoints" \
    --cacert=/etc/etcdctl/ca.crt \
    "$@"
}

wait_for_cluster() {
  local deadline=$((SECONDS + READY_TIMEOUT))
  local health

  while ((SECONDS < deadline)); do
    if LAST_MEMBERS="$(etcdctl "$ALL_ENDPOINTS" member list -w json 2>/dev/null \
      | sed -E 's/"(ID|member_id|leader)":([0-9]+)/"\1":"\2"/g')" \
      && LAST_STATUS="$(etcdctl "$ALL_ENDPOINTS" endpoint status --cluster -w json 2>/dev/null \
      | sed -E 's/"(ID|member_id|leader)":([0-9]+)/"\1":"\2"/g')" \
      && jq -e -n \
        --argjson members "$LAST_MEMBERS" \
        --argjson statuses "$LAST_STATUS" '
          ($members.members | length) == 3
          and ([ $members.members[].name ] | sort) == ["etcd-1", "etcd-2", "etcd-3"]
          and all($members.members[]; (.isLearner // false) == false)
          and ($statuses | length) == 3
          and ([ $statuses[].Status.header.member_id ] | unique | length) == 3
          and ([ $statuses[].Status.leader ] | unique | length) == 1
          and $statuses[0].Status.leader != "0"
          and ($statuses[0].Status.leader as $leader | any($members.members[]; .ID == $leader))
        ' >/dev/null; then
      if health="$(etcdctl "$ALL_ENDPOINTS" endpoint health --cluster -w json 2>/dev/null)" \
        && jq -e 'length == 3 and all(.[]; .health == true)' \
          <<< "$health" >/dev/null; then
        return 0
      fi
    fi
    sleep 1
  done
  fail "Three-member etcd cluster did not become healthy within ${READY_TIMEOUT}s"
}

wait_for_cluster
leader_name="$(jq -er -n \
  --argjson members "$LAST_MEMBERS" \
  --argjson statuses "$LAST_STATUS" '
    ([ $statuses[].Status.leader ] | unique) as $leaders
    | if ($leaders | length) != 1 or $leaders[0] == "0" then
        error("expected one nonzero leader")
      else $leaders[0] end as $leader
    | [ $members.members[] | select(.ID == $leader) | .name ] as $names
    | if ($names | length) == 1 then $names[0]
      else error("leader did not map to one member") end
  ')"
[[ -n "${CONTAINERS[$leader_name]:-}" ]] \
  || fail "Unknown elected etcd leader: ${leader_name}"

unauthenticated_status=0
unauthenticated_output="$(unauthenticated_etcdctl "$ALL_ENDPOINTS" endpoint health 2>&1)" \
  || unauthenticated_status=$?
[[ "$unauthenticated_status" != 0 ]] \
  || fail 'etcd accepted a client without a certificate'
grep -Eqi 'certificate required|tls:' <<< "$unauthenticated_output" \
  || fail "Unexpected unauthenticated client failure: ${unauthenticated_output}"

etcdctl "$ALL_ENDPOINTS" put qualification-initial initial-value >/dev/null
[[ "$(etcdctl "$ALL_ENDPOINTS" get qualification-initial --print-value-only)" == initial-value ]] \
  || fail 'Initial etcd cluster write/read failed'

timeout "$OPERATION_TIMEOUT" podman stop --time 10 \
  "${CONTAINERS[$leader_name]}" >/dev/null
survivor_endpoints=
for member in "${MEMBERS[@]}"; do
  if [[ "$member" != "$leader_name" ]]; then
    survivor_endpoints+="https://${member}:2379,"
  fi
done
survivor_endpoints="${survivor_endpoints%,}"
quorum_write_complete=false
quorum_deadline=$((SECONDS + 60))
while ((SECONDS < quorum_deadline)); do
  if etcdctl "$survivor_endpoints" put qualification-quorum quorum-value \
    >/dev/null 2>&1; then
    quorum_write_complete=true
    break
  fi
  sleep 1
done
[[ "$quorum_write_complete" == true ]] \
  || fail 'Two surviving etcd members did not regain write quorum'
[[ "$(etcdctl "$survivor_endpoints" get qualification-quorum --print-value-only)" == quorum-value ]] \
  || fail 'Two-member quorum write/read failed'

timeout "$OPERATION_TIMEOUT" podman start "${CONTAINERS[$leader_name]}" >/dev/null
wait_for_cluster
leader_endpoint="https://${leader_name}:2379"
[[ "$(etcdctl "$leader_endpoint" get qualification-initial --print-value-only)" == initial-value ]] \
  || fail 'Restarted etcd member did not serve the pre-failure value'
[[ "$(etcdctl "$leader_endpoint" get qualification-quorum --print-value-only)" == quorum-value ]] \
  || fail 'Restarted etcd member did not catch up with the quorum write'

timeout "$OPERATION_TIMEOUT" podman stop --time 10 \
  "${CONTAINERS[etcd-2]}" "${CONTAINERS[etcd-3]}" >/dev/null
no_quorum_status=0
no_quorum_output="$(etcdctl 'https://etcd-1:2379' \
  put qualification-no-quorum forbidden-value 2>&1)" || no_quorum_status=$?
[[ "$no_quorum_status" != 0 ]] \
  || fail 'Single etcd member accepted a write without quorum'
grep -Eqi 'deadline exceeded|request timed out|unhealthy cluster' \
  <<< "$no_quorum_output" \
  || fail "Unexpected no-quorum write failure: ${no_quorum_output}"

timeout "$OPERATION_TIMEOUT" podman start \
  "${CONTAINERS[etcd-2]}" "${CONTAINERS[etcd-3]}" >/dev/null
wait_for_cluster
# A timed-out Raft proposal may commit after quorum returns; only acknowledgement
# is ruled out while quorum is absent, not eventual application.
[[ "$(etcdctl "$ALL_ENDPOINTS" get qualification-initial --print-value-only)" == initial-value ]] \
  || fail 'Initial value was lost after full cluster recovery'
[[ "$(etcdctl "$ALL_ENDPOINTS" get qualification-quorum --print-value-only)" == quorum-value ]] \
  || fail 'Quorum value was lost after full cluster recovery'

printf '%s\n' 'Monitoring etcd 3.6.14 three-member mTLS qualification passed'
