#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="${ROOT_DIR}/tests/fixtures/monitoring-artifacts/candidates.json"
POSTGRES_IMAGE="${MONITORING_GRAFANA_POSTGRES_IMAGE:-localhost/postgres-patroni:dev}"
POSTGRES_EXPECTED_DIGEST='sha256:aa1fa024dd06337ae70ad55775ed07f8e472f630f903125b975fb26b8b63f52b'
ETCD_IMAGE='gcr.io/etcd-development/etcd@sha256:a491baeaa0cb0c9cd89c0062ac44ece53886e3e5bddad18d2daf36678ce665b6'
TEST_DIR="$(mktemp -d)"
RUN_ID="platform-config-grafana-postgresql-${TEST_DIR##*/}"
LABEL="platform-config.grafana-postgresql-run=${RUN_ID}"
NETWORK="${RUN_ID}-application-network"
DCS_NETWORK="${RUN_ID}-dcs-network"
GRAFANA_MIGRATION_LOCK_ID=4004004031
GRAFANA_EXPECTED_MIGRATIONS=713
OPERATION_TIMEOUT="${MONITORING_GRAFANA_POSTGRESQL_OPERATION_TIMEOUT:-30}"
READY_TIMEOUT="${MONITORING_GRAFANA_POSTGRESQL_READY_TIMEOUT:-180}"
PULL_TIMEOUT="${MONITORING_GRAFANA_POSTGRESQL_PULL_TIMEOUT:-300}"
POSTGRES_PASSWORD="$(openssl rand -hex 24)"
REPLICATION_PASSWORD="$(openssl rand -hex 24)"
REWIND_PASSWORD="$(openssl rand -hex 24)"
GRAFANA_DB_PASSWORD="$(openssl rand -hex 24)"
GRAFANA_ADMIN_PASSWORD="$(openssl rand -hex 24)"
GRAFANA_SECRET_KEY="$(openssl rand -hex 32)"
GRAFANA_MEMBERS=(grafana-1 grafana-2 grafana-3)
CREATED_CONTAINERS=()
LAST_STAGE=initialization
POSTGRES_CONTAINER=
MIGRATION_LOCK_MEMBER=
declare -A GRAFANA_CONTAINERS=()
declare -A GRAFANA_ENDPOINTS=()

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

cleanup() {
  local status=$?
  local cleanup_failed=false
  local container_id
  local leftovers_output
  local network_status
  local -a leftovers=()

  trap - EXIT INT TERM
  if ((status != 0)); then
    printf '\nGrafana/PostgreSQL qualification failed during: %s\n' "$LAST_STAGE" >&2
    for container_id in "${CREATED_CONTAINERS[@]}"; do
      if timeout 5 podman container exists "$container_id" >/dev/null 2>&1; then
        printf '\n===== %s logs =====\n' "$container_id" >&2
        timeout 10 podman logs "$container_id" >&2 2>/dev/null || true
      fi
    done
  fi
  if leftovers_output="$(
    timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null
  )"; then
    if [[ -n "$leftovers_output" ]]; then
      mapfile -t leftovers <<< "$leftovers_output"
    fi
  else
    printf 'Could not inspect labeled containers during cleanup\n' >&2
    cleanup_failed=true
  fi
  if ((${#leftovers[@]})); then
    timeout 30 podman rm -f "${leftovers[@]}" >/dev/null 2>&1 || true
  fi
  leftovers=()
  if leftovers_output="$(
    timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null
  )"; then
    if [[ -n "$leftovers_output" ]]; then
      mapfile -t leftovers <<< "$leftovers_output"
      printf 'Cleanup left labeled containers: %s\n' "${leftovers[*]}" >&2
      cleanup_failed=true
    fi
  else
    printf 'Could not verify labeled container cleanup\n' >&2
    cleanup_failed=true
  fi
  timeout 10 podman network rm -f "$NETWORK" >/dev/null 2>&1 || true
  timeout 10 podman network rm -f "$DCS_NETWORK" >/dev/null 2>&1 || true
  if timeout 10 podman network exists "$NETWORK" >/dev/null 2>&1; then
    printf 'Cleanup left network: %s\n' "$NETWORK" >&2
    cleanup_failed=true
  else
    network_status=$?
    if ((network_status != 1)); then
      printf 'Could not verify network cleanup: %s\n' "$NETWORK" >&2
      cleanup_failed=true
    fi
  fi
  if timeout 10 podman network exists "$DCS_NETWORK" >/dev/null 2>&1; then
    printf 'Cleanup left network: %s\n' "$DCS_NETWORK" >&2
    cleanup_failed=true
  else
    network_status=$?
    if ((network_status != 1)); then
      printf 'Could not verify network cleanup: %s\n' "$DCS_NETWORK" >&2
      cleanup_failed=true
    fi
  fi
  if [[ "$cleanup_failed" == false ]]; then
    rm -rf -- "$TEST_DIR"
  else
    printf 'Preserved test directory: %s\n' "$TEST_DIR" >&2
  fi
  if [[ "$cleanup_failed" == true && "$status" == 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in curl grep jq openssl podman timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done
for timeout_name in OPERATION_TIMEOUT READY_TIMEOUT PULL_TIMEOUT; do
  [[ "${!timeout_name}" =~ ^[1-9][0-9]*$ ]] \
    || fail "${timeout_name} must be a positive integer"
done

GRAFANA_VERSION="$(jq -er '.components.grafana.version' "$LOCK")"
[[ "$GRAFANA_VERSION" == 13.1.3 ]] \
  || fail "Unexpected Grafana candidate version: ${GRAFANA_VERSION}"
GRAFANA_IMAGE="$(jq -er '
  .components.grafana.repository + "@" + .components.grafana.index_digest
' "$LOCK")"

LAST_STAGE='exact image preflight'
timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 \
  "$GRAFANA_IMAGE" >/dev/null
timeout "$PULL_TIMEOUT" podman pull --quiet --platform linux/amd64 \
  "$ETCD_IMAGE" >/dev/null
postgres_metadata="$(timeout "$OPERATION_TIMEOUT" \
  podman image inspect "$POSTGRES_IMAGE" 2>/dev/null)" \
  || fail "Qualified PostgreSQL image is unavailable: ${POSTGRES_IMAGE}; build it in ../postgres-patroni"
postgres_digest="$(jq -er '.[0].Digest' <<< "$postgres_metadata")"
[[ "$postgres_digest" == "$POSTGRES_EXPECTED_DIGEST" ]] \
  || fail "PostgreSQL candidate digest mismatch: ${postgres_digest}"
[[ "$(jq -er '.[0].Os + "/" + .[0].Architecture' <<< "$postgres_metadata")" == linux/amd64 ]] \
  || fail 'PostgreSQL candidate is not Linux/AMD64'
[[ "$(jq -er '.[0].Config.User' <<< "$postgres_metadata")" == 26:26 ]] \
  || fail 'PostgreSQL candidate does not use configured UID/GID 26:26'
POSTGRES_IMAGE_ID="$(jq -er '.[0].Id' <<< "$postgres_metadata")"
GRAFANA_IMAGE_ID="$(timeout "$OPERATION_TIMEOUT" \
  podman image inspect --format '{{.Id}}' "$GRAFANA_IMAGE")"
ETCD_IMAGE_ID="$(timeout "$OPERATION_TIMEOUT" \
  podman image inspect --format '{{.Id}}' "$ETCD_IMAGE")"

mkdir -p \
  "$TEST_DIR/etcd-data" \
  "$TEST_DIR/postgresql/config" \
  "$TEST_DIR/postgresql/data" \
  "$TEST_DIR/postgresql/wal" \
  "$TEST_DIR/grafana-pki"
chmod 0700 "$TEST_DIR/etcd-data" "$TEST_DIR/postgresql/data" "$TEST_DIR/postgresql/wal"

openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj "/CN=${RUN_ID}-ca" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$TEST_DIR/ca.key" \
  -out "$TEST_DIR/ca.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 1 \
  -subj "/CN=${RUN_ID}-untrusted-ca" \
  -keyout "$TEST_DIR/untrusted-ca.key" \
  -out "$TEST_DIR/grafana-pki/untrusted-ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=postgresql' \
  -keyout "$TEST_DIR/postgresql/config/tls.key" \
  -out "$TEST_DIR/postgresql/config/tls.csr" >/dev/null 2>&1
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:postgresql' >"$TEST_DIR/postgresql/config/extensions.cnf"
openssl x509 -req -sha256 -days 1 \
  -in "$TEST_DIR/postgresql/config/tls.csr" \
  -CA "$TEST_DIR/ca.crt" \
  -CAkey "$TEST_DIR/ca.key" \
  -CAcreateserial \
  -extfile "$TEST_DIR/postgresql/config/extensions.cnf" \
  -out "$TEST_DIR/postgresql/config/tls.crt" >/dev/null 2>&1
cp "$TEST_DIR/ca.crt" "$TEST_DIR/postgresql/config/ca.crt"
cp "$TEST_DIR/ca.crt" "$TEST_DIR/grafana-pki/ca.crt"
chmod 0400 "$TEST_DIR/postgresql/config/tls.key"
chmod 0444 \
  "$TEST_DIR/postgresql/config/ca.crt" \
  "$TEST_DIR/postgresql/config/tls.crt" \
  "$TEST_DIR/grafana-pki/ca.crt" \
  "$TEST_DIR/grafana-pki/untrusted-ca.crt"

cat >"$TEST_DIR/postgresql/config/patroni.yml" <<EOF
scope: grafana-qualification
namespace: /platform-config/
name: postgresql
log:
  type: plain
  level: INFO
  traceback_level: ERROR
restapi:
  listen: 0.0.0.0:8008
  connect_address: postgresql:8008
etcd3:
  hosts: etcd:2379
  protocol: http
bootstrap:
  dcs:
    loop_wait: 5
    retry_timeout: 5
    ttl: 20
    check_timeline: true
    postgresql:
      use_pg_rewind: true
      use_slots: true
      parameters:
        fsync: "on"
        full_page_writes: "on"
        wal_log_hints: "on"
  initdb:
    - encoding: UTF8
    - data-checksums
    - waldir: /var/lib/pgsql/18/wal
  pg_hba:
    - local replication replicator scram-sha-256
    - local all all trust
    - hostssl all all 0.0.0.0/0 scram-sha-256
    - hostssl replication replicator 0.0.0.0/0 scram-sha-256
postgresql:
  listen: 0.0.0.0:5432
  connect_address: postgresql:5432
  data_dir: /var/lib/pgsql/18/data
  bin_dir: /usr/pgsql-18/bin
  pgpass: /run/postgresql/pgpass
  authentication:
    superuser:
      username: postgres
      password: ${POSTGRES_PASSWORD}
    replication:
      username: replicator
      password: ${REPLICATION_PASSWORD}
      sslmode: verify-full
      sslrootcert: /etc/patroni/ca.crt
    rewind:
      username: rewind_user
      password: ${REWIND_PASSWORD}
      sslmode: verify-full
      sslrootcert: /etc/patroni/ca.crt
  parameters:
    ssl: "on"
    ssl_cert_file: /etc/patroni/tls.crt
    ssl_key_file: /etc/patroni/tls.key
    ssl_ca_file: /etc/patroni/ca.crt
    ssl_min_protocol_version: TLSv1.2
    password_encryption: scram-sha-256
    unix_socket_directories: /run/postgresql
EOF
chmod 0444 "$TEST_DIR/postgresql/config/patroni.yml"

timeout "$OPERATION_TIMEOUT" podman network create \
  --internal --label "$LABEL" "$NETWORK" >/dev/null
timeout "$OPERATION_TIMEOUT" podman network create \
  --internal --label "$LABEL" "$DCS_NETWORK" >/dev/null
[[ "$(timeout "$OPERATION_TIMEOUT" \
  podman network inspect --format '{{.Internal}}' "$NETWORK")" == true ]] \
  || fail 'Disposable Grafana/PostgreSQL application network is not internal'
[[ "$(timeout "$OPERATION_TIMEOUT" \
  podman network inspect --format '{{.Internal}}' "$DCS_NETWORK")" == true ]] \
  || fail 'Disposable Grafana/PostgreSQL DCS network is not internal'

etcd_container="$(timeout "$OPERATION_TIMEOUT" podman run \
  --detach \
  --name "${RUN_ID}-etcd" \
  --label "$LABEL" \
  --platform linux/amd64 \
  --pull never \
  --network "$DCS_NETWORK" \
  --network-alias etcd \
  --hostname etcd \
  --read-only \
  --userns=keep-id:uid=10001,gid=10001 \
  --user 10001:10001 \
  --cap-drop all \
  --security-opt no-new-privileges \
  --volume "$TEST_DIR/etcd-data:/var/lib/etcd:Z" \
  --entrypoint /usr/local/bin/etcd \
  "$ETCD_IMAGE_ID" \
  --name etcd \
  --data-dir /var/lib/etcd \
  --listen-client-urls http://0.0.0.0:2379 \
  --advertise-client-urls http://etcd:2379 \
  --listen-peer-urls http://0.0.0.0:2380 \
  --initial-advertise-peer-urls http://etcd:2380 \
  --initial-cluster etcd=http://etcd:2380 \
  --initial-cluster-token "$RUN_ID" \
  --initial-cluster-state new \
  --logger zap \
  --log-level warn \
  --log-outputs stderr)"
CREATED_CONTAINERS+=("$etcd_container")

start_postgresql() {
  POSTGRES_CONTAINER="$(timeout "$OPERATION_TIMEOUT" podman run \
    --detach \
    --name "${RUN_ID}-postgresql" \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$DCS_NETWORK" \
    --network-alias postgresql \
    --hostname postgresql \
    --read-only \
    --userns=keep-id:uid=26,gid=26 \
    --user 26:26 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --env MALLOC_ARENA_MAX=1 \
    --tmpfs /run/postgresql:rw,nosuid,nodev,size=16m,mode=1777 \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m,mode=1777 \
    --tmpfs /var/tmp:rw,nosuid,nodev,size=16m,mode=1777 \
    --tmpfs /var/spool/pgbackrest:rw,nosuid,nodev,size=16m,mode=0700 \
    --volume "$TEST_DIR/postgresql/config:/etc/patroni:ro,Z" \
    --volume "$TEST_DIR/postgresql/data:/var/lib/pgsql/18/data:Z" \
    --volume "$TEST_DIR/postgresql/wal:/var/lib/pgsql/18/wal:Z" \
    --entrypoint /opt/patroni/bin/patroni \
    "$POSTGRES_IMAGE_ID" \
    /etc/patroni/patroni.yml)"
  CREATED_CONTAINERS+=("$POSTGRES_CONTAINER")
  timeout "$OPERATION_TIMEOUT" podman network connect \
    --alias postgresql "$NETWORK" "$POSTGRES_CONTAINER"
}

postgres_query() {
  local database=$1
  local query=$2

  timeout "$OPERATION_TIMEOUT" podman exec \
    --env PGHOST=/run/postgresql \
    "$POSTGRES_CONTAINER" \
    psql -X -v ON_ERROR_STOP=1 -Atq -U postgres -d "$database" -c "$query"
}

wait_for_postgresql() {
  local deadline=$((SECONDS + READY_TIMEOUT))
  local state

  while ((SECONDS < deadline)); do
    if state="$(postgres_query postgres \
      "SELECT current_setting('server_version') || '|' || pg_is_in_recovery()" \
      2>&1)" && [[ "$state" == '18.4|false' ]]; then
      return 0
    fi
    sleep 1
  done
  fail "PostgreSQL 18.4 did not become writable within ${READY_TIMEOUT}s: ${state:-no response}"
}

create_grafana() {
  local member=$1
  local ca_cert=${2:-ca.crt}
  local restart_policy=${3:-on-failure:20}
  local data_dir="$TEST_DIR/grafana/${member}"
  local container_id

  mkdir -p "$data_dir"
  chmod 0700 "$data_dir"
  container_id="$(timeout "$OPERATION_TIMEOUT" podman create \
    --name "${RUN_ID}-${member}" \
    --label "$LABEL" \
    --platform linux/amd64 \
    --pull never \
    --network "$NETWORK" \
    --network-alias "$member" \
    --hostname "$member" \
    --read-only \
    --userns=keep-id:uid=472,gid=472 \
    --user 472:472 \
    --cap-drop all \
    --security-opt no-new-privileges \
    --restart "$restart_policy" \
    --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 \
    --volume "$data_dir:/var/lib/grafana:Z" \
    --volume "$TEST_DIR/grafana-pki:/etc/grafana-pki:ro,z" \
    --publish 127.0.0.1::3000 \
    --env GF_ANALYTICS_CHECK_FOR_UPDATES=false \
    --env GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false \
    --env GF_ANALYTICS_REPORTING_ENABLED=false \
    --env GF_DATABASE_TYPE=postgres \
    --env GF_DATABASE_HOST=postgresql:5432 \
    --env GF_DATABASE_NAME=grafana \
    --env GF_DATABASE_USER=grafana \
    --env "GF_DATABASE_PASSWORD=${GRAFANA_DB_PASSWORD}" \
    --env GF_DATABASE_SSL_MODE=verify-full \
    --env "GF_DATABASE_CA_CERT_PATH=/etc/grafana-pki/${ca_cert}" \
    --env GF_LOG_MODE=console \
    --env GF_LOG_CONSOLE_FORMAT=json \
    --env GF_PLUGINS_PREINSTALL_DISABLED=true \
    --env "GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}" \
    --env GF_SECURITY_ADMIN_USER=admin \
    --env "GF_SECURITY_SECRET_KEY=${GRAFANA_SECRET_KEY}" \
    --env GF_SERVER_HTTP_ADDR=0.0.0.0 \
    --env GF_SERVER_HTTP_PORT=3000 \
    "$GRAFANA_IMAGE_ID")"
  CREATED_CONTAINERS+=("$container_id")
  GRAFANA_CONTAINERS[$member]="$container_id"
}

set_grafana_endpoint() {
  local member=$1
  local deadline=$((SECONDS + READY_TIMEOUT))
  local host

  while ((SECONDS < deadline)); do
    if host="$(timeout "$OPERATION_TIMEOUT" podman port \
      "${GRAFANA_CONTAINERS[$member]}" 3000/tcp 2>/dev/null)" \
      && [[ "$host" == 127.0.0.1:* ]]; then
      GRAFANA_ENDPOINTS[$member]="http://${host}"
      return 0
    fi
    sleep 0.2
  done
  fail "${member} did not expose a valid published endpoint within ${READY_TIMEOUT}s"
}

wait_for_grafana() {
  local member=$1
  local deadline=$((SECONDS + READY_TIMEOUT))
  local health

  while ((SECONDS < deadline)); do
    if health="$(curl -fsS --connect-timeout 2 --max-time 5 \
      "${GRAFANA_ENDPOINTS[$member]}/api/health" 2>/dev/null)" \
      && jq -e --arg version "$GRAFANA_VERSION" '
        .database == "ok" and .version == $version
      ' <<< "$health" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  fail "${member} did not become healthy within ${READY_TIMEOUT}s"
}

wait_for_all_grafana() {
  local member

  for member in "${GRAFANA_MEMBERS[@]}"; do
    wait_for_grafana "$member"
  done
}

assert_dashboard() {
  local member=$1
  local uid=$2
  local title=$3
  local dashboard

  dashboard="$(curl -fsS --connect-timeout 2 --max-time 10 \
    --user "admin:${GRAFANA_ADMIN_PASSWORD}" \
    "${GRAFANA_ENDPOINTS[$member]}/api/dashboards/uid/${uid}")"
  jq -e --arg uid "$uid" --arg title "$title" '
    .dashboard.uid == $uid and .dashboard.title == $title
  ' <<< "$dashboard" >/dev/null \
    || fail "${member} did not return the persisted dashboard canary"
}

wait_for_database_outage() {
  local deadline=$((SECONDS + OPERATION_TIMEOUT))
  local member
  local response
  local all_degraded
  local reported_degradation

  while ((SECONDS < deadline)); do
    all_degraded=true
    reported_degradation=false
    for member in "${GRAFANA_MEMBERS[@]}"; do
      if response="$(curl -sS --connect-timeout 2 --max-time 5 \
        "${GRAFANA_ENDPOINTS[$member]}/api/health" 2>/dev/null)"; then
        if jq -e '.database == "ok"' <<< "$response" >/dev/null 2>&1; then
          all_degraded=false
          break
        fi
        if jq -e '
          type == "object" and
          (.database | type == "string") and
          .database != "ok"
        ' <<< "$response" >/dev/null 2>&1; then
          reported_degradation=true
        fi
      fi
    done
    if [[ "$all_degraded" == true && "$reported_degradation" == true ]]; then
      return 0
    fi
    sleep 1
  done
  fail 'Grafana did not expose database degradation after PostgreSQL was disconnected'
}

wait_for_migration_lock() {
  local deadline=$((SECONDS + OPERATION_TIMEOUT))
  local lock_count

  while ((SECONDS < deadline)); do
    lock_count="$(postgres_query grafana "
      SELECT count(*)
      FROM pg_locks
      WHERE locktype = 'advisory'
        AND classid = 0
        AND objid = ${GRAFANA_MIGRATION_LOCK_ID}
        AND granted IS TRUE
    ")"
    if [[ "$lock_count" == 1 ]]; then
      return 0
    fi
    sleep 0.2
  done
  fail 'Synthetic Grafana migration lock holder did not acquire the advisory lock'
}

wait_for_migration_lock_restart() {
  local deadline=$((SECONDS + OPERATION_TIMEOUT))
  local member
  local restart_count

  while ((SECONDS < deadline)); do
    for member in "${GRAFANA_MEMBERS[@]}"; do
      restart_count="$(timeout "$OPERATION_TIMEOUT" podman inspect \
        --format '{{.RestartCount}}' "${GRAFANA_CONTAINERS[$member]}")"
      if [[ "$restart_count" =~ ^[1-9][0-9]*$ ]] \
        && timeout "$OPERATION_TIMEOUT" podman logs \
          "${GRAFANA_CONTAINERS[$member]}" 2>&1 \
          | jq -eR '
              fromjson?
              | select(
                  .logger == "migrator" and
                  .level == "error" and
                  .msg == "Failed to lock database" and
                  .error == "failed to obtain lock"
                )
            ' >/dev/null; then
        MIGRATION_LOCK_MEMBER="$member"
        return 0
      fi
    done
    sleep 0.2
  done
  fail 'No restarted Grafana contender reported migration-lock contention'
}

LAST_STAGE='PostgreSQL bootstrap'
start_postgresql
wait_for_postgresql
postgres_container_image="$(timeout "$OPERATION_TIMEOUT" podman inspect \
  --format '{{.Image}}' "$POSTGRES_CONTAINER")"
[[ "$postgres_container_image" == "${POSTGRES_IMAGE_ID#sha256:}" \
  || "$postgres_container_image" == "$POSTGRES_IMAGE_ID" ]] \
  || fail 'PostgreSQL container did not use the qualified image'
[[ "$(timeout "$OPERATION_TIMEOUT" podman exec "$POSTGRES_CONTAINER" \
  /opt/patroni/bin/patroni --version)" == 'patroni 4.1.4' ]] \
  || fail 'PostgreSQL candidate did not provide Patroni 4.1.4'
postgres_query postgres \
  "CREATE ROLE grafana LOGIN PASSWORD '${GRAFANA_DB_PASSWORD}'" >/dev/null
postgres_query postgres 'CREATE DATABASE grafana OWNER grafana' >/dev/null

LAST_STAGE='Grafana untrusted CA rejection'
create_grafana grafana-untrusted untrusted-ca.crt no
untrusted_ca_status=0
timeout "$OPERATION_TIMEOUT" podman start --attach \
  "${GRAFANA_CONTAINERS[grafana-untrusted]}" >/dev/null 2>&1 \
  || untrusted_ca_status=$?
[[ "$untrusted_ca_status" != 0 && "$untrusted_ca_status" != 124 ]] \
  || fail "Grafana untrusted-CA startup returned unexpected status: ${untrusted_ca_status}"
timeout "$OPERATION_TIMEOUT" podman logs \
  "${GRAFANA_CONTAINERS[grafana-untrusted]}" 2>&1 \
  | grep -F 'tls: failed to verify certificate: x509: certificate signed by unknown authority' \
    >/dev/null \
  || fail 'Grafana did not report PostgreSQL certificate rejection with an untrusted CA'
timeout "$OPERATION_TIMEOUT" podman rm \
  "${GRAFANA_CONTAINERS[grafana-untrusted]}" >/dev/null

LAST_STAGE='concurrent Grafana migration startup'
timeout "$OPERATION_TIMEOUT" podman exec --detach \
  --env PGHOST=/run/postgresql \
  "$POSTGRES_CONTAINER" \
  psql -X -v ON_ERROR_STOP=1 -U postgres -d grafana \
  -c "SELECT pg_advisory_lock(${GRAFANA_MIGRATION_LOCK_ID}); SELECT pg_sleep(300)" \
  >/dev/null
wait_for_migration_lock
for member in "${GRAFANA_MEMBERS[@]}"; do
  create_grafana "$member"
done
timeout "$OPERATION_TIMEOUT" podman start \
  "${GRAFANA_CONTAINERS[grafana-1]}" \
  "${GRAFANA_CONTAINERS[grafana-2]}" \
  "${GRAFANA_CONTAINERS[grafana-3]}" >/dev/null
wait_for_migration_lock_restart
lock_holder_pid="$(postgres_query grafana "
  SELECT pid
  FROM pg_locks
  WHERE locktype = 'advisory'
    AND classid = 0
    AND objid = ${GRAFANA_MIGRATION_LOCK_ID}
    AND granted IS TRUE
  LIMIT 1
")"
[[ "$lock_holder_pid" =~ ^[1-9][0-9]*$ ]] \
  || fail "Grafana migration lock holder returned an invalid PID: ${lock_holder_pid}"
[[ "$(postgres_query grafana "SELECT pg_terminate_backend(${lock_holder_pid})")" == t ]] \
  || fail 'Grafana migration lock holder did not terminate cleanly'
for member in "${GRAFANA_MEMBERS[@]}"; do
  set_grafana_endpoint "$member"
done
wait_for_all_grafana

grafana_tls_connections="$(postgres_query postgres '
  SELECT count(*)
  FROM pg_stat_ssl
  JOIN pg_stat_activity USING (pid)
  WHERE pg_stat_ssl.ssl IS TRUE
    AND pg_stat_activity.usename = '\''grafana'\''
')"
[[ "$grafana_tls_connections" =~ ^[0-9]+$ ]] \
  || fail "Grafana TLS database connection count is invalid: ${grafana_tls_connections}"
((grafana_tls_connections >= 3)) \
  || fail "Expected at least three Grafana TLS database connections, found ${grafana_tls_connections}"

migration_count="$(postgres_query grafana \
  "SELECT count(*) FROM migration_log WHERE success IS TRUE")"
[[ "$migration_count" == "$GRAFANA_EXPECTED_MIGRATIONS" ]] \
  || fail "Grafana completed ${migration_count} migrations; expected ${GRAFANA_EXPECTED_MIGRATIONS}"
failed_migrations="$(postgres_query grafana \
  "SELECT count(*) FROM migration_log WHERE success IS NOT TRUE")"
[[ "$failed_migrations" == 0 ]] \
  || fail "Grafana recorded failed migrations: ${failed_migrations}"
duplicate_migrations="$(postgres_query grafana '
  SELECT count(*)
  FROM (
    SELECT migration_id
    FROM migration_log
    WHERE success IS TRUE
    GROUP BY migration_id
    HAVING count(*) != 1
  ) duplicates
')"
[[ "$duplicate_migrations" == 0 ]] \
  || fail "Grafana recorded duplicate successful migrations: ${duplicate_migrations}"

LAST_STAGE='shared Grafana API state'
dashboard_uid="qualification-${RANDOM}-${RANDOM}"
dashboard_title="Grafana PostgreSQL qualification ${dashboard_uid}"
dashboard_payload="$(jq -nc \
  --arg uid "$dashboard_uid" \
  --arg title "$dashboard_title" '
    {
      dashboard: {
        id: null,
        uid: $uid,
        title: $title,
        tags: ["qualification"],
        timezone: "browser",
        schemaVersion: 41,
        version: 0,
        panels: []
      },
      overwrite: false
    }
  ')"
dashboard_response="$(curl -fsS --connect-timeout 2 --max-time 10 \
  --user "admin:${GRAFANA_ADMIN_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -X POST \
  --data-binary "$dashboard_payload" \
  "${GRAFANA_ENDPOINTS[grafana-1]}/api/dashboards/db")"
jq -e --arg uid "$dashboard_uid" '.status == "success" and .uid == $uid' \
  <<< "$dashboard_response" >/dev/null \
  || fail 'Grafana rejected the dashboard canary'
for member in "${GRAFANA_MEMBERS[@]}"; do
  assert_dashboard "$member" "$dashboard_uid" "$dashboard_title"
done

LAST_STAGE='one Grafana member failure and recovery'
timeout "$OPERATION_TIMEOUT" podman stop --time 10 \
  "${GRAFANA_CONTAINERS[grafana-2]}" >/dev/null
if curl -fsS --connect-timeout 2 --max-time 3 \
  "${GRAFANA_ENDPOINTS[grafana-2]}/api/health" >/dev/null 2>&1; then
  fail 'Stopped Grafana member remained reachable'
fi
assert_dashboard grafana-1 "$dashboard_uid" "$dashboard_title"
assert_dashboard grafana-3 "$dashboard_uid" "$dashboard_title"
timeout "$OPERATION_TIMEOUT" podman start \
  "${GRAFANA_CONTAINERS[grafana-2]}" >/dev/null
wait_for_grafana grafana-2
assert_dashboard grafana-2 "$dashboard_uid" "$dashboard_title"

LAST_STAGE='fresh-local-state Grafana replacement'
old_grafana_1="${GRAFANA_CONTAINERS[grafana-1]}"
timeout "$OPERATION_TIMEOUT" podman stop --time 10 "$old_grafana_1" >/dev/null
timeout "$OPERATION_TIMEOUT" podman rm "$old_grafana_1" >/dev/null
rm -rf -- "$TEST_DIR/grafana/grafana-1"
create_grafana grafana-1
timeout "$OPERATION_TIMEOUT" podman start \
  "${GRAFANA_CONTAINERS[grafana-1]}" >/dev/null
set_grafana_endpoint grafana-1
wait_for_grafana grafana-1
assert_dashboard grafana-1 "$dashboard_uid" "$dashboard_title"

LAST_STAGE='PostgreSQL connection outage and recovery'
timeout "$OPERATION_TIMEOUT" podman network disconnect \
  "$NETWORK" "$POSTGRES_CONTAINER"
wait_for_database_outage
timeout "$OPERATION_TIMEOUT" podman network connect \
  --alias postgresql "$NETWORK" "$POSTGRES_CONTAINER"
wait_for_postgresql
wait_for_all_grafana
for member in "${GRAFANA_MEMBERS[@]}"; do
  assert_dashboard "$member" "$dashboard_uid" "$dashboard_title"
done
[[ "$(postgres_query grafana \
  "SELECT count(*) FROM migration_log WHERE success IS NOT TRUE")" == 0 ]] \
  || fail 'Grafana migration state was not clean after PostgreSQL recovery'

printf '%s\n' \
  "Verified Grafana ${GRAFANA_VERSION} concurrent migrations (${migration_count} unique successful records; lock contender ${MIGRATION_LOCK_MEMBER}) and shared-state recovery against PostgreSQL 18.4 (${POSTGRES_EXPECTED_DIGEST})."
