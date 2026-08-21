#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${PLATFORM_CONFIG_PKI_ONE_RUNNER_INNER:-0}" != 1 ]]; then
  command -v timeout >/dev/null 2>&1 || {
    printf 'Required command not found: timeout\n' >&2
    exit 1
  }
  LANE_TIMEOUT="${PKI_ONE_RUNNER_LANE_TIMEOUT:-1800}"
  [[ "$LANE_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || {
    printf 'PKI_ONE_RUNNER_LANE_TIMEOUT must be a positive integer\n' >&2
    exit 1
  }
  export PLATFORM_CONFIG_PKI_ONE_RUNNER_INNER=1
  exec timeout --foreground --signal=TERM --kill-after=150 \
    "$LANE_TIMEOUT" bash "$0" "$@"
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_DIR="${ROOT_DIR}/tests/fixtures/pki-host-local-zot-one-runner"
ZOT_PLAYBOOK=/workspace/tests/fixtures/pki-host-local-zot-one-runner/zot.yml
ROCKY_IMAGE="${PKI_ONE_RUNNER_ROCKY_IMAGE:-docker.io/rockylinux/rockylinux:10.1}"
DEV_IMAGE="${PLATFORM_CONFIG_DEV_IMAGE:-platform-config-dev:latest}"
BOOTSTRAP_NETWORK="${PKI_ONE_RUNNER_BOOTSTRAP_NETWORK:-podman}"
OPERATION_TIMEOUT="${PKI_ONE_RUNNER_OPERATION_TIMEOUT:-60}"
PULL_TIMEOUT="${PKI_ONE_RUNNER_PULL_TIMEOUT:-300}"
READY_TIMEOUT="${PKI_ONE_RUNNER_READY_TIMEOUT:-90}"
CONTROLLER_TIMEOUT="${PKI_ONE_RUNNER_CONTROLLER_TIMEOUT:-300}"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/platform-config-pki-zot.XXXXXXXX")"
RUN_ID="platform-config-pki-zot-${TEST_DIR##*/}"
LABEL="platform-config.pki-zot-one-runner=${RUN_ID}"
NETWORK="${RUN_ID}-network"
TARGET_CONTAINER="${RUN_ID}-target"
RUNNER_CONTAINER="${RUN_ID}-runner"
TARGET=registry-one.test
RUNNER=runner-one.test
SERVICE=registry-dev
ENDPOINT="https://${TARGET}:8443/v2/"
TRUST_ID="${RUN_ID}-trust"
STATE_ROOT=/var/lib/platform-config/pki/host-local/registry-dev
PENDING_ROOT=/etc/zot/tls-pending
VERSIONS_ROOT=/etc/zot/tls-versions
EXCHANGE_ROOT="${TEST_DIR}/controller-exchange"
SIGNER_ROOT="${TEST_DIR}/synthetic-signer"
SIGNER_MEDIA="${SIGNER_ROOT}/media"
LOG_DIR="${TEST_DIR}/command-logs"
CONTROLLER_HOME="${TEST_DIR}/controller-home"
INVENTORY="${TEST_DIR}/inventory.yml"
INVENTORY_IDENTITY="${TEST_DIR}/inventory.identity"
VARS_FILE="${TEST_DIR}/vars.json"
KNOWN_HOSTS="${TEST_DIR}/known_hosts"
CONTROLLER_KEY="${TEST_DIR}/controller-ssh"
HTPASSWD_FILE="${TEST_DIR}/zot.htpasswd"
RESPONSE_KEY="${SIGNER_ROOT}/response-signing-key"
APPROVER_KEY="${SIGNER_ROOT}/approver-signing-key"
RESPONSE_PRINCIPAL=synthetic-response
APPROVER_PRINCIPAL=synthetic-approver
COMMON_NAME="$TARGET"
NETWORK_CREATED=false
TARGET_CREATED=false
RUNNER_CREATED=false
LAST_STAGE=initialization
REQUEST_ID=
ARTIFACT_SHA256=
DEPLOYMENT_SHA256=
REVIEWED_CA_SHA256=
SERVED_INTERMEDIATE_SHA256=
RESPONSE_SOURCE_DIR=
BOUNDARY_FILE=
TARGET_BOUNDARY=
RUNNER_BOUNDARY=
TARGET_CA=
RUNNER_CA=
INVENTORY_SHA256=
CURRENT_CERT_SHA256=none
TRANSPORT_HOST_KEY_SHA256=
ZOT_IMAGE=
EXCHANGE_MODE=controller-local

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

print_file() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '%s\n' "$line" >&2
  done < "$1"
}

cleanup() {
  local status=$?
  local cleanup_failed=false
  local leftovers_output
  local -a leftovers=()

  trap - EXIT INT TERM
  if ((status != 0)); then
    printf '\nPKI/Zot one-runner lane failed during: %s\n' "$LAST_STAGE" >&2
    if [[ "$TARGET_CREATED" == true ]] \
      && timeout 5 podman container exists "$TARGET_CONTAINER" >/dev/null 2>&1; then
      printf '\n===== target system state =====\n' >&2
      timeout 10 podman exec "$TARGET_CONTAINER" systemctl --failed --no-pager >&2 2>/dev/null || true
      printf '\n===== Zot service status =====\n' >&2
      timeout 10 podman exec "$TARGET_CONTAINER" systemctl status zot.service --no-pager >&2 2>/dev/null || true
      printf '\n===== Zot service journal =====\n' >&2
      timeout 10 podman exec "$TARGET_CONTAINER" journalctl -u zot.service -n 80 --no-pager >&2 2>/dev/null || true
    fi
  fi

  if leftovers_output="$(
    timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null
  )"; then
    if [[ -n "$leftovers_output" ]]; then
      mapfile -t leftovers <<< "$leftovers_output"
    fi
  else
    printf 'Could not inspect test-labeled containers during cleanup\n' >&2
    cleanup_failed=true
  fi
  if ((${#leftovers[@]})); then
    timeout 30 podman rm -f "${leftovers[@]}" >/dev/null 2>&1 || cleanup_failed=true
  fi
  if leftovers_output="$(timeout 10 podman ps -aq --filter "label=${LABEL}" 2>/dev/null)"; then
    if [[ -n "$leftovers_output" ]]; then
      printf 'Cleanup left test-labeled containers\n' >&2
      cleanup_failed=true
    fi
  else
    printf 'Could not verify test-labeled container cleanup\n' >&2
    cleanup_failed=true
  fi
  if [[ "$NETWORK_CREATED" == true ]]; then
    timeout 15 podman network rm -f "$NETWORK" >/dev/null 2>&1 || cleanup_failed=true
  fi
  if timeout 5 podman network exists "$NETWORK" >/dev/null 2>&1; then
    printf 'Cleanup left test-owned network: %s\n' "$NETWORK" >&2
    cleanup_failed=true
  fi
  rm -rf -- "$TEST_DIR"
  if [[ "$cleanup_failed" == true && "$status" == 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in base64 find grep jq openssl podman sha256sum ssh-keygen ssh-keyscan timeout; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "Required command not found: ${command}"
done
for timeout_name in OPERATION_TIMEOUT PULL_TIMEOUT READY_TIMEOUT CONTROLLER_TIMEOUT; do
  [[ "${!timeout_name}" =~ ^[1-9][0-9]*$ ]] \
    || fail "${timeout_name} must be a positive integer"
done
[[ -f "${FIXTURE_DIR}/zot.yml" && -f "${FIXTURE_DIR}/synthetic_signer.py" ]] \
  || fail 'PKI/Zot one-runner fixtures are incomplete'
timeout "$OPERATION_TIMEOUT" podman image exists "$DEV_IMAGE" >/dev/null 2>&1 \
  || fail "Development image ${DEV_IMAGE} is absent; run 'make deps' before this opt-in lane"
timeout "$OPERATION_TIMEOUT" podman network exists "$BOOTSTRAP_NETWORK" >/dev/null 2>&1 \
  || fail "Bootstrap bridge ${BOOTSTRAP_NETWORK} does not exist"
[[ "$(timeout "$OPERATION_TIMEOUT" podman network inspect --format '{{.Internal}}' "$BOOTSTRAP_NETWORK")" == false ]] \
  || fail "Bootstrap bridge ${BOOTSTRAP_NETWORK} must provide external connectivity"

verify_default_exclusion() {
  local target=$1
  local line
  local found=false

  while IFS= read -r line; do
    if [[ "$line" == "${target}:"* ]]; then
      found=true
      [[ "$line" != *test-pki-host-local-zot-one-runner* ]] \
        || fail "${target} unexpectedly includes the disposable PKI/Zot lane"
    fi
  done < "${ROOT_DIR}/Makefile"
  [[ "$found" == true ]] || fail "Could not verify the ${target} dependency line"
}
verify_default_exclusion verify
verify_default_exclusion verify-parallel

while IFS=' ' read -r key value remainder; do
  if [[ "$key" == zot_registry_image: ]]; then
    [[ -z "$ZOT_IMAGE" && -n "$value" && -z "${remainder:-}" ]] \
      || fail 'Could not resolve one exact Zot role image'
    ZOT_IMAGE=$value
  fi
done < "${ROOT_DIR}/roles/zot_registry/defaults/main.yml"
[[ "$ZOT_IMAGE" == ghcr.io/project-zot/zot:v2.1.17 ]] \
  || fail "Unexpected Zot role image: ${ZOT_IMAGE:-missing}"

mkdir -p "$EXCHANGE_ROOT" "$SIGNER_MEDIA" "$LOG_DIR" \
  "$CONTROLLER_HOME/.ansible/tmp"
chmod 0700 "$EXCHANGE_ROOT" "$SIGNER_ROOT" "$SIGNER_MEDIA" "$LOG_DIR" \
  "$CONTROLLER_HOME" "$CONTROLLER_HOME/.ansible" "$CONTROLLER_HOME/.ansible/tmp"

LAST_STAGE='synthetic bootstrap material'
ssh-keygen -q -t ed25519 -N '' -f "$CONTROLLER_KEY"
ssh-keygen -q -t ed25519 -N '' -f "$RESPONSE_KEY"
ssh-keygen -q -t ed25519 -N '' -f "$APPROVER_KEY"
LAST_STAGE='container and network creation'
timeout "$PULL_TIMEOUT" podman pull --quiet "$ROCKY_IMAGE" >/dev/null
timeout "$OPERATION_TIMEOUT" podman network create \
  --internal --label "$LABEL" "$NETWORK" >/dev/null
NETWORK_CREATED=true
[[ "$(timeout "$OPERATION_TIMEOUT" podman network inspect --format '{{.Internal}}' "$NETWORK")" == true ]] \
  || fail 'Disposable PKI/Zot network is not internal'

timeout "$OPERATION_TIMEOUT" podman run --detach \
  --name "$TARGET_CONTAINER" \
  --label "$LABEL" \
  --hostname "$TARGET" \
  --privileged \
  --security-opt label=disable \
  --systemd=always \
  --network "$BOOTSTRAP_NETWORK" \
  --publish 127.0.0.1::22 \
  "$ROCKY_IMAGE" \
  bash -lc 'dnf -qy install systemd && exec /sbin/init' >/dev/null
TARGET_CREATED=true
timeout "$OPERATION_TIMEOUT" podman run --detach \
  --name "$RUNNER_CONTAINER" \
  --label "$LABEL" \
  --hostname "$RUNNER" \
  --network "$BOOTSTRAP_NETWORK" \
  --publish 127.0.0.1::22 \
  "$ROCKY_IMAGE" sleep infinity >/dev/null
RUNNER_CREATED=true

system_state=starting
for ((attempt = 0; attempt < READY_TIMEOUT; attempt++)); do
  system_state="$(timeout 5 podman exec "$TARGET_CONTAINER" systemctl is-system-running 2>/dev/null || true)"
  if [[ "$system_state" == running || "$system_state" == degraded ]]; then
    break
  fi
  sleep 1
done
if [[ "$system_state" != running && "$system_state" != degraded ]]; then
  fail "Disposable Rocky target did not become ready: ${system_state}"
fi

LAST_STAGE='runtime bootstrap before network isolation'
timeout "$PULL_TIMEOUT" podman exec "$TARGET_CONTAINER" dnf -qy install \
  httpd-tools openssh-clients openssh-server openssl podman python3 python3-cryptography >/dev/null
timeout "$PULL_TIMEOUT" podman exec "$RUNNER_CONTAINER" dnf -qy install \
  openssh-server python3 >/dev/null
timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" bash -c \
  'install -d -m 0755 /etc/containers && printf "%s\n" "[storage]" "driver = \"vfs\"" "runroot = \"/run/containers/storage\"" "graphroot = \"/var/lib/containers/storage\"" > /etc/containers/storage.conf'
timeout "$PULL_TIMEOUT" podman exec "$TARGET_CONTAINER" podman pull --quiet "$ZOT_IMAGE" >/dev/null
timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  htpasswd -Bbn synthetic disposable-validation-only > "$HTPASSWD_FILE"
chmod 0600 "$HTPASSWD_FILE"

for container in "$TARGET_CONTAINER" "$RUNNER_CONTAINER"; do
  timeout "$OPERATION_TIMEOUT" podman exec "$container" ssh-keygen -A
  timeout "$OPERATION_TIMEOUT" podman exec "$container" install -d -m 0700 /root/.ssh
  timeout "$OPERATION_TIMEOUT" podman cp "${CONTROLLER_KEY}.pub" "${container}:/root/.ssh/authorized_keys"
  timeout "$OPERATION_TIMEOUT" podman exec "$container" chmod 0600 /root/.ssh/authorized_keys
  timeout "$OPERATION_TIMEOUT" podman exec "$container" bash -c \
    'printf "%s\n" "PasswordAuthentication no" "PermitRootLogin prohibit-password" > /etc/ssh/sshd_config.d/99-disposable-pki.conf'
done
timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl enable --now sshd.service >/dev/null
timeout "$OPERATION_TIMEOUT" podman exec --detach "$RUNNER_CONTAINER" /usr/sbin/sshd -D -e >/dev/null

timeout "$OPERATION_TIMEOUT" podman network connect \
  --alias "$TARGET" "$NETWORK" "$TARGET_CONTAINER"
timeout "$OPERATION_TIMEOUT" podman network connect \
  --alias "$RUNNER" "$NETWORK" "$RUNNER_CONTAINER"
timeout "$OPERATION_TIMEOUT" podman network disconnect "$BOOTSTRAP_NETWORK" "$TARGET_CONTAINER"
timeout "$OPERATION_TIMEOUT" podman network disconnect "$BOOTSTRAP_NETWORK" "$RUNNER_CONTAINER"

network_members="$(timeout "$OPERATION_TIMEOUT" podman network inspect \
  --format '{{range .Containers}}{{println .Name}}{{end}}' "$NETWORK")"
member_count=0
target_seen=false
runner_seen=false
while IFS= read -r member; do
  [[ -z "$member" ]] && continue
  ((member_count += 1))
  case "$member" in
    "$TARGET_CONTAINER") target_seen=true ;;
    "$RUNNER_CONTAINER") runner_seen=true ;;
    *) fail "Unexpected identity attached to isolated network: ${member}" ;;
  esac
done <<< "$network_members"
[[ "$member_count" -eq 2 && "$target_seen" == true && "$runner_seen" == true ]] \
  || fail 'Isolated network does not contain exactly the target and one runner'

TARGET_PORT="$(timeout "$OPERATION_TIMEOUT" podman port "$TARGET_CONTAINER" 22/tcp | while IFS=: read -r _ port; do printf '%s' "$port"; done)"
RUNNER_PORT="$(timeout "$OPERATION_TIMEOUT" podman port "$RUNNER_CONTAINER" 22/tcp | while IFS=: read -r _ port; do printf '%s' "$port"; done)"
[[ "$TARGET_PORT" =~ ^[1-9][0-9]*$ && "$RUNNER_PORT" =~ ^[1-9][0-9]*$ ]] \
  || fail 'Could not resolve disposable SSH ports'

: > "$KNOWN_HOSTS"
for port in "$TARGET_PORT" "$RUNNER_PORT"; do
  host_key=
  for ((attempt = 0; attempt < READY_TIMEOUT; attempt++)); do
    host_key="$(timeout 5 ssh-keyscan -T 3 -t ed25519 -p "$port" 127.0.0.1 2>/dev/null || true)"
    [[ -n "$host_key" ]] && break
    sleep 1
  done
  [[ -n "$host_key" ]] || fail "SSH did not become ready on disposable port ${port}"
  printf '%s\n' "$host_key" >> "$KNOWN_HOSTS"
done
chmod 0600 "$KNOWN_HOSTS"

target_host_key="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  bash -c 'read -r algorithm payload comment < /etc/ssh/ssh_host_ed25519_key.pub; printf "%s %s" "$algorithm" "$payload"')"
read -r target_algorithm target_payload <<< "$target_host_key"
[[ "$target_algorithm" == ssh-ed25519 && -n "$target_payload" ]] \
  || fail 'Target deployment/request signing key is not Ed25519'
TRANSPORT_HOST_KEY_SHA256="$(printf '%s' "$target_payload" | base64 -d | sha256sum | while read -r value _; do printf '%s' "$value"; done)"

response_public="$(while read -r algorithm payload comment; do printf '%s %s' "$algorithm" "$payload"; break; done < "${RESPONSE_KEY}.pub")"
approver_public="$(while read -r algorithm payload comment; do printf '%s %s' "$algorithm" "$payload"; break; done < "${APPROVER_KEY}.pub")"
TRUST_SOURCE="${TEST_DIR}/reviewed-trust"
mkdir -m 0700 "$TRUST_SOURCE"
printf '%s %s\n' "$TARGET" "$target_host_key" > "${TRUST_SOURCE}/requesters.allowed_signers"
printf '%s %s\n' "$TARGET" "$target_host_key" > "${TRUST_SOURCE}/deployers.allowed_signers"
printf '%s %s\n' "$RESPONSE_PRINCIPAL" "$response_public" > "${TRUST_SOURCE}/responses.allowed_signers"
printf '%s %s\n' "$APPROVER_PRINCIPAL" "$approver_public" > "${TRUST_SOURCE}/approvers.allowed_signers"
printf '%s\n' \
  'schema=2' \
  'request_namespace=platform-pki-csr-request-v1' \
  'approval_namespace=platform-pki-csr-approval-v1' \
  'response_namespace=platform-pki-csr-response-v1' \
  'deployment_namespace=platform-pki-csr-deployment-v1' \
  'request_max_age_seconds=604800' \
  'sole_operator_min_delay_seconds=86400' \
  'approval_max_age_seconds=86400' \
  'deployment_max_age_seconds=86400' \
  'clock_skew_seconds=300' \
  "approver_principal=${APPROVER_PRINCIPAL}" \
  "response_principal=${RESPONSE_PRINCIPAL}" > "${TRUST_SOURCE}/policy"
chmod 0600 "${TRUST_SOURCE}"/*

declare -A TRUST_SHA
for name in policy requesters.allowed_signers approvers.allowed_signers responses.allowed_signers deployers.allowed_signers; do
  TRUST_SHA[$name]="$(sha256sum "${TRUST_SOURCE}/${name}" | while read -r value _; do printf '%s' "$value"; done)"
done

cat > "$INVENTORY" <<EOF
---
all:
  vars:
    ansible_user: root
    ansible_python_interpreter: /usr/bin/python3
    ansible_ssh_private_key_file: ${CONTROLLER_KEY}
    ansible_ssh_common_args: >-
      -o UserKnownHostsFile=${KNOWN_HOSTS}
      -o StrictHostKeyChecking=yes
      -o IdentitiesOnly=yes
      -o PasswordAuthentication=no
  children:
    registry:
      hosts:
        ${TARGET}:
          ansible_host: 127.0.0.1
          ansible_port: ${TARGET_PORT}
    validators:
      hosts:
        ${RUNNER}:
          ansible_host: 127.0.0.1
          ansible_port: ${RUNNER_PORT}
EOF
chmod 0600 "$INVENTORY"
printf '%s\n' \
  "schema=1" \
  "kind=synthetic-disposable-inventory" \
  "target=${TARGET}" \
  "runner=${RUNNER}" \
  "network=${NETWORK}" > "$INVENTORY_IDENTITY"
INVENTORY_SHA256="$(sha256sum "$INVENTORY_IDENTITY" | while read -r value _; do printf '%s' "$value"; done)"

write_vars() {
  jq -n \
    --arg service "$SERVICE" \
    --arg target "$TARGET" \
    --arg runner "$RUNNER" \
    --arg inventory_sha "$INVENTORY_SHA256" \
    --arg current_sha "$CURRENT_CERT_SHA256" \
    --arg response_principal "$RESPONSE_PRINCIPAL" \
    --arg common_name "$COMMON_NAME" \
    --arg trust_id "$TRUST_ID" \
    --arg state_root "$STATE_ROOT" \
    --arg pending_root "$PENDING_ROOT" \
    --arg versions_root "$VERSIONS_ROOT" \
    --arg exchange_root "$EXCHANGE_ROOT" \
    --arg transport_sha "$TRANSPORT_HOST_KEY_SHA256" \
    --arg request_id "$REQUEST_ID" \
    --arg artifact_sha "$ARTIFACT_SHA256" \
    --arg response_dir "$RESPONSE_SOURCE_DIR" \
    --arg boundary_sha "${BOUNDARY_SHA256:-}" \
    --arg target_boundary "$TARGET_BOUNDARY" \
    --arg runner_boundary "$RUNNER_BOUNDARY" \
    --arg target_ca "$TARGET_CA" \
    --arg runner_ca "$RUNNER_CA" \
    --arg ca_sha "$REVIEWED_CA_SHA256" \
    --arg endpoint "$ENDPOINT" \
    --arg deployment_sha "$DEPLOYMENT_SHA256" \
    --arg intermediate_sha "$SERVED_INTERMEDIATE_SHA256" \
    --arg htpasswd "$HTPASSWD_FILE" \
    --arg policy "${TRUST_SOURCE}/policy" \
    --arg requesters "${TRUST_SOURCE}/requesters.allowed_signers" \
    --arg approvers "${TRUST_SOURCE}/approvers.allowed_signers" \
    --arg responses "${TRUST_SOURCE}/responses.allowed_signers" \
    --arg deployers "${TRUST_SOURCE}/deployers.allowed_signers" \
    --arg policy_sha "${TRUST_SHA[policy]}" \
    --arg requesters_sha "${TRUST_SHA[requesters.allowed_signers]}" \
    --arg approvers_sha "${TRUST_SHA[approvers.allowed_signers]}" \
    --arg responses_sha "${TRUST_SHA[responses.allowed_signers]}" \
    --arg deployers_sha "${TRUST_SHA[deployers.allowed_signers]}" \
    --arg exchange_mode "$EXCHANGE_MODE" \
    '{
      pki_host_local_certificate_service: $service,
      pki_host_local_certificate_target: $target,
      pki_host_local_certificate_operation: "issue",
      pki_host_local_certificate_profile: "server-p384-sha384-v1",
      pki_host_local_certificate_inventory_sha256: $inventory_sha,
      pki_host_local_certificate_current_cert_sha256: $current_sha,
      pki_host_local_certificate_current_cert_path: "",
      pki_host_local_certificate_requester_principal: $target,
      pki_host_local_certificate_response_principal: $response_principal,
      pki_host_local_certificate_common_name: $common_name,
      pki_host_local_certificate_dns_sans: [$common_name],
      pki_host_local_certificate_ip_sans: [],
      pki_host_local_certificate_validity_days: 7,
      pki_host_local_certificate_request_ttl_seconds: (if $request_id == "" then 3600 else 0 end),
      pki_host_local_certificate_trust_id: $trust_id,
      pki_host_local_certificate_state_root: $state_root,
      pki_host_local_certificate_pending_root: $pending_root,
      pki_host_local_certificate_versions_root: $versions_root,
      pki_host_local_certificate_controller_exchange_root: $exchange_root,
      pki_host_local_certificate_exchange_mode: $exchange_mode,
      pki_host_local_certificate_transport: "ssh",
      pki_host_local_certificate_transport_host_key_sha256: $transport_sha,
      pki_host_local_certificate_request_id: $request_id,
      pki_host_local_certificate_artifact_manifest_sha256: $artifact_sha,
      pki_host_local_certificate_response_source_dir: $response_dir,
      pki_host_local_certificate_validation_boundary_sha256: $boundary_sha,
      pki_host_local_certificate_validation_boundary_target_path: $target_boundary,
      pki_host_local_certificate_validation_boundary_runner_path: $runner_boundary,
      pki_host_local_certificate_reviewed_ca_target_path: $target_ca,
      pki_host_local_certificate_reviewed_ca_runner_path: $runner_ca,
      pki_host_local_certificate_reviewed_ca_sha256: $ca_sha,
      pki_host_local_certificate_reviewed_ca_mode: (if $ca_sha == "" then "" else "0600" end),
      pki_host_local_certificate_remote_validator: $runner,
      pki_host_local_certificate_endpoint: $endpoint,
      pki_host_local_certificate_minimum_remaining_lifetime_seconds: 3600,
      pki_host_local_certificate_validation_wait_seconds: 0,
      pki_host_local_certificate_zot_config_path: "/etc/zot/config.json",
      pki_host_local_certificate_rollback_seconds: (if $artifact_sha == "" then 0 else 1209600 end),
      pki_host_local_certificate_deployment_sha256: $deployment_sha,
      pki_host_local_certificate_served_intermediate_sha256: $intermediate_sha,
      pki_host_local_certificate_activation_action: (if $artifact_sha == "" then "" else "finalize" end),
      pki_host_local_certificate_activation_result: (if $artifact_sha == "" then "" else "activated" end),
      pki_host_local_certificate_trust_sources: {
        "policy": $policy,
        "requesters.allowed_signers": $requesters,
        "approvers.allowed_signers": $approvers,
        "responses.allowed_signers": $responses,
        "deployers.allowed_signers": $deployers
      },
      pki_host_local_certificate_trust_paths: {
        "policy": ($state_root + "/trust/" + $trust_id + "/policy"),
        "requesters.allowed_signers": ($state_root + "/trust/" + $trust_id + "/requesters.allowed_signers"),
        "approvers.allowed_signers": ($state_root + "/trust/" + $trust_id + "/approvers.allowed_signers"),
        "responses.allowed_signers": ($state_root + "/trust/" + $trust_id + "/responses.allowed_signers"),
        "deployers.allowed_signers": ($state_root + "/trust/" + $trust_id + "/deployers.allowed_signers")
      },
      pki_host_local_certificate_trust_sha256: {
        "policy": $policy_sha,
        "requesters.allowed_signers": $requesters_sha,
        "approvers.allowed_signers": $approvers_sha,
        "responses.allowed_signers": $responses_sha,
        "deployers.allowed_signers": $deployers_sha
      },
      zot_registry_tls_host_local_target: $target,
      zot_registry_tls_cert_src: "",
      zot_registry_tls_key_src: "",
      zot_registry_auth_enabled: false,
      zot_registry_auth_htpasswd_src: $htpasswd,
      zot_registry_allow_insecure_anonymous_access: true,
      zot_registry_host_port: 8443,
      zot_registry_firewalld_manage: false,
      zot_registry_service_enabled: true,
      zot_registry_service_state: "started"
    }' > "$VARS_FILE"
  chmod 0600 "$VARS_FILE"
}

controller_command() {
  local log=$1
  shift
  local status
  local -a execution=("$@")
  local -a command=(
    timeout "$((CONTROLLER_TIMEOUT + 30))" podman run --rm
    --label "$LABEL"
    --network host
    --userns=keep-id
    --user "$(id -u):$(id -g)"
    --security-opt label=disable
    --workdir /workspace
    --env "HOME=${CONTROLLER_HOME}"
    --env ANSIBLE_CONFIG=/workspace/ansible.cfg
    --env "ANSIBLE_LOCAL_TEMP=${CONTROLLER_HOME}/.ansible/tmp"
    --env "ANSIBLE_REMOTE_TEMP=/tmp/${RUN_ID}-ansible"
    --env ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections
    --env PYTHONPATH=/workspace
    --volume "${ROOT_DIR}:/workspace:ro"
    --volume "${TEST_DIR}:${TEST_DIR}:rw"
    "$DEV_IMAGE"
    "${execution[@]}"
  )

  if "${command[@]}" > "$log" 2>&1 < /dev/null; then status=0; else status=$?; fi
  if grep -Fq 'tls.key' "$log"; then
    fail "Command log contains a private-key basename: ${log##*/}"
  fi
  return "$status"
}

run_playbook() {
  local phase=$1
  local playbook=$2
  shift 2
  local log="${LOG_DIR}/${phase}.log"

  if ! controller_command "$log" \
    ansible-playbook -i "$INVENTORY" "$playbook" -e "@${VARS_FILE}" "$@"; then
    print_file "$log"
    fail "Ansible phase failed: ${phase}"
  fi
}

assert_idempotent() {
  local log="${LOG_DIR}/$1.log"
  grep -qE 'changed=0.*failed=0' "$log" \
    || { print_file "$log"; fail "Phase was not idempotent: $1"; }
}

assert_exact_local_dir() {
  local directory=$1
  shift
  local -A expected=()
  local entry
  local count=0
  local -a entries=()

  for entry in "$@"; do expected[$entry]=1; done
  shopt -s nullglob dotglob
  entries=("$directory"/*)
  shopt -u nullglob dotglob
  [[ "${#entries[@]}" -eq "$#" ]] \
    || fail "Unexpected entries in exact directory ${directory}: ${entries[*]##*/}"
  for entry in "${entries[@]}"; do
    [[ -f "$entry" && ! -L "$entry" && -n "${expected[${entry##*/}]:-}" ]] \
      || fail "Unexpected entry in exact directory: ${entry}"
    ((count += 1))
  done
  [[ "$count" -eq "$#" ]] || fail "Exact directory validation failed: ${directory}"
}

assert_exact_target_dir() {
  local directory=$1
  local expected=$2
  local actual
  actual="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" python3 -c \
    'import os,sys; print(",".join(sorted(os.listdir(sys.argv[1]))))' "$directory")"
  [[ "$actual" == "$expected" ]] \
    || fail "Unexpected target directory entries at ${directory}: ${actual}"
}

stage_direct_response() {
  local ingress="${VERSIONS_ROOT}/.ingress-${REQUEST_ID}"
  local name
  local prepare

  prepare="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
    /usr/local/libexec/platform-pki-host-local-lifecycle response-prepare \
    --state-root "$STATE_ROOT" --pending-root "$PENDING_ROOT" \
    --versions-root "$VERSIONS_ROOT" --service "$SERVICE" --target "$TARGET" \
    --trust-id "$TRUST_ID" --request-id "$REQUEST_ID")"
  [[ "$(jq -er '.status' <<< "$prepare")" == prepared ]] \
    || fail 'Direct response ingress preparation did not create the exact stage'
  for name in artifact tls.crt ca-chain.crt fullchain.crt response response.sig; do
    timeout "$OPERATION_TIMEOUT" podman cp \
      "${RESPONSE_SOURCE_DIR}/${name}" "${TARGET_CONTAINER}:/tmp/${REQUEST_ID}-${name}"
    timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" install \
      -o root -g root -m 0600 "/tmp/${REQUEST_ID}-${name}" "${ingress}/${name}"
    timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" rm -f \
      "/tmp/${REQUEST_ID}-${name}"
  done
  assert_exact_target_dir "$ingress" \
    'artifact,ca-chain.crt,fullchain.crt,response,response.sig,tls.crt'
}

extract_coordinate() {
  local file=$1
  local name=$2
  local line remainder value
  local found=

  while IFS= read -r line; do
    remainder=$line
    while [[ "$remainder" =~ ${name}=([0-9a-f]{64}) ]]; do
      value=${BASH_REMATCH[1]}
      [[ -z "$found" || "$found" == "$value" ]] \
        || fail "Multiple ${name} coordinates appeared in ${file##*/}"
      found=$value
      remainder=${remainder#*"${name}=${value}"}
    done
  done < "$file"
  [[ "$found" =~ ^[0-9a-f]{64}$ ]] \
    || fail "Could not extract exact ${name} coordinate from ${file##*/}"
  printf '%s' "$found"
}

write_vars

LAST_STAGE='Zot role check mode and dormant convergence'
run_playbook zot-check "$ZOT_PLAYBOOK" --check
if timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" test -e /etc/zot/config.json; then
  fail 'Zot role check mode created its configuration'
fi
run_playbook zot-initial "$ZOT_PLAYBOOK"
run_playbook zot-idempotent "$ZOT_PLAYBOOK"
assert_idempotent zot-idempotent
if timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl is-active --quiet zot.service; then
  fail 'Dormant Zot service is unexpectedly active'
fi
[[ "$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl is-enabled zot.service)" == masked ]] \
  || fail 'Dormant Zot service is not masked'
for dormant_path in /etc/zot/tls/tls.crt /etc/zot/tls/tls.key; do
  if timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" test -e "$dormant_path"; then
    fail "Dormant Zot TLS material exists: ${dormant_path}"
  fi
done
quadlet_image="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  bash -c 'while IFS= read -r line; do case "$line" in Image=*) printf "%s" "${line#Image=}";; esac; done < /etc/containers/systemd/zot.container')"
[[ "$quadlet_image" == "$ZOT_IMAGE" ]] \
  || fail "Zot Quadlet image differs from the role default: ${quadlet_image}"
if timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" podman container exists zot; then
  fail 'Dormant convergence created a Zot container'
fi

LAST_STAGE='real trust bootstrap and request collection'
run_playbook trust /workspace/playbooks/registry-pki-trust.yml
run_playbook trust-check /workspace/playbooks/registry-pki-trust.yml --check
run_playbook trust-idempotent /workspace/playbooks/registry-pki-trust.yml
assert_idempotent trust-idempotent
run_playbook request /workspace/playbooks/registry-pki-request.yml
status_json="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  /usr/local/libexec/platform-pki-host-local-lifecycle status \
  --state-root "$STATE_ROOT" --pending-root "$PENDING_ROOT" \
  --versions-root "$VERSIONS_ROOT" --service "$SERVICE" --target "$TARGET" \
  --operation issue \
  --zot-config /etc/zot/config.json --trust-id "$TRUST_ID" \
  --common-name "$COMMON_NAME" --dns-san "$TARGET" \
  --minimum-remaining-lifetime-seconds 3600)"
[[ "$(jq -er '.status' <<< "$status_json")" == request-pending ]] \
  || fail 'Authenticated target status did not report request-pending'
REQUEST_ID="$(jq -er '.pending_request_id' <<< "$status_json")"
[[ "$REQUEST_ID" =~ ^[0-9a-f]{32}$ ]] || fail 'Target status returned a noncanonical request ID'
run_playbook request-check /workspace/playbooks/registry-pki-request.yml --check
run_playbook request-idempotent /workspace/playbooks/registry-pki-request.yml
assert_idempotent request-idempotent
write_vars

LAST_STAGE='initialized lifecycle dormant Zot custody'
run_playbook zot-initialized-dormant "$ZOT_PLAYBOOK"
assert_idempotent zot-initialized-dormant
if timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl is-active --quiet zot.service; then
  fail 'Initialized dormant Zot service is unexpectedly active'
fi
[[ "$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl is-enabled zot.service)" == masked ]] \
  || fail 'Initialized dormant Zot service is not masked'

REQUEST_PUBLICATION="${EXCHANGE_ROOT}/${SERVICE}/${REQUEST_ID}/request"
assert_exact_local_dir "$REQUEST_PUBLICATION" \
  tls.csr request request.sig collection-receipt
if [[ -e "${REQUEST_PUBLICATION}/tls.key" ]]; then
  fail 'Target-local private key appeared in controller request publication'
fi
assert_exact_target_dir "${PENDING_ROOT}/${REQUEST_ID}" \
  'request,request.sig,tls.csr,tls.key'
[[ "$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  stat -c '%U:%G:%a:%h' "${PENDING_ROOT}/${REQUEST_ID}/tls.key")" == root:root:600:1 ]] \
  || fail 'Pending target key is not root-owned, mode 0600, and singly linked'

LAST_STAGE='synthetic offline approval and signing'
RESPONSE_SOURCE_DIR="${SIGNER_MEDIA}/response-${REQUEST_ID}"
APPROVAL_DIR="${SIGNER_MEDIA}/approval-${REQUEST_ID}"
REVIEWED_CA_FILE="${SIGNER_ROOT}/reviewed-ca-${REQUEST_ID}.pem"
SIGNER_RESULT="${SIGNER_ROOT}/result-${REQUEST_ID}.json"
SIGNER_LOG="${LOG_DIR}/synthetic-signer.log"
if ! timeout "$CONTROLLER_TIMEOUT" podman run --rm \
  --label "$LABEL" --network none --userns=keep-id --user "$(id -u):$(id -g)" \
  --security-opt label=disable --workdir /workspace \
  --env PYTHONPATH=/workspace \
  --volume "${ROOT_DIR}:/workspace:ro" --volume "${TEST_DIR}:${TEST_DIR}:rw" \
  "$DEV_IMAGE" python3 \
  /workspace/tests/fixtures/pki-host-local-zot-one-runner/synthetic_signer.py \
  --request-dir "$REQUEST_PUBLICATION" \
  --trust-dir "${EXCHANGE_ROOT}/${SERVICE}/${REQUEST_ID}/trust" \
  --response-dir "$RESPONSE_SOURCE_DIR" \
  --approval-dir "$APPROVAL_DIR" \
  --reviewed-ca "$REVIEWED_CA_FILE" \
  --result-json "$SIGNER_RESULT" \
  --response-key "$RESPONSE_KEY" \
  --approver-key "$APPROVER_KEY" \
  --service "$SERVICE" --target "$TARGET" \
  --response-principal "$RESPONSE_PRINCIPAL" \
  --approver-principal "$APPROVER_PRINCIPAL" \
  --common-name "$COMMON_NAME" --dns-san "$TARGET" > "$SIGNER_LOG" 2>&1 < /dev/null; then
  print_file "$SIGNER_LOG"
  fail 'Synthetic offline signer failed'
fi
[[ ! -s "$SIGNER_LOG" ]] || fail 'Synthetic offline signer emitted unexpected command output'
openssl verify -CAfile "$REVIEWED_CA_FILE" \
  "${RESPONSE_SOURCE_DIR}/tls.crt" >/dev/null 2>&1 \
  || fail 'Synthetic response does not pass strict offline chain verification'
assert_exact_local_dir "$RESPONSE_SOURCE_DIR" \
  artifact tls.crt ca-chain.crt fullchain.crt response response.sig
assert_exact_local_dir "$APPROVAL_DIR" approval approval.sig
ssh-keygen -Y verify -f "${TRUST_SOURCE}/approvers.allowed_signers" \
  -I "$APPROVER_PRINCIPAL" -n platform-pki-csr-approval-v1 \
  -s "${APPROVAL_DIR}/approval.sig" < "${APPROVAL_DIR}/approval" >/dev/null 2>&1 \
  || fail 'Synthetic offline approval signature did not verify'
ARTIFACT_SHA256="$(jq -er '.artifact_sha256' "$SIGNER_RESULT")"
REVIEWED_CA_SHA256="$(jq -er '.reviewed_ca_sha256' "$SIGNER_RESULT")"
SERVED_INTERMEDIATE_SHA256="$(jq -er '.served_intermediate_sha256' "$SIGNER_RESULT")"
[[ "$(jq -er '.approval_sha256' "$SIGNER_RESULT")" == \
  "$(sha256sum "${APPROVAL_DIR}/approval" | while read -r value _; do printf '%s' "$value"; done)" ]] \
  || fail 'Signed response does not bind the synthetic approval digest'

BOUNDARY_FILE="${TEST_DIR}/validation-boundary-${REQUEST_ID}"
printf '%s\n' \
  'schema=1' \
  'kind=pki-validation-boundary' \
  "service=${SERVICE}" \
  "target=${TARGET}" \
  "local_validator=${TARGET}" \
  "remote_validator=${RUNNER}" \
  "endpoint=${ENDPOINT}" \
  'local_check=platform-zot-local-active-tls-v1' \
  'remote_check=platform-oci-v2-read-only-strict-tls-v1' > "$BOUNDARY_FILE"
chmod 0600 "$BOUNDARY_FILE" "$REVIEWED_CA_FILE"
BOUNDARY_SHA256="$(sha256sum "$BOUNDARY_FILE" | while read -r value _; do printf '%s' "$value"; done)"
TARGET_BOUNDARY="/etc/platform-pki-test/${REQUEST_ID}.boundary"
RUNNER_BOUNDARY="/etc/platform-pki-test/${REQUEST_ID}.boundary"
TARGET_CA="/etc/platform-pki-test/${REQUEST_ID}.ca"
RUNNER_CA="/etc/platform-pki-test/${REQUEST_ID}.ca"

for container in "$TARGET_CONTAINER" "$RUNNER_CONTAINER"; do
  timeout "$OPERATION_TIMEOUT" podman exec "$container" install -d -o root -g root -m 0700 /etc/platform-pki-test
  timeout "$OPERATION_TIMEOUT" podman cp "$BOUNDARY_FILE" "${container}:/tmp/${REQUEST_ID}.boundary"
  timeout "$OPERATION_TIMEOUT" podman cp "$REVIEWED_CA_FILE" "${container}:/tmp/${REQUEST_ID}.ca"
  timeout "$OPERATION_TIMEOUT" podman exec "$container" install -o root -g root -m 0600 \
    "/tmp/${REQUEST_ID}.boundary" "/etc/platform-pki-test/${REQUEST_ID}.boundary"
  timeout "$OPERATION_TIMEOUT" podman exec "$container" install -o root -g root -m 0600 \
    "/tmp/${REQUEST_ID}.ca" "/etc/platform-pki-test/${REQUEST_ID}.ca"
  timeout "$OPERATION_TIMEOUT" podman exec "$container" rm -f \
    "/tmp/${REQUEST_ID}.boundary" "/tmp/${REQUEST_ID}.ca"
done
timeout "$OPERATION_TIMEOUT" podman cp \
  "${ROOT_DIR}/roles/pki_host_local_certificate/files/platform-pki-zot-read-only-validate" \
  "${RUNNER_CONTAINER}:/tmp/platform-pki-zot-read-only-validate"
timeout "$OPERATION_TIMEOUT" podman exec "$RUNNER_CONTAINER" install -o root -g root -m 0755 \
  /tmp/platform-pki-zot-read-only-validate \
  /usr/local/libexec/platform-pki-zot-read-only-validate
timeout "$OPERATION_TIMEOUT" podman exec "$RUNNER_CONTAINER" rm -f \
  /tmp/platform-pki-zot-read-only-validate
[[ "$(sha256sum "${ROOT_DIR}/roles/pki_host_local_certificate/files/platform-pki-zot-read-only-validate" | while read -r value _; do printf '%s' "$value"; done)" == \
  "$(timeout "$OPERATION_TIMEOUT" podman exec "$RUNNER_CONTAINER" sha256sum \
    /usr/local/libexec/platform-pki-zot-read-only-validate | while read -r value _; do printf '%s' "$value"; done)" ]] \
  || fail 'Runner validator differs from the reviewed public helper'
write_vars

LAST_STAGE='controller response check and exact target response installation'
run_playbook response-check /workspace/playbooks/registry-pki-response-check.yml
run_playbook response-check-idempotent /workspace/playbooks/registry-pki-response-check.yml
assert_idempotent response-check-idempotent
assert_exact_local_dir "${EXCHANGE_ROOT}/${SERVICE}/${REQUEST_ID}/response" \
  artifact tls.crt ca-chain.crt fullchain.crt response response.sig

LAST_STAGE='direct first activation and strict local/external validation'
stage_direct_response
EXCHANGE_MODE=direct
write_vars
run_playbook activate /workspace/playbooks/registry-pki-activate.yml
DEPLOYMENT_SHA256="$(extract_coordinate "${LOG_DIR}/activate.log" deployment)"
timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl is-active --quiet zot.service \
  || fail 'Zot is not active after host-local certificate activation'
timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" systemctl is-enabled --quiet zot.service \
  || fail 'Zot is not enabled after first host-local certificate activation'
zot_container_image="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  podman inspect --format '{{.ImageName}}' zot)"
[[ "$zot_container_image" == "$ZOT_IMAGE" ]] \
  || fail "Running Zot did not use the exact role-selected image: ${zot_container_image}"
zot_image_id="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  podman image inspect --format '{{.Id}}' "$ZOT_IMAGE")"
[[ "$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  podman inspect --format '{{.Image}}' zot)" == "$zot_image_id" ]] \
  || fail 'Running Zot image ID differs from the role-selected image ID'
zot_tls_paths="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" python3 -c \
  'import json; value=json.load(open("/etc/zot/config.json", encoding="ascii")); print(value["http"]["tls"]["cert"]); print(value["http"]["tls"]["key"])')"
expected_tls_paths="${VERSIONS_ROOT}/${REQUEST_ID}/fullchain.crt
${VERSIONS_ROOT}/${REQUEST_ID}/tls.key"
[[ "$zot_tls_paths" == "$expected_tls_paths" ]] \
  || fail 'Zot configuration does not select the exact immutable request version'
assert_exact_target_dir "${VERSIONS_ROOT}/${REQUEST_ID}" \
  'artifact,ca-chain.crt,fullchain.crt,response,response.sig,tls.crt,tls.csr,tls.key'
for key_path in "${PENDING_ROOT}/${REQUEST_ID}/tls.key" "${VERSIONS_ROOT}/${REQUEST_ID}/tls.key"; do
  [[ "$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" stat -c '%U:%G:%a:%h' "$key_path")" == root:root:600:1 ]] \
    || fail "Target-local key metadata is unsafe: ${key_path}"
done
EXCHANGE_MODE=controller-local
write_vars
run_playbook zot-host-local /workspace/tests/fixtures/pki-host-local-zot-one-runner/zot.yml
run_playbook zot-host-local-idempotent /workspace/tests/fixtures/pki-host-local-zot-one-runner/zot.yml
assert_idempotent zot-host-local-idempotent
TARGET_EVIDENCE="${STATE_ROOT}/evidence/${REQUEST_ID}/${DEPLOYMENT_SHA256}"
assert_exact_target_dir "$TARGET_EVIDENCE" \
  'deployment,deployment.sig,validation-boundary,validation-result,validation-result.sig'
write_vars

LAST_STAGE='exact evidence export, authenticated status, and decision preflight'
run_playbook evidence-export /workspace/playbooks/registry-pki-evidence-export.yml
EXPORTED_EVIDENCE="${EXCHANGE_ROOT}/${SERVICE}/${REQUEST_ID}/evidence/${DEPLOYMENT_SHA256}"
assert_exact_local_dir "$EXPORTED_EVIDENCE" \
  deployment deployment.sig validation-boundary validation-result validation-result.sig
run_playbook evidence-export-idempotent /workspace/playbooks/registry-pki-evidence-export.yml
assert_idempotent evidence-export-idempotent
run_playbook exported-status /workspace/playbooks/registry-pki-status.yml
grep -Fq 'evidence-exported' "${LOG_DIR}/exported-status.log" \
  || fail 'Authenticated lifecycle status did not report evidence-exported'
run_playbook exported-status-check /workspace/playbooks/registry-pki-status.yml --check
run_playbook decision-preflight /workspace/playbooks/registry-pki-decision-preflight.yml
grep -Fq 'result=passed' "${LOG_DIR}/decision-preflight.log" \
  || fail 'Decision preflight did not publish a passed exact-coordinate summary'

LAST_STAGE='final custody, method, and isolation assertions'
TARGET_KEY_SHA256="$(timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  sha256sum "${VERSIONS_ROOT}/${REQUEST_ID}/tls.key" | while read -r value _; do printf '%s' "$value"; done)"
validator_source="${ROOT_DIR}/roles/pki_host_local_certificate/files/platform-pki-zot-read-only-validate"
[[ "$(grep -Fc 'GET /v2/ HTTP/1.1' "$validator_source")" -eq 1 ]] \
  || fail 'Reviewed runner validator does not contain one exact GET /v2/ request constructor'
if grep -Eq '(^|[^A-Z])(POST|PUT|PATCH|DELETE) /v2/' "$validator_source"; then
  fail 'Reviewed runner validator contains a mutating OCI method'
fi
if grep -REq -- '--tls-verify=false|--insecure-skip-tls-verify|curl[[:space:]].*(-k|--insecure)' "$LOG_DIR"; then
  fail 'A command log contains an insecure TLS option'
fi
for protected_root in "$EXCHANGE_ROOT" "$SIGNER_ROOT" "$SIGNER_MEDIA" "$LOG_DIR"; do
  if find "$protected_root" -name tls.key -print -quit | grep -q .; then
    fail "Private target key basename escaped into protected harness state: ${protected_root}"
  fi
  while IFS= read -r file; do
    [[ "$(sha256sum "$file" | while read -r value _; do printf '%s' "$value"; done)" != "$TARGET_KEY_SHA256" ]] \
      || fail "Target private-key material escaped into protected harness state: ${protected_root}"
  done < <(find "$protected_root" -type f -print)
done
if grep -RFl 'tls.key' "$LOG_DIR" | grep -q .; then
  fail 'A command log contains a private-key basename'
fi
if grep -REl -- '-----BEGIN (EC |RSA |OPENSSH )?PRIVATE KEY-----' "$LOG_DIR" | grep -q .; then
  fail 'A command log contains private-key PEM material'
fi
if timeout "$OPERATION_TIMEOUT" podman exec "$RUNNER_CONTAINER" \
  bash -c 'find / -xdev -name tls.key -print -quit 2>/dev/null | grep -q .'; then
  fail 'Target private-key material appeared on the delegated runner'
fi
if timeout "$OPERATION_TIMEOUT" podman exec \
  --env "TARGET_KEY_SHA256=${TARGET_KEY_SHA256}" "$RUNNER_CONTAINER" bash -c \
  'while IFS= read -r file; do
     test "$(sha256sum "$file" | while read -r value _; do printf "%s" "$value"; done)" != "$TARGET_KEY_SHA256" || exit 1
   done < <(find / -xdev -type f -print 2>/dev/null)'; then
  :
else
  fail 'Target private-key material appeared on the delegated runner'
fi
for root in "$EXCHANGE_ROOT" "$SIGNER_ROOT"; do
  if find "$root" \( -name latest -o -name current \) -print -quit | grep -q .; then
    fail "A moving coordinate appeared in exact PKI harness state: ${root}"
  fi
done
if timeout "$OPERATION_TIMEOUT" podman exec "$TARGET_CONTAINER" \
  bash -c 'find /etc/zot/tls-pending /etc/zot/tls-versions -mindepth 1 \( -name latest -o -name current \) -print -quit | grep -q .'; then
  fail 'A moving latest/current coordinate appeared in target PKI state'
fi
network_members="$(timeout "$OPERATION_TIMEOUT" podman network inspect \
  --format '{{range .Containers}}{{println .Name}}{{end}}' "$NETWORK")"
member_count=0
while IFS= read -r member; do
  [[ -z "$member" ]] || ((member_count += 1))
done <<< "$network_members"
[[ "$member_count" -eq 2 ]] || fail 'Isolated network identity count changed during the lane'

printf '%s\n' \
  "PKI/Zot one-runner integration passed: request=${REQUEST_ID} artifact=${ARTIFACT_SHA256} deployment=${DEPLOYMENT_SHA256}"
