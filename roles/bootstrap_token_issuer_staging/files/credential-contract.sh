#!/usr/bin/env bash
set -uo pipefail

kubectl_bin="${KUBECTL_BIN:-kubectl}"
namespace="${STAGING_NAMESPACE:?}"
service_name="${STAGING_SERVICE_NAME:?}"
service_port_name="${STAGING_SERVICE_PORT_NAME:?}"
bootstrap_group="${STAGING_BOOTSTRAP_GROUP:?}"
ttl_seconds="${STAGING_TTL_SECONDS:?}"
request_timeout="${STAGING_REQUEST_TIMEOUT_SECONDS:?}"
revoke_wait="${STAGING_REVOKE_PROPAGATION_SECONDS:?}"
state_dir="${STAGING_STATE_DIR:?}"
run_id="${STAGING_RUN_ID:?}"
run_csr_check="${STAGING_RUN_CSR_CHECK:-true}"
proxy_path="/api/v1/namespaces/${namespace}/services/${service_name}:${service_port_name}/proxy"

issue_contract=not_run
bootstrap_identity=not_run
bootstrap_group_status=not_run
token_secret_present=not_run
revoke_contract=not_run
token_secret_absent=not_run
credential_rejected=not_run
admin_auth_healthy=not_run
redaction_enforced=not_run
csr_check=not_run

emit_result() {
  jq -n -c \
    --arg issue_contract "$issue_contract" \
    --arg bootstrap_identity "$bootstrap_identity" \
    --arg bootstrap_group "$bootstrap_group_status" \
    --arg token_secret_present "$token_secret_present" \
    --arg revoke_contract "$revoke_contract" \
    --arg token_secret_absent "$token_secret_absent" \
    --arg credential_rejected "$credential_rejected" \
    --arg admin_auth_healthy "$admin_auth_healthy" \
    --arg redaction_enforced "$redaction_enforced" \
    --arg csr_check "$csr_check" \
    '{issue_contract: $issue_contract, bootstrap_identity: $bootstrap_identity,
      bootstrap_group: $bootstrap_group, token_secret_present: $token_secret_present,
      revoke_contract: $revoke_contract, token_secret_absent: $token_secret_absent,
      credential_rejected: $credential_rejected, admin_auth_healthy: $admin_auth_healthy,
      redaction_enforced: $redaction_enforced, csr_check: $csr_check}'
}

fail_check() {
  printf -v "$1" '%s' fail
  emit_result
  exit 1
}

kctl() {
  "$kubectl_bin" --context "${KUBE_CONTEXT:?}" --request-timeout="${request_timeout}s" "$@"
}

raw_post_file() {
  local path="$1"
  local body_file="$2"
  timeout "${request_timeout}s" "$kubectl_bin" --context "${KUBE_CONTEXT:?}" \
    create --raw "$path" -f "$body_file" 2>/dev/null
}

cleanup_exact() {
  local token_id=""
  local csr_name=""
  local body_file="$state_dir/cleanup-revoke.json"
  local cleanup_rc=0

  if [[ -f "$state_dir/token-id" ]]; then
    token_id="$(<"$state_dir/token-id")"
  fi
  if [[ "$token_id" =~ ^[a-z0-9]{6}$ ]]; then
    jq -n --arg token_id "$token_id" '{tokenId: $token_id}' >"$body_file"
    raw_post_file "$proxy_path/v1/bootstrap-token/revoke" "$body_file" >/dev/null 2>&1 || true
    kctl -n kube-system delete secret "bootstrap-token-$token_id" --ignore-not-found >/dev/null 2>&1 || cleanup_rc=1
    if kctl -n kube-system get secret "bootstrap-token-$token_id" >/dev/null 2>&1; then
      cleanup_rc=1
    fi
  fi
  if [[ -f "$state_dir/csr-name" ]]; then
    csr_name="$(<"$state_dir/csr-name")"
  fi
  if [[ "$csr_name" =~ ^[a-z0-9.-]+$ ]]; then
    kctl delete certificatesigningrequest "$csr_name" --ignore-not-found >/dev/null 2>&1 || cleanup_rc=1
    if kctl get certificatesigningrequest "$csr_name" >/dev/null 2>&1; then
      cleanup_rc=1
    fi
  fi
  return "$cleanup_rc"
}

if [[ "${1:-}" == cleanup ]]; then
  cleanup_exact
  exit $?
fi
if [[ "${1:-}" != validate ]]; then
  exit 2
fi

mkdir -p "$state_dir"
chmod 0700 "$state_dir"

expected_api_server="$(kctl -n "$namespace" get configmap "$service_name" \
  -o jsonpath='{.data.ISSUER_BOOTSTRAP_API_SERVER}' 2>/dev/null)" || fail_check issue_contract
[[ -n "$expected_api_server" ]] || fail_check issue_contract
ttl_seconds="$(kctl -n "$namespace" get configmap "$service_name" \
  -o jsonpath='{.data.ISSUER_MIN_TTL_SECONDS}' 2>/dev/null)" || fail_check issue_contract
[[ "$ttl_seconds" =~ ^[1-9][0-9]*$ ]] || fail_check issue_contract

issue_body_file="$state_dir/issue.json"
jq -n --arg user "staging-validation" --arg reason "manual-recovery" \
  --argjson ttl "$ttl_seconds" '{user: $user, reason: $reason, ttlSeconds: $ttl}' >"$issue_body_file"
issue_response="$(raw_post_file "$proxy_path/v1/bootstrap-token/issue" "$issue_body_file")" || fail_check issue_contract
token_id="$(jq -r '.tokenId // ""' <<<"$issue_response" 2>/dev/null)" || fail_check issue_contract
expires_at="$(jq -r '.expiresAt // ""' <<<"$issue_response" 2>/dev/null)" || fail_check issue_contract
bootstrap_kubeconfig="$(jq -r '.bootstrapKubeconfig // ""' <<<"$issue_response" 2>/dev/null)" || fail_check issue_contract
[[ "$token_id" =~ ^[a-z0-9]{6}$ ]] || fail_check issue_contract
printf '%s' "$token_id" >"$state_dir/token-id"
chmod 0600 "$state_dir/token-id"
jq -e '.expiresAt | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")' \
  <<<"$issue_response" >/dev/null 2>&1 || fail_check issue_contract
jq -e --argjson ttl "$ttl_seconds" \
  '(.expiresAt | fromdateiso8601) as $expires | $expires > now and $expires <= (now + $ttl + 5)' \
  <<<"$issue_response" >/dev/null 2>&1 || fail_check issue_contract
[[ "$bootstrap_kubeconfig" == *"server: $expected_api_server"* ]] || fail_check issue_contract
printf '%s\n' "$bootstrap_kubeconfig" >"$state_dir/bootstrap.kubeconfig"
chmod 0600 "$state_dir/bootstrap.kubeconfig"
bearer_token="$("$kubectl_bin" --kubeconfig "$state_dir/bootstrap.kubeconfig" config view --raw \
  -o jsonpath='{.users[0].user.token}' 2>/dev/null)" || fail_check issue_contract
[[ "$bearer_token" =~ ^${token_id}\.[a-z0-9]{16}$ ]] || fail_check issue_contract
issue_contract=pass

bootstrap_username="$(timeout "${request_timeout}s" "$kubectl_bin" --request-timeout="${request_timeout}s" \
  --kubeconfig "$state_dir/bootstrap.kubeconfig" auth whoami \
  -o jsonpath='{.status.userInfo.username}' 2>/dev/null)" || fail_check bootstrap_identity
[[ "$bootstrap_username" == "system:bootstrap:$token_id" ]] || fail_check bootstrap_identity
bootstrap_identity=pass

bootstrap_groups="$(timeout "${request_timeout}s" "$kubectl_bin" --request-timeout="${request_timeout}s" \
  --kubeconfig "$state_dir/bootstrap.kubeconfig" auth whoami \
  -o jsonpath='{range .status.userInfo.groups[*]}{.}{"\n"}{end}' 2>/dev/null)" || fail_check bootstrap_group_status
grep -Fxq "$bootstrap_group" <<<"$bootstrap_groups" || fail_check bootstrap_group_status
bootstrap_group_status=pass

secret_json="$(kctl -n kube-system get secret "bootstrap-token-$token_id" -o json 2>/dev/null)" || fail_check token_secret_present
jq -e --arg id "$token_id" --arg secret "${bearer_token#*.}" --arg expires "$expires_at" --arg group "$bootstrap_group" '
  .type == "bootstrap.kubernetes.io/token" and
  (.data["token-id"] | @base64d) == $id and
  (.data["token-secret"] | @base64d) == $secret and
  (.data.expiration | @base64d) == $expires and
  (.data["usage-bootstrap-authentication"] | @base64d) == "true" and
  ((.data["auth-extra-groups"] | @base64d | split(",")) | index($group) != null)
' <<<"$secret_json" >/dev/null 2>&1 || fail_check token_secret_present
token_secret_present=pass

if [[ "$run_csr_check" == true ]]; then
  can_create_csr="$(timeout "${request_timeout}s" "$kubectl_bin" --request-timeout="${request_timeout}s" \
    --kubeconfig "$state_dir/bootstrap.kubeconfig" auth can-i create certificatesigningrequests 2>/dev/null)" \
    || fail_check csr_check
  [[ "$can_create_csr" == yes ]] || fail_check csr_check
  csr_name="$(tr '[:upper:]_' '[:lower:]-' <<<"${run_id}-csr")"
  printf '%s' "$csr_name" >"$state_dir/csr-name"
  openssl genrsa -out "$state_dir/csr.key" 2048 >/dev/null 2>&1 || fail_check csr_check
  openssl req -new -key "$state_dir/csr.key" -subj "/CN=system:bootstrap:$token_id" \
    -out "$state_dir/csr.pem" >/dev/null 2>&1 || fail_check csr_check
  csr_request="$(base64 -w 0 <"$state_dir/csr.pem")" || fail_check csr_check
  jq -n --arg name "$csr_name" --arg request "$csr_request" '{apiVersion: "certificates.k8s.io/v1", kind: "CertificateSigningRequest", metadata: {name: $name}, spec: {request: $request, signerName: "staging.platform.example/bootstrap-validation", expirationSeconds: 600, usages: ["client auth"]}}' >"$state_dir/csr.json"
  timeout "${request_timeout}s" "$kubectl_bin" --request-timeout="${request_timeout}s" \
    --kubeconfig "$state_dir/bootstrap.kubeconfig" create -f "$state_dir/csr.json" >/dev/null 2>&1 || fail_check csr_check
  csr_json="$(kctl get certificatesigningrequest "$csr_name" -o json 2>/dev/null)" || fail_check csr_check
  jq -e --arg username "system:bootstrap:$token_id" --arg group "$bootstrap_group" \
    '.spec.username == $username and (.spec.groups | index($group) != null) and ((.status.conditions // []) | length == 0)' \
    <<<"$csr_json" >/dev/null 2>&1 || fail_check csr_check
  kctl delete certificatesigningrequest "$csr_name" >/dev/null 2>&1 || fail_check csr_check
  rm -f "$state_dir/csr-name"
  csr_check=pass
fi

revoke_body_file="$state_dir/revoke.json"
jq -n --arg token_id "$token_id" '{tokenId: $token_id}' >"$revoke_body_file"
revoke_response="$(raw_post_file "$proxy_path/v1/bootstrap-token/revoke" "$revoke_body_file")" || fail_check revoke_contract
jq -e 'type == "object" and .revoked == true' <<<"$revoke_response" >/dev/null 2>&1 || fail_check revoke_contract

if kctl -n kube-system get secret "bootstrap-token-$token_id" >/dev/null 2>&1; then
  fail_check token_secret_absent
fi
token_secret_absent=pass

deadline=$((SECONDS + revoke_wait))
while ((SECONDS <= deadline)); do
  auth_error=""
  if timeout "${request_timeout}s" "$kubectl_bin" --request-timeout="${request_timeout}s" \
    --kubeconfig "$state_dir/bootstrap.kubeconfig" auth whoami >/dev/null 2>"$state_dir/auth-error"; then
    :
  else
    auth_error="$(<"$state_dir/auth-error")"
    if [[ "$auth_error" == *Unauthorized* || "$auth_error" == *"provide credentials"* ]]; then
      if kctl auth whoami >/dev/null 2>&1; then
        credential_rejected=pass
        admin_auth_healthy=pass
        break
      fi
      fail_check admin_auth_healthy
    fi
  fi
  sleep 5
done
[[ "$credential_rejected" == pass ]] || fail_check credential_rejected

second_revoke_response="$(raw_post_file "$proxy_path/v1/bootstrap-token/revoke" "$revoke_body_file")" || fail_check revoke_contract
jq -e 'type == "object" and .revoked == false' <<<"$second_revoke_response" >/dev/null 2>&1 || fail_check revoke_contract
revoke_contract=pass

issuer_pods_json="$(kctl -n "$namespace" get pods \
  -l "app.kubernetes.io/name=$service_name" -o json 2>/dev/null)" || fail_check redaction_enforced
jq -e '.items | length > 0' <<<"$issuer_pods_json" >/dev/null 2>&1 || fail_check redaction_enforced
mapfile -t issuer_pod_rows < <(jq -r '.items[] |
  [.metadata.name, ([.status.containerStatuses[]? | select(.name == "issuer") | .restartCount][0] // 0)] |
  @tsv' <<<"$issuer_pods_json")
issuer_logs=""
for issuer_pod_row in "${issuer_pod_rows[@]}"; do
  IFS=$'\t' read -r issuer_pod restart_count <<<"$issuer_pod_row"
  current_logs="$(kctl -n "$namespace" logs "$issuer_pod" -c issuer 2>/dev/null)" \
    || fail_check redaction_enforced
  previous_logs=""
  if ((restart_count > 0)); then
    previous_logs="$(kctl -n "$namespace" logs "$issuer_pod" -c issuer --previous 2>/dev/null)" \
      || fail_check redaction_enforced
  fi
  issuer_logs+=$'\n'"$current_logs"$'\n'"$previous_logs"
done
if grep -Fq -- "$token_id" <<<"$issuer_logs" || \
   grep -Fq -- "$bearer_token" <<<"$issuer_logs" || \
   grep -Fq -- "$bootstrap_kubeconfig" <<<"$issuer_logs" || \
   grep -Fq -- "$issue_response" <<<"$issuer_logs"; then
  fail_check redaction_enforced
fi
redaction_enforced=pass

rm -f "$state_dir/token-id"
emit_result
